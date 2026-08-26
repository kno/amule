//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2026 aMule Team ( https://amule-org.github.io )
//
// Any parts of this program derived from the xMule, lMule or eMule project,
// or contributed by third-party developers are copyrighted by their
// respective authors.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA
//

#ifndef QUICSOCKETTRANSPORT_H
#define QUICSOCKETTRANSPORT_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

#include "NetworkAddress.h"  // Needed for CNetworkAddress
#include "QuicContext.h"     // Needed for IQuicStreamWriter
#include "StreamTransport.h" // Needed for IStreamTransport

/**
 * A validated QUIC connection wearing the shape CLibSocket presents upwards.
 *
 * The QUIC twin of CUtpSocketTransport, and the piece task 2.1 was missing: the
 * adapter could complete a handshake and validate a peer proof, and then had
 * nowhere to put the bytes. `CQuicConnection::ReceiveStreamBytes()` named the
 * seam and dropped what arrived past it, because a stream nothing could reach
 * would have been dead code no test could exercise. It is reachable now that
 * FindExpectation() has a source.
 *
 * Three properties differ from the uTP transport, and each is a consequence of
 * QUIC rather than a choice:
 *
 *   - **There is no separate connect event.** A QUIC connection reaches this
 *     object only after its handshake completed *and* its 37-byte peer proof
 *     validated, because that is when the adapter creates it. So it is connected
 *     on arrival, and OnStreamTransportConnected() fires once, from the accept
 *     path -- there is no state to wait for and a transport that waited for one
 *     would refuse every write for the life of the connection.
 *   - **Reads are already ordered and complete.** QUIC delivers stream bytes in
 *     order with no gaps, so the receive side is a plain byte queue and needs
 *     none of CUtpStream's reassembly.
 *   - **The proof is never visible here.** The adapter consumes the 37-byte
 *     record before this object exists, so the first byte this transport ever
 *     hands upwards is the first byte of the ed2k hello. Anything else would put
 *     five magic bytes into CEncryptedStreamSocket.
 *
 * The threading rule is the uTP transport's, unchanged and for the identical
 * reason: **ngtcp2 is only ever entered from the thread that owns it.**
 * CUpDownClient's send path runs on the upload throttler's thread
 * (CEMSocket::SendFileAndControlData), so Write() only queues -- under this
 * object's own mutex, because the library's callbacks deliver on the core
 * thread -- and the queue is handed to ngtcp2 on the tick, which is the core
 * thread. Calling into ngtcp2 from the throttler thread would corrupt its
 * per-connection state with no reliable symptom.
 *
 * Free of ngtcp2, GnuTLS, wxWidgets and theApp: the library sits behind
 * IQuicStreamWriter, so every behaviour below is assertable in the default
 * -DENABLE_QUIC=NO build, which is the only one macOS gets.
 */
class CQuicSocketTransport : public IStreamTransport
{
public:
	CQuicSocketTransport(const CNetworkAddress &peer, std::uint16_t port)
	: m_peer(peer)
	, m_port(port)
	{
	}

	/**
	 * Clears the writer's back-pointer before letting go of it.
	 *
	 * The two objects point at each other and either may die first: this one is
	 * owned by a CClientTCPSocket that the ordinary teardown paths delete, while
	 * the connection is owned by the endpoint and dies when ngtcp2 closes it. So
	 * each side detaches the other, and both directions are needed -- one alone
	 * leaves a dangling pointer on whichever path was not taken.
	 */
	~CQuicSocketTransport() override
	{
		IQuicStreamWriter *writer = nullptr;
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			writer = m_writer;
			m_writer = nullptr;
		}

		if (writer != nullptr) {
			writer->DetachStreamTransport();
			writer->CloseQuicStream();
		}
	}

	CQuicSocketTransport(const CQuicSocketTransport &) = delete;
	CQuicSocketTransport &operator=(const CQuicSocketTransport &) = delete;

	/**
	 * Bind this transport to the connection that will carry its bytes.
	 *
	 * @param writer  the validated connection. Connected on arrival -- see the
	 *        class comment.
	 */
	void AttachWriter(IQuicStreamWriter *writer)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_writer = writer;
		m_connected = writer != nullptr;
	}

	//! Who receives connect/readable/writable/lost. NULL until the socket
	//! wrapper attaches itself, which is safe: nothing is delivered before the
	//! first callback from the connection.
	void SetEventSink(IStreamTransportEvents *sink)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_sink = sink;
	}

	bool IsConnected() const override
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_connected && !m_closed;
	}

	bool IsOk() const override { return IsConnected(); }

	std::uint32_t Read(void *buffer, std::uint32_t nbytes) override
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		if (buffer == nullptr || nbytes == 0) {
			return 0;
		}

		const std::size_t taken =
			(m_readQueue.size() < nbytes) ? m_readQueue.size() : (std::size_t)nbytes;
		if (taken == 0) {
			// Zero with the flag set and LastError() still zero: CEMSocket
			// tests BlocksRead() before LastError(), so an error here would
			// turn "nothing right now" into a dropped connection.
			m_blocksRead = true;
			return 0;
		}

		std::memcpy(buffer, m_readQueue.data(), taken);
		m_readQueue.erase(m_readQueue.begin(), m_readQueue.begin() + (long)taken);
		m_blocksRead = m_readQueue.empty();
		return (std::uint32_t)taken;
	}

	/**
	 * Queue bytes for the peer.
	 *
	 * Arrives on the upload throttler's thread as well as the core thread, so it
	 * only ever queues; the hand-off to ngtcp2 happens on the tick. See the
	 * class comment for why entering ngtcp2 from the wrong thread has no
	 * reliable symptom.
	 *
	 * The queue is bounded. Without a bound, a peer that stops reading would
	 * have this end buffering everything the throttler produces -- and the
	 * throttler produces at the configured upload rate, indefinitely. Over the
	 * bound the write blocks, which is the TCP convention the layers above
	 * already implement.
	 */
	std::uint32_t Write(const void *buffer, std::uint32_t nbytes) override
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		if (buffer == nullptr || nbytes == 0) {
			return 0;
		}

		if (!m_connected || m_closed || m_writer == nullptr) {
			// Not usable yet or any more. Blocked rather than failed while the
			// connection is merely not up: the caller retries on the send
			// event, exactly as it does for a TCP connect in flight.
			m_blocksWrite = true;
			return 0;
		}

		if (m_writeQueue.size() >= kMaxWriteQueueBytes) {
			m_blocksWrite = true;
			return 0;
		}

		const std::size_t room = kMaxWriteQueueBytes - m_writeQueue.size();
		const std::size_t accepted = (nbytes < room) ? (std::size_t)nbytes : room;
		const std::uint8_t *bytes = static_cast<const std::uint8_t *>(buffer);
		m_writeQueue.insert(m_writeQueue.end(), bytes, bytes + accepted);
		m_blocksWrite = accepted < nbytes;
		return (std::uint32_t)accepted;
	}

	//! Ordinary close. Does not set a failure: a closed connection and a failed
	//! one are different answers, and only the second must keep the peer
	//! blameless.
	void Close() override
	{
		IQuicStreamWriter *writer = nullptr;
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			if (m_closed) {
				return;
			}
			m_closed = true;
			writer = m_writer;
		}

		if (writer != nullptr) {
			writer->CloseQuicStream();
		}
	}

	bool BlocksRead() const override
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_blocksRead;
	}

	bool BlocksWrite() const override
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_blocksWrite;
	}

	/**
	 * Zero while healthy or merely blocked, non-zero once failed.
	 *
	 * The value carries no meaning beyond that -- see IStreamTransport. What a
	 * QUIC failure *means* travels the other route entirely, through
	 * IQuicConnectionObserver, because that is the one that has to keep an
	 * authentication failure distinguishable from a timeout.
	 */
	int LastError() const override
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_failed ? QUIC_TRANSPORT_LAST_ERROR : 0;
	}

	const CNetworkAddress &GetPeerAddress() const override { return m_peer; }
	std::uint16_t GetPeerPort() const override { return m_port; }

	//
	// Driven by the QUIC connection, through IQuicStreamWriter's owner. All on
	// the core thread.
	//

	/**
	 * Stream bytes arrived from the peer, past the proof.
	 *
	 * Only ever called after the 37-byte proof validated -- the adapter does not
	 * create this object before then -- so the first byte delivered here is the
	 * first byte of the ed2k hello.
	 */
	void OnQuicStreamData(const std::uint8_t *data, std::size_t length)
	{
		IStreamTransportEvents *sink = nullptr;

		{
			std::lock_guard<std::mutex> lock(m_mutex);
			if (data == nullptr || length == 0) {
				return;
			}
			m_readQueue.insert(m_readQueue.end(), data, data + length);
			m_blocksRead = false;
			sink = m_sink;
		}

		if (sink != nullptr) {
			sink->OnStreamTransportReadable();
		}
	}

	//! The connection is gone, for any reason. The writer is dropped here rather
	//! than in the destructor's path, because the object it points at is being
	//! destroyed by its own owner and must not be called again.
	void OnQuicStreamLost(bool failed)
	{
		IStreamTransportEvents *sink = nullptr;

		{
			std::lock_guard<std::mutex> lock(m_mutex);
			m_writer = nullptr;
			m_closed = true;
			m_failed = m_failed || failed;
			sink = m_sink;
		}

		if (sink != nullptr) {
			sink->OnStreamTransportLost();
		}
	}

	/**
	 * The tick: hand queued bytes to ngtcp2.
	 *
	 * The only place the write queue is drained, and therefore the only place
	 * ngtcp2 is entered from -- which is what confines it to the core thread.
	 * A partial acceptance is ordinary: ngtcp2's stream window is finite and the
	 * remainder goes on the next tick.
	 */
	void OnQuicTick()
	{
		IStreamTransportEvents *sink = nullptr;
		bool writable = false;

		{
			std::lock_guard<std::mutex> lock(m_mutex);
			if (m_closed || m_writer == nullptr || m_writeQueue.empty()) {
				return;
			}

			const std::size_t accepted =
				m_writer->WriteQuicStream(m_writeQueue.data(), m_writeQueue.size());
			if (accepted == 0) {
				return;
			}

			const std::size_t taken =
				(accepted < m_writeQueue.size()) ? accepted : m_writeQueue.size();
			m_writeQueue.erase(m_writeQueue.begin(), m_writeQueue.begin() + (long)taken);

			if (m_blocksWrite && m_writeQueue.size() < kMaxWriteQueueBytes) {
				m_blocksWrite = false;
				writable = true;
				sink = m_sink;
			}
		}

		if (writable && sink != nullptr) {
			sink->OnStreamTransportWritable();
		}
	}

	//! How much this end has buffered but not yet handed upwards. For the
	//! bound's tests; nothing in the transport branches on it.
	std::size_t GetPendingReadBytes() const
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_readQueue.size();
	}

	std::size_t GetPendingWriteBytes() const
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_writeQueue.size();
	}

	/**
	 * The write queue's ceiling.
	 *
	 * 256 kB is four times the stream window the adapter advertises
	 * (initial_max_stream_data_bidi_local, QuicLibraryAdapter.cpp), so an
	 * ordinary connection whose peer is reading never reaches it, and one whose
	 * peer has stopped reading reports blocked instead of growing without limit.
	 */
	static const std::size_t kMaxWriteQueueBytes = 256 * 1024;

private:
	//! Non-zero, and nothing more. See LastError().
	static const int QUIC_TRANSPORT_LAST_ERROR = -1;

	CNetworkAddress m_peer;
	std::uint16_t m_port = 0;

	//! Guards everything below. Write() arrives on the upload throttler's
	//! thread; every other caller is the core thread.
	mutable std::mutex m_mutex;

	IQuicStreamWriter *m_writer = nullptr;
	IStreamTransportEvents *m_sink = nullptr;

	std::vector<std::uint8_t> m_readQueue;
	std::vector<std::uint8_t> m_writeQueue;

	bool m_connected = false;
	bool m_blocksRead = false;
	bool m_blocksWrite = false;
	bool m_closed = false;
	bool m_failed = false;
};

#endif // QUICSOCKETTRANSPORT_H
