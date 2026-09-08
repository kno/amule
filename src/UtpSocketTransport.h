//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2026 aMule Team ( https://amule-org.github.io )
//
// Parts of this file are ported from eMule AI's CUtpSocket:
// Copyright (C) 2013 David Xanatos ( XanatosDavid (a) gmail.com / http://NeoLoader.to )
// Copyright (C) 2026 eMule AI
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

#ifndef UTPSOCKETTRANSPORT_H
#define UTPSOCKETTRANSPORT_H

#include <cstddef>
#include <cstdint>
#include <mutex>

#include "NetworkAddress.h"      // Needed for CNetworkAddress
#include "StreamTransport.h"     // Needed for IStreamTransport / IStreamTransportEvents
#include "UtpContext.h"          // Needed for CUtpContext / IUtpTickable
#include "UtpStream.h"           // Needed for CUtpStream
#include "UtpTransportFailure.h" // Needed for EUtpAttemptOutcome

/**
 * A uTP connection wearing the shape CLibSocket presents to everything above
 * it.
 *
 * This is the substitution the change was missing. CUtpStream (UtpStream.h)
 * already presented aMule's Write/Read convention over libutp, but nothing put
 * it underneath a socket, so uTP carried no data. A CLibSocket that has one of
 * these routes Read/Write/IsConnected/IsOk/BlocksRead/BlocksWrite/Close and the
 * peer accessors through it instead of through its asio TCP socket, and
 * CEncryptedStreamSocket, CEMSocket and CClientTCPSocket above it are unchanged
 * -- they were always talking to that interface, not to TCP.
 *
 * Two properties are load-bearing and neither is obvious.
 *
 * **The would-block contract is exact.** CEMSocket checks BlocksRead() and
 * BlocksWrite() *before* LastError() (EMSocket.cpp:240, :658), so "nothing right
 * now" must be a zero return with the blocks flag set and LastError() still
 * zero. Report an error there instead and an ordinary closed send window
 * becomes a dropped connection.
 *
 * **utp_write() is only ever called from the thread that owns libutp.**
 * CUpDownClient's send path runs on the upload throttler's thread
 * (CEMSocket::SendFileAndControlData), so Write() only queues -- under this
 * object's own mutex, because libutp's callbacks deliver on the core thread --
 * and the queue is handed to libutp on the tick, which is the core thread. A
 * utp_write() from the throttler thread would corrupt libutp's per-context
 * state with no reliable symptom.
 */

// How a uTP connection reports itself upwards is IStreamTransportEvents
// (StreamTransport.h), shared with the QUIC transport. It used to be a uTP-named
// interface here; it moved when the second transport arrived, because both post
// exactly the same four CoreNotify_LibSocket* events and two interfaces would
// have meant two notifiers in LibSocketAsio.cpp saying the same thing.

class CUtpSocketTransport : public IUtpTickable, public IStreamTransport
{
public:
	CUtpSocketTransport(CUtpContext &context, const CNetworkAddress &peer, std::uint16_t port)
	: m_context(context)
	, m_peer(peer)
	, m_port(port)
	{
		m_context.RegisterTickable(this);
	}

	~CUtpSocketTransport() override
	{
		m_context.UnregisterTickable(this);
		// Clears the socket's user data before utp_close(), so a callback
		// arriving while libutp flushes cannot reach this object after it is
		// gone. See IUtpLibrary::CloseSocket().
		m_context.CloseSocket(m_socket);
		m_socket = nullptr;
	}

	CUtpSocketTransport(const CUtpSocketTransport &) = delete;
	CUtpSocketTransport &operator=(const CUtpSocketTransport &) = delete;

	/**
	 * Bind this transport to a libutp socket, after a dial or an accept.
	 *
	 * @param socket    a `utp_socket *`.
	 * @param connected true for an accepted connection, which libutp has
	 *                  already handshaken by the time it hands it over. An
	 *                  outbound dial is not connected until UTP_STATE_CONNECT.
	 */
	void AttachSocket(void *socket, bool connected = false)
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_socket = socket;
		m_stream.Attach(m_context.GetLibrary(), socket);
		if (connected) {
			m_stream.OnConnected();
		}
	}

	//! Who receives connect/readable/writable/lost. NULL until the socket
	//! wrapper attaches itself, which is safe: nothing is delivered before the
	//! first callback from libutp.
	void SetEventSink(IStreamTransportEvents *sink) { m_sink = sink; }

	bool IsAttached() const
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_socket != nullptr;
	}

	//! Mirrors CAsioSocketImpl::IsConnected(): true only once the handshake
	//! completed.
	bool IsConnected() const override
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_stream.IsConnected() && !m_closed;
	}

	/**
	 * Mirrors CAsioSocketImpl::IsOk(): true once the connection is usable.
	 *
	 * CUpDownClient::ConnectToCurrentCandidate() dials only when this is
	 * false, exactly as for TCP, where a connect in flight also reports false.
	 * A second dial while a uTP attempt is pending is prevented by the attempt
	 * itself, not by this -- see CUpDownClient::ConnectOverUtp().
	 */
	bool IsOk() const override { return IsConnected(); }

	/**
	 * Read what the peer sent.
	 *
	 * @return bytes copied. Zero with BlocksRead() true is "nothing right
	 *         now", which is what CEMSocket expects; LastError() stays zero.
	 */
	std::uint32_t Read(void *buffer, std::uint32_t nbytes) override
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		if (buffer == nullptr || nbytes == 0) {
			return 0;
		}

		const int taken = m_stream.Read(static_cast<std::uint8_t *>(buffer), nbytes);
		m_blocksRead = taken == 0;
		if (taken > 0) {
			// Tell libutp the window reopened. Only ever reached on the core
			// thread -- CEMSocket::OnReceive is this method's only caller --
			// which is the thread that owns libutp.
			m_context.NotifyReadDrained(m_socket);
		}
		return (std::uint32_t)(taken > 0 ? taken : 0);
	}

	/**
	 * Queue bytes for the peer.
	 *
	 * Called from the upload throttler's thread as well as the core thread, so
	 * it only ever queues: the hand-off to libutp happens on the tick. See the
	 * class comment.
	 *
	 * @return bytes accepted. Zero with BlocksWrite() true means the buffer is
	 *         full and the caller must retry, which is the TCP convention.
	 */
	std::uint32_t Write(const void *buffer, std::uint32_t nbytes) override
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		if (buffer == nullptr || nbytes == 0) {
			return 0;
		}

		if (!m_stream.IsConnected() || m_closed) {
			// Not up yet. Blocked rather than failed: the handshake is
			// still in flight and the caller retries on the send event.
			m_blocksWrite = true;
			return 0;
		}

		const int accepted =
			m_stream.Write(static_cast<const std::uint8_t *>(buffer), nbytes, m_nowMs);
		m_blocksWrite = accepted == 0;
		return (std::uint32_t)(accepted > 0 ? accepted : 0);
	}

	//! Ordinary close. Does not set a transport failure: a closed connection
	//! and a failed one are different answers, and only the second must keep
	//! the peer blameless.
	void Close() override
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		if (m_closed) {
			return;
		}
		m_closed = true;
		m_stream.Close();
		m_context.CloseSocket(m_socket);
		m_socket = nullptr;
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
	 * Zero while the connection is healthy or merely blocked, non-zero once it
	 * failed.
	 *
	 * The value itself carries no meaning beyond that: every call site in this
	 * tree tests it for truth (`if (LastError())`), and inventing an errno for
	 * a uTP failure would suggest a precision that does not exist. What the
	 * failure *means* is GetOutcome(), which is the question that decides
	 * whether the peer may be blamed.
	 */
	int LastError() const override
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_failed ? UTP_TRANSPORT_LAST_ERROR : 0;
	}

	const CNetworkAddress &GetPeerAddress() const override { return m_peer; }
	std::uint16_t GetPeerPort() const override { return m_port; }

	//
	// Driven by libutp, through CUtpLibraryAdapter. All on the core thread.
	//

	void OnUtpStateChange(EUtpSocketState state)
	{
		IStreamTransportEvents *sink = nullptr;
		bool connected = false;
		bool writable = false;
		bool lost = false;

		{
			std::lock_guard<std::mutex> lock(m_mutex);
			sink = m_sink;

			switch (state) {
			case UTP_SOCKET_CONNECTED:
				m_stream.OnConnected();
				m_blocksWrite = false;
				connected = true;
				// UTP_STATE_CONNECT implies writability, so anything
				// queued before the handshake finished goes now.
				m_stream.OnWindowOpened();
				m_stream.PumpWrites(m_nowMs);
				break;

			case UTP_SOCKET_WRITABLE:
				// libutp said the window is open, which retires any
				// backoff a previous zero-byte write installed. Keeping
				// it would idle the connection for up to
				// UTP_ZERO_WRITE_RETRY_MAX_MS after being told it could
				// send.
				m_stream.OnWindowOpened();
				m_stream.PumpWrites(m_nowMs);
				if (m_blocksWrite) {
					m_blocksWrite = false;
					writable = true;
				}
				break;

			case UTP_SOCKET_EOF:
				// The peer closed. Not a transport failure and not a
				// refusal: an ordinary end of connection.
				m_closed = true;
				m_stream.Close();
				lost = true;
				break;

			case UTP_SOCKET_DESTROYING:
				// libutp is about to free the socket, so nothing may
				// refer to it after this returns -- including our own
				// destructor's utp_close().
				m_socket = nullptr;
				m_closed = true;
				m_stream.Close();
				lost = true;
				break;
			}
		}

		if (sink == nullptr) {
			return;
		}
		if (connected) {
			sink->OnStreamTransportConnected();
		}
		if (writable) {
			sink->OnStreamTransportWritable();
		}
		if (lost) {
			sink->OnStreamTransportLost();
		}
	}

	/**
	 * libutp gave up on this connection.
	 *
	 * The mapping is the whole point of this function. A refusal is a fact
	 * about the peer and goes down the pre-uTP path. A timeout or a reset is a
	 * fact about the path -- a middlebox dropping UDP, a NAT that did not hold
	 * -- and must never cost the source. See UtpTransportFailure.h.
	 */
	void OnUtpError(EUtpSocketError error)
	{
		IStreamTransportEvents *sink = nullptr;

		{
			std::lock_guard<std::mutex> lock(m_mutex);
			sink = m_sink;
			m_failed = true;

			switch (error) {
			case UTP_SOCKET_REFUSED:
				m_stream.OnPeerRefused();
				break;
			case UTP_SOCKET_RESET:
			case UTP_SOCKET_TIMEDOUT:
				m_stream.OnTransportFailure();
				break;
			}

			m_closed = true;
			m_stream.Close();
		}

		if (sink != nullptr) {
			sink->OnStreamTransportLost();
		}
	}

	//! libutp delivered bytes. Wakes the socket above so it reads them.
	void OnUtpDataReceived(const std::uint8_t *data, std::size_t length)
	{
		IStreamTransportEvents *sink = nullptr;

		{
			std::lock_guard<std::mutex> lock(m_mutex);
			if (data == nullptr || length == 0) {
				return;
			}
			m_stream.OnDataReceived(data, length);
			m_blocksRead = false;
			sink = m_sink;
		}

		if (sink != nullptr) {
			sink->OnStreamTransportReadable();
		}
	}

	/**
	 * How much this end has buffered but not yet handed to the application.
	 *
	 * This is UTP_GET_READ_BUFFER_SIZE: libutp subtracts it from the receive
	 * window it advertises, so answering zero while bytes pile up here would
	 * invite the peer to keep sending into a buffer that is not draining.
	 */
	std::size_t GetPendingReadBytes() const
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_stream.GetPendingReadBytes();
	}

	std::size_t GetPendingWriteBytes() const
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_stream.GetPendingWriteBytes();
	}

	/**
	 * The tick: hand queued bytes to libutp, then give back an idle buffer.
	 *
	 * Also the only place `nowMs` enters, which is why Write() uses the last
	 * tick's value for the buffer's idle accounting: it cannot take a clock
	 * reading of its own without introducing one on the throttler thread.
	 */
	void OnUtpTick(std::uint64_t nowMs) override
	{
		IStreamTransportEvents *sink = nullptr;
		bool writable = false;

		{
			std::lock_guard<std::mutex> lock(m_mutex);
			m_nowMs = nowMs;
			if (m_closed) {
				return;
			}

			const std::size_t before = m_stream.GetPendingWriteBytes();
			m_stream.OnTick(nowMs);
			if (m_blocksWrite && m_stream.GetPendingWriteBytes() < before) {
				m_blocksWrite = false;
				writable = true;
				sink = m_sink;
			}
		}

		if (writable && sink != nullptr) {
			sink->OnStreamTransportWritable();
		}
	}

	//! What happened to the attempt, in the vocabulary
	//! CUpDownClient::GetUtpDisposition() reads.
	EUtpAttemptOutcome GetOutcome() const
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_stream.GetOutcome();
	}

	bool HasTransportFailed() const
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_stream.HasTransportFailed();
	}

private:
	//! Non-zero, and nothing more. See LastError().
	static const int UTP_TRANSPORT_LAST_ERROR = -1;

	CUtpContext &m_context;
	CNetworkAddress m_peer;
	std::uint16_t m_port = 0;

	//! Guards the stream and the block flags. Write() arrives on the upload
	//! throttler's thread; every other caller is the core thread.
	mutable std::mutex m_mutex;

	CUtpStream m_stream;
	void *m_socket = nullptr;
	IStreamTransportEvents *m_sink = nullptr;

	bool m_blocksRead = false;
	bool m_blocksWrite = false;
	bool m_closed = false;
	bool m_failed = false;

	//! The last tick's millisecond reading, used by Write() for the write
	//! buffer's idle accounting.
	std::uint64_t m_nowMs = 0;
};

/**
 * Dial a peer over uTP.
 *
 * @return the transport, or NULL when the dial could not be started at all --
 *         no libutp, no context, or an address family this transport does not
 *         carry yet. A NULL return is a transport failure in the sense
 *         UtpTransportFailure.h defines: it is about our side of the path, so
 *         the peer keeps its place in the source list.
 */
inline CUtpSocketTransport *DialUtp(CUtpContext &context, const CNetworkAddress &peer, std::uint16_t port)
{
	CUtpSocketTransport *transport = new CUtpSocketTransport(context, peer, port);

	// The transport is the socket's user data from before the SYN leaves, so
	// the connection's first callback already finds it.
	void *socket = context.CreateOutboundSocket(transport, peer, port);
	if (socket == nullptr) {
		delete transport;
		return nullptr;
	}

	transport->AttachSocket(socket);
	return transport;
}

#endif // UTPSOCKETTRANSPORT_H
