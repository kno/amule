//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2026 aMule Team ( https://amule-org.github.io )
//
// The write-drain budget, the zero-write backoff and the transport-failure
// handling in this file are ported from eMule AI's CUtpSocket
// (srchybrid/eMuleAI/UtpSocket.cpp):
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

#ifndef UTPSTREAM_H
#define UTPSTREAM_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "UtpContext.h"           // Needed for IUtpLibrary
#include "UtpTransportFailure.h"  // Needed for CUtpTransportState
#include "UtpWriteBufferPolicy.h" // Needed for CUtpWriteBufferPolicy

/**
 * One uTP connection, presented the way the client already consumes a TCP one.
 *
 * aMule's stream sockets expose Write()/Read() returning a transferred byte
 * count, with zero meaning "not now, retry later"
 * (CEncryptedStreamSocket::Write / ::Read). This class presents the same shape
 * over libutp, which is what lets the client path treat a uTP connection as a
 * connection rather than as a special case.
 *
 * The interesting part is the drain, not the copying. libutp accepts a write
 * only while its own send window allows, so the application's bytes queue here
 * and are handed over on the pump pass, under a budget:
 *
 *   - at most UTP_WRITE_MAX_ATTEMPTS_PER_PASS calls to utp_write, so one
 *     connection with a full buffer cannot hold the pump,
 *   - at most UTP_WRITE_MAX_BYTES_PER_PASS bytes for the same reason,
 *   - and after a zero-byte write, a backoff, because a closed window
 *     otherwise turns the pump into a busy loop that calls utp_write thousands
 *     of times a second to be told no.
 *
 * How large the queue may grow is CUtpWriteBufferPolicy's decision, including
 * the duplex trim -- see that header for why growth and trim are one mechanism.
 */

//! Largest single utp_write. Beyond this the call is split across passes.
constexpr std::size_t UTP_WRITE_MAX_ATTEMPT_SIZE = 256u * 1024u;
//! Calls to utp_write in one pump pass.
constexpr unsigned UTP_WRITE_MAX_ATTEMPTS_PER_PASS = 4u;
//! Bytes handed to libutp in one pump pass.
constexpr std::size_t UTP_WRITE_MAX_BYTES_PER_PASS = 256u * 1024u;
//! Backoff after a zero-byte write: base, per-burst step, and cap.
constexpr std::uint64_t UTP_ZERO_WRITE_RETRY_BASE_MS = 20u;
constexpr std::uint64_t UTP_ZERO_WRITE_RETRY_STEP_MS = 5u;
constexpr std::uint64_t UTP_ZERO_WRITE_RETRY_MAX_MS = 125u;

class CUtpStream
{
public:
	CUtpStream() = default;

	CUtpStream(const CUtpStream &) = delete;
	CUtpStream &operator=(const CUtpStream &) = delete;
	CUtpStream(CUtpStream &&) = default;
	CUtpStream &operator=(CUtpStream &&) = default;

	/**
	 * Bind the stream to a libutp socket, after a connect or an accept.
	 *
	 * @param socket  a `utp_socket *`. The type does not appear here so this
	 *                header stays includable without libutp.
	 */
	void Attach(IUtpLibrary *library, void *socket)
	{
		m_library = library;
		m_socket = socket;
	}

	//! Whether there is a libutp socket to write through at all.
	bool IsAttached() const { return m_library != nullptr && m_socket != nullptr; }

	void OnConnected() { m_transport.OnConnected(); }
	void OnTransportFailure() { m_transport.OnTransportFailure(); }
	void OnPeerRefused() { m_transport.OnPeerRefused(); }

	bool IsConnected() const { return IsAttached() && m_transport.GetOutcome() == UTP_ATTEMPT_CONNECTED; }

	/**
	 * Whether uTP itself failed, as opposed to the peer refusing.
	 *
	 * This is what the client path reads to decide on a TCP fallback without
	 * blaming the peer -- see UtpTransportFailure.h. An ordinary Close() does
	 * not set it, which is why a closed stream and a failed one are different
	 * answers here.
	 */
	bool HasTransportFailed() const { return m_transport.HasTransportFailed(); }
	EUtpAttemptOutcome GetOutcome() const { return m_transport.GetOutcome(); }

	//! Ordinary close. Detaches from libutp; the outcome is left alone so a
	//! close cannot be mistaken for a transport failure.
	void Close()
	{
		m_socket = nullptr;
		m_pendingWrite.clear();
		m_pendingRead.clear();
	}

	/**
	 * Queue bytes for the peer.
	 *
	 * @param nowMs  a millisecond tick, for the buffer's idle accounting.
	 * @return bytes accepted; 0 means the buffer is full and the caller must
	 *         retry -- the same convention as the TCP-side Write().
	 */
	int Write(const std::uint8_t *data, std::size_t length, std::uint64_t nowMs)
	{
		if (!IsAttached() || data == nullptr) {
			return 0;
		}

		const std::size_t accepted = m_writeBuffer.Enqueue(length, nowMs);
		if (accepted != 0) {
			m_pendingWrite.insert(m_pendingWrite.end(), data, data + accepted);
		}
		return (int)accepted;
	}

	//! libutp delivered bytes from the peer (its read callback).
	void OnDataReceived(const std::uint8_t *data, std::size_t length)
	{
		if (data == nullptr || length == 0) {
			return;
		}
		m_pendingRead.insert(m_pendingRead.end(), data, data + length);
	}

	/**
	 * Read what the peer sent.
	 *
	 * @return bytes copied; 0 when nothing has arrived, which is
	 *         would-block rather than end-of-stream.
	 */
	int Read(std::uint8_t *out, std::size_t length)
	{
		if (out == nullptr || length == 0 || m_pendingRead.empty()) {
			return 0;
		}

		const std::size_t taken = length < m_pendingRead.size() ? length : m_pendingRead.size();
		for (std::size_t i = 0; i < taken; ++i) {
			out[i] = m_pendingRead[i];
		}
		m_pendingRead.erase(m_pendingRead.begin(), m_pendingRead.begin() + (long)taken);
		return (int)taken;
	}

	/**
	 * Hand queued bytes to libutp, within the per-pass budget.
	 *
	 * @return bytes libutp took this pass.
	 */
	std::size_t PumpWrites(std::uint64_t nowMs)
	{
		if (!IsAttached() || m_pendingWrite.empty()) {
			return 0;
		}

		// Still backing off from a closed window: attempt nothing. The
		// tick will come back.
		if (m_zeroWriteBackoffMs != 0 && nowMs < m_nextWriteAttemptMs) {
			return 0;
		}

		std::size_t writtenThisPass = 0;
		unsigned attempts = 0;

		while (attempts < UTP_WRITE_MAX_ATTEMPTS_PER_PASS &&
			writtenThisPass < UTP_WRITE_MAX_BYTES_PER_PASS && !m_pendingWrite.empty()) {
			const std::size_t budget = UTP_WRITE_MAX_BYTES_PER_PASS - writtenThisPass;
			std::size_t attemptSize = m_pendingWrite.size();
			if (attemptSize > UTP_WRITE_MAX_ATTEMPT_SIZE) {
				attemptSize = UTP_WRITE_MAX_ATTEMPT_SIZE;
			}
			if (attemptSize > budget) {
				attemptSize = budget;
			}

			++attempts;
			const long written =
				m_library->WriteToSocket(m_socket, &m_pendingWrite[0], attemptSize);

			if (written > 0) {
				const std::size_t taken = (std::size_t)written;
				m_pendingWrite.erase(
					m_pendingWrite.begin(), m_pendingWrite.begin() + written);
				m_writeBuffer.Drain(taken);
				writtenThisPass += taken;
				ClearZeroWriteBackoff();
				continue;
			}

			if (written == 0) {
				// Window closed. Back off, growing with the burst, and
				// capped: a backoff that kept doubling would stop
				// retrying altogether on a long-blocked connection.
				if (m_zeroWriteBurst < 0xFFu) {
					++m_zeroWriteBurst;
				}
				std::uint64_t delay = UTP_ZERO_WRITE_RETRY_BASE_MS +
						      (m_zeroWriteBurst * UTP_ZERO_WRITE_RETRY_STEP_MS);
				if (delay > UTP_ZERO_WRITE_RETRY_MAX_MS) {
					delay = UTP_ZERO_WRITE_RETRY_MAX_MS;
				}
				m_zeroWriteBackoffMs = delay;
				m_nextWriteAttemptMs = nowMs + delay;
			} else {
				// A real error. The queue is left alone: whoever
				// tears the connection down owns it, and this is not
				// the place that decides whether the peer is at
				// fault.
				ClearZeroWriteBackoff();
			}
			break;
		}

		return writtenThisPass;
	}

	/**
	 * libutp says its send window is open again.
	 *
	 * Clears the zero-write backoff. That backoff exists to stop the pump
	 * calling utp_write thousands of times a second to be told no; an explicit
	 * notification that the window opened makes holding it not merely
	 * unnecessary but wrong, because the connection would then sit idle for up
	 * to UTP_ZERO_WRITE_RETRY_MAX_MS after libutp had said it could take data.
	 * A stall with nothing failing anywhere.
	 */
	void OnWindowOpened() { ClearZeroWriteBackoff(); }

	/**
	 * The periodic tick for one stream: drain what can be drained, then give
	 * back a buffer that has been idle long enough.
	 */
	void OnTick(std::uint64_t nowMs)
	{
		PumpWrites(nowMs);
		m_writeBuffer.ShrinkIfIdle(nowMs);
	}

	//! Whether this connection is carrying traffic in both directions, which
	//! moves the write buffer's ceiling. eMuleAI derives it from the owning
	//! client's upload and download state; the caller does that here.
	void SetDuplexTransfer(bool duplex) { m_writeBuffer.SetDuplexTransfer(duplex); }

	std::size_t GetPendingWriteBytes() const { return m_pendingWrite.size(); }
	//! Bytes libutp delivered that the application has not read yet. This is
	//! what UTP_GET_READ_BUFFER_SIZE answers: libutp subtracts it from the
	//! receive window it advertises, so a stale zero here invites the peer to
	//! keep sending into a buffer that is not draining.
	std::size_t GetPendingReadBytes() const { return m_pendingRead.size(); }
	std::size_t GetWriteBufferCapacity() const { return m_writeBuffer.GetCapacity(); }
	std::size_t GetWriteBufferMaxCapacity() const { return m_writeBuffer.GetMaxCapacity(); }
	std::uint64_t GetZeroWriteBackoffMs() const { return m_zeroWriteBackoffMs; }

private:
	void ClearZeroWriteBackoff()
	{
		m_zeroWriteBurst = 0;
		m_zeroWriteBackoffMs = 0;
		m_nextWriteAttemptMs = 0;
	}

	IUtpLibrary *m_library = nullptr;
	void *m_socket = nullptr;

	CUtpTransportState m_transport;
	CUtpWriteBufferPolicy m_writeBuffer;

	std::vector<std::uint8_t> m_pendingWrite;
	std::vector<std::uint8_t> m_pendingRead;

	std::uint64_t m_nextWriteAttemptMs = 0;
	std::uint64_t m_zeroWriteBackoffMs = 0;
	std::uint32_t m_zeroWriteBurst = 0;
};

#endif // UTPSTREAM_H
