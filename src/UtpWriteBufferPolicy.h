//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2026 aMule Team ( https://amule-org.github.io )
//
// The write-buffer thresholds, the duplex-transfer heuristic and the
// blocked-write accounting in this file are ported from eMule AI's CUtpSocket
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

#ifndef UTPWRITEBUFFERPOLICY_H
#define UTPWRITEBUFFERPOLICY_H

#include <cstddef>
#include <cstdint>

/**
 * Sizing policy for the application-side write buffer of a uTP connection.
 *
 * libutp accepts a write only when its own window allows, so the application
 * side needs a buffer in front of it. How big that buffer should be is not a
 * constant, and getting it wrong has no visible failure mode -- only a
 * transfer that runs slower than it should, or a client that holds more memory
 * than it needs:
 *
 *   - Too small and a bulk transfer stalls waiting for the buffer to drain one
 *     window at a time.
 *   - Too large and a client with hundreds of connections holds megabytes per
 *     peer, most of it idle.
 *   - Too large on a connection that is transferring in BOTH directions and
 *     each direction holds its own multi-megabyte buffer for no benefit --
 *     which is the case a single-direction test cannot show. This is why the
 *     growth thresholds and the duplex trim have to ship together: either one
 *     alone changes behaviour under load, as the proposal for this change
 *     says in as many words.
 *
 * The thresholds and the heuristic are eMuleAI's, unchanged. What is different
 * is that they live here as pure arithmetic over two numbers -- capacity and
 * queued bytes -- rather than inside a socket, so that
 * UtpWriteBufferPolicyTest can drive the duplex trim, the sustained-blocking
 * promotion and the ceiling without a peer, a network or libutp.
 *
 * Not thread-safe. eMuleAI guards the equivalent state with a critical section
 * because it writes from a worker; in aMule every socket callback is posted to
 * the main thread (GuiEvents.h), so the buffer is only ever touched there.
 */

//! Where a connection starts. Handshake traffic is tiny and a client may have
//! hundreds of connections, so nothing is committed up front.
constexpr std::size_t UTP_WRITE_BUFFER_INITIAL = 64u * 1024u;
//! First promotion, taken on the first blocked write rather than after 64.
constexpr std::size_t UTP_WRITE_BUFFER_FIRST_ADAPTIVE = 512u * 1024u;
//! Second promotion, which costs sustained blocking.
constexpr std::size_t UTP_WRITE_BUFFER_SECOND_ADAPTIVE = 2u * 1024u * 1024u;
//! The documented maximum. Growth stops here.
constexpr std::size_t UTP_WRITE_BUFFER_MAX_ADAPTIVE = 4u * 1024u * 1024u;
//! The ceiling while the connection is carrying traffic both ways. Deliberately
//! the same value as the first adaptive step: a duplex connection gets the
//! first promotion and no more.
constexpr std::size_t UTP_WRITE_BUFFER_DUPLEX_MAX = UTP_WRITE_BUFFER_FIRST_ADAPTIVE;
//! Blocked writes at capacity needed for a promotion past the first one. One
//! blocked write is the peer's window closing for a moment, not pressure.
constexpr std::uint32_t UTP_WRITE_BUFFER_PROMOTION_BLOCKS = 64u;
//! How long a grown, empty buffer stays grown before it is given back.
constexpr std::uint64_t UTP_WRITE_BUFFER_IDLE_SHRINK_MS = 30000u;

class CUtpWriteBufferPolicy
{
public:
	CUtpWriteBufferPolicy() = default;

	//! Allocated capacity.
	std::size_t GetCapacity() const { return m_capacity; }
	//! Bytes queued and not yet handed to libutp.
	std::size_t GetPendingBytes() const { return m_pending; }

	/**
	 * Whether the connection is transferring in both directions.
	 *
	 * eMuleAI derives this from the owning client's upload and download
	 * state (CUtpSocket::IsDuplexTransferLikely). Here it is set by the
	 * caller, which is what keeps the policy free of the client object and
	 * testable without one.
	 */
	void SetDuplexTransfer(bool duplex) { m_duplex = duplex; }
	bool IsDuplexTransfer() const { return m_duplex; }

	//! The ceiling that currently applies.
	std::size_t GetMaxCapacity() const
	{
		return m_duplex ? UTP_WRITE_BUFFER_DUPLEX_MAX : UTP_WRITE_BUFFER_MAX_ADAPTIVE;
	}

	//! What a write may actually use: the capacity, clamped by the ceiling.
	//! These differ exactly when a buffer grown before the transfer became
	//! duplex has not been trimmed yet.
	std::size_t GetUsableCapacity() const
	{
		const std::size_t maxCapacity = GetMaxCapacity();
		return m_capacity < maxCapacity ? m_capacity : maxCapacity;
	}

	//! The next step up from here, clamped by the ceiling.
	std::size_t GetNextCapacity() const
	{
		const std::size_t maxCapacity = GetMaxCapacity();
		if (m_capacity >= maxCapacity) {
			return m_capacity;
		}
		if (m_capacity < UTP_WRITE_BUFFER_FIRST_ADAPTIVE) {
			return Min(UTP_WRITE_BUFFER_FIRST_ADAPTIVE, maxCapacity);
		}
		if (m_capacity < UTP_WRITE_BUFFER_SECOND_ADAPTIVE) {
			return Min(UTP_WRITE_BUFFER_SECOND_ADAPTIVE, maxCapacity);
		}
		return Min(UTP_WRITE_BUFFER_MAX_ADAPTIVE, maxCapacity);
	}

	std::uint32_t GetBlockedWritesAtCapacity() const { return m_blockedAtCapacity; }
	//! Whether the buffer is above the initial size, i.e. has something to
	//! give back when the connection goes idle.
	bool HasGrown() const { return m_grown; }

	/**
	 * Grow, clamped to the ceiling.
	 *
	 * @return false only when the request cannot be honoured; a request at or
	 *         below the current capacity is a no-op success, so callers do not
	 *         have to test whether anything moved.
	 */
	bool GrowTo(std::size_t newCapacity)
	{
		const std::size_t maxCapacity = GetMaxCapacity();
		if (newCapacity > maxCapacity) {
			newCapacity = maxCapacity;
		}
		if (newCapacity <= m_capacity) {
			return true;
		}
		if (m_pending >= newCapacity) {
			return false;
		}

		SetCapacity(newCapacity);
		return true;
	}

	/**
	 * Shrink.
	 *
	 * @return false when the queued bytes would not fit. Refusing is the
	 *         whole contract: a shrink that dropped queued bytes would lose
	 *         data the application already believes was accepted.
	 */
	bool ShrinkTo(std::size_t newCapacity)
	{
		if (newCapacity >= m_capacity) {
			return true;
		}
		if (m_pending > newCapacity) {
			return false;
		}

		SetCapacity(newCapacity);
		return true;
	}

	/**
	 * Bring a buffer grown before the transfer became duplex back to the
	 * duplex ceiling.
	 *
	 * @return true when it trimmed. False is the ordinary answer -- not
	 *         duplex, already at or below the ceiling, or too much queued to
	 *         do it safely yet.
	 */
	bool TrimForDuplex()
	{
		if (!m_duplex || m_capacity <= UTP_WRITE_BUFFER_DUPLEX_MAX ||
			m_pending > UTP_WRITE_BUFFER_DUPLEX_MAX) {
			return false;
		}

		return ShrinkTo(UTP_WRITE_BUFFER_DUPLEX_MAX);
	}

	/**
	 * A write found the buffer full.
	 *
	 * The trim comes first: a duplex connection sitting on an untrimmed
	 * buffer must come down rather than be promoted. Then the first
	 * promotion out of the initial capacity is taken immediately, and every
	 * later one costs UTP_WRITE_BUFFER_PROMOTION_BLOCKS blocked writes. At
	 * the ceiling nothing happens at all -- not even counting, so the counter
	 * cannot run away on a connection that is simply blocked.
	 */
	void OnWriteBlocked()
	{
		TrimForDuplex();

		if (m_capacity >= GetMaxCapacity()) {
			return;
		}

		const bool firstPromotion = m_capacity < UTP_WRITE_BUFFER_FIRST_ADAPTIVE;
		if (!firstPromotion && ++m_blockedAtCapacity < UTP_WRITE_BUFFER_PROMOTION_BLOCKS) {
			return;
		}

		GrowTo(GetNextCapacity());
	}

	/**
	 * Queue bytes for libutp, ported from CUtpSocket::Send.
	 *
	 * @param bytes  what the application wants to write.
	 * @param nowMs  a millisecond tick, remembered as the last send time for
	 *               ShrinkIfIdle().
	 * @return how many bytes were accepted. A partial accept is normal; zero
	 *         means blocked, i.e. the caller must retry later. A write that
	 *         finds the buffer full triggers the promotion accounting and is
	 *         then served out of whatever space that opened, which is why the
	 *         first blocked write at the initial capacity still returns a
	 *         non-zero count.
	 */
	std::size_t Enqueue(std::size_t bytes, std::uint64_t nowMs)
	{
		TrimForDuplex();

		if (m_pending >= GetUsableCapacity()) {
			OnWriteBlocked();
			if (m_pending >= GetUsableCapacity()) {
				return 0;
			}
		}

		const std::size_t room = GetUsableCapacity() - m_pending;
		const std::size_t accepted = Min(room, bytes);
		if (accepted != 0) {
			m_pending += accepted;
			m_lastSendMs = nowMs;
		}
		return accepted;
	}

	/**
	 * libutp took bytes off the front of the buffer.
	 *
	 * A buffer that drains completely while the transfer is duplex is
	 * trimmed here (eMuleAI's "duplex-drained"), because otherwise it would
	 * stay grown until some later write happened to notice.
	 */
	void Drain(std::size_t bytes)
	{
		m_pending = bytes >= m_pending ? 0 : m_pending - bytes;

		if (m_pending == 0) {
			TrimForDuplex();
		}
	}

	/**
	 * Give a grown buffer back after UTP_WRITE_BUFFER_IDLE_SHRINK_MS with
	 * nothing queued. Without this, one burst per connection leaves a client
	 * holding its peak buffer per peer for the rest of the session.
	 *
	 * Only the application buffer shrinks; libutp's own buffers are its
	 * business and are needed for protocol reliability.
	 *
	 * @return true when it shrank.
	 */
	bool ShrinkIfIdle(std::uint64_t nowMs)
	{
		if (!m_grown || m_pending != 0 || m_lastSendMs == 0 ||
			nowMs - m_lastSendMs <= UTP_WRITE_BUFFER_IDLE_SHRINK_MS) {
			return false;
		}

		SetCapacity(UTP_WRITE_BUFFER_INITIAL);
		m_lastSendMs = 0;
		return true;
	}

private:
	static std::size_t Min(std::size_t left, std::size_t right) { return left < right ? left : right; }

	//! Every capacity change goes through here, so the two pieces of state
	//! that depend on it cannot be updated in one place and forgotten in
	//! another: whether the buffer is above the initial size, and the blocked
	//! -write count, which is per-capacity and meaningless once it moves.
	void SetCapacity(std::size_t newCapacity)
	{
		m_capacity = newCapacity;
		m_grown = newCapacity > UTP_WRITE_BUFFER_INITIAL;
		m_blockedAtCapacity = 0;
	}

	std::size_t m_capacity = UTP_WRITE_BUFFER_INITIAL;
	std::size_t m_pending = 0;
	std::uint64_t m_lastSendMs = 0;
	std::uint32_t m_blockedAtCapacity = 0;
	bool m_duplex = false;
	bool m_grown = false;
};

#endif // UTPWRITEBUFFERPOLICY_H
