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

#ifndef NATHOLEPUNCHSCHEDULE_H
#define NATHOLEPUNCHSCHEDULE_H

#include <cstdint>

#include "NatRendezvousProtocol.h" // Needed for the rendezvous bounds

/**
 * What bounds a hole punch for one pair of peers, and what the client may
 * conclude when it fails.
 *
 * ## The two budgets
 *
 * Five attempts and 120 seconds, whichever comes first. Both are needed and
 * neither implies the other: the attempt count bounds the packets, and the
 * wall-clock budget bounds a client whose core timer is slow or whose process
 * was suspended, where five attempts could otherwise be spread over an hour.
 *
 * The spacing is derived rather than chosen. Five attempts have to fit inside
 * the 120-second budget, so the attempt spacing is the budget divided by the
 * attempt count -- a fourth independent number would be a fourth thing to keep
 * consistent with the other three.
 *
 * ## Why the failure path is a value and not a return code
 *
 * When the budget is spent, the source stays queued. A failed traversal is a
 * fact about two NAT mappings and says nothing at all about the peer, so
 * marking it dead or dropping it from the source list turns a transient
 * condition into a permanently lost peer, with no symptom but a download that
 * has fewer sources than it should.
 *
 * That has a specific trap in this tree. CUpDownClient::Connect() returning
 * false means "the client was deleted" to CUpDownClient::TryToConnect(), which
 * responds by calling Safe_Delete(). So the natural-looking way to report "I
 * could not connect right now" destroys exactly the source this rule protects.
 * DisposeExhaustedHolePunch() is therefore a value with every field spelled
 * out, on the same pattern as DisposeUtpAttempt() in UtpTransportFailure.h: the
 * caller asks one question and gets one answer instead of having to remember a
 * rule.
 *
 * Header-only and free of theApp and of wxWidgets so that the bounds and the
 * cancellation are assertable without a network or a peer -- neither is
 * observable through a real NAT without a lab.
 */

//! Packets in one hole-punch burst. Three, a quarter second apart: enough to
//! cross a mapping that drops the first packet, and far under any rate a peer
//! could mistake for an attack. A burst, not a flood.
constexpr uint32_t kHolePunchPacketsPerAttempt = 3;
constexpr uint32_t kHolePunchPacketSpacingMs = 250;

//! Gap between the starts of two attempts, derived so that
//! kRendezvousMaxAttempts of them fit inside kRendezvousTotalBudgetMs.
constexpr uint32_t kHolePunchAttemptSpacingMs = kRendezvousTotalBudgetMs / kRendezvousMaxAttempts;

//! What the caller should do at this tick.
enum EHolePunchAction
{
	//! Nobody started a punch for this pair.
	HOLEPUNCH_IDLE,
	//! Send one OP_HOLEPUNCH packet now.
	HOLEPUNCH_SEND,
	//! Not yet. NextDueMs() says when.
	HOLEPUNCH_WAIT,
	//! The connection came up. Cancelled: never send for this pair again.
	HOLEPUNCH_SUCCEEDED,
	//! The budget is spent and the backoff is running. The source stays
	//! queued -- see DisposeExhaustedHolePunch().
	HOLEPUNCH_EXHAUSTED,
	//! The backoff has passed. A fresh rendezvous may be started.
	HOLEPUNCH_BACKOFF_ELAPSED
};

/**
 * What happens to the peer after a hole punch ran out of budget.
 *
 * Every field is spelled out, including the three that must be false, because
 * the cost of any of them being true is a source that quietly disappears. There
 * are no arguments: exhaustion means the same thing every time it happens.
 */
struct SHolePunchDisposition
{
	//! Keep the source in the queue. Always true.
	bool keepSourceQueued = true;
	//! Add the peer to the dead-source list. Always false: a NAT that did not
	//! open taught us nothing about the peer.
	bool markPeerDead = false;
	//! Remove the peer from the download's source list. Always false.
	bool dropFromSourceList = false;
	//! Count it toward any "dead sources" statistic. Always false, for the same
	//! reason -- a statistic that counts it will eventually be acted on.
	bool countAsDeadSource = false;
	//! Try the paths that predate this change instead. The spec requires the
	//! existing server callback and Kad buddy routes to remain the fallback.
	bool fallBackToCallbackOrBuddy = true;
	//! How long before this pair may be tried again.
	uint32_t retryAfterMs = kRendezvousBackoffMs;
};

//! The one answer to "the punch ran out of budget, now what". A function rather
//! than a comment, so a caller that forgets the rule cannot compile past it.
inline SHolePunchDisposition DisposeExhaustedHolePunch()
{
	return SHolePunchDisposition();
}

/**
 * The hole-punch schedule for one pair of peers.
 *
 * Driven by polling from the core timer rather than by its own timer, so it
 * holds no thread, no wx event and no clock of its own: every decision is a
 * function of the tick count the caller passes in, which is what makes the
 * whole state machine testable without waiting 120 seconds.
 */
class CHolePunchSchedule
{
public:
	CHolePunchSchedule() = default;

	/**
	 * Begin, or begin again after a backoff.
	 *
	 * A cancelled schedule is NOT revived: the pair is connected, and honouring
	 * a restart would put packets on the wire for a live connection. An
	 * exhausted schedule is only restarted once its backoff has elapsed, so a
	 * caller cannot spend a fresh budget early by calling this in a loop.
	 */
	void Start(uint64_t nowMs)
	{
		if (m_cancelled) {
			return;
		}
		if (m_exhausted && !MayRestart(nowMs)) {
			return;
		}

		m_started = true;
		m_exhausted = false;
		m_startMs = nowMs;
		m_attemptStartMs = nowMs;
		m_nextDueMs = nowMs;
		m_attemptsMade = 0;
		m_packetsInAttempt = 0;
		m_packetsSent = 0;
		m_exhaustedAtMs = 0;
	}

	/**
	 * The connection came up. Cancels every remaining attempt, permanently.
	 *
	 * Also cancels a schedule that had already exhausted its budget: a punch
	 * that lands as the budget runs out is a success, and reporting a backoff
	 * for a pair that is connected would have the client wait 60 seconds before
	 * using a live connection.
	 */
	void OnConnectionEstablished()
	{
		m_cancelled = true;
		m_exhausted = false;
	}

	/**
	 * What to do at `nowMs`. Recording the send is part of this call, so a
	 * caller cannot poll twice and send twice.
	 */
	EHolePunchAction Poll(uint64_t nowMs)
	{
		if (m_cancelled) {
			return HOLEPUNCH_SUCCEEDED;
		}
		if (!m_started) {
			return HOLEPUNCH_IDLE;
		}
		if (m_exhausted) {
			return MayRestart(nowMs) ? HOLEPUNCH_BACKOFF_ELAPSED : HOLEPUNCH_EXHAUSTED;
		}

		// The wall-clock bound. Tested before the spacing so a client that was
		// suspended for two minutes stops rather than resuming a burst nobody
		// is waiting for. Guarded against a tick count that moved backwards,
		// which would otherwise underflow into an instant exhaustion.
		if (nowMs >= m_startMs && nowMs - m_startMs >= kRendezvousTotalBudgetMs) {
			Exhaust(nowMs);
			return HOLEPUNCH_EXHAUSTED;
		}

		if (nowMs < m_nextDueMs) {
			// Also the branch a backwards clock takes: the spacing is what
			// keeps a burst a burst, and a clock adjustment is not permission
			// to send the whole budget at once.
			return HOLEPUNCH_WAIT;
		}

		++m_packetsSent;
		++m_packetsInAttempt;

		if (m_packetsInAttempt >= kHolePunchPacketsPerAttempt) {
			++m_attemptsMade;
			m_packetsInAttempt = 0;
			if (m_attemptsMade >= kRendezvousMaxAttempts) {
				// The last packet of the last attempt. Exhausted from here,
				// with m_nextDueMs left where it is so the caller's notion of
				// "now" does not jump into the backoff.
				Exhaust(nowMs);
				return HOLEPUNCH_SEND;
			}
			// The next attempt is spaced from the start of this one, not from
			// its last packet, so the burst length does not shift the schedule.
			m_attemptStartMs += kHolePunchAttemptSpacingMs;
			m_nextDueMs = m_attemptStartMs;
		} else {
			m_nextDueMs = nowMs + kHolePunchPacketSpacingMs;
		}

		return HOLEPUNCH_SEND;
	}

	//! When the next packet is due. Only meaningful while the schedule is
	//! running; after exhaustion it stays at the last send time.
	uint64_t NextDueMs() const { return m_nextDueMs; }

	//! Whether the backoff after exhaustion has passed. False for a schedule
	//! that has not exhausted -- there is nothing to restart.
	bool MayRestart(uint64_t nowMs) const
	{
		if (!m_exhausted) {
			return false;
		}
		return nowMs >= m_exhaustedAtMs && nowMs - m_exhaustedAtMs >= kRendezvousBackoffMs;
	}

	bool IsCancelled() const { return m_cancelled; }
	bool IsExhausted() const { return m_exhausted; }
	uint32_t AttemptsMade() const { return m_attemptsMade; }
	uint32_t PacketsSent() const { return m_packetsSent; }

private:
	void Exhaust(uint64_t nowMs)
	{
		m_exhausted = true;
		m_exhaustedAtMs = nowMs;
	}

	bool m_started = false;
	bool m_cancelled = false;
	bool m_exhausted = false;
	uint64_t m_startMs = 0;
	uint64_t m_attemptStartMs = 0;
	uint64_t m_nextDueMs = 0;
	uint64_t m_exhaustedAtMs = 0;
	uint32_t m_attemptsMade = 0;
	uint32_t m_packetsInAttempt = 0;
	uint32_t m_packetsSent = 0;
};

#endif // NATHOLEPUNCHSCHEDULE_H
