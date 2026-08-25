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

#ifndef NATRENDEZVOUSMANAGER_H
#define NATRENDEZVOUSMANAGER_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

#include "NatHolePunchSchedule.h"  // Needed for CHolePunchSchedule
#include "NatRendezvousProtocol.h" // Needed for the codec and the bounds
#include "NatRendezvousRelay.h"    // Needed for SRelayedRendezvousDecision
#include "NatTraversalPolicy.h"    // Needed for CNattCandidateSet
#include "NetworkAddress.h"        // Needed for CNetworkAddress

/**
 * The in-flight rendezvous exchanges, one per peer.
 *
 * CHolePunchSchedule bounds one pair. This holds the set of them, decides which
 * endpoints each pair is punched toward, and is what the UDP receive path and
 * the core timer actually talk to -- so that CClientUDPSocket contains dispatch
 * and no policy, and every bound stays assertable in a test binary.
 *
 * ## Keyed by user hash, not by address
 *
 * The address is the thing a NAT rewrites, so it is the one field that cannot
 * identify the pair. A punch from a peer arrives from whatever source port its
 * NAT chose, which is frequently not the port it was punched at; matching by
 * address would fail exactly in the case this change exists for. The identity
 * travels inside the message for that reason (SNattHolePunch::senderHash).
 *
 * ## Why the table is capped
 *
 * An entry is created by inbound traffic -- a relay can cause one. A table that
 * grew per peer hash would let a relay allocate as many entries as it cares to
 * invent hashes, and each entry is a punch budget. Past the cap nothing new is
 * tracked, which fails closed: a genuine rendezvous during a flood is refused
 * and retried, and no traffic is generated for a hash nobody vouched for.
 *
 * ## What is not here
 *
 * No timer, no thread, no clock. Every decision is a function of the tick the
 * caller passes in, which is what makes 120 seconds testable in microseconds.
 * Not thread-safe and does not need to be: the client UDP receive path and
 * CamuleApp::OnCoreTimer are both the main thread.
 */

/**
 * How many pairs may be tracked at once.
 *
 * Sized against what a client plausibly has in flight rather than against what
 * a peer could ask for: a rendezvous exists only for a firewalled peer this
 * client wants a source from, and 64 simultaneous ones is already more than a
 * download queue produces. See the cap discussion above.
 */
constexpr size_t kNattMaxTrackedRendezvous = 64;

//! How long a finished entry is kept before it is reclaimed. One backoff plus
//! the total budget: long enough that a pair's backoff is still remembered when
//! the connect path asks about it, which is the whole point of the backoff.
constexpr uint64_t kNattEntryRetentionMs = kRendezvousTotalBudgetMs + kRendezvousBackoffMs;

//! An ed2k user hash as a map key. A std::array would do the same, but this
//! keeps the comparison in one named place next to the length constant it
//! depends on.
struct SNattPeerKey
{
	uint8_t bytes[NATT_PEER_HASH_LENGTH] = { 0 };

	bool operator<(const SNattPeerKey &other) const
	{
		for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
			if (bytes[i] != other.bytes[i]) {
				return bytes[i] < other.bytes[i];
			}
		}
		return false;
	}
};

inline SNattPeerKey MakeNattPeerKey(const uint8_t *hash)
{
	SNattPeerKey key;
	if (hash != NULL) {
		for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
			key.bytes[i] = hash[i];
		}
	}
	return key;
}

//! One packet the manager wants sent: an OP_HOLEPUNCH toward one candidate.
struct SNattPunchRequest
{
	CNetworkAddress destination;
	uint16_t port = 0;
};

class CNatRendezvousManager
{
public:
	CNatRendezvousManager() = default;

	/**
	 * Begin a rendezvous with a peer this client wants to reach.
	 *
	 * @param peerHash the peer's user hash.
	 * @param candidates every endpoint worth punching toward, already ordered
	 *        and already de-duplicated by CNattCandidateSet -- which is also
	 *        what bounds the count, because the candidate set multiplies the
	 *        packets in a burst.
	 * @param nowMs a millisecond tick.
	 * @return false when nothing was started: an empty candidate set, a pair
	 *         whose backoff has not elapsed, a pair already connected, or a
	 *         full table. The caller's answer to all four is the same -- use
	 *         the callback and buddy paths -- so they are not told apart here.
	 */
	bool BeginRendezvous(const uint8_t *peerHash, const CNattCandidateSet &candidates, uint64_t nowMs)
	{
		if (peerHash == NULL || candidates.Count() == 0) {
			return false;
		}

		const SNattPeerKey key = MakeNattPeerKey(peerHash);
		const auto existing = m_entries.find(key);
		if (existing != m_entries.end()) {
			SEntry &entry = existing->second;
			if (entry.schedule.IsCancelled()) {
				// Connected. Restarting would put packets on the wire for
				// a live connection.
				return false;
			}
			if (entry.schedule.IsExhausted() && !entry.schedule.MayRestart(nowMs)) {
				// Backing off. The source keeps its place throughout;
				// this is a refusal to punch, not a verdict on the peer.
				return false;
			}
			entry.candidates = candidates;
			entry.lastActivityMs = nowMs;
			entry.schedule.Start(nowMs);
			return true;
		}

		if (m_entries.size() >= kNattMaxTrackedRendezvous) {
			Reclaim(nowMs);
			if (m_entries.size() >= kNattMaxTrackedRendezvous) {
				return false;
			}
		}

		SEntry entry;
		entry.candidates = candidates;
		entry.lastActivityMs = nowMs;
		entry.schedule.Start(nowMs);
		m_entries[key] = entry;
		return true;
	}

	/**
	 * Act on a rendezvous a relay forwarded to this client.
	 *
	 * @param decision the output of AcceptRelayedRendezvous(), which is where
	 *        every guard on this direction lives. A decision that did not
	 *        accept is ignored here rather than re-checked, so there is exactly
	 *        one place those guards can be got wrong.
	 * @param known every endpoint this client already held for that peer. The
	 *        relayed endpoint is added AFTER them, so it is one candidate among
	 *        the addresses already known and can never displace one -- and when
	 *        the set is full it is the relayed endpoint that is dropped.
	 * @return whether a punch was started.
	 */
	bool OnRelayedRendezvous(
		const SRelayedRendezvousDecision &decision, const CNattCandidateSet &known, uint64_t nowMs)
	{
		if (!decision.punch) {
			return false;
		}

		CNattCandidateSet candidates = known;
		candidates.AddHint(decision.punchEndpoint, decision.punchPort);
		return BeginRendezvous(decision.peerHash, candidates, nowMs);
	}

	/**
	 * A hole punch arrived from a peer: its NAT let one through, so the mapping
	 * this end has been punching at is open.
	 *
	 * A punch is an inbound packet from an arbitrary host, so it may not create
	 * an entry: a peer that was never punched toward gets no schedule and no
	 * budget out of sending one. It is matched against the pairs already in
	 * flight and ignored otherwise.
	 *
	 * @param source where the punch actually arrived from, which is the
	 *        peer's real mapping and is worth more than the endpoint either
	 *        side predicted. Recorded so the connect path dials the observed
	 *        address rather than the claimed one.
	 * @return whether it matched a rendezvous in flight.
	 */
	bool OnHolePunchReceived(
		const uint8_t *senderHash, const CNetworkAddress &source, uint16_t port, uint64_t nowMs)
	{
		if (senderHash == NULL || port == 0 || source.IsAbsent() || source.IsUnspecified()) {
			return false;
		}

		const auto existing = m_entries.find(MakeNattPeerKey(senderHash));
		if (existing == m_entries.end()) {
			return false;
		}

		SEntry &entry = existing->second;
		entry.observedEndpoint = source;
		entry.observedPort = port;
		entry.lastActivityMs = nowMs;
		return true;
	}

	/**
	 * The connection to this peer came up. Cancels every remaining attempt for
	 * the pair: from here Tick() emits nothing for it, and the next Tick()
	 * reclaims the entry.
	 *
	 * Reclaiming a cancelled pair is what lets the same peer be rendezvoused
	 * with again after the connection eventually drops -- the cancellation is
	 * permanent for the exchange that succeeded, which is what the spec
	 * requires, and not a permanent verdict on the peer. Nothing is emitted in
	 * between: an entry is created only by BeginRendezvous().
	 *
	 * Called for a pair that is not tracked too, and does nothing then -- the
	 * connect path should not have to know whether a rendezvous was involved.
	 */
	void OnConnectionEstablished(const uint8_t *peerHash)
	{
		if (peerHash == NULL) {
			return;
		}
		const auto existing = m_entries.find(MakeNattPeerKey(peerHash));
		if (existing != m_entries.end()) {
			existing->second.schedule.OnConnectionEstablished();
		}
	}

	/**
	 * Emit whatever is due at `nowMs`.
	 *
	 * @param send void(const uint8_t *peerHash, const SNattPunchRequest &).
	 *        A forwarding reference, so a recording sender in a test observes
	 *        what it recorded rather than a copy that threw it away.
	 *
	 * One CHolePunchSchedule packet is one packet per candidate: the schedule
	 * bounds when a burst happens and the candidate set bounds how wide it is,
	 * and multiplying them is what the fixed kNattMaxCandidates caps. Polling
	 * records the send inside the schedule, so calling Tick() twice for the
	 * same tick cannot send twice.
	 */
	template <class Sender> void Tick(uint64_t nowMs, Sender &&send)
	{
		for (auto &pair : m_entries) {
			SEntry &entry = pair.second;
			const EHolePunchAction action = entry.schedule.Poll(nowMs);
			if (action != HOLEPUNCH_SEND) {
				continue;
			}

			entry.lastActivityMs = nowMs;
			for (size_t i = 0; i < entry.candidates.Count(); ++i) {
				const SNattEndpointCandidate &candidate = entry.candidates.At(i);
				SNattPunchRequest request;
				request.destination = candidate.address;
				request.port = candidate.port;
				send(pair.first.bytes, request);
			}
		}

		Reclaim(nowMs);
	}

	/**
	 * Whether a pair is inside the 60 second backoff after exhaustion.
	 *
	 * What SRendezvousInputs::backoffActive is filled from. False for a pair
	 * nobody has punched for, which is the ordinary peer.
	 */
	bool IsBackoffActive(const uint8_t *peerHash, uint64_t nowMs) const
	{
		if (peerHash == NULL) {
			return false;
		}
		const auto existing = m_entries.find(MakeNattPeerKey(peerHash));
		if (existing == m_entries.end()) {
			return false;
		}
		const CHolePunchSchedule &schedule = existing->second.schedule;
		return schedule.IsExhausted() && !schedule.MayRestart(nowMs);
	}

	/**
	 * The endpoint a punch was actually observed arriving from, if one was.
	 *
	 * @return false when no punch has been seen for that pair, in which case
	 *         the outputs are untouched. The connect path uses this instead of
	 *         the endpoint the peer claimed: a mapping that delivered a packet
	 *         is evidence, and a hint is a guess.
	 */
	bool ObservedEndpoint(const uint8_t *peerHash, CNetworkAddress &address, uint16_t &port) const
	{
		if (peerHash == NULL) {
			return false;
		}
		const auto existing = m_entries.find(MakeNattPeerKey(peerHash));
		if (existing == m_entries.end() || existing->second.observedPort == 0 ||
			existing->second.observedEndpoint.IsAbsent()) {
			return false;
		}
		address = existing->second.observedEndpoint;
		port = existing->second.observedPort;
		return true;
	}

	//! How many pairs are tracked. Exposed so the memory bound is assertable.
	size_t TrackedCount() const { return m_entries.size(); }

	//! What to do about a pair whose budget is spent. One value, no arguments:
	//! see DisposeExhaustedHolePunch(). Present here so a caller holding only
	//! the manager does not have to reach for another header to find the rule
	//! that keeps the source queued.
	static SHolePunchDisposition ExhaustionDisposition() { return DisposeExhaustedHolePunch(); }

private:
	struct SEntry
	{
		CHolePunchSchedule schedule;
		CNattCandidateSet candidates;
		//! Where a punch was seen arriving from, absent until one is.
		CNetworkAddress observedEndpoint;
		uint16_t observedPort = 0;
		uint64_t lastActivityMs = 0;
	};

	/**
	 * Drop entries that can no longer do anything.
	 *
	 * A cancelled pair is connected and a reclaimed backoff would let a pair be
	 * punched again early, so the retention is one full budget plus one full
	 * backoff -- the entry outlives the fact it is remembering.
	 */
	void Reclaim(uint64_t nowMs)
	{
		for (auto it = m_entries.begin(); it != m_entries.end();) {
			const SEntry &entry = it->second;
			const bool aged = nowMs >= entry.lastActivityMs &&
					  nowMs - entry.lastActivityMs >= kNattEntryRetentionMs;
			if (entry.schedule.IsCancelled() || aged) {
				it = m_entries.erase(it);
			} else {
				++it;
			}
		}
	}

	std::map<SNattPeerKey, SEntry> m_entries;
};

#endif // NATRENDEZVOUSMANAGER_H
