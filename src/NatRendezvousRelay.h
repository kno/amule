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

#ifndef NATRENDEZVOUSRELAY_H
#define NATRENDEZVOUSRELAY_H

#include <cstddef>
#include <cstdint>
#include <map>

#include "NatRendezvousProtocol.h" // Needed for the OP_RENDEZVOUS codec and bounds
#include "NetworkAddress.h"        // Needed for CNetworkAddress
#include "PeerIdentity.h"          // Needed for PeerIdentity::RateLimitScope

/**
 * The relaying side of the rendezvous exchange.
 *
 * This is the security-relevant half of the change and it belongs to the party
 * that gets nothing out of the traversal. A rendezvous request asks this client
 * to generate traffic toward an address on behalf of whoever asked, which is
 * the shape of a reflector: an attacker names a victim as its own endpoint,
 * every aMule instance it can reach aims packets at that victim, and the victim
 * sees a flood from hosts that never attacked it.
 *
 * Three rules keep that from being possible, and all three are in this file so
 * that no caller has to remember any of them:
 *
 *  1. **Nothing an attacker names becomes a destination.** The target is named
 *     by user hash and resolved against this client's own client list. There is
 *     no code path in which an address from a datagram is sent to.
 *  2. **The endpoint that travels is the one this relay observed**, never the
 *     one the request claimed. A claim that matches is still not the value
 *     forwarded, so a matching claim cannot launder an address through either.
 *  3. **The requester's identity comes from our own state.** A host this client
 *     knows nothing about cannot cause an emission at all.
 *
 * On top of those, the request is validated against the source and the
 * requester is rate limited. The rate limit is charged *before* validation, so
 * a flood of malformed requests exhausts the flooder's own budget instead of
 * being free.
 *
 * The emission lives inside RelayRendezvousRequest() rather than being left to
 * the caller, so "no packet is sent toward an unrelated address" is a property
 * of a function a test can drive with a recording sender -- not a convention
 * spread across a socket class that cannot be linked into a test at all. See
 * NatRendezvousRelayTest.
 */

//! What happened to a relay request. Everything but RELAY_FORWARD sends nothing
//! at all -- not to the named address, and not back to the requester either. A
//! refusal reply would be a second amplification channel with a smaller factor.
enum ERelayDisposition
{
	//! Validated and forwarded to the target from our own client list.
	RELAY_FORWARD,
	//! No usable source address or port. Identifies nobody, so there is no
	//! budget to charge and no endpoint to forward.
	RELAY_DISCARD_UNUSABLE_SOURCE,
	//! The requester has spent its budget for this window.
	RELAY_DISCARD_RATE_LIMITED,
	//! We hold no identity for the host that sent this.
	RELAY_DISCARD_UNKNOWN_REQUESTER,
	//! Not a well-formed OP_RENDEZVOUS message.
	RELAY_DISCARD_MALFORMED,
	//! The traversal asked for is not the one this build can serve.
	RELAY_DISCARD_UNSUPPORTED_TRAVERSAL,
	//! No endpoint hint, so there is nothing to validate against the source.
	RELAY_DISCARD_NO_ENDPOINT_HINT,
	//! The hint names a host other than the one the request arrived from. This
	//! is the reflection attempt, and it is the reason this file exists.
	RELAY_DISCARD_HINT_NAMES_ANOTHER_HOST,
	//! The request names its own sender as the target: a loop.
	RELAY_DISCARD_TARGET_IS_REQUESTER,
	//! We hold no address for the named target.
	RELAY_DISCARD_UNKNOWN_TARGET
};

/**
 * How many rate-limit buckets the relay will hold at once.
 *
 * A limit that allocates a bucket per source address is itself an amplifier: a
 * single attacker delegated an IPv6 /64 has more source addresses than this
 * process has bytes. Past this cap the limiter never grows.
 *
 * It does not simply deny past it, though, and the reason is that this relay
 * never replies: a source address costs an attacker nothing to forge, so 1024
 * spoofed sources renewed once per window -- about seventeen packets a second
 * -- hold the table full indefinitely, and every peer without a bucket is
 * denied for as long as that runs. That is an outage rather than the retry an
 * earlier version of this comment claimed, and one bucket table serves both
 * directions of this opcode, so the service given away to strangers was
 * starving the capability this client needs for itself.
 *
 * So the cap bounds the class it was written for. A requester this client
 * already holds an identity for is admitted even when the table is full, taking
 * the slot of whichever bucket has been open longest; an unknown one is denied.
 * Flooding is then no longer a matter of picking addresses: to deny anybody the
 * attacker must be in this client's own client list at the source it sends
 * from, which spoofing does not achieve.
 *
 * What that costs, because every eviction policy is itself an attack surface:
 * an attacker in the client list can evict an honest peer's bucket and so RESET
 * that peer's window, handing it up to one extra window of budget. It cannot do
 * that to itself -- its own bucket is found before the table is consulted for
 * room, so a throttled peer stays throttled -- and it cannot use eviction to
 * emit anything, because a relay still needs a hint that matches the observed
 * source and a target out of our own client list. The gain is bounded by
 * kRendezvousMaxAttempts per honest identity per window; the alternative,
 * denying every peer we know during any flood, costs the whole feature.
 */
constexpr size_t kRendezvousRelayBucketCap = 1024;

/**
 * Per-requester relay budget: kRendezvousMaxAttempts relays per
 * kRendezvousBackoffMs.
 *
 * Both numbers are the rendezvous bounds rather than two new ones. A requester
 * that is behaving needs at most one relayed rendezvous per attempt, and a
 * rendezvous is bounded at five attempts inside 120 seconds, so five relays per
 * minute is a budget an honest peer cannot notice and a flooder cannot use.
 * Inventing separate numbers here would give the change two independent safety
 * arguments to keep consistent.
 *
 * Keyed on PeerIdentity::RateLimitScope(), so IPv4 counts per address and IPv6
 * counts per /64 -- the same asymmetry every other per-peer limit in this tree
 * uses, and for the same reason: a per-/128 budget counts to one forever for a
 * subscriber with a prefix, which is the same as having no budget.
 *
 * Not thread-safe, and does not need to be: the client UDP receive path is
 * posted to the main thread.
 */
class CRendezvousRelayLimiter
{
public:
	CRendezvousRelayLimiter() = default;

	/**
	 * Charge one relay request against its requester's budget.
	 *
	 * @param requester the address the request arrived from.
	 * @param nowMs a millisecond tick count.
	 * @param requesterIsKnown whether this client already holds an identity for
	 *        that host -- a user hash on the relay path, a buddy relation on
	 *        the acting one. Answered from our own state, never from the
	 *        datagram. It buys a slot in a full table and nothing else: the
	 *        budget itself is the same five per window either way.
	 * @return true when the request is within budget.
	 */
	bool Admit(const CNetworkAddress &requester, uint64_t nowMs, bool requesterIsKnown)
	{
		const CNetworkAddress scope = PeerIdentity::RateLimitScope(requester);
		if (scope.IsAbsent()) {
			// Identifies nobody. Charging a shared "unknown" bucket would
			// let one such request throttle every other.
			return false;
		}

		const auto existing = m_buckets.find(scope);
		if (existing != m_buckets.end()) {
			SBucket &bucket = existing->second;
			if (nowMs >= bucket.windowStartMs &&
				nowMs - bucket.windowStartMs >= kRendezvousBackoffMs) {
				bucket.windowStartMs = nowMs;
				bucket.count = 1;
				return true;
			}
			// Inside the window -- and also the branch a tick count that
			// moved backwards takes. A clock adjustment is not evidence
			// that a flood stopped, so it does not hand out a new budget.
			if (bucket.count >= kRendezvousMaxAttempts) {
				return false;
			}
			++bucket.count;
			return true;
		}

		if (m_buckets.size() >= kRendezvousRelayBucketCap) {
			PruneExpired(nowMs);
		}
		if (m_buckets.size() >= kRendezvousRelayBucketCap) {
			if (!requesterIsKnown) {
				// The flooder's class, and the cap is doing what it was
				// written for: memory does not grow, and the request is
				// denied rather than served.
				return false;
			}
			// A peer we already hold takes the slot of whichever bucket has
			// been open longest -- the one closest to expiring anyway. The
			// table does not grow, so the memory bound is unchanged.
			if (!EvictOldest()) {
				return false;
			}
		}

		SBucket bucket;
		bucket.windowStartMs = nowMs;
		bucket.count = 1;
		m_buckets[scope] = bucket;
		return true;
	}

	//! How many buckets are held. Exposed so the memory bound is assertable.
	size_t BucketCount() const { return m_buckets.size(); }

private:
	struct SBucket
	{
		uint64_t windowStartMs = 0;
		uint32_t count = 0;
	};

	/**
	 * Drop the bucket whose window opened longest ago, to make room for one
	 * this limiter owes a slot to.
	 *
	 * Linear, and it runs only when the table is full and a known peer
	 * arrives -- the same branch PruneExpired() already scans in.
	 *
	 * @return false only for an empty table, which the caller cannot reach.
	 */
	bool EvictOldest()
	{
		auto oldest = m_buckets.begin();
		if (oldest == m_buckets.end()) {
			return false;
		}
		for (auto it = m_buckets.begin(); it != m_buckets.end(); ++it) {
			if (it->second.windowStartMs < oldest->second.windowStartMs) {
				oldest = it;
			}
		}
		m_buckets.erase(oldest);
		return true;
	}

	//! Drop every bucket whose window has passed. Called only when the table is
	//! full, so the ordinary path costs one map lookup.
	void PruneExpired(uint64_t nowMs)
	{
		for (auto it = m_buckets.begin(); it != m_buckets.end();) {
			const bool expired = nowMs >= it->second.windowStartMs &&
					     nowMs - it->second.windowStartMs >= kRendezvousBackoffMs;
			if (expired) {
				it = m_buckets.erase(it);
			} else {
				++it;
			}
		}
	}

	std::map<CNetworkAddress, SBucket> m_buckets;
};

//! The outcome of one relay request.
struct SRelayDecision
{
	ERelayDisposition disposition = RELAY_DISCARD_MALFORMED;
	//! Whether a packet was sent. True only for RELAY_FORWARD, always.
	bool emitted = false;
	//! The endpoint that was forwarded: the one this relay observed. Absent
	//! when nothing was emitted.
	CNetworkAddress forwardedEndpoint;
	uint16_t forwardedPort = 0;
};

/**
 * Validate and, if it survives, relay one OP_RENDEZVOUS request.
 *
 * @param frame points at the OP_RENDEZVOUS body, i.e. past the 0xC5 protocol
 *        byte and the opcode byte. The body carries no opcode of its own; see
 *        the envelope comment in NatRendezvousProtocol.h.
 * @param frameLength bytes available from there.
 * @param source the address the datagram arrived from, at full width. Not a
 *        32-bit narrowing: a rendezvous can arrive over either family and
 *        attributing an IPv6 request to 0.0.0.0 would put every IPv6 requester
 *        in one rate-limit bucket.
 * @param sourcePort the port it arrived from.
 * @param requesterHash the user hash this client holds for that host, or NULL
 *        when it holds none. NEVER taken from the datagram: this is the value
 *        the forwarded message carries, so a datagram that could set it would
 *        be able to make this relay vouch for anyone.
 * @param nowMs a millisecond tick count.
 * @param limiter the per-requester budget.
 * @param resolveTarget bool(const uint8_t *hash, CNetworkAddress &address,
 *        uint16_t &port) -- this client's own client list. The only source of a
 *        destination address in this function.
 * @param send void(const CNetworkAddress &destination, uint16_t port,
 *        const uint8_t *payload, size_t payloadLength).
 *
 * Both are forwarding references rather than by-value parameters. A by-value
 * copy of a stateful functor silently discards what it recorded, which in this
 * function would mean a test observing zero packets sent because it was looking
 * at the wrong object -- the exact false negative this file must never have.
 *
 * @return what happened. `emitted` is true only on RELAY_FORWARD, and on every
 *         other disposition `send` was not called at all.
 */
template <class TargetResolver, class Sender>
inline SRelayDecision RelayRendezvousRequest(const uint8_t *frame,
	size_t frameLength,
	const CNetworkAddress &source,
	uint16_t sourcePort,
	const uint8_t *requesterHash,
	uint64_t nowMs,
	CRendezvousRelayLimiter &limiter,
	TargetResolver &&resolveTarget,
	Sender &&send)
{
	SRelayDecision decision;

	// An address that identifies nobody cannot be rate limited and cannot be
	// forwarded as an endpoint. Reaching here means a caller bug rather than
	// hostile traffic -- the receive path already rejects such a peer -- and
	// the answer is still to send nothing.
	if (source.IsAbsent() || source.IsUnspecified() || sourcePort == 0) {
		decision.disposition = RELAY_DISCARD_UNUSABLE_SOURCE;
		return decision;
	}

	// Charged before the message is parsed, so garbage is not free. Five
	// malformed requests spend the sender's own budget and its sixth request,
	// valid or not, is throttled.
	if (!limiter.Admit(source, nowMs, requesterHash != nullptr)) {
		decision.disposition = RELAY_DISCARD_RATE_LIMITED;
		return decision;
	}

	if (requesterHash == nullptr) {
		// We would have nothing to put in the forwarded message but something
		// out of the datagram, which is the one thing this function will not do.
		decision.disposition = RELAY_DISCARD_UNKNOWN_REQUESTER;
		return decision;
	}

	SNattRendezvousRequest request;
	if (!ParseRendezvousRequest(frame, frameLength, request)) {
		decision.disposition = RELAY_DISCARD_MALFORMED;
		return decision;
	}

	if (!request.requestsUtpTraversal) {
		// A traversal this build cannot serve. Relaying it anyway would have
		// the target spend its own attempt budget punching toward a transport
		// that will never answer, on our word.
		decision.disposition = RELAY_DISCARD_UNSUPPORTED_TRAVERSAL;
		return decision;
	}

	if (!request.hasEndpointHint) {
		// Nothing to validate against the source. Filling the blank in
		// ourselves would mean relaying for a peer that never said where it is.
		decision.disposition = RELAY_DISCARD_NO_ENDPOINT_HINT;
		return decision;
	}

	// THE check, and it is now doing two jobs. It is the reflection guard: a
	// request may only name the host it arrived from, so this relay cannot be
	// aimed at a third party. And it is what keeps a FORWARD off this path --
	// a forward carries the endpoint of the peer it is about, which is not the
	// relay that sent it, so it fails here and is not forwarded on. Two willing
	// relays therefore cannot loop a message between them, which is what the
	// deleted CONNECT_OPT_NATT_RELAYED bit used to prevent by asking the sender.
	//
	// Compared on the address and not on its spelling, so a
	// dual-stack peer naming ::ffff:a.b.c.d for an IPv4 datagram is accepted --
	// that is the same host -- while any other address is not.
	//
	// The port is deliberately not compared. The address is the reflection
	// vector: a packet aimed at a host it did not ask for is the attack, and a
	// wrong port on the requester's own address reaches the requester either
	// way. Peers behind port-rewriting NATs routinely report a port that is not
	// the one observed, and rejecting them would remove exactly the peers this
	// change exists to connect. It costs nothing to allow, because the port
	// that travels is the observed one too.
	if (request.hintAddress.Unmapped() != source.Unmapped()) {
		decision.disposition = RELAY_DISCARD_HINT_NAMES_ANOTHER_HOST;
		return decision;
	}

	bool namesItself = true;
	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		if (request.peerHash[i] != requesterHash[i]) {
			namesItself = false;
			break;
		}
	}
	if (namesItself) {
		decision.disposition = RELAY_DISCARD_TARGET_IS_REQUESTER;
		return decision;
	}

	CNetworkAddress targetAddress;
	uint16_t targetPort = 0;
	if (!resolveTarget(request.peerHash, targetAddress, targetPort) || targetAddress.IsAbsent() ||
		targetAddress.IsUnspecified() || targetPort == 0) {
		// A hash we do not know is not an address we may invent.
		decision.disposition = RELAY_DISCARD_UNKNOWN_TARGET;
		return decision;
	}

	// The forwarded message names the requester by the identity we hold for it,
	// and carries the endpoint we observed -- not the one that was claimed.
	// The file hash travels on exactly as it arrived, and it is the ONE field
	// here that comes from the datagram. That is not a hole in the rule above:
	// the rule guards the identity and the endpoint, because those are what a
	// forged value would aim traffic with. A file hash names no host and is
	// never dialled -- it is the subject line of the rendezvous -- and this
	// relay has no other source for it. Its client list knows who the requester
	// is, not what it wanted. A request that named no file is forwarded naming
	// none, rather than naming a zero hash that is not the file in question.
	uint8_t forwarded[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length = EncodeRelayedRendezvous(requesterHash,
		request.hasFileHash ? request.fileHash : nullptr,
		source,
		sourcePort,
		forwarded,
		sizeof(forwarded));
	if (length == 0) {
		// The observed endpoint could not be encoded -- an address family this
		// hint format does not carry. Nothing is sent; a rendezvous with no
		// endpoint in it would have the target punch at nothing.
		decision.disposition = RELAY_DISCARD_UNUSABLE_SOURCE;
		return decision;
	}

	send(targetAddress, targetPort, forwarded, length);

	decision.disposition = RELAY_FORWARD;
	decision.emitted = true;
	decision.forwardedEndpoint = source;
	decision.forwardedPort = sourcePort;
	return decision;
}

/**
 * What this client may do with a rendezvous a relay forwarded to it.
 *
 * The other direction, and the only path in this change that acts on an
 * endpoint it did not observe -- so it is the one that has to be argued rather
 * than merely implemented.
 *
 * Four guards stand in front of the punch:
 *
 *  1. **The sender is our buddy.** Answered by the caller from its own client
 *     list, and this is the guard the whole path rests on. It replaced a bit in
 *     the options byte that said "a relay forwarded me": a flag a sender sets
 *     is a claim, and the one thing an attacker crafting this message would set
 *     first. A buddy relation is a fact this client already holds, established
 *     over Kad long before any datagram arrives, and nothing in the packet can
 *     assert it. eMuleAI gates the same step the same way -- their forwarded
 *     rendezvous is accepted only from a serving or served buddy
 *     (srchybrid/ListenSocket.cpp) -- so this is convergence and not a local
 *     invention.
 *  2. **The endpoint is not the sender's own.** A message from our buddy naming
 *     the buddy itself is that buddy asking US to relay, not telling us where
 *     someone else is; it belongs on the relay path. See
 *     RELAYED_REJECT_ENDPOINT_IS_THE_RELAY. This is a disambiguation between
 *     two honest uses, not a security guard -- an attacker chooses the endpoint
 *     freely, and is stopped by guard 1 before reaching here.
 *  3. **The same per-peer budget**, out of the same bucket a requester spends
 *     from, so a peer cannot get a second allowance by switching roles.
 *  4. **A usable endpoint that is not our own.**
 *  5. **An endpoint on the public internet.** The one gate that does not
 *     compare the named address against something this client holds, and so
 *     the only one that still works when this client knows nothing about
 *     itself. See RELAYED_REJECT_ENDPOINT_NOT_ROUTABLE.
 *
 * Guard 4 is weaker than it reads, and the weakness is worth stating rather
 * than leaving for a reader to find: it is skipped whenever `ownEndpoint` is
 * absent, and behind NAT -- the deployment this whole path exists for --
 * CamuleApp::GetPublicIP() frequently has nothing to give. Guard 5 covers the
 * half of it that matters there. A forward naming this client's loopback or its
 * address on the LAN is refused as unroutable whether or not we know who we
 * are; what is left uncovered is our own PUBLIC address while we do not know
 * it, and a punch aimed at that is one bounded burst at ourselves through our
 * own NAT -- no amplification, no third party, and nothing guard 4 could catch
 * without an address it does not have. Inventing one, by trusting a peer's word
 * for our address, would put the value an attacker chooses on both sides of the
 * comparison.
 *
 * The residual exposure is that OUR BUDDY can cause this client to send a
 * bounded burst -- three packets per attempt, five attempts, 120 seconds, all
 * enforced by CHolePunchSchedule -- toward a globally routable address of its
 * choosing. That is inherent to hole punching and is the same trust the design
 * already places in a buddy, which relays this client's callbacks. It is not
 * unbounded, it is not free, and it is a trust one named peer holds rather than
 * every host in the client list.

 */
enum ERelayedAcceptance
{
	//! Act on it: punch toward the endpoint in the decision.
	RELAYED_ACCEPT,
	//! Not a well-formed OP_RENDEZVOUS message.
	RELAYED_REJECT_MALFORMED,
	//! No usable address for the relay itself.
	RELAYED_REJECT_UNUSABLE_RELAY,
	//! The host that sent this is not this client's buddy. The crafted-packet
	//! case, and the only guard that stands between a stranger and a punch.
	RELAYED_REJECT_RELAY_IS_NOT_OUR_BUDDY,
	//! The relay has spent its budget for this window.
	RELAYED_REJECT_RATE_LIMITED,
	//! The traversal asked for is not the one this build can serve.
	RELAYED_REJECT_UNSUPPORTED_TRAVERSAL,
	//! The forward carries no endpoint, so there is nothing to punch toward.
	RELAYED_REJECT_NO_ENDPOINT,
	//! The endpoint is this client's own address: a small self-amplifier that
	//! could accomplish nothing else.
	RELAYED_REJECT_ENDPOINT_IS_OURSELVES,
	//! The endpoint is not an address on the public internet: loopback, a
	//! private or link-local block, CGNAT, documentation space, multicast or
	//! broadcast. Our buddy naming one of those is asking this client to aim a
	//! burst at its own loopback or at a host inside its operator's LAN.
	RELAYED_REJECT_ENDPOINT_NOT_ROUTABLE,
	//! The endpoint is the sender's own address, so this is our buddy asking us
	//! to relay rather than telling us where a third peer is. Not a refusal of
	//! the message: the caller hands it to RelayRendezvousRequest() instead.
	RELAYED_REJECT_ENDPOINT_IS_THE_RELAY
};

//! The outcome of one relayed rendezvous.
struct SRelayedRendezvousDecision
{
	ERelayedAcceptance acceptance = RELAYED_REJECT_MALFORMED;
	//! Whether to punch. True only for RELAYED_ACCEPT, always.
	bool punch = false;
	//! Where to punch. Absent unless `punch` -- absent rather than zero, so a
	//! caller that ignores the acceptance code still cannot dial anything.
	CNetworkAddress punchEndpoint;
	uint16_t punchPort = 0;
	//! The peer to punch toward, by identity. Zero unless `punch`.
	uint8_t peerHash[NATT_PEER_HASH_LENGTH] = { 0 };
};

/**
 * Validate one relayed OP_RENDEZVOUS.
 *
 * @param frame points at the OP_RENDEZVOUS body, past the 0xC5 protocol byte
 *        and the opcode byte.
 * @param frameLength bytes available from there.
 * @param relay the address the forward arrived from, at full width.
 * @param senderIsOurBuddy whether that host is this client's buddy. The
 *        caller's own client list answers this, and nothing in the datagram
 *        can. It replaced a "this was forwarded" bit in the options byte, which
 *        an attacker sets as easily as a relay does -- and which collided with
 *        eMuleAI's QUIC capability bit besides; see ENattConnectOptions.
 * @param ownEndpoint this client's own believed external address, so a forward
 *        naming us can be refused. An absent address disables that one check
 *        rather than failing the whole message -- a client that does not know
 *        its own external address is the ordinary case behind NAT, and the
 *        other three guards do not depend on it.
 * @param nowMs a millisecond tick count.
 * @param limiter the same per-peer budget the relay path charges.
 *
 * Emits nothing itself. The punch is CHolePunchSchedule's, which is what keeps
 * the bounds in one place instead of two.
 */
inline SRelayedRendezvousDecision AcceptRelayedRendezvous(const uint8_t *frame,
	size_t frameLength,
	const CNetworkAddress &relay,
	bool senderIsOurBuddy,
	const CNetworkAddress &ownEndpoint,
	uint64_t nowMs,
	CRendezvousRelayLimiter &limiter)
{
	SRelayedRendezvousDecision decision;

	if (relay.IsAbsent() || relay.IsUnspecified()) {
		decision.acceptance = RELAYED_REJECT_UNUSABLE_RELAY;
		return decision;
	}

	// Charged before the message is parsed, on the same reasoning as the relay
	// path: garbage from a peer spends that peer's own budget.
	if (!limiter.Admit(relay, nowMs, senderIsOurBuddy)) {
		decision.acceptance = RELAYED_REJECT_RATE_LIMITED;
		return decision;
	}

	SNattRendezvousRequest request;
	if (!ParseRendezvousRequest(frame, frameLength, request)) {
		decision.acceptance = RELAYED_REJECT_MALFORMED;
		return decision;
	}

	if (!senderIsOurBuddy) {
		decision.acceptance = RELAYED_REJECT_RELAY_IS_NOT_OUR_BUDDY;
		return decision;
	}

	if (!request.requestsUtpTraversal) {
		decision.acceptance = RELAYED_REJECT_UNSUPPORTED_TRAVERSAL;
		return decision;
	}

	if (!request.hasEndpointHint || request.hintPort == 0 || request.hintAddress.IsAbsent() ||
		request.hintAddress.IsUnspecified()) {
		decision.acceptance = RELAYED_REJECT_NO_ENDPOINT;
		return decision;
	}

	// Our buddy naming ITSELF is our buddy asking us to relay for it, which is
	// the other thing a buddy legitimately sends on this opcode. Reported
	// rather than accepted, so the caller routes it to RelayRendezvousRequest()
	// -- where naming the source is not merely allowed but required. Acting on
	// it here would punch at the one peer we are already in contact with and
	// silently drop the relay the buddy actually asked for.
	//
	// Address only, on the same reasoning as the reflection check on the relay
	// path: a peer behind a port-rewriting NAT reports a port that is not the
	// one observed, and the port does not change which host is meant.
	if (request.hintAddress.Unmapped() == relay.Unmapped()) {
		decision.acceptance = RELAYED_REJECT_ENDPOINT_IS_THE_RELAY;
		return decision;
	}

	// Compared on the address alone. The port a NAT presents for our own
	// mapping is not something this client reliably knows, and an endpoint on
	// our own address is not worth punching at whichever port it names.
	if (!ownEndpoint.IsAbsent() && !ownEndpoint.IsUnspecified() &&
		request.hintAddress.Unmapped() == ownEndpoint.Unmapped()) {
		decision.acceptance = RELAYED_REJECT_ENDPOINT_IS_OURSELVES;
		return decision;
	}

	// The last gate, and the one that does not need to know anything about
	// this client to be right. Everything above compares the named endpoint
	// with an address we hold; this asks whether the address is one a packet
	// has any business reaching at all. Our buddy naming 127.0.0.1 has us punch
	// at our own loopback services; naming 10.0.0.5 or 192.168.1.1 has us punch
	// inside our operator's LAN, a network the buddy cannot reach itself, which
	// is exactly why it would ask us to. Multicast and broadcast turn the
	// bounded burst into a fan-out on top of that.
	//
	// Last rather than first on purpose. The two comparisons above name a
	// specific host -- the relay, or us -- and those answers stay true for a
	// peer on a private network, where an aMule pair on one LAN is an ordinary
	// deployment. Reporting "not routable" for a forward that is really our
	// buddy asking us to relay would send the caller down the wrong path with
	// the right refusal.
	//
	// CNetworkAddress::IsGloballyRoutableIPv4() is the predicate, unchanged and
	// unduplicated: UtpEncryptionPolicy.h already asks it the mirror-image
	// question about our own address. A second list of blocks maintained here
	// would be a second thing to keep correct. It answers false for every IPv6
	// address, which costs nothing here because the endpoint tail this hint
	// arrives in carries four octets and cannot spell one.
	if (!request.hintAddress.IsGloballyRoutableIPv4()) {
		decision.acceptance = RELAYED_REJECT_ENDPOINT_NOT_ROUTABLE;
		return decision;
	}

	decision.acceptance = RELAYED_ACCEPT;
	decision.punch = true;
	decision.punchEndpoint = request.hintAddress;
	decision.punchPort = request.hintPort;
	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		decision.peerHash[i] = request.peerHash[i];
	}
	return decision;
}

#endif // NATRENDEZVOUSRELAY_H
