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
	RELAY_DISCARD_UNKNOWN_TARGET,
	//! The message already carries CONNECT_OPT_NATT_RELAYED. It is a forward
	//! addressed to this client, not a request to relay, and forwarding a
	//! forward is a loop between two willing relays that only the rate limit
	//! would stop -- and only after both had spent their budgets.
	RELAY_DISCARD_ALREADY_RELAYED
};

/**
 * How many rate-limit buckets the relay will hold at once.
 *
 * A limit that allocates a bucket per source address is itself an amplifier: a
 * single attacker delegated an IPv6 /64 has more source addresses than this
 * process has bytes. Past this cap the limiter denies rather than growing,
 * which is the safe direction -- a full table means a flood is in progress, and
 * the cost of denying a genuine request during one is a retry.
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
	 * @return true when the request is within budget.
	 */
	bool Admit(const CNetworkAddress &requester, uint64_t nowMs)
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
			if (m_buckets.size() >= kRendezvousRelayBucketCap) {
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
 * @param frame points at the OP_RENDEZVOUS opcode byte, i.e. past the 0xB2 and
 *        0x00 framing bytes.
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
	if (!limiter.Admit(source, nowMs)) {
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

	if (request.isRelayed) {
		// A forward, not a request to relay. The direction is read off the
		// wire rather than inferred from local state precisely so that this
		// branch exists: a crafted request cannot reach the acting path, and
		// a forward cannot reach this one.
		decision.disposition = RELAY_DISCARD_ALREADY_RELAYED;
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

	// THE check. Compared on the address and not on its spelling, so a
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
	// Marked relayed, so the target acts on it instead of relaying it on, and
	// so this same function refuses it if it ever comes back here.
	uint8_t forwarded[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length =
		EncodeRelayedRendezvous(requesterHash, source, sourcePort, forwarded, sizeof(forwarded));
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
 *  1. **The relayed bit.** A plain relay request -- the shape an attacker sends
 *     to make this client aim traffic somewhere -- cannot reach this path at
 *     all, whatever endpoint it names.
 *  2. **A relay we already know.** Signalling is acted on only from a peer
 *     already in this client's client list. A stranger cannot make it punch.
 *  3. **The same per-peer budget**, out of the same bucket a requester spends
 *     from, so a peer cannot get a second allowance by switching roles.
 *  4. **A usable endpoint that is not our own.**
 *
 * The residual exposure is that a KNOWN relay can cause this client to send a
 * bounded burst -- three packets per attempt, five attempts, 120 seconds, all
 * enforced by CHolePunchSchedule -- toward an address of that relay's choosing.
 * That is inherent to hole punching and is the same trust the design places in
 * R for signalling. It is not unbounded and it is not free.
 */
enum ERelayedAcceptance
{
	//! Act on it: punch toward the endpoint in the decision.
	RELAYED_ACCEPT,
	//! Not a well-formed OP_RENDEZVOUS message.
	RELAYED_REJECT_MALFORMED,
	//! CONNECT_OPT_NATT_RELAYED is clear, so this is a request to relay and
	//! not a forward. The crafted-packet case.
	RELAYED_REJECT_NOT_RELAYED,
	//! No usable address for the relay itself.
	RELAYED_REJECT_UNUSABLE_RELAY,
	//! We hold no identity for the host that forwarded this.
	RELAYED_REJECT_UNKNOWN_RELAY,
	//! The relay has spent its budget for this window.
	RELAYED_REJECT_RATE_LIMITED,
	//! The traversal asked for is not the one this build can serve.
	RELAYED_REJECT_UNSUPPORTED_TRAVERSAL,
	//! The forward carries no endpoint, so there is nothing to punch toward.
	RELAYED_REJECT_NO_ENDPOINT,
	//! The endpoint is this client's own address: a small self-amplifier that
	//! could accomplish nothing else.
	RELAYED_REJECT_ENDPOINT_IS_OURSELVES
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
 * @param frame points at the OP_RENDEZVOUS opcode byte.
 * @param frameLength bytes available from there.
 * @param relay the address the forward arrived from, at full width.
 * @param relayIsKnown whether this client holds an identity for that host. The
 *        caller's own client list answers this; there is no way to assert it
 *        from inside the datagram.
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
	bool relayIsKnown,
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
	if (!limiter.Admit(relay, nowMs)) {
		decision.acceptance = RELAYED_REJECT_RATE_LIMITED;
		return decision;
	}

	SNattRendezvousRequest request;
	if (!ParseRendezvousRequest(frame, frameLength, request)) {
		decision.acceptance = RELAYED_REJECT_MALFORMED;
		return decision;
	}

	if (!request.isRelayed) {
		decision.acceptance = RELAYED_REJECT_NOT_RELAYED;
		return decision;
	}

	if (!relayIsKnown) {
		decision.acceptance = RELAYED_REJECT_UNKNOWN_RELAY;
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

	// Compared on the address alone. The port a NAT presents for our own
	// mapping is not something this client reliably knows, and an endpoint on
	// our own address is not worth punching at whichever port it names.
	if (!ownEndpoint.IsAbsent() && !ownEndpoint.IsUnspecified() &&
		request.hintAddress.Unmapped() == ownEndpoint.Unmapped()) {
		decision.acceptance = RELAYED_REJECT_ENDPOINT_IS_OURSELVES;
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
