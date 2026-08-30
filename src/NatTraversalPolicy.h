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

#ifndef NATTRAVERSALPOLICY_H
#define NATTRAVERSALPOLICY_H

#include <cstddef>
#include <cstdint>

#include <protocol/Protocols.h> // Needed for OP_NATT_FRAME_UTP / OP_NATT_FRAME_QUIC

#include "NatRendezvousProtocol.h" // Needed for kNattFrameTypeFallbackWaitMs
#include "NetworkAddress.h"        // Needed for CNetworkAddress

/**
 * Whether a rendezvous is attempted at all, which frame type carries it, and
 * what a peer's endpoint hint is worth.
 *
 * These are three decisions rather than one because they are asked at three
 * different moments, but they share one property: each has a wrong answer with
 * no visible symptom, which is why all three are functions with tests rather
 * than conditions inside CUpDownClient.
 *
 * The case that matters most is the ordinary peer. Almost nothing on the ed2k
 * network advertises NAT traversal, and for every one of those peers the
 * connection must be the connection aMule made before this change: no
 * rendezvous, no punch, the server callback and Kad buddy paths used exactly as
 * they were. A stray rendezvous there does not fail loudly -- it spends a
 * relay's budget and this client's attempt budget on a peer that was always
 * reachable the ordinary way, and the symptom is slower connections for no
 * reason anyone can find.
 *
 * Header-only and free of theApp and of wxWidgets, on the same reasoning as
 * UtpDialPolicy.h.
 */

//! Everything the initiation decision depends on, gathered so the call site
//! reads as a list of facts rather than six positional booleans.
struct SRendezvousInputs
{
	//! The peer's MOD_MISCOPT_NAT_TRAVERSAL bit.
	bool peerAdvertisesUtpTraversal = false;
	//! Whether this end can actually serve the traversal it would be asking
	//! for: a uTP context that exists and would carry a connection. The same
	//! question CUtpContext::CanServeConnections() answers, and the same rule
	//! as every capability bit in this tree -- compiled in is not the same as
	//! able to serve.
	bool localCanServeUtpTraversal = false;
	//! This end has a LowID / no inbound reachability.
	bool localIsFirewalled = false;
	//! The peer has a LowID / no inbound reachability.
	bool peerIsFirewalled = false;
	//! A mutually reachable third party that can relay to the peer is known.
	bool relayAvailable = false;
	//! A previous rendezvous for this pair exhausted its budget and its 60
	//! second backoff has not elapsed.
	bool backoffActive = false;
};

//! Why initiation went the way it did, so a log line can name the reason rather
//! than saying "no traversal" for six different situations.
enum ERendezvousRefusal
{
	//! A rendezvous is being initiated.
	RENDEZVOUS_INITIATE,
	//! The peer never claimed traversal. The ordinary peer, and the ordinary
	//! path.
	RENDEZVOUS_REFUSE_PEER_ADVERTISES_NO_TRAVERSAL,
	//! This end cannot serve the traversal. Ours, not the peer's.
	RENDEZVOUS_REFUSE_LOCAL_CANNOT_SERVE,
	//! The peer accepts inbound connections: nothing to traverse.
	RENDEZVOUS_REFUSE_PEER_NOT_FIREWALLED,
	//! This end accepts inbound connections, so the peer can be called back.
	RENDEZVOUS_REFUSE_LOCAL_NOT_FIREWALLED,
	//! No third party that can reach the peer.
	RENDEZVOUS_REFUSE_NO_RELAY,
	//! A previous attempt for this pair is still backing off.
	RENDEZVOUS_REFUSE_BACKOFF_ACTIVE
};

//! What to do instead of a rendezvous.
enum ERendezvousAlternative
{
	//! Nothing special: connect the way this client always did. Either a
	//! rendezvous is under way, or the peer is directly reachable.
	NATT_ALT_NONE,
	//! Use the server callback and Kad buddy paths. The spec delta requires
	//! these to keep working and to remain the fallback.
	NATT_ALT_CALLBACK_OR_BUDDY
};

//! The answer, in one value.
struct SRendezvousDecision
{
	bool initiate = false;
	ERendezvousRefusal refusal = RENDEZVOUS_REFUSE_PEER_ADVERTISES_NO_TRAVERSAL;
	ERendezvousAlternative alternative = NATT_ALT_CALLBACK_OR_BUDDY;
	//! Always false. Present so that adding a refusal reason forces whoever
	//! adds it to decide the question, rather than inheriting a default from a
	//! caller that guessed. There is no reason to refuse a rendezvous that is
	//! also a reason to blame the peer: every one of them is a fact about a
	//! capability, a reachability state or our own budget.
	bool markPeerDead = false;
	bool dropFromSourceList = false;
};

/**
 * Decide whether to initiate a rendezvous with one peer.
 *
 * The order of the tests is part of the decision. Reachability comes first,
 * because a peer that can simply be connected to must not be routed through any
 * of this; the capability tests come next, so a peer that never claimed
 * traversal produces the refusal that names that and nothing else.
 */
inline SRendezvousDecision DecideRendezvousInitiation(const SRendezvousInputs &inputs)
{
	SRendezvousDecision decision;

	if (!inputs.peerIsFirewalled) {
		// Directly reachable. Not the callback path either: the ordinary
		// direct connection, unchanged.
		decision.refusal = RENDEZVOUS_REFUSE_PEER_NOT_FIREWALLED;
		decision.alternative = NATT_ALT_NONE;
		return decision;
	}

	if (!inputs.localIsFirewalled) {
		// The peer can reach us, so the existing callback machinery is exactly
		// the right tool. Rendezvous is for the pair neither of whom can be
		// called.
		decision.refusal = RENDEZVOUS_REFUSE_LOCAL_NOT_FIREWALLED;
		decision.alternative = NATT_ALT_CALLBACK_OR_BUDDY;
		return decision;
	}

	if (!inputs.peerAdvertisesUtpTraversal) {
		decision.refusal = RENDEZVOUS_REFUSE_PEER_ADVERTISES_NO_TRAVERSAL;
		decision.alternative = NATT_ALT_CALLBACK_OR_BUDDY;
		return decision;
	}

	if (!inputs.localCanServeUtpTraversal) {
		decision.refusal = RENDEZVOUS_REFUSE_LOCAL_CANNOT_SERVE;
		decision.alternative = NATT_ALT_CALLBACK_OR_BUDDY;
		return decision;
	}

	if (!inputs.relayAvailable) {
		// Nothing to relay through. In particular this does NOT fall back to
		// punching on our own: a punch toward a mapping the peer was never
		// asked to open is traffic toward a host that did not agree to it.
		decision.refusal = RENDEZVOUS_REFUSE_NO_RELAY;
		decision.alternative = NATT_ALT_CALLBACK_OR_BUDDY;
		return decision;
	}

	if (inputs.backoffActive) {
		// Honoured here as well as in CHolePunchSchedule, so a caller polling
		// every core tick cannot restart a rendezvous the schedule is still
		// backing off from. The source keeps its place throughout.
		decision.refusal = RENDEZVOUS_REFUSE_BACKOFF_ACTIVE;
		decision.alternative = NATT_ALT_CALLBACK_OR_BUDDY;
		return decision;
	}

	decision.initiate = true;
	decision.refusal = RENDEZVOUS_INITIATE;
	decision.alternative = NATT_ALT_NONE;
	return decision;
}

//! Everything the frame-type decision depends on, gathered so the call site
//! reads as a list of facts rather than four positional values. Omitting one of
//! them is exactly the mistake this struct exists to make impossible: the
//! capability frame and the elapsed time answer different halves of the same
//! question, and a call site that passed only the clock would drop a confirmed
//! QUIC exchange back to uTP at the boundary.
struct SNattFrameTypeInputs
{
	//! The peer's MOD_MISCOPT_NAT_TRAVERSAL_QUIC bit.
	bool peerAdvertisesQuic = false;
	//! Whether this end can actually serve a QUIC NAT-T exchange -- compiled
	//! in *and* able to carry a connection. See LocalCanServeQuicNatTraversal().
	bool localCanServeQuic = false;
	//! Whether the peer's QUIC capability frame has arrived for this exchange.
	//! Until it has, QUIC is an expectation rather than a fact.
	bool quicCapabilityFrameSeen = false;
	//! How long the exchange has been running.
	uint64_t msSinceRendezvousStarted = 0;
};

//! Why the frame type went the way it did, so a log line can name the reason
//! rather than saying "QUIC unavailable" for four different situations.
enum ENattFrameTypeReason
{
	//! The peer's capability frame arrived. QUIC is a fact, not a hope.
	NATT_FRAME_QUIC_CONFIRMED,
	//! Inside the 1500 ms window, still hoping.
	NATT_FRAME_QUIC_AWAITING_CAPABILITY,
	//! The peer never claimed QUIC. No wait applies.
	NATT_FRAME_UTP_PEER_HAS_NO_QUIC,
	//! This build has no QUIC transport, or it cannot serve one right now.
	NATT_FRAME_UTP_LOCAL_HAS_NO_QUIC,
	//! The window closed with no capability frame. This is the spec delta's
	//! "capability frame lost".
	NATT_FRAME_UTP_CAPABILITY_TIMED_OUT
};

//! The transport a NAT-T exchange concluded on.
//!
//! Separate from the frame-type byte because they answer different questions
//! for different callers: this one is "what did we negotiate", which a caller
//! can log, gate on, or store, and the byte is "where do these particular bytes
//! go". Making a caller compare a decision against 0x01 to learn the first is
//! how a frame-type constant ends up standing in for a transport in code that
//! has nothing to do with framing.
enum ENattTransport : uint8_t
{
	NATT_TRANSPORT_UTP,
	NATT_TRANSPORT_QUIC
};

/**
 * Which OP_UDPRESERVEDPROT2 frame type carries the exchange's TRANSPORT DATA
 * right now, and which transport that is.
 *
 * Transport data, and not the control messages. That distinction did not exist
 * when this was written -- rendezvous and hole punches rode 0xB2 with a frame
 * type too, so one byte answered both questions and the name was the whole
 * truth. It is not any more: control messages ride 0xC5 with their opcode as
 * the datagram's second byte (NATT_CONTROL_PROTOCOL, NatRendezvousProtocol.h),
 * which is a constant with no inputs and nothing to negotiate.
 *
 * So the two questions the name used to conflate are now separated by shape.
 * The one that depends on what the peer advertised and on the clock is this
 * function; the one that depends on nothing is a constant. Neither can be
 * mistaken for the other at a call site, which is the point.
 */
struct SNattFrameTypeDecision
{
	//! OP_NATT_FRAME_QUIC (0x01) or OP_NATT_FRAME_UTP (0x00). The frame type
	//! for transport data on 0xB2; never the envelope of a control message.
	uint8_t frameType = OP_NATT_FRAME_UTP;
	//! The same conclusion, said as a transport. Always consistent with
	//! frameType -- they are one decision reported twice, not two.
	ENattTransport transport = NATT_TRANSPORT_UTP;
	//! True only while the QUIC frame type is still being given its chance,
	//! i.e. inside the window with no capability frame yet. The caller should
	//! re-ask after the wait rather than treating silence as a failure. A
	//! confirmed QUIC exchange is not "waiting" -- there is nothing left to
	//! wait for.
	bool waitingForQuic = false;
	ENattFrameTypeReason reason = NATT_FRAME_UTP_PEER_HAS_NO_QUIC;
	/**
	 * Always false, and present so that adding a reason forces whoever adds it
	 * to decide the question rather than inheriting a default.
	 *
	 * The spec delta states it plainly: when the capability frame is lost the
	 * user-visible state must show a connected peer, not a failure. Falling
	 * back is the ordinary outcome of a negotiation with a peer that turned
	 * out not to speak QUIC -- the connection still happens, over uTP. A user
	 * who saw "QUIC failed" would be reading a diagnosis of nothing.
	 */
	bool surfacesFailure = false;
};

/**
 * Whether this build can serve a QUIC NAT-T exchange.
 *
 * Two independent conditions, and the difference between them is the failure
 * mode PeerCapabilities.h describes. Compiled in (AMULE_QUIC_TRANSPORT, i.e.
 * -DENABLE_QUIC=YES against ngtcp2 and its GnuTLS binding) is necessary and not
 * sufficient: a build with a QUIC context that has no usable TLS credentials
 * would answer an exchange it cannot finish, and neither side would log a
 * reason.
 *
 * The runtime half therefore travels as an argument rather than being read from
 * a macro here, for the same reason AdvertisedModMiscOptions() takes
 * utpTransportCanServe: both branches have to be reachable in the one build a
 * test binary is, and only one of them exists in any real build. The caller
 * passes CQuicContext::CanServeConnections().
 *
 * On a platform where QUIC is not built -- macOS, where Homebrew's libngtcp2
 * links OpenSSL and no GnuTLS-bound build is packaged; see design.md -- this is
 * false whatever the runtime answer, and every exchange rides the uTP frame
 * type with no wait at all.
 */
inline bool LocalCanServeQuicNatTraversal(bool quicTransportCanServe)
{
#ifdef AMULE_QUIC_TRANSPORT
	return quicTransportCanServe;
#else
	// Unused in this configuration; named rather than dropped so the two
	// branches keep the same signature.
	(void)quicTransportCanServe;
	return false;
#endif
}

/**
 * Whether this client knows a third party that can relay a rendezvous to a
 * given peer.
 *
 * False, and a function rather than a constant for the same reason
 * LocalCanServeQuicNatTraversal() takes an argument: it is the one place that
 * has to change when relay discovery exists, and until then every call site
 * reads as a fact about this build rather than as a guess.
 *
 * The gap is specific and is not an oversight. A usable relay R must satisfy
 * two conditions: this client can reach R, and R can reach the firewalled peer
 * B. The first is knowable -- any peer with a live connection here qualifies.
 * The second is not knowable from this side at all. B is firewalled, so B is
 * reachable only by a host B is already connected to, and nothing in this tree
 * tells this client who those hosts are: CClientList holds our own peers, not
 * theirs. The two mechanisms that do know are B's server (which answers a
 * callback and does not speak this protocol) and B's Kad buddy -- which are
 * precisely the existing fallback paths, and are what a refused initiation
 * returns to.
 *
 * So the requester half of the exchange is gated off in this build, while the
 * responder half is live: a rendezvous a relay forwards to this client is
 * validated by AcceptRelayedRendezvous() and punched by CNatRendezvousManager.
 * An eMuleAI peer that has relay discovery can therefore traverse to aMule; an
 * aMule that wants to initiate cannot yet choose an R to ask. Returning false
 * here is what keeps that honest -- a client that guessed at an R would spend
 * that peer's relay budget and its own attempt budget on a signalling message
 * nobody could forward, and the symptom would be slower connections with no
 * traceable cause.
 */
inline bool LocalCanDiscoverRendezvousRelay()
{
	return false;
}

/**
 * Pick the frame type, applying the documented 1500 ms wait.
 *
 * Three outcomes, in this order, and the order is the decision:
 *
 *   1. Either side lacking QUIC ends it immediately, on the uTP frame type,
 *      with no wait. A capability frame cannot conjure a transport that is not
 *      there, which is why the two capability tests come before it -- otherwise
 *      a peer could talk this end onto a frame type it has no context for.
 *   2. The peer's capability frame having arrived ends the wait the other way:
 *      QUIC carries the exchange for as long as it runs. Without this the
 *      1500 ms would be a lifetime rather than a wait, and a confirmed QUIC
 *      exchange would drop back to uTP mid-flight at the boundary -- the one
 *      outcome neither side can diagnose.
 *   3. Otherwise the window decides: QUIC optimistically while it is open,
 *      uTP once it has closed. This is the spec delta's "capability frame
 *      lost", and falling back is not a failure -- see
 *      SNattFrameTypeDecision::surfacesFailure.
 */
inline SNattFrameTypeDecision SelectNattFrameType(const SNattFrameTypeInputs &inputs)
{
	SNattFrameTypeDecision decision;

	if (!inputs.peerAdvertisesQuic) {
		decision.reason = NATT_FRAME_UTP_PEER_HAS_NO_QUIC;
		return decision;
	}

	if (!inputs.localCanServeQuic) {
		decision.reason = NATT_FRAME_UTP_LOCAL_HAS_NO_QUIC;
		return decision;
	}

	if (inputs.quicCapabilityFrameSeen) {
		decision.frameType = OP_NATT_FRAME_QUIC;
		decision.transport = NATT_TRANSPORT_QUIC;
		decision.waitingForQuic = false;
		decision.reason = NATT_FRAME_QUIC_CONFIRMED;
		return decision;
	}

	if (inputs.msSinceRendezvousStarted < kNattFrameTypeFallbackWaitMs) {
		decision.frameType = OP_NATT_FRAME_QUIC;
		decision.transport = NATT_TRANSPORT_QUIC;
		decision.waitingForQuic = true;
		decision.reason = NATT_FRAME_QUIC_AWAITING_CAPABILITY;
		return decision;
	}

	decision.reason = NATT_FRAME_UTP_CAPABILITY_TIMED_OUT;
	return decision;
}

/**
 * Which transport the exchange concluded on: the "what did we negotiate" half.
 *
 * Delegates rather than deciding again, because two functions answering the
 * same question from the same inputs is two functions that can disagree -- and
 * the disagreement would be a transport chosen on one path and a frame type
 * chosen on another, which is a stall with nothing logged on either side.
 */
inline ENattTransport SelectNattTransport(const SNattFrameTypeInputs &inputs)
{
	return SelectNattFrameType(inputs).transport;
}

//! One endpoint worth punching toward.
struct SNattEndpointCandidate
{
	CNetworkAddress address;
	uint16_t port = 0;
	//! True when this endpoint came from a peer's OP_NATT_ENDPOINT_HINT rather
	//! than from what this client already knew.
	bool fromHint = false;
};

/**
 * How many endpoints one pair is punched toward.
 *
 * Four: the peer's known ed2k address, an IPv6 address it advertised, and a
 * hint each way. Fixed rather than unbounded because the set is multiplied by
 * the packets in a burst -- an unbounded candidate list turns a three-packet
 * burst into as many packets as a peer cares to name endpoints, which is the
 * amplifier this change exists to not be.
 */
constexpr size_t kNattMaxCandidates = 4;

/**
 * The endpoints to punch toward, in the order they should be tried.
 *
 * The rule the spec delta states is one sentence -- a hint is one candidate
 * among the addresses already known, never a replacement for them -- and it is
 * enforced structurally here rather than by remembering it: there is no method
 * on this class that removes anything, so no hint can displace a known address.
 * When the set is full the hint is what is dropped.
 *
 * That matters because a peer behind symmetric NAT reports a port that is
 * already stale by the time it arrives. A client that preferred the hint over
 * what it knew would stop reaching peers it used to reach, and the hint would
 * look like the fix rather than the cause.
 */
class CNattCandidateSet
{
public:
	CNattCandidateSet() = default;

	//! Add an endpoint this client already knew for the peer.
	bool AddKnown(const CNetworkAddress &address, uint16_t port) { return Add(address, port, false); }

	//! Add an endpoint a peer named in an OP_NATT_ENDPOINT_HINT.
	bool AddHint(const CNetworkAddress &address, uint16_t port) { return Add(address, port, true); }

	size_t Count() const { return m_count; }

	//! @pre index < Count().
	const SNattEndpointCandidate &At(size_t index) const { return m_candidates[index]; }

private:
	/**
	 * @return true when the endpoint was added. False when it is not an
	 *         endpoint, when it is already in the set, or when the set is full
	 *         -- three different reasons the caller does not have to tell
	 *         apart, because the answer to all of them is the same: this
	 *         endpoint is not punched toward and nothing already in the set
	 *         changed.
	 */
	bool Add(const CNetworkAddress &address, uint16_t port, bool fromHint)
	{
		if (port == 0 || address.IsAbsent() || address.IsUnspecified()) {
			// Each of these would otherwise become a punch attempt spent
			// finding out that nothing is there.
			return false;
		}

		const CNetworkAddress unmapped = address.Unmapped();
		for (size_t i = 0; i < m_count; ++i) {
			if (m_candidates[i].port == port && m_candidates[i].address.Unmapped() == unmapped) {
				// Already here. The one that stays is the one that was
				// already in the set, so a hint that happens to agree with a
				// known address does not relabel it as a hint.
				return false;
			}
		}

		if (m_count >= kNattMaxCandidates) {
			return false;
		}

		m_candidates[m_count].address = address;
		m_candidates[m_count].port = port;
		m_candidates[m_count].fromHint = fromHint;
		++m_count;
		return true;
	}

	SNattEndpointCandidate m_candidates[kNattMaxCandidates];
	size_t m_count = 0;
};

#endif // NATTRAVERSALPOLICY_H
