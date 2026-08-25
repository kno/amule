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

// When a rendezvous is attempted at all, which frame type carries it, and what
// a peer's endpoint hint is worth.
//
// The characterisation that matters most is the one with nothing to do with
// NAT traversal. The overwhelming majority of peers advertise no traversal
// capability, and for every one of them the connection must be the connection
// aMule made before this change existed: no rendezvous, no hole punch, and the
// server callback and Kad buddy paths used exactly as they were. A stray
// rendezvous there would not fail loudly -- it would spend a relay's budget and
// this client's attempt budget on a peer that was always reachable the ordinary
// way, and the symptom would be slower connections for no visible reason.
//
// The frame-type rule is the other half. The QUIC frame type is preferred for
// 1500 ms when the peer advertised QUIC NAT-T *and this build can serve it*, and
// falls back to the legacy uTP frame type after that. This tree ships no QUIC
// transport, so the second condition is false in every real build here and the
// exchange always rides 0x00 -- which is why the flag is an argument rather than
// something read from a macro inside the function. Both branches have to be
// reachable in the one build a test binary is, on the same reasoning as
// AdvertisedModMiscOptions()'s utpTransportCanServe argument.
//
// The hint rule is a single sentence with an invisible failure: a hint is one
// candidate among the addresses already known, never a replacement for them. A
// peer behind symmetric NAT reports a port that is already stale by the time it
// arrives, so a client that trusted the hint over what it knew would stop
// reaching peers it used to reach.

#include <muleunit/test.h>

#include <NatRendezvousProtocol.h>
#include <NatTraversalPolicy.h>
#include <NetworkAddress.h>

using namespace muleunit;

DECLARE_SIMPLE(NatTraversalPolicy)

namespace
{

//! Both ends firewalled, the peer advertises uTP NAT-T, we can serve it, a
//! relay is known and no backoff is running: the one case that initiates.
SRendezvousInputs Viable()
{
	SRendezvousInputs inputs;
	inputs.peerAdvertisesUtpTraversal = true;
	inputs.localCanServeUtpTraversal = true;
	inputs.localIsFirewalled = true;
	inputs.peerIsFirewalled = true;
	inputs.relayAvailable = true;
	inputs.backoffActive = false;
	return inputs;
}

} // namespace

// Task 4.1's positive case, so the negatives below mean something.
TEST(NatTraversalPolicy, TwoFirewalledPeersWithTheCapabilityAndARelayInitiate)
{
	const SRendezvousDecision decision = DecideRendezvousInitiation(Viable());

	ASSERT_TRUE(decision.initiate);
	ASSERT_EQUALS((int)RENDEZVOUS_INITIATE, (int)decision.refusal);
	ASSERT_EQUALS((int)NATT_ALT_NONE, (int)decision.alternative);
}

// The spec scenario, and the regression with no symptom. A peer that advertised
// no traversal capability triggers no rendezvous at all, and the paths that
// predate this change are what is used instead.
TEST(NatTraversalPolicy, PeerWithoutATraversalCapabilityTriggersNoRendezvous)
{
	SRendezvousInputs inputs = Viable();
	inputs.peerAdvertisesUtpTraversal = false;

	const SRendezvousDecision decision = DecideRendezvousInitiation(inputs);

	ASSERT_FALSE(decision.initiate);
	ASSERT_EQUALS((int)RENDEZVOUS_REFUSE_PEER_ADVERTISES_NO_TRAVERSAL, (int)decision.refusal);
	ASSERT_EQUALS((int)NATT_ALT_CALLBACK_OR_BUDDY, (int)decision.alternative);
}

// This end cannot serve the traversal it would be asking for. Refused here
// rather than discovered by the peer: initiating would have a relay spend its
// budget and the peer spend its attempts punching toward a transport that will
// never answer. Same rule as every capability bit in this tree -- do not claim,
// and do not act on, a transport that is not there.
TEST(NatTraversalPolicy, LocalEndThatCannotServeTheTraversalDoesNotInitiate)
{
	SRendezvousInputs inputs = Viable();
	inputs.localCanServeUtpTraversal = false;

	const SRendezvousDecision decision = DecideRendezvousInitiation(inputs);

	ASSERT_FALSE(decision.initiate);
	ASSERT_EQUALS((int)RENDEZVOUS_REFUSE_LOCAL_CANNOT_SERVE, (int)decision.refusal);
	ASSERT_EQUALS((int)NATT_ALT_CALLBACK_OR_BUDDY, (int)decision.alternative);
}

// A peer that accepts inbound connections needs no traversal. The alternative
// is not the callback path either -- it is the ordinary direct connection, which
// is what this client did before and must keep doing byte for byte.
TEST(NatTraversalPolicy, PeerThatIsNotFirewalledIsConnectedToDirectly)
{
	SRendezvousInputs inputs = Viable();
	inputs.peerIsFirewalled = false;

	const SRendezvousDecision decision = DecideRendezvousInitiation(inputs);

	ASSERT_FALSE(decision.initiate);
	ASSERT_EQUALS((int)RENDEZVOUS_REFUSE_PEER_NOT_FIREWALLED, (int)decision.refusal);
	ASSERT_EQUALS((int)NATT_ALT_NONE, (int)decision.alternative);
}

// This end accepts inbound connections, so the peer can reach us and the
// existing callback machinery is exactly the right tool. Rendezvous is for the
// pair neither of whom can be called.
TEST(NatTraversalPolicy, LocalEndThatIsNotFirewalledUsesTheCallbackPath)
{
	SRendezvousInputs inputs = Viable();
	inputs.localIsFirewalled = false;

	const SRendezvousDecision decision = DecideRendezvousInitiation(inputs);

	ASSERT_FALSE(decision.initiate);
	ASSERT_EQUALS((int)RENDEZVOUS_REFUSE_LOCAL_NOT_FIREWALLED, (int)decision.refusal);
	ASSERT_EQUALS((int)NATT_ALT_CALLBACK_OR_BUDDY, (int)decision.alternative);
}

// No third party that can reach the peer means there is nothing to relay
// through. Nothing is sent -- in particular, this client does not try to reach
// the peer's hinted endpoint on its own, which would be punching at a mapping
// no rendezvous ever asked the peer to open.
TEST(NatTraversalPolicy, NoRelayMeansNoRendezvous)
{
	SRendezvousInputs inputs = Viable();
	inputs.relayAvailable = false;

	const SRendezvousDecision decision = DecideRendezvousInitiation(inputs);

	ASSERT_FALSE(decision.initiate);
	ASSERT_EQUALS((int)RENDEZVOUS_REFUSE_NO_RELAY, (int)decision.refusal);
	ASSERT_EQUALS((int)NATT_ALT_CALLBACK_OR_BUDDY, (int)decision.alternative);
}

// And in this build there is never a relay, so the requester half of the
// exchange is gated off entirely and every LowID peer takes the callback and
// buddy paths it took before this change.
//
// This is the assertion that pins the gap rather than papering over it. A
// usable relay must be reachable by us AND able to reach the firewalled peer,
// and the second condition is not knowable from this side: the peer is
// firewalled, so it is reachable only by hosts it is already connected to, and
// CClientList holds our peers and not theirs. The responder half is live --
// AcceptRelayedRendezvous() and CNatRendezvousManager handle a rendezvous a
// relay forwards here -- so this asserts a one-directional build, on purpose.
// When relay discovery exists, this test is what fails first.
TEST(NatTraversalPolicy, ThisBuildDiscoversNoRelayAndSoInitiatesNothing)
{
	ASSERT_FALSE(LocalCanDiscoverRendezvousRelay());

	SRendezvousInputs inputs = Viable();
	inputs.relayAvailable = LocalCanDiscoverRendezvousRelay();

	const SRendezvousDecision decision = DecideRendezvousInitiation(inputs);

	ASSERT_FALSE(decision.initiate);
	ASSERT_EQUALS((int)RENDEZVOUS_REFUSE_NO_RELAY, (int)decision.refusal);
	ASSERT_EQUALS((int)NATT_ALT_CALLBACK_OR_BUDDY, (int)decision.alternative);
	// The source is untouched, which is the whole point of refusing rather
	// than failing.
	ASSERT_FALSE(decision.markPeerDead);
	ASSERT_FALSE(decision.dropFromSourceList);
}

// The backoff is honoured here as well as in the schedule, so a caller that
// polls the decision every core tick cannot restart a rendezvous the schedule
// is still backing off from. The source keeps its place throughout.
TEST(NatTraversalPolicy, ActiveBackoffSuppressesInitiationWithoutCostingTheSource)
{
	SRendezvousInputs inputs = Viable();
	inputs.backoffActive = true;

	const SRendezvousDecision decision = DecideRendezvousInitiation(inputs);

	ASSERT_FALSE(decision.initiate);
	ASSERT_EQUALS((int)RENDEZVOUS_REFUSE_BACKOFF_ACTIVE, (int)decision.refusal);
	ASSERT_EQUALS((int)NATT_ALT_CALLBACK_OR_BUDDY, (int)decision.alternative);
}

// Every refusal keeps the source. There is no reason to refuse a rendezvous
// that is also a reason to blame the peer, and enumerating it here means a new
// refusal cannot be added without deciding that question.
TEST(NatTraversalPolicy, NoRefusalReasonEverBlamesThePeer)
{
	SRendezvousInputs variants[6] = { Viable(), Viable(), Viable(), Viable(), Viable(), Viable() };
	variants[0].peerAdvertisesUtpTraversal = false;
	variants[1].localCanServeUtpTraversal = false;
	variants[2].peerIsFirewalled = false;
	variants[3].localIsFirewalled = false;
	variants[4].relayAvailable = false;
	variants[5].backoffActive = true;

	for (const SRendezvousInputs &inputs : variants) {
		const SRendezvousDecision decision = DecideRendezvousInitiation(inputs);
		ASSERT_FALSE(decision.initiate);
		ASSERT_FALSE(decision.markPeerDead);
		ASSERT_FALSE(decision.dropFromSourceList);
	}
}

// Task 4.2. With QUIC advertised on both sides the QUIC frame type is preferred,
// for exactly 1500 ms.
TEST(NatTraversalPolicy, QuicFrameTypeIsPreferredForFifteenHundredMilliseconds)
{
	const SNattFrameTypeDecision early = SelectNattFrameType(true, true, 0);
	ASSERT_EQUALS(0x01, (int)early.frameType);
	ASSERT_TRUE(early.waitingForQuic);

	const SNattFrameTypeDecision justBefore =
		SelectNattFrameType(true, true, kNattFrameTypeFallbackWaitMs - 1);
	ASSERT_EQUALS(0x01, (int)justBefore.frameType);
	ASSERT_TRUE(justBefore.waitingForQuic);

	// At the boundary, not after it: 1500 ms is the whole wait.
	const SNattFrameTypeDecision atBoundary =
		SelectNattFrameType(true, true, kNattFrameTypeFallbackWaitMs);
	ASSERT_EQUALS(0x00, (int)atBoundary.frameType);
	ASSERT_FALSE(atBoundary.waitingForQuic);
}

// A peer that never advertised QUIC is not waited for. The 1500 ms is a wait for
// an answer that might come, not a delay applied to everybody.
TEST(NatTraversalPolicy, PeerWithoutQuicIsNotWaitedForAtAll)
{
	const SNattFrameTypeDecision decision = SelectNattFrameType(false, true, 0);

	ASSERT_EQUALS(0x00, (int)decision.frameType);
	ASSERT_FALSE(decision.waitingForQuic);
}

// And the case every build in this tree is actually in: the peer advertises
// QUIC, this build has no QUIC transport, so there is nothing to wait for and
// the exchange rides the legacy uTP frame type immediately. Waiting 1500 ms for
// a transport this build does not have would delay every traversal with an
// eMuleAI peer by a second and a half and gain nothing.
TEST(NatTraversalPolicy, BuildWithoutQuicUsesTheLegacyFrameTypeWithNoWait)
{
	const SNattFrameTypeDecision decision = SelectNattFrameType(true, false, 0);

	ASSERT_EQUALS(0x00, (int)decision.frameType);
	ASSERT_FALSE(decision.waitingForQuic);

	// And that is what this build reports about itself.
	ASSERT_FALSE(LocalCanServeQuicNatTraversal());
}

// Task 2.3 and 2.4. The hint is appended to what is already known, in that
// order, and the known endpoint survives.
TEST(NatTraversalPolicy, StaleHintDoesNotDisplaceAKnownAddress)
{
	CNattCandidateSet candidates;
	ASSERT_TRUE(candidates.AddKnown(CNetworkAddress::FromString("192.0.2.10"), 4662));
	// The peer's own view of its external port, already stale.
	ASSERT_TRUE(candidates.AddHint(CNetworkAddress::FromString("192.0.2.10"), 55000));

	ASSERT_EQUALS(2u, candidates.Count());
	ASSERT_TRUE(candidates.At(0).address == CNetworkAddress::FromString("192.0.2.10"));
	ASSERT_EQUALS(4662, (int)candidates.At(0).port);
	ASSERT_FALSE(candidates.At(0).fromHint);
	ASSERT_EQUALS(55000, (int)candidates.At(1).port);
	ASSERT_TRUE(candidates.At(1).fromHint);
}

// The same endpoint arriving twice is one candidate. Punching the same mapping
// twice per burst doubles the traffic and opens nothing extra.
TEST(NatTraversalPolicy, DuplicateEndpointsAreNotAddedTwice)
{
	CNattCandidateSet candidates;
	ASSERT_TRUE(candidates.AddKnown(CNetworkAddress::FromString("192.0.2.10"), 4662));
	ASSERT_FALSE(candidates.AddHint(CNetworkAddress::FromString("192.0.2.10"), 4662));
	ASSERT_FALSE(candidates.AddKnown(CNetworkAddress::FromString("192.0.2.10"), 4662));

	ASSERT_EQUALS(1u, candidates.Count());
	// And the survivor is the known one, not a hint that happened to agree.
	ASSERT_FALSE(candidates.At(0).fromHint);
}

// A full set drops the hint, never a known address. This is the requirement
// stated as a structural property: there is no code path in which adding a hint
// removes anything.
TEST(NatTraversalPolicy, HintIsDroppedRatherThanEvictingAKnownAddressWhenFull)
{
	CNattCandidateSet candidates;
	for (uint16_t i = 0; i < kNattMaxCandidates; ++i) {
		ASSERT_TRUE(candidates.AddKnown(CNetworkAddress::FromString("192.0.2.10"), 4000 + i));
	}
	ASSERT_EQUALS((size_t)kNattMaxCandidates, candidates.Count());

	ASSERT_FALSE(candidates.AddHint(CNetworkAddress::FromString("198.51.100.7"), 4662));

	ASSERT_EQUALS((size_t)kNattMaxCandidates, candidates.Count());
	for (size_t i = 0; i < candidates.Count(); ++i) {
		ASSERT_FALSE(candidates.At(i).fromHint);
	}
}

// An endpoint that is not one is not a candidate. Absence, the unspecified
// address and port zero are all rejected: each of them would otherwise become a
// punch attempt spent finding out that nothing is there.
TEST(NatTraversalPolicy, UnusableEndpointsAreNotCandidates)
{
	CNattCandidateSet candidates;

	ASSERT_FALSE(candidates.AddKnown(CNetworkAddress::Absent(), 4662));
	ASSERT_FALSE(candidates.AddKnown(CNetworkAddress::FromString("0.0.0.0"), 4662));
	ASSERT_FALSE(candidates.AddKnown(CNetworkAddress::FromString("192.0.2.10"), 0));
	ASSERT_FALSE(candidates.AddHint(CNetworkAddress::Absent(), 4662));
	ASSERT_FALSE(candidates.AddHint(CNetworkAddress::FromString("::"), 4662));

	ASSERT_EQUALS(0u, candidates.Count());
}

// A hint arriving before anything else is known is still a candidate. This is
// the peer that reached us over a family we have no other address for; refusing
// the hint outright would leave nothing at all to punch toward.
TEST(NatTraversalPolicy, HintAloneIsUsableWhenNothingElseIsKnown)
{
	CNattCandidateSet candidates;
	ASSERT_TRUE(candidates.AddHint(CNetworkAddress::FromString("192.0.2.10"), 4662));

	ASSERT_EQUALS(1u, candidates.Count());
	ASSERT_TRUE(candidates.At(0).fromHint);
}
