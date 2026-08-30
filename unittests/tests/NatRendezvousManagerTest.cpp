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

// The set of in-flight rendezvous exchanges: what CClientUDPSocket's receive
// path and CamuleApp::OnCoreTimer drive.
//
// CHolePunchSchedule bounds one pair and NatHolePunchScheduleTest asserts those
// bounds. What this suite asserts is what the manager adds on top, all of which
// has the same failure mode -- a bound that is right for one pair and wrong for
// the set:
//
//   - a punch that succeeds cancels the remaining attempts for that pair, and
//     for that pair only;
//   - an inbound punch from a peer nobody punched toward creates no entry, so
//     it buys no budget;
//   - a relayed endpoint is added after the addresses already known, so it can
//     never displace one;
//   - the table is capped, because inbound traffic is what creates entries and
//     an entry is a punch budget.
//
// Every emission goes through the recording sender, so "no further hole-punch
// packets for that pair" is asserted as an empty recorded list rather than as
// the absence of a particular call.

#include <muleunit/test.h>

#include <NatRendezvousManager.h>
#include <NatRendezvousProtocol.h>
#include <NatRendezvousRelay.h>
#include <NatTraversalPolicy.h>
#include <NetworkAddress.h>

#include <cstdio>
#include <vector>

using namespace muleunit;

DECLARE_SIMPLE(NatRendezvousManager)

namespace
{

const uint16_t kPeerPort = 4662;

void FillHash(uint8_t *out, uint8_t seed)
{
	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		out[i] = static_cast<uint8_t>(seed + i);
	}
}

//! Records every punch the manager asked for, with the peer it was for.
struct CRecordingPuncher
{
	struct SSent
	{
		uint8_t peerHash[NATT_PEER_HASH_LENGTH];
		CNetworkAddress destination;
		uint16_t port;
	};

	void operator()(const uint8_t *peerHash, const SNattPunchRequest &request)
	{
		SSent sent;
		for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
			sent.peerHash[i] = peerHash[i];
		}
		sent.destination = request.destination;
		sent.port = request.port;
		m_sent.push_back(sent);
	}

	//! How many packets went to one peer, by hash rather than by address --
	//! the address is what a NAT rewrites.
	size_t CountFor(const uint8_t *peerHash) const
	{
		size_t count = 0;
		for (const SSent &sent : m_sent) {
			bool same = true;
			for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
				if (sent.peerHash[i] != peerHash[i]) {
					same = false;
					break;
				}
			}
			if (same) {
				++count;
			}
		}
		return count;
	}

	std::vector<SSent> m_sent;
};

CNattCandidateSet OneCandidate(const char *address, uint16_t port)
{
	CNattCandidateSet set;
	set.AddKnown(CNetworkAddress::FromString(address), port);
	return set;
}

} // namespace

// A tracked pair punches, and it punches once per candidate per due packet:
// the schedule bounds when, the candidate set bounds how wide. Multiplying them
// is what kNattMaxCandidates caps.
TEST(NatRendezvousManager, StartedRendezvousPunchesEveryCandidate)
{
	uint8_t peer[NATT_PEER_HASH_LENGTH];
	FillHash(peer, 0x10);

	CNattCandidateSet candidates;
	candidates.AddKnown(CNetworkAddress::FromString("192.0.2.10"), kPeerPort);
	candidates.AddKnown(CNetworkAddress::FromString("192.0.2.11"), kPeerPort);

	CNatRendezvousManager manager;
	ASSERT_TRUE(manager.BeginRendezvous(peer, candidates, 1000));

	CRecordingPuncher puncher;
	manager.Tick(1000, puncher);

	ASSERT_EQUALS(2u, puncher.m_sent.size());
	ASSERT_TRUE(puncher.m_sent[0].destination == CNetworkAddress::FromString("192.0.2.10"));
	ASSERT_TRUE(puncher.m_sent[1].destination == CNetworkAddress::FromString("192.0.2.11"));
	ASSERT_EQUALS(kPeerPort, puncher.m_sent[0].port);
}

// An untracked peer is punched at nothing at all. The default state of the
// manager is silence: every other test in this file has to start something
// first.
TEST(NatRendezvousManager, NothingIsPunchedForAnUntrackedPeer)
{
	uint8_t peer[NATT_PEER_HASH_LENGTH];
	FillHash(peer, 0x10);

	CNatRendezvousManager manager;
	CRecordingPuncher puncher;
	manager.Tick(1000, puncher);

	ASSERT_EQUALS(0u, puncher.m_sent.size());
	ASSERT_EQUALS(0u, manager.TrackedCount());
	ASSERT_FALSE(manager.IsBackoffActive(peer, 1000));
}

// A rendezvous with nothing to punch toward is not started. An empty candidate
// set would otherwise spend a budget discovering that it has no destinations.
TEST(NatRendezvousManager, RendezvousWithNoCandidatesIsNotStarted)
{
	uint8_t peer[NATT_PEER_HASH_LENGTH];
	FillHash(peer, 0x10);

	CNatRendezvousManager manager;
	ASSERT_FALSE(manager.BeginRendezvous(peer, CNattCandidateSet(), 1000));
	ASSERT_EQUALS(0u, manager.TrackedCount());
}

// THE cancellation requirement. Once the connection is up, the recorded list
// for that pair stops growing -- not "grows more slowly", stops.
TEST(NatRendezvousManager, SuccessStopsEveryFurtherPunchForThatPair)
{
	uint8_t peer[NATT_PEER_HASH_LENGTH];
	FillHash(peer, 0x10);

	CNatRendezvousManager manager;
	ASSERT_TRUE(manager.BeginRendezvous(peer, OneCandidate("192.0.2.10", kPeerPort), 1000));

	CRecordingPuncher puncher;
	manager.Tick(1000, puncher);
	const size_t beforeSuccess = puncher.m_sent.size();
	ASSERT_TRUE(beforeSuccess > 0);

	manager.OnConnectionEstablished(peer);

	// Two full budgets' worth of ticks, spaced so that every attempt of a
	// still-running schedule would have come due.
	for (uint64_t tick = 1000; tick <= 1000 + 2 * kRendezvousTotalBudgetMs; tick += 1000) {
		manager.Tick(tick, puncher);
	}

	ASSERT_EQUALS(beforeSuccess, puncher.m_sent.size());
}

// Cancellation is per pair. A second peer's rendezvous is untouched by the
// first one connecting -- a manager that cancelled the set would silently stop
// traversing for every other download.
TEST(NatRendezvousManager, SuccessForOnePairDoesNotCancelAnother)
{
	uint8_t first[NATT_PEER_HASH_LENGTH];
	FillHash(first, 0x10);
	uint8_t second[NATT_PEER_HASH_LENGTH];
	FillHash(second, 0x20);

	CNatRendezvousManager manager;
	ASSERT_TRUE(manager.BeginRendezvous(first, OneCandidate("192.0.2.10", kPeerPort), 1000));
	ASSERT_TRUE(manager.BeginRendezvous(second, OneCandidate("192.0.2.20", kPeerPort), 1000));

	manager.OnConnectionEstablished(first);

	CRecordingPuncher puncher;
	manager.Tick(1000, puncher);

	ASSERT_EQUALS(0u, puncher.CountFor(first));
	ASSERT_EQUALS(1u, puncher.CountFor(second));
}

// The budget still ends the exchange, and the manager reports the backoff so
// the connect path refuses to start another one -- the source keeping its place
// throughout, which is DisposeExhaustedHolePunch()'s business and is asserted
// again here because this is the object the connect path actually asks.
TEST(NatRendezvousManager, ExhaustionReportsBackoffAndBlamesNobody)
{
	uint8_t peer[NATT_PEER_HASH_LENGTH];
	FillHash(peer, 0x10);

	CNatRendezvousManager manager;
	ASSERT_TRUE(manager.BeginRendezvous(peer, OneCandidate("192.0.2.10", kPeerPort), 0));

	CRecordingPuncher puncher;
	for (uint64_t tick = 0; tick <= kRendezvousTotalBudgetMs; tick += 250) {
		manager.Tick(tick, puncher);
	}

	ASSERT_TRUE(manager.IsBackoffActive(peer, kRendezvousTotalBudgetMs));

	// And no restart while it is backing off.
	ASSERT_FALSE(manager.BeginRendezvous(
		peer, OneCandidate("192.0.2.10", kPeerPort), kRendezvousTotalBudgetMs));

	const SHolePunchDisposition disposition = CNatRendezvousManager::ExhaustionDisposition();
	ASSERT_TRUE(disposition.keepSourceQueued);
	ASSERT_FALSE(disposition.markPeerDead);
	ASSERT_FALSE(disposition.dropFromSourceList);
	ASSERT_FALSE(disposition.countAsDeadSource);
	ASSERT_TRUE(disposition.fallBackToCallbackOrBuddy);
	ASSERT_EQUALS(kRendezvousBackoffMs, disposition.retryAfterMs);
}

// After the backoff, and not before, a fresh rendezvous is allowed.
TEST(NatRendezvousManager, BackoffElapsesAndThenAllowsARestart)
{
	uint8_t peer[NATT_PEER_HASH_LENGTH];
	FillHash(peer, 0x10);

	CNatRendezvousManager manager;
	ASSERT_TRUE(manager.BeginRendezvous(peer, OneCandidate("192.0.2.10", kPeerPort), 0));

	// Driven until the budget runs out, and the tick it ran out ON is read off
	// the manager rather than assumed. Five attempts inside 120 seconds means
	// the attempt count is what exhausts first -- the last packet of the fifth
	// attempt lands well before the wall-clock budget -- and a test that
	// hard-coded 120000 here would be asserting the backoff from the wrong
	// instant while still passing.
	CRecordingPuncher puncher;
	uint64_t exhausted = 0;
	for (uint64_t tick = 0; tick <= kRendezvousTotalBudgetMs; tick += 250) {
		manager.Tick(tick, puncher);
		if (exhausted == 0 && manager.IsBackoffActive(peer, tick)) {
			exhausted = tick;
		}
	}
	ASSERT_TRUE(exhausted > 0);

	ASSERT_TRUE(manager.IsBackoffActive(peer, exhausted + kRendezvousBackoffMs - 1));
	ASSERT_FALSE(manager.IsBackoffActive(peer, exhausted + kRendezvousBackoffMs));
	ASSERT_TRUE(manager.BeginRendezvous(
		peer, OneCandidate("192.0.2.10", kPeerPort), exhausted + kRendezvousBackoffMs));
}

// An inbound punch from a peer nobody punched toward creates nothing. Otherwise
// any host on the internet could allocate an entry, and an entry is a budget.
TEST(NatRendezvousManager, UnsolicitedHolePunchCreatesNoEntry)
{
	uint8_t stranger[NATT_PEER_HASH_LENGTH];
	FillHash(stranger, 0x77);

	CNatRendezvousManager manager;
	ASSERT_FALSE(manager.OnHolePunchReceived(
		stranger, CNetworkAddress::FromString("198.51.100.9"), 4662, 1000));
	ASSERT_EQUALS(0u, manager.TrackedCount());

	CRecordingPuncher puncher;
	manager.Tick(1000, puncher);
	ASSERT_EQUALS(0u, puncher.m_sent.size());
}

// A punch that DOES match records where it actually arrived from, which is the
// peer's real mapping and is not necessarily the endpoint either side
// predicted. That observed value is what the connect path dials.
TEST(NatRendezvousManager, MatchingHolePunchRecordsTheObservedMapping)
{
	uint8_t peer[NATT_PEER_HASH_LENGTH];
	FillHash(peer, 0x10);

	CNatRendezvousManager manager;
	ASSERT_TRUE(manager.BeginRendezvous(peer, OneCandidate("192.0.2.10", kPeerPort), 1000));

	CNetworkAddress observed;
	uint16_t observedPort = 0;
	ASSERT_FALSE(manager.ObservedEndpoint(peer, observed, observedPort));

	// A different port from the one it was punched at: the NAT chose it.
	ASSERT_TRUE(
		manager.OnHolePunchReceived(peer, CNetworkAddress::FromString("192.0.2.10"), 51413, 1500));

	ASSERT_TRUE(manager.ObservedEndpoint(peer, observed, observedPort));
	ASSERT_TRUE(observed == CNetworkAddress::FromString("192.0.2.10"));
	ASSERT_EQUALS(51413, (int)observedPort);
}

// A relayed rendezvous that was accepted starts a punch, and the endpoint the
// relay carried is added AFTER the addresses this client already held.
TEST(NatRendezvousManager, RelayedEndpointIsOneCandidateAfterTheKnownOnes)
{
	uint8_t peer[NATT_PEER_HASH_LENGTH];
	FillHash(peer, 0x30);

	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length = EncodeRelayedRendezvous(
		peer, NULL, CNetworkAddress::FromString("198.51.100.7"), 4662, frame, sizeof(frame));

	CRendezvousRelayLimiter limiter;
	const SRelayedRendezvousDecision accepted = AcceptRelayedRendezvous(frame,
		length,
		CNetworkAddress::FromString("203.0.113.5"),
		true,
		CNetworkAddress::FromString("192.0.2.1"),
		1000,
		limiter);
	ASSERT_EQUALS((int)RELAYED_ACCEPT, (int)accepted.acceptance);

	CNatRendezvousManager manager;
	ASSERT_TRUE(manager.OnRelayedRendezvous(accepted, OneCandidate("203.0.113.99", kPeerPort), 1000));

	CRecordingPuncher puncher;
	manager.Tick(1000, puncher);

	ASSERT_EQUALS(2u, puncher.m_sent.size());
	// The known address first, the relayed endpoint second. A manager that
	// preferred the relayed endpoint would stop reaching peers it used to
	// reach, and the endpoint would look like the fix rather than the cause.
	ASSERT_TRUE(puncher.m_sent[0].destination == CNetworkAddress::FromString("203.0.113.99"));
	ASSERT_TRUE(puncher.m_sent[1].destination == CNetworkAddress::FromString("198.51.100.7"));
}

// A relayed rendezvous that was NOT accepted starts nothing. The guards live in
// AcceptRelayedRendezvous(), and this is the assertion that the manager honours
// its answer rather than re-deriving it -- which is what keeps those guards in
// one place.
TEST(NatRendezvousManager, RejectedRelayedRendezvousStartsNothing)
{
	// The crafted-packet shape: a well-formed forward naming an unrelated
	// victim, sent by someone who is not this client's buddy. Indistinguishable
	// from a genuine forward, and rejected on who sent it rather than on
	// anything it says.
	uint8_t targetHash[NATT_PEER_HASH_LENGTH];
	FillHash(targetHash, 0x30);
	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length = EncodeRelayedRendezvous(
		targetHash, NULL, CNetworkAddress::FromString("198.51.100.200"), 4662, frame, sizeof(frame));

	CRendezvousRelayLimiter limiter;
	const SRelayedRendezvousDecision rejected = AcceptRelayedRendezvous(frame,
		length,
		CNetworkAddress::FromString("203.0.113.5"),
		false,
		CNetworkAddress::FromString("192.0.2.1"),
		1000,
		limiter);
	ASSERT_EQUALS((int)RELAYED_REJECT_RELAY_IS_NOT_OUR_BUDDY, (int)rejected.acceptance);

	CNatRendezvousManager manager;
	ASSERT_FALSE(manager.OnRelayedRendezvous(rejected, CNattCandidateSet(), 1000));
	ASSERT_EQUALS(0u, manager.TrackedCount());

	CRecordingPuncher puncher;
	manager.Tick(1000, puncher);
	ASSERT_EQUALS(0u, puncher.m_sent.size());
}

// The table is bounded and fails closed. Inbound traffic is what creates
// entries, so an unbounded table would be an allocation channel and each entry
// would be a punch budget.
TEST(NatRendezvousManager, TrackedSetIsBoundedAndFailsClosedWhenFull)
{
	CNatRendezvousManager manager;

	for (size_t i = 0; i < kNattMaxTrackedRendezvous; ++i) {
		uint8_t peer[NATT_PEER_HASH_LENGTH];
		FillHash(peer, static_cast<uint8_t>(i));
		ASSERT_TRUE(manager.BeginRendezvous(peer, OneCandidate("192.0.2.10", kPeerPort), 1000));
	}
	ASSERT_EQUALS(kNattMaxTrackedRendezvous, manager.TrackedCount());

	uint8_t overflow[NATT_PEER_HASH_LENGTH];
	FillHash(overflow, 0xF0);
	ASSERT_FALSE(manager.BeginRendezvous(overflow, OneCandidate("192.0.2.10", kPeerPort), 1000));
	ASSERT_EQUALS(kNattMaxTrackedRendezvous, manager.TrackedCount());
}

// Polling twice for the same tick does not send twice. The send is recorded
// inside the schedule by the poll itself, so a caller that drives the manager
// from two places cannot double the packet rate.
TEST(NatRendezvousManager, TickingTwiceForOneTickDoesNotSendTwice)
{
	uint8_t peer[NATT_PEER_HASH_LENGTH];
	FillHash(peer, 0x10);

	CNatRendezvousManager manager;
	ASSERT_TRUE(manager.BeginRendezvous(peer, OneCandidate("192.0.2.10", kPeerPort), 1000));

	CRecordingPuncher puncher;
	manager.Tick(1000, puncher);
	const size_t once = puncher.m_sent.size();
	manager.Tick(1000, puncher);

	ASSERT_EQUALS(once, puncher.m_sent.size());
}
