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

// The relaying half of the rendezvous exchange -- the side that gets no benefit
// from the traversal and carries all of its risk.
//
// A rendezvous request asks this client to generate traffic toward an address
// on behalf of whoever asked. Unvalidated, that is the definition of a traffic
// reflector: an attacker names a victim's address as its own endpoint and aMule
// aims packets at it, with the victim seeing an unsolicited flood from an
// address that never attacked it. Multiply by the number of aMule instances
// reachable from one host and it amplifies.
//
// So the emission itself is inside the unit under test, not left to the caller.
// The fake sender in this suite records every destination anything was sent to,
// which is what lets the central requirement be asserted as an absolute rather
// than as an absence of a particular call: for a request from X whose hint
// names an unrelated Y, the recorded destination list is EMPTY. Not "does not
// contain Y" -- empty. A test that only checked "not Y" would pass a relay that
// sent to Y's /24 broadcast, or to Y on another port.
//
// The second property is that nothing an attacker controls ever becomes a
// destination or an advertised endpoint:
//
//   - The requester's identity comes from this client's own client list, not
//     from the datagram. An unknown host cannot make this relay send anything.
//   - The destination comes from this client's own client list, looked up by
//     hash. A datagram cannot name an address to send to.
//   - The endpoint forwarded to the target is the one this relay OBSERVED the
//     request arrive from, never the one the request claimed. A matching claim
//     is still not the value that travels, so even an honest-looking request
//     cannot launder an address through.
//
// The rate limit is charged before validation, so a flood of malformed requests
// exhausts the flooder's own budget rather than being free.

#include <muleunit/test.h>

#include <NatRendezvousProtocol.h>
#include <NatRendezvousRelay.h>
#include <NetworkAddress.h>

#include <cstdio>
#include <vector>

using namespace muleunit;

DECLARE_SIMPLE(NatRendezvousRelay)

namespace
{

const uint16_t kSourcePort = 4662;
const uint16_t kTargetPort = 5000;

CNetworkAddress Requester()
{
	return CNetworkAddress::FromString("192.0.2.10");
}

//! The unrelated third party an attacker would name. Nothing in any test may
//! ever send a byte here.
CNetworkAddress Victim()
{
	return CNetworkAddress::FromString("198.51.100.200");
}

CNetworkAddress Target()
{
	return CNetworkAddress::FromString("203.0.113.5");
}

void FillHash(uint8_t *out, uint8_t seed)
{
	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		out[i] = static_cast<uint8_t>(seed + i);
	}
}

//! Every packet the relay tried to send, and where to.
struct SSentPacket
{
	CNetworkAddress destination;
	uint16_t port;
	std::vector<uint8_t> payload;
};

class CRecordingSender
{
public:
	void operator()(const CNetworkAddress &destination,
		uint16_t port,
		const uint8_t *payload,
		size_t payloadLength)
	{
		SSentPacket packet;
		packet.destination = destination;
		packet.port = port;
		packet.payload.assign(payload, payload + payloadLength);
		m_sent.push_back(packet);
	}

	std::vector<SSentPacket> m_sent;
};

//! Stands in for the relay's own client list: the only place a destination
//! address can come from.
class CFakeClientList
{
public:
	CFakeClientList(const CNetworkAddress &address, uint16_t port, uint8_t hashSeed)
	: m_address(address)
	, m_port(port)
	, m_known(true)
	{
		FillHash(m_hash, hashSeed);
	}

	static CFakeClientList Empty()
	{
		CFakeClientList list(CNetworkAddress::Absent(), 0, 0);
		list.m_known = false;
		return list;
	}

	bool operator()(const uint8_t *hash, CNetworkAddress &address, uint16_t &port)
	{
		++m_lookups;
		if (!m_known) {
			return false;
		}
		for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
			if (hash[i] != m_hash[i]) {
				return false;
			}
		}
		address = m_address;
		port = m_port;
		return true;
	}

	int m_lookups = 0;

private:
	CNetworkAddress m_address;
	uint16_t m_port;
	bool m_known;
	uint8_t m_hash[NATT_PEER_HASH_LENGTH];
};

//! A well-formed request from `Requester()` for the peer with hash seed 0x20,
//! claiming `claimedEndpoint` as its own external endpoint.
std::vector<uint8_t> Request(const CNetworkAddress &claimedEndpoint, uint16_t claimedPort)
{
	uint8_t targetHash[NATT_PEER_HASH_LENGTH];
	FillHash(targetHash, 0x20);

	std::vector<uint8_t> frame(NATT_RENDEZVOUS_MAX_LENGTH, 0);
	const size_t written =
		EncodeRendezvousRequest(targetHash, claimedEndpoint, claimedPort, frame.data(), frame.size());
	frame.resize(written);
	return frame;
}

} // namespace

// Task 1.4, and the property the whole change is judged on. A request arrives
// from X and names an unrelated Y as its endpoint. Nothing is sent -- anywhere.
//
// The assertion is on the size of the recorded destination list, not on whether
// Y appears in it, because "no packet toward Y" is only meaningful as "no packet
// at all". A relay that answered X instead would also be wrong: X did not ask
// to be answered, it asked for a relay, and an error reply is a second
// amplification channel with a smaller factor.
TEST(NatRendezvousRelay, EndpointHintNamingAnUnrelatedHostEmitsNoPacketAtAll)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	const std::vector<uint8_t> frame = Request(Victim(), 4662);
	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	const SRelayDecision decision = RelayRendezvousRequest(frame.data(),
		frame.size(),
		Requester(),
		kSourcePort,
		requesterHash,
		1000,
		limiter,
		clients,
		sender);

	ASSERT_EQUALS(0u, sender.m_sent.size());
	ASSERT_FALSE(decision.emitted);
	ASSERT_EQUALS((int)RELAY_DISCARD_HINT_NAMES_ANOTHER_HOST, (int)decision.disposition);
	// The client list was never consulted either: the request was rejected
	// before anything could turn a hash into an address.
	ASSERT_EQUALS(0, clients.m_lookups);
}

// The same, for a hint naming a host in a different family. An IPv6 hint from an
// IPv4 requester is not "an address we cannot compare", it is an unrelated
// address, and it is discarded on the same terms.
TEST(NatRendezvousRelay, EndpointHintInAnotherFamilyEmitsNoPacketAtAll)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	const std::vector<uint8_t> frame = Request(CNetworkAddress::FromString("2001:db8::dead"), 4662);
	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	const SRelayDecision decision = RelayRendezvousRequest(frame.data(),
		frame.size(),
		Requester(),
		kSourcePort,
		requesterHash,
		1000,
		limiter,
		clients,
		sender);

	ASSERT_EQUALS(0u, sender.m_sent.size());
	ASSERT_EQUALS((int)RELAY_DISCARD_HINT_NAMES_ANOTHER_HOST, (int)decision.disposition);
}

// The one path that does emit. Exactly one packet, to the address the relay's
// own client list holds for the named hash, and the forwarded endpoint is the
// one the relay observed.
//
// The claimed port here is deliberately wrong (9999 against an observed 4662).
// The address matched, so the request is honest enough to relay, but the value
// that travels is still the observed one -- which is the property that makes a
// matching claim unable to launder anything through.
TEST(NatRendezvousRelay, ValidRequestForwardsTheObservedEndpointToTheTargetFromOurClientList)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	const std::vector<uint8_t> frame = Request(Requester(), 9999);
	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	const SRelayDecision decision = RelayRendezvousRequest(frame.data(),
		frame.size(),
		Requester(),
		kSourcePort,
		requesterHash,
		1000,
		limiter,
		clients,
		sender);

	ASSERT_EQUALS((int)RELAY_FORWARD, (int)decision.disposition);
	ASSERT_TRUE(decision.emitted);
	ASSERT_EQUALS(1u, sender.m_sent.size());
	ASSERT_TRUE(sender.m_sent[0].destination == Target());
	ASSERT_EQUALS(kTargetPort, sender.m_sent[0].port);

	// The forwarded frame: a rendezvous naming the requester, carrying the
	// observed endpoint.
	SNattRendezvousRequest forwarded;
	ASSERT_TRUE(ParseRendezvousRequest(
		sender.m_sent[0].payload.data(), sender.m_sent[0].payload.size(), forwarded));
	ASSERT_TRUE(forwarded.hasEndpointHint);
	ASSERT_TRUE(forwarded.hintAddress == Requester());
	ASSERT_EQUALS(kSourcePort, forwarded.hintPort);
	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		ASSERT_EQUALS((int)requesterHash[i], (int)forwarded.peerHash[i]);
	}
}

// An IPv4-mapped claim of the same IPv4 address is the same address respelled,
// and is accepted. The comparison is on the address, not on its spelling --
// otherwise a dual-stack peer would be rejected for being correct.
TEST(NatRendezvousRelay, MappedSpellingOfTheSourceAddressIsAccepted)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	const std::vector<uint8_t> frame = Request(CNetworkAddress::FromString("::ffff:192.0.2.10"), 4662);
	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	const SRelayDecision decision = RelayRendezvousRequest(frame.data(),
		frame.size(),
		Requester(),
		kSourcePort,
		requesterHash,
		1000,
		limiter,
		clients,
		sender);

	ASSERT_EQUALS((int)RELAY_FORWARD, (int)decision.disposition);
	ASSERT_EQUALS(1u, sender.m_sent.size());
}

// Task 1.5. Five relays for one requester, then nothing. The sixth request is
// well-formed and honest and is still discarded, because the budget -- not the
// request -- is what is exhausted.
TEST(NatRendezvousRelay, RelayRateLimitIsEnforcedPerRequester)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	const std::vector<uint8_t> frame = Request(Requester(), kSourcePort);
	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	for (uint32_t i = 0; i < kRendezvousMaxAttempts; ++i) {
		const SRelayDecision decision = RelayRendezvousRequest(frame.data(),
			frame.size(),
			Requester(),
			kSourcePort,
			requesterHash,
			1000 + i,
			limiter,
			clients,
			sender);
		ASSERT_EQUALS((int)RELAY_FORWARD, (int)decision.disposition);
	}
	ASSERT_EQUALS((size_t)kRendezvousMaxAttempts, sender.m_sent.size());

	const SRelayDecision denied = RelayRendezvousRequest(frame.data(),
		frame.size(),
		Requester(),
		kSourcePort,
		requesterHash,
		1010,
		limiter,
		clients,
		sender);

	ASSERT_EQUALS((int)RELAY_DISCARD_RATE_LIMITED, (int)denied.disposition);
	ASSERT_FALSE(denied.emitted);
	// Still five: the discarded request added nothing.
	ASSERT_EQUALS((size_t)kRendezvousMaxAttempts, sender.m_sent.size());
}

// The limit is a window, not a lifetime ban. A peer that was throttled is
// relayed for again once the window has passed -- the backoff period is the
// same 60 seconds the rendezvous bounds use, so there is one number here and
// not two.
TEST(NatRendezvousRelay, RelayRateLimitRecoversAfterTheWindow)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	const std::vector<uint8_t> frame = Request(Requester(), kSourcePort);
	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	for (uint32_t i = 0; i < kRendezvousMaxAttempts; ++i) {
		RelayRendezvousRequest(frame.data(),
			frame.size(),
			Requester(),
			kSourcePort,
			requesterHash,
			1000,
			limiter,
			clients,
			sender);
	}

	const SRelayDecision afterWindow = RelayRendezvousRequest(frame.data(),
		frame.size(),
		Requester(),
		kSourcePort,
		requesterHash,
		1000 + kRendezvousBackoffMs,
		limiter,
		clients,
		sender);

	ASSERT_EQUALS((int)RELAY_FORWARD, (int)afterWindow.disposition);
}

// One requester's flood does not spend another requester's budget. If it did,
// a single host could stop this relay serving anybody -- which is a denial of
// service dressed as a rate limit.
TEST(NatRendezvousRelay, RateLimitBucketsAreSeparatePerRequester)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	const std::vector<uint8_t> flooderFrame = Request(CNetworkAddress::FromString("192.0.2.99"), 4662);
	const std::vector<uint8_t> honestFrame = Request(Requester(), kSourcePort);
	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	for (uint32_t i = 0; i < kRendezvousMaxAttempts * 3; ++i) {
		RelayRendezvousRequest(flooderFrame.data(),
			flooderFrame.size(),
			CNetworkAddress::FromString("192.0.2.99"),
			kSourcePort,
			requesterHash,
			1000,
			limiter,
			clients,
			sender);
	}

	const SRelayDecision honest = RelayRendezvousRequest(honestFrame.data(),
		honestFrame.size(),
		Requester(),
		kSourcePort,
		requesterHash,
		1000,
		limiter,
		clients,
		sender);

	ASSERT_EQUALS((int)RELAY_FORWARD, (int)honest.disposition);
}

// The budget is charged before the request is validated, so garbage is not
// free. Five malformed requests from one host exhaust that host's own budget,
// and its sixth -- perfectly valid -- request is throttled.
//
// Charging afterwards would make a malformed-request flood cost the flooder
// nothing while still costing this client a parse per packet.
TEST(NatRendezvousRelay, MalformedRequestsSpendTheSendersOwnBudget)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	const uint8_t garbage[3] = { OP_RENDEZVOUS, 0x00, 0x00 };
	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	for (uint32_t i = 0; i < kRendezvousMaxAttempts; ++i) {
		const SRelayDecision decision = RelayRendezvousRequest(garbage,
			sizeof(garbage),
			Requester(),
			kSourcePort,
			requesterHash,
			1000,
			limiter,
			clients,
			sender);
		ASSERT_EQUALS((int)RELAY_DISCARD_MALFORMED, (int)decision.disposition);
	}
	ASSERT_EQUALS(0u, sender.m_sent.size());

	const std::vector<uint8_t> valid = Request(Requester(), kSourcePort);
	const SRelayDecision throttled = RelayRendezvousRequest(valid.data(),
		valid.size(),
		Requester(),
		kSourcePort,
		requesterHash,
		1000,
		limiter,
		clients,
		sender);

	ASSERT_EQUALS((int)RELAY_DISCARD_RATE_LIMITED, (int)throttled.disposition);
	ASSERT_EQUALS(0u, sender.m_sent.size());
}

// A host this client knows nothing about cannot make it send anything. The
// requester's identity is what the forwarded message carries, and it comes from
// our own client list -- so there is no path where a stranger's datagram
// results in an emission.
TEST(NatRendezvousRelay, RequestFromAnUnknownHostEmitsNothing)
{
	const std::vector<uint8_t> frame = Request(Requester(), kSourcePort);
	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	const SRelayDecision decision = RelayRendezvousRequest(
		frame.data(), frame.size(), Requester(), kSourcePort, NULL, 1000, limiter, clients, sender);

	ASSERT_EQUALS((int)RELAY_DISCARD_UNKNOWN_REQUESTER, (int)decision.disposition);
	ASSERT_EQUALS(0u, sender.m_sent.size());
	ASSERT_EQUALS(0, clients.m_lookups);
}

// The target is named by hash and resolved against our own client list. A hash
// we do not know is not an address we can invent -- nothing is sent.
TEST(NatRendezvousRelay, RequestForAnUnknownTargetEmitsNothing)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	const std::vector<uint8_t> frame = Request(Requester(), kSourcePort);
	CRendezvousRelayLimiter limiter;
	CFakeClientList clients = CFakeClientList::Empty();
	CRecordingSender sender;

	const SRelayDecision decision = RelayRendezvousRequest(frame.data(),
		frame.size(),
		Requester(),
		kSourcePort,
		requesterHash,
		1000,
		limiter,
		clients,
		sender);

	ASSERT_EQUALS((int)RELAY_DISCARD_UNKNOWN_TARGET, (int)decision.disposition);
	ASSERT_EQUALS(0u, sender.m_sent.size());
}

// A request naming its own sender as the target is a loop, and a one-packet
// amplifier if it is honoured. Discarded.
TEST(NatRendezvousRelay, RequestNamingItsOwnSenderAsTheTargetEmitsNothing)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x20); // Same seed as the target hash in Request().

	const std::vector<uint8_t> frame = Request(Requester(), kSourcePort);
	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	const SRelayDecision decision = RelayRendezvousRequest(frame.data(),
		frame.size(),
		Requester(),
		kSourcePort,
		requesterHash,
		1000,
		limiter,
		clients,
		sender);

	ASSERT_EQUALS((int)RELAY_DISCARD_TARGET_IS_REQUESTER, (int)decision.disposition);
	ASSERT_EQUALS(0u, sender.m_sent.size());
}

// A request that carries no hint at all cannot be validated against anything,
// so there is nothing to validate and it is discarded. This is the strict
// reading of the requirement on purpose: a relay that filled in the blank
// itself would be relaying for a peer that never said where it is, and the
// only way to find out that was wrong is a punch that never lands.
TEST(NatRendezvousRelay, RequestWithoutAnEndpointHintEmitsNothing)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	const std::vector<uint8_t> frame = Request(CNetworkAddress::Absent(), 0);
	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	const SRelayDecision decision = RelayRendezvousRequest(frame.data(),
		frame.size(),
		Requester(),
		kSourcePort,
		requesterHash,
		1000,
		limiter,
		clients,
		sender);

	ASSERT_EQUALS((int)RELAY_DISCARD_NO_ENDPOINT_HINT, (int)decision.disposition);
	ASSERT_EQUALS(0u, sender.m_sent.size());
}

// A request that does not ask for the uTP traversal asks for one this build
// cannot serve. Relaying it would have the target punch toward a transport that
// will never answer, which costs the target its own attempt budget on our word.
// Discarded, on the same rule as every capability bit in this tree: do not
// claim, and do not act on behalf of, a transport that is not there.
TEST(NatRendezvousRelay, RequestForATraversalThisBuildCannotServeEmitsNothing)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	std::vector<uint8_t> frame = Request(Requester(), kSourcePort);
	frame[1] &= static_cast<uint8_t>(~CONNECT_OPT_NAT_TRAVERSAL_UTP);

	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	const SRelayDecision decision = RelayRendezvousRequest(frame.data(),
		frame.size(),
		Requester(),
		kSourcePort,
		requesterHash,
		1000,
		limiter,
		clients,
		sender);

	ASSERT_EQUALS((int)RELAY_DISCARD_UNSUPPORTED_TRAVERSAL, (int)decision.disposition);
	ASSERT_EQUALS(0u, sender.m_sent.size());
}

// An absent source address identifies nobody, so it has no budget and no
// endpoint to forward. Reaching here means a caller bug rather than hostile
// traffic, and the answer is still to send nothing.
TEST(NatRendezvousRelay, RequestFromAnUnusableSourceAddressEmitsNothing)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	const std::vector<uint8_t> frame = Request(Requester(), kSourcePort);
	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	const SRelayDecision absent = RelayRendezvousRequest(frame.data(),
		frame.size(),
		CNetworkAddress::Absent(),
		kSourcePort,
		requesterHash,
		1000,
		limiter,
		clients,
		sender);
	ASSERT_EQUALS((int)RELAY_DISCARD_UNUSABLE_SOURCE, (int)absent.disposition);

	const SRelayDecision noPort = RelayRendezvousRequest(
		frame.data(), frame.size(), Requester(), 0, requesterHash, 1000, limiter, clients, sender);
	ASSERT_EQUALS((int)RELAY_DISCARD_UNUSABLE_SOURCE, (int)noPort.disposition);

	ASSERT_EQUALS(0u, sender.m_sent.size());
}

// The limiter's own memory is bounded. A rate limit that allocates a bucket per
// source address is a memory amplifier: an attacker with a /64 has more source
// addresses than this process has bytes. Past the cap the limiter denies rather
// than growing, which is the safe direction -- a full table means a flood is in
// progress.
TEST(NatRendezvousRelay, LimiterMemoryIsBoundedAndFailsClosedWhenFull)
{
	CRendezvousRelayLimiter limiter;

	// Distinct /64s, so PeerIdentity::RateLimitScope() cannot collapse them.
	for (uint32_t i = 0; i < kRendezvousRelayBucketCap; ++i) {
		char text[64];
		std::snprintf(text, sizeof(text), "2001:db8:%x:%x::1", (i >> 16) & 0xFFFF, i & 0xFFFF);
		ASSERT_TRUE(limiter.Admit(CNetworkAddress::FromString(text), 1000));
	}

	ASSERT_EQUALS((size_t)kRendezvousRelayBucketCap, limiter.BucketCount());
	ASSERT_FALSE(limiter.Admit(CNetworkAddress::FromString("2001:db8:ffff:ffff::1"), 1000));
	ASSERT_EQUALS((size_t)kRendezvousRelayBucketCap, limiter.BucketCount());

	// Once the window has passed, the expired buckets are reclaimed and the
	// limiter serves again. Without this the first flood would be permanent.
	ASSERT_TRUE(limiter.Admit(
		CNetworkAddress::FromString("2001:db8:ffff:ffff::1"), 1000 + kRendezvousBackoffMs));
}

// IPv6 budgets count per /64, exactly as every other per-peer limit in this
// tree does (PeerIdentity::RateLimitScope). A per-/128 limit would count to one
// forever for a subscriber delegated a prefix, which is the same as no limit.
TEST(NatRendezvousRelay, IPv6RequestersShareABudgetPerSixtyFour)
{
	CRendezvousRelayLimiter limiter;

	for (uint32_t i = 0; i < kRendezvousMaxAttempts; ++i) {
		char text[64];
		std::snprintf(text, sizeof(text), "2001:db8:1:1::%x", i + 1);
		ASSERT_TRUE(limiter.Admit(CNetworkAddress::FromString(text), 1000));
	}

	// A sixth address in the same /64 is the same customer.
	ASSERT_FALSE(limiter.Admit(CNetworkAddress::FromString("2001:db8:1:1::99"), 1000));
	// A different /64 is not.
	ASSERT_TRUE(limiter.Admit(CNetworkAddress::FromString("2001:db8:1:2::1"), 1000));
}

// A tick count that appears to move backwards must not hand out a fresh budget.
// Clock adjustments happen, and "the clock went back" is not evidence that a
// flood stopped.
TEST(NatRendezvousRelay, BackwardsClockDoesNotResetABudget)
{
	CRendezvousRelayLimiter limiter;

	for (uint32_t i = 0; i < kRendezvousMaxAttempts; ++i) {
		ASSERT_TRUE(limiter.Admit(Requester(), 100000));
	}

	ASSERT_FALSE(limiter.Admit(Requester(), 1));
}

// The forwarded message is marked as relayed, which is what lets the peer that
// receives it act on it without having to guess the direction -- and what keeps
// this relay from acting on a relay request as though it were one.
TEST(NatRendezvousRelay, ForwardedMessageIsMarkedRelayed)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	const std::vector<uint8_t> frame = Request(Requester(), kSourcePort);
	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	RelayRendezvousRequest(frame.data(),
		frame.size(),
		Requester(),
		kSourcePort,
		requesterHash,
		1000,
		limiter,
		clients,
		sender);

	ASSERT_EQUALS(1u, sender.m_sent.size());
	SNattRendezvousRequest forwarded;
	ASSERT_TRUE(ParseRendezvousRequest(
		sender.m_sent[0].payload.data(), sender.m_sent[0].payload.size(), forwarded));
	ASSERT_TRUE(forwarded.isRelayed);
}

// A message that is already relayed is not relayed again. Two relays willing to
// forward each other's forwards is a loop that only the rate limit would stop,
// and only after both had spent their budgets.
TEST(NatRendezvousRelay, AlreadyRelayedMessageIsNotRelayedAgain)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);
	uint8_t targetHash[NATT_PEER_HASH_LENGTH];
	FillHash(targetHash, 0x20);

	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length =
		EncodeRelayedRendezvous(targetHash, Requester(), kSourcePort, frame, sizeof(frame));

	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	const SRelayDecision decision = RelayRendezvousRequest(
		frame, length, Requester(), kSourcePort, requesterHash, 1000, limiter, clients, sender);

	ASSERT_EQUALS((int)RELAY_DISCARD_ALREADY_RELAYED, (int)decision.disposition);
	ASSERT_EQUALS(0u, sender.m_sent.size());
}

// The other direction: what this client does with a rendezvous a relay
// forwarded to it.
//
// This is the one path in the change that acts on an endpoint it did not
// observe, so it is the one that has to be argued rather than merely
// implemented. Four guards stand in front of it -- the relayed bit, a relay
// this client already knows, a per-relay rate limit, and a usable endpoint --
// and the punch that follows is bounded by CHolePunchSchedule to three packets
// per attempt. The residual exposure is that a known relay can cause this
// client to send that bounded burst toward an address of the relay's choosing.
// That is inherent to hole punching and is the same trust the design places in
// R for signalling; it is not unbounded and it is not free.
TEST(NatRendezvousRelay, RelayedRendezvousFromAKnownRelayIsAccepted)
{
	uint8_t peerHash[NATT_PEER_HASH_LENGTH];
	FillHash(peerHash, 0x30);

	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length = EncodeRelayedRendezvous(
		peerHash, CNetworkAddress::FromString("198.51.100.7"), 4662, frame, sizeof(frame));

	CRendezvousRelayLimiter limiter;
	const SRelayedRendezvousDecision decision = AcceptRelayedRendezvous(
		frame, length, Target(), true, CNetworkAddress::FromString("192.0.2.10"), 1000, limiter);

	ASSERT_EQUALS((int)RELAYED_ACCEPT, (int)decision.acceptance);
	ASSERT_TRUE(decision.punch);
	ASSERT_TRUE(decision.punchEndpoint == CNetworkAddress::FromString("198.51.100.7"));
	ASSERT_EQUALS(4662, (int)decision.punchPort);
	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		ASSERT_EQUALS((int)peerHash[i], (int)decision.peerHash[i]);
	}
}

// The crafted packet. A plain relay request -- the shape an attacker sends to
// make this client aim traffic somewhere -- is never accepted down the relayed
// path, whatever endpoint it names. Without this the relay validation could be
// bypassed simply by having the request read as a forward.
TEST(NatRendezvousRelay, RelayRequestIsNeverAcceptedAsARelayedRendezvous)
{
	const std::vector<uint8_t> frame = Request(Victim(), 4662);

	CRendezvousRelayLimiter limiter;
	const SRelayedRendezvousDecision decision = AcceptRelayedRendezvous(frame.data(),
		frame.size(),
		Requester(),
		true,
		CNetworkAddress::FromString("192.0.2.99"),
		1000,
		limiter);

	ASSERT_EQUALS((int)RELAYED_REJECT_NOT_RELAYED, (int)decision.acceptance);
	ASSERT_FALSE(decision.punch);
	ASSERT_TRUE(decision.punchEndpoint.IsAbsent());
}

// A relay this client does not know cannot make it punch. Signalling is trusted
// only from peers already in the client list.
TEST(NatRendezvousRelay, RelayedRendezvousFromAnUnknownRelayIsRejected)
{
	uint8_t peerHash[NATT_PEER_HASH_LENGTH];
	FillHash(peerHash, 0x30);

	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length = EncodeRelayedRendezvous(
		peerHash, CNetworkAddress::FromString("198.51.100.7"), 4662, frame, sizeof(frame));

	CRendezvousRelayLimiter limiter;
	const SRelayedRendezvousDecision decision = AcceptRelayedRendezvous(
		frame, length, Target(), false, CNetworkAddress::FromString("192.0.2.10"), 1000, limiter);

	ASSERT_EQUALS((int)RELAYED_REJECT_UNKNOWN_RELAY, (int)decision.acceptance);
	ASSERT_FALSE(decision.punch);
}

// The same budget bounds this direction. A relay that forwards more than its
// share is throttled on exactly the terms a requester is, and out of the same
// bucket -- so a peer cannot get a second allowance by switching roles.
TEST(NatRendezvousRelay, RelayedRendezvousIsRateLimitedPerRelay)
{
	uint8_t peerHash[NATT_PEER_HASH_LENGTH];
	FillHash(peerHash, 0x30);

	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length = EncodeRelayedRendezvous(
		peerHash, CNetworkAddress::FromString("198.51.100.7"), 4662, frame, sizeof(frame));

	CRendezvousRelayLimiter limiter;
	for (uint32_t i = 0; i < kRendezvousMaxAttempts; ++i) {
		const SRelayedRendezvousDecision accepted = AcceptRelayedRendezvous(frame,
			length,
			Target(),
			true,
			CNetworkAddress::FromString("192.0.2.10"),
			1000,
			limiter);
		ASSERT_EQUALS((int)RELAYED_ACCEPT, (int)accepted.acceptance);
	}

	const SRelayedRendezvousDecision throttled = AcceptRelayedRendezvous(
		frame, length, Target(), true, CNetworkAddress::FromString("192.0.2.10"), 1000, limiter);
	ASSERT_EQUALS((int)RELAYED_REJECT_RATE_LIMITED, (int)throttled.acceptance);
	ASSERT_FALSE(throttled.punch);
}

// An endpoint naming this client itself is a request to punch at our own
// address. Nothing useful can come of it and it is a small self-amplifier.
TEST(NatRendezvousRelay, RelayedRendezvousNamingOurOwnEndpointIsRejected)
{
	uint8_t peerHash[NATT_PEER_HASH_LENGTH];
	FillHash(peerHash, 0x30);

	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length = EncodeRelayedRendezvous(
		peerHash, CNetworkAddress::FromString("192.0.2.10"), 4662, frame, sizeof(frame));

	CRendezvousRelayLimiter limiter;
	const SRelayedRendezvousDecision decision = AcceptRelayedRendezvous(
		frame, length, Target(), true, CNetworkAddress::FromString("192.0.2.10"), 1000, limiter);

	ASSERT_EQUALS((int)RELAYED_REJECT_ENDPOINT_IS_OURSELVES, (int)decision.acceptance);
	ASSERT_FALSE(decision.punch);
}

// A malformed relayed message yields no punch and no endpoint. The endpoint
// field of the decision is absent rather than zero, so a caller that ignores
// the acceptance code still cannot dial anything.
TEST(NatRendezvousRelay, MalformedRelayedRendezvousYieldsNoEndpoint)
{
	const uint8_t garbage[3] = { OP_RENDEZVOUS, NATT_OPT_RELAYED, 0x00 };

	CRendezvousRelayLimiter limiter;
	const SRelayedRendezvousDecision decision = AcceptRelayedRendezvous(garbage,
		sizeof(garbage),
		Target(),
		true,
		CNetworkAddress::FromString("192.0.2.10"),
		1000,
		limiter);

	ASSERT_EQUALS((int)RELAYED_REJECT_MALFORMED, (int)decision.acceptance);
	ASSERT_FALSE(decision.punch);
	ASSERT_TRUE(decision.punchEndpoint.IsAbsent());
}
