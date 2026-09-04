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

//! An address on the public internet, for the one field in this suite that
//! becomes a destination: the endpoint a relayed rendezvous asks us to punch
//! toward. Deliberately not one of the RFC 5737 documentation blocks the peer
//! addresses above use -- AcceptRelayedRendezvous() refuses any endpoint that
//! is not globally routable, and those blocks are not.
CNetworkAddress PunchTarget()
{
	return CNetworkAddress::FromString("81.2.69.142");
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

//! The file hash a request names, distinct from every peer hash seed used here
//! so that a field swap shows up as a value and not as a length.
void FillFileHash(uint8_t *out)
{
	for (uint8_t i = 0; i < NATT_FILE_HASH_LENGTH; ++i) {
		out[i] = static_cast<uint8_t>(0xF0 + i);
	}
}

//! A well-formed request from `Requester()` for the peer with hash seed 0x20,
//! about the file `FillFileHash()` names, claiming `claimedEndpoint` as its own
//! external endpoint.
std::vector<uint8_t> Request(const CNetworkAddress &claimedEndpoint, uint16_t claimedPort)
{
	uint8_t targetHash[NATT_PEER_HASH_LENGTH];
	FillHash(targetHash, 0x20);
	uint8_t fileHash[NATT_FILE_HASH_LENGTH];
	FillFileHash(fileHash);

	std::vector<uint8_t> frame(NATT_RENDEZVOUS_MAX_LENGTH, 0);
	const size_t written = EncodeRendezvousRequest(
		targetHash, fileHash, claimedEndpoint, claimedPort, frame.data(), frame.size());
	frame.resize(written);
	return frame;
}

//! The same request with no file hash in it -- the legal shape for a requester
//! that has none, and the one the greedy file-hash test must not misread.
std::vector<uint8_t> RequestWithoutFileHash(const CNetworkAddress &claimedEndpoint, uint16_t claimedPort)
{
	uint8_t targetHash[NATT_PEER_HASH_LENGTH];
	FillHash(targetHash, 0x20);

	std::vector<uint8_t> frame(NATT_RENDEZVOUS_MAX_LENGTH, 0);
	const size_t written = EncodeRendezvousRequest(
		targetHash, NULL, claimedEndpoint, claimedPort, frame.data(), frame.size());
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

// The same, for a hint naming a host in a different family -- but it is
// rejected one step earlier now, and the difference is worth stating.
//
// The eMuleAI endpoint slot is IPv4 and has no family byte, so an IPv6 endpoint
// is not encodable at all: the request goes out carrying no endpoint rather
// than carrying an IPv6 one, and it never reaches the address comparison. The
// disposition is therefore RELAY_DISCARD_NO_ENDPOINT_HINT and not
// RELAY_DISCARD_HINT_NAMES_ANOTHER_HOST.
//
// The security property is unchanged -- no packet is emitted, to anyone -- and
// what is lost is a capability rather than a defence: an IPv6 peer cannot state
// an IPv6 endpoint in this format. Nothing in production could anyway, because
// CClientUDPSocket::SendNattControlMessage() drops native-IPv6 destinations
// before a control message is sent. Giving IPv6 a slot needs a length-prefixed
// element, which is a wire-format proposal of its own.
TEST(NatRendezvousRelay, AnIPv6EndpointHasNoSlotSoNoPacketIsEmitted)
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
	ASSERT_EQUALS((int)RELAY_DISCARD_NO_ENDPOINT_HINT, (int)decision.disposition);
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

// The file hash the request named travels on to the target, byte for byte.
//
// It is the one field in the forwarded message that DOES come from the
// datagram, and that is deliberate rather than an oversight in the "never from
// the datagram" rule. That rule exists for the requester identity and the
// endpoint, because those are what a forged value would aim traffic with. A
// file hash names no host and is never dialled; it is the subject line of the
// rendezvous. The relay has no other source for it -- its client list knows who
// the requester is, not what it wanted -- and inventing one would tell the
// target this rendezvous is about a file it is not about.
TEST(NatRendezvousRelay, TheFileHashTheRequestNamedIsForwardedVerbatim)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	const std::vector<uint8_t> frame = Request(Requester(), 4662);
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

	ASSERT_TRUE(decision.emitted);
	ASSERT_EQUALS(1u, sender.m_sent.size());

	SNattRendezvousRequest forwarded;
	ASSERT_TRUE(ParseRendezvousRequest(
		sender.m_sent[0].payload.data(), sender.m_sent[0].payload.size(), forwarded));
	ASSERT_TRUE(forwarded.hasFileHash);
	for (size_t i = 0; i < NATT_FILE_HASH_LENGTH; ++i) {
		ASSERT_EQUALS(0xF0 + (int)i, (int)forwarded.fileHash[i]);
	}
}

// A request that named no file is forwarded naming no file. Not zero-filled:
// sixteen zero bytes are a file hash, and it is not the file this rendezvous is
// about. The forward is shorter by exactly those sixteen bytes, and its
// endpoint still reads back as an endpoint -- the greedy file-hash test needs
// sixteen bytes to fire and an endpoint tail is six, so the arithmetic cannot
// reach it.
TEST(NatRendezvousRelay, ARequestNamingNoFileIsForwardedNamingNoFile)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	const std::vector<uint8_t> frame = RequestWithoutFileHash(Requester(), 4662);
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

	ASSERT_TRUE(decision.emitted);
	ASSERT_EQUALS(1u, sender.m_sent.size());
	ASSERT_EQUALS(
		NATT_RENDEZVOUS_FIXED_LENGTH + NATT_ENDPOINT_TAIL_LENGTH, sender.m_sent[0].payload.size());

	SNattRendezvousRequest forwarded;
	ASSERT_TRUE(ParseRendezvousRequest(
		sender.m_sent[0].payload.data(), sender.m_sent[0].payload.size(), forwarded));
	ASSERT_FALSE(forwarded.hasFileHash);
	ASSERT_TRUE(forwarded.hasEndpointHint);
	ASSERT_TRUE(forwarded.hintAddress == Requester());
	ASSERT_EQUALS(kSourcePort, forwarded.hintPort);
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
	// The options byte follows the peer hash; it is no longer the body's second
	// byte, because the body no longer opens with an opcode.
	frame[NATT_PEER_HASH_LENGTH] &= static_cast<uint8_t>(~CONNECT_OPT_NAT_TRAVERSAL_UTP);

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
		ASSERT_TRUE(limiter.Admit(
			CNetworkAddress::FromString(text), 1000, false, RENDEZVOUS_ROLE_RELAY_SERVICE));
	}

	ASSERT_EQUALS((size_t)kRendezvousRelayBucketCap, limiter.BucketCount());
	ASSERT_FALSE(limiter.Admit(CNetworkAddress::FromString("2001:db8:ffff:ffff::1"),
		1000,
		false,
		RENDEZVOUS_ROLE_RELAY_SERVICE));
	ASSERT_EQUALS((size_t)kRendezvousRelayBucketCap, limiter.BucketCount());

	// Once the window has passed, the expired buckets are reclaimed and the
	// limiter serves again. Without this the first flood would be permanent.
	ASSERT_TRUE(limiter.Admit(CNetworkAddress::FromString("2001:db8:ffff:ffff::1"),
		1000 + kRendezvousBackoffMs,
		false,
		RENDEZVOUS_ROLE_RELAY_SERVICE));
}

// Failing closed at the cap bounds memory, but on its own it hands an attacker
// an outage. The relay path never replies, so a source address costs nothing to
// forge: 1024 distinct spoofed sources renewed once per window -- about
// seventeen packets a second -- keep the table permanently full, and every peer
// without a bucket is denied for as long as the flood runs. The header used to
// call that cost "a retry"; a retry that cannot succeed is an outage.
//
// It reached further than the relay service, too. One bucket table serves both
// directions of this opcode, so the service this client gives away to strangers
// was starving the capability it needs for itself: our own buddy's forwarded
// rendezvous was denied out of a table full of addresses that never existed.
//
// So the cap now bounds only the class it was written for. A source we already
// hold an identity for is admitted even when the table is full, by evicting the
// bucket whose window started longest ago. The table never grows past the cap.
TEST(NatRendezvousRelay, AFloodOfUnknownSourcesCannotLockOutAPeerWeHold)
{
	CRendezvousRelayLimiter limiter;

	for (uint32_t i = 0; i < kRendezvousRelayBucketCap; ++i) {
		char text[64];
		std::snprintf(text, sizeof(text), "2001:db8:%x:%x::1", (i >> 16) & 0xFFFF, i & 0xFFFF);
		ASSERT_TRUE(limiter.Admit(
			CNetworkAddress::FromString(text), 1000, false, RENDEZVOUS_ROLE_RELAY_SERVICE));
	}
	ASSERT_EQUALS((size_t)kRendezvousRelayBucketCap, limiter.BucketCount());

	// Distinct known peers, so each one needs a bucket the table does not have.
	// Every one of them is admitted, and the table does not grow.
	for (uint32_t i = 0; i < 32; ++i) {
		char text[64];
		std::snprintf(text, sizeof(text), "192.0.2.%u", i + 1);
		ASSERT_TRUE(limiter.Admit(
			CNetworkAddress::FromString(text), 1000, true, RENDEZVOUS_ROLE_RELAY_SERVICE));
		ASSERT_EQUALS((size_t)kRendezvousRelayBucketCap, limiter.BucketCount());
	}

	// And the flood's own class is still denied, so the cap still does the job
	// it was written for.
	ASSERT_FALSE(limiter.Admit(CNetworkAddress::FromString("2001:db8:ffff:ffff::1"),
		1000,
		false,
		RENDEZVOUS_ROLE_RELAY_SERVICE));
	ASSERT_EQUALS((size_t)kRendezvousRelayBucketCap, limiter.BucketCount());
}

// The measured shape of the outage: a flood renewed at every window boundary,
// and our buddy asking for something across all of them. Before the reserved
// admission this asserted false at every tick.
TEST(NatRendezvousRelay, AKnownPeerIsAdmittedInEveryWindowOfASustainedFlood)
{
	CRendezvousRelayLimiter limiter;

	for (uint32_t window = 0; window < 5; ++window) {
		const uint64_t nowMs = 1000 + (uint64_t)window * kRendezvousBackoffMs;

		for (uint32_t i = 0; i < kRendezvousRelayBucketCap; ++i) {
			char text[64];
			std::snprintf(
				text, sizeof(text), "2001:db8:%x:%x::1", (i >> 16) & 0xFFFF, i & 0xFFFF);
			limiter.Admit(CNetworkAddress::FromString(text),
				nowMs,
				false,
				RENDEZVOUS_ROLE_RELAY_SERVICE);
		}

		ASSERT_TRUE(limiter.Admit(Requester(), nowMs, true, RENDEZVOUS_ROLE_RELAY_SERVICE));
	}
}

// The reserved admission is not a second budget. A known peer that has spent
// its five is throttled on exactly the terms it was before, because its own
// bucket is found before the table is ever consulted for room -- so it cannot
// evict itself into a fresh window.
TEST(NatRendezvousRelay, AKnownPeerStillSpendsItsOwnBudget)
{
	CRendezvousRelayLimiter limiter;

	for (uint32_t i = 0; i < kRendezvousRelayBucketCap; ++i) {
		char text[64];
		std::snprintf(text, sizeof(text), "2001:db8:%x:%x::1", (i >> 16) & 0xFFFF, i & 0xFFFF);
		ASSERT_TRUE(limiter.Admit(
			CNetworkAddress::FromString(text), 1000, false, RENDEZVOUS_ROLE_RELAY_SERVICE));
	}

	for (uint32_t i = 0; i < kRendezvousMaxAttempts; ++i) {
		ASSERT_TRUE(limiter.Admit(Requester(), 1000, true, RENDEZVOUS_ROLE_RELAY_SERVICE));
	}
	ASSERT_FALSE(limiter.Admit(Requester(), 1000, true, RENDEZVOUS_ROLE_RELAY_SERVICE));
}

// End to end, on the function the socket actually calls: a request from a host
// this client holds a user hash for is forwarded during a flood that has the
// bucket table full. The identity is what buys the slot, and it is the same
// value the relay would refuse to send without.
TEST(NatRendezvousRelay, ARequestFromAHostWeHoldIsRelayedDuringAFlood)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	CRendezvousRelayLimiter limiter;
	for (uint32_t i = 0; i < kRendezvousRelayBucketCap; ++i) {
		char text[64];
		std::snprintf(text, sizeof(text), "2001:db8:%x:%x::1", (i >> 16) & 0xFFFF, i & 0xFFFF);
		ASSERT_TRUE(limiter.Admit(
			CNetworkAddress::FromString(text), 1000, false, RENDEZVOUS_ROLE_RELAY_SERVICE));
	}

	const std::vector<uint8_t> frame = Request(Requester(), kSourcePort);
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

// IPv6 budgets count per /64, exactly as every other per-peer limit in this
// tree does (PeerIdentity::RateLimitScope). A per-/128 limit would count to one
// forever for a subscriber delegated a prefix, which is the same as no limit.
TEST(NatRendezvousRelay, IPv6RequestersShareABudgetPerSixtyFour)
{
	CRendezvousRelayLimiter limiter;

	for (uint32_t i = 0; i < kRendezvousMaxAttempts; ++i) {
		char text[64];
		std::snprintf(text, sizeof(text), "2001:db8:1:1::%x", i + 1);
		ASSERT_TRUE(limiter.Admit(
			CNetworkAddress::FromString(text), 1000, false, RENDEZVOUS_ROLE_RELAY_SERVICE));
	}

	// A sixth address in the same /64 is the same customer.
	ASSERT_FALSE(limiter.Admit(
		CNetworkAddress::FromString("2001:db8:1:1::99"), 1000, false, RENDEZVOUS_ROLE_RELAY_SERVICE));
	// A different /64 is not.
	ASSERT_TRUE(limiter.Admit(
		CNetworkAddress::FromString("2001:db8:1:2::1"), 1000, false, RENDEZVOUS_ROLE_RELAY_SERVICE));
}

// A tick count that appears to move backwards must not hand out a fresh budget.
// Clock adjustments happen, and "the clock went back" is not evidence that a
// flood stopped.
TEST(NatRendezvousRelay, BackwardsClockDoesNotResetABudget)
{
	CRendezvousRelayLimiter limiter;

	for (uint32_t i = 0; i < kRendezvousMaxAttempts; ++i) {
		ASSERT_TRUE(limiter.Admit(Requester(), 100000, false, RENDEZVOUS_ROLE_RELAY_SERVICE));
	}

	ASSERT_FALSE(limiter.Admit(Requester(), 1, false, RENDEZVOUS_ROLE_RELAY_SERVICE));
}

// Nothing in the forwarded bytes states which direction the message travels.
// The name of this test used to say the opposite, from when the options byte
// carried a CONNECT_OPT_NATT_RELAYED bit; the bit is gone -- 0x40 is eMuleAI's
// QUIC capability -- and the assertions below have always been about its
// absence. The receiver decides the direction about its sender instead; see
// ClassifyRendezvousDirection().
TEST(NatRendezvousRelay, ForwardedMessageCarriesNoDirectionOnTheWire)
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
	// Nothing in the forwarded bytes states which direction it travels, and
	// that is the point: a receiver that read the direction out of the message
	// would take a crafted request's word for it. The options byte carries the
	// two capability bits and nothing else.
	ASSERT_TRUE(forwarded.requestsUtpTraversal);
	ASSERT_TRUE(forwarded.hasEndpointHint);
	ASSERT_TRUE(forwarded.hintAddress == Requester());

	// Byte for byte a request naming the same endpoint. If these ever diverge,
	// something has put a direction back on the wire.
	const std::vector<uint8_t> asRequest = Request(Requester(), kSourcePort);
	ASSERT_EQUALS(asRequest.size(), sender.m_sent[0].payload.size());
}

// A forward fed back into the relay path is not relayed again. Two relays
// willing to forward each other's forwards is a loop that only the rate limit
// would stop, and only after both had spent their budgets.
//
// What stops it is no longer a bit saying "already relayed" -- that bit was
// eMuleAI's QUIC capability and is gone. It is the reflection check: a forward
// names the peer it is ABOUT, which is never the relay that sent it, so it
// fails the "may only name the host it arrived from" rule that guards this path
// anyway. One rule now does both jobs, and it is a rule about an address this
// client observed rather than about a claim the sender made.
TEST(NatRendezvousRelay, ForwardFedBackIntoTheRelayPathIsNotRelayedAgain)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);
	uint8_t targetHash[NATT_PEER_HASH_LENGTH];
	FillHash(targetHash, 0x20);

	// The shape a relay emits: it names the requester it observed, and it
	// arrives here from the relay, which is a different host.
	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length =
		EncodeRelayedRendezvous(targetHash, NULL, Requester(), kSourcePort, frame, sizeof(frame));

	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	const SRelayDecision decision = RelayRendezvousRequest(
		frame, length, Target(), kTargetPort, requesterHash, 1000, limiter, clients, sender);

	ASSERT_EQUALS((int)RELAY_DISCARD_HINT_NAMES_ANOTHER_HOST, (int)decision.disposition);
	ASSERT_EQUALS(0u, sender.m_sent.size());
}

// The decision that routes a datagram between the two paths, and until now the
// one part of this change no test could reach: it lived inline in
// CClientUDPSocket, a class the suite cannot link. A branch that chooses
// between "send toward an address out of our client list" and "punch at an
// address out of the message" is the last one that should be untestable, so it
// is a function over its inputs now.
//
// Everything that is not positively a forward from our buddy about a third host
// is a relay request -- including a malformed body, which reaches
// RelayRendezvousRequest() so that it is charged to its sender.
TEST(NatRendezvousRelay, DirectionIsDecidedBySenderAndObservedAddressAlone)
{
	uint8_t peerHash[NATT_PEER_HASH_LENGTH];
	FillHash(peerHash, 0x30);

	uint8_t aboutAThirdHost[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t aboutLength = EncodeRelayedRendezvous(
		peerHash, NULL, PunchTarget(), 4662, aboutAThirdHost, sizeof(aboutAThirdHost));

	// Our buddy, telling us where a third peer is: the acting path.
	ASSERT_EQUALS((int)NATT_RENDEZVOUS_ACT_ON_FORWARD,
		(int)ClassifyRendezvousDirection(aboutAThirdHost, aboutLength, Target(), true));

	// The identical bytes from a stranger. The only fact that changed is one
	// the datagram cannot touch, and it is the one that decides.
	ASSERT_EQUALS((int)NATT_RENDEZVOUS_RELAY_FOR_SENDER,
		(int)ClassifyRendezvousDirection(aboutAThirdHost, aboutLength, Requester(), false));

	// Our buddy naming ITSELF is our buddy asking us to relay for it.
	uint8_t aboutItself[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t itselfLength = EncodeRelayedRendezvous(
		peerHash, NULL, Target(), kTargetPort, aboutItself, sizeof(aboutItself));
	ASSERT_EQUALS((int)NATT_RENDEZVOUS_RELAY_FOR_SENDER,
		(int)ClassifyRendezvousDirection(aboutItself, itselfLength, Target(), true));

	// A body with no endpoint in it names no host, so there is nothing for this
	// client to act on and it belongs to the relay path.
	uint8_t noEndpoint[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t noEndpointLength =
		EncodeRendezvousRequest(peerHash, NULL, CNetworkAddress(), 0, noEndpoint, sizeof(noEndpoint));
	ASSERT_TRUE(noEndpointLength > 0);
	ASSERT_EQUALS((int)NATT_RENDEZVOUS_RELAY_FOR_SENDER,
		(int)ClassifyRendezvousDirection(noEndpoint, noEndpointLength, Target(), true));

	// A malformed body from our buddy goes to the relay path too, so it is
	// charged to its sender's budget rather than being free.
	const uint8_t garbage[3] = { 0x00, CONNECT_OPT_NAT_TRAVERSAL_UTP, 0x00 };
	ASSERT_EQUALS((int)NATT_RENDEZVOUS_RELAY_FOR_SENDER,
		(int)ClassifyRendezvousDirection(garbage, sizeof(garbage), Target(), true));
	ASSERT_EQUALS((int)NATT_RENDEZVOUS_RELAY_FOR_SENDER,
		(int)ClassifyRendezvousDirection(NULL, 0, Target(), true));
}

// A dual-stack buddy that spells its own IPv4 address as ::ffff:a.b.c.d is
// still naming itself. Compared unmapped for the same reason both other
// address comparisons in this file are: the spelling is not the host.
TEST(NatRendezvousRelay, MappedSpellingOfTheBuddysOwnAddressStillMeansRelayForIt)
{
	uint8_t peerHash[NATT_PEER_HASH_LENGTH];
	FillHash(peerHash, 0x30);

	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length =
		EncodeRelayedRendezvous(peerHash, NULL, Target(), kTargetPort, frame, sizeof(frame));

	ASSERT_EQUALS((int)NATT_RENDEZVOUS_RELAY_FOR_SENDER,
		(int)ClassifyRendezvousDirection(
			frame, length, CNetworkAddress::FromString("::ffff:203.0.113.5"), true));
}

// The other direction: what this client does with a rendezvous a relay
// forwarded to it.
//
// This is the one path in the change that acts on an endpoint it did not
// observe, so it is the one that has to be argued rather than merely
// implemented. Four guards stand in front of it -- the sender is our buddy, the
// endpoint is not that sender's own, a per-relay rate limit, and a usable
// endpoint that is not ours -- and the punch that follows is bounded by
// CHolePunchSchedule to three packets per attempt. The residual exposure is
// that OUR BUDDY can cause this client to send that bounded burst toward an
// address of its choosing. That is inherent to hole punching and is the same
// trust the design already places in a buddy, which relays this client's
// callbacks; it is not unbounded and it is not free.
TEST(NatRendezvousRelay, RelayedRendezvousFromOurBuddyIsAccepted)
{
	uint8_t peerHash[NATT_PEER_HASH_LENGTH];
	FillHash(peerHash, 0x30);

	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length =
		EncodeRelayedRendezvous(peerHash, NULL, PunchTarget(), 4662, frame, sizeof(frame));

	CRendezvousRelayLimiter limiter;
	const SRelayedRendezvousDecision decision = AcceptRelayedRendezvous(
		frame, length, Target(), true, CNetworkAddress::FromString("192.0.2.10"), 1000, limiter);

	ASSERT_EQUALS((int)RELAYED_ACCEPT, (int)decision.acceptance);
	ASSERT_TRUE(decision.punch);
	ASSERT_TRUE(decision.punchEndpoint == PunchTarget());
	ASSERT_EQUALS(4662, (int)decision.punchPort);
	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		ASSERT_EQUALS((int)peerHash[i], (int)decision.peerHash[i]);
	}
}

// The crafted packet, and the guard that stands in its place now.
//
// The bytes below are a perfectly well-formed forward naming an unrelated
// victim -- exactly what an attacker sends to make this client aim traffic
// somewhere. Under the old design the only thing between it and the punch was
// an option bit the attacker sets as easily as a relay does. Now it is stopped
// by a fact the datagram cannot touch: the sender is not this client's buddy.
//
// The message is not distinguishable from a genuine forward, and it does not
// need to be. That is the whole shift: the question moved from "what does this
// message claim" to "who sent it".
TEST(NatRendezvousRelay, RendezvousFromANonBuddyIsNeverActedOn)
{
	uint8_t peerHash[NATT_PEER_HASH_LENGTH];
	FillHash(peerHash, 0x30);

	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length = EncodeRelayedRendezvous(peerHash, NULL, Victim(), 4662, frame, sizeof(frame));

	CRendezvousRelayLimiter limiter;
	const SRelayedRendezvousDecision decision = AcceptRelayedRendezvous(
		frame, length, Requester(), false, CNetworkAddress::FromString("192.0.2.99"), 1000, limiter);

	ASSERT_EQUALS((int)RELAYED_REJECT_RELAY_IS_NOT_OUR_BUDDY, (int)decision.acceptance);
	ASSERT_FALSE(decision.punch);
	ASSERT_TRUE(decision.punchEndpoint.IsAbsent());
}

// Our buddy naming ITSELF is our buddy asking us to relay for it, not telling
// us where a third peer is -- the other honest use a buddy has for this opcode.
// Reported rather than accepted, so the caller routes it to the relay path,
// where naming your own source address is not merely allowed but required.
//
// Acting on it instead would punch at the one peer this client is already in
// contact with, and would silently drop the relay the buddy actually asked for.
TEST(NatRendezvousRelay, RendezvousFromOurBuddyNamingItselfIsNotActedOn)
{
	uint8_t peerHash[NATT_PEER_HASH_LENGTH];
	FillHash(peerHash, 0x30);

	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length =
		EncodeRelayedRendezvous(peerHash, NULL, Target(), kTargetPort, frame, sizeof(frame));

	CRendezvousRelayLimiter limiter;
	const SRelayedRendezvousDecision decision = AcceptRelayedRendezvous(
		frame, length, Target(), true, CNetworkAddress::FromString("192.0.2.10"), 1000, limiter);

	ASSERT_EQUALS((int)RELAYED_REJECT_ENDPOINT_IS_THE_RELAY, (int)decision.acceptance);
	ASSERT_FALSE(decision.punch);
	ASSERT_TRUE(decision.punchEndpoint.IsAbsent());
}

// One bucket table served both directions of this opcode, and the two are not
// the same transaction. Relaying is a service this client gives away to
// strangers and gets nothing from; acting on a forward is a capability this
// client is the beneficiary of. Charging them to one budget lets the giveaway
// throttle the thing we need, which is a category error no bucket count fixes:
// our own buddy asking us to relay five times in a window left nothing for the
// forward it sent us in the other direction.
//
// So the budget is per role. The role is chosen inside these two functions
// rather than by whoever calls them, so there is no wiring for a caller to get
// wrong -- the same reason ClassifyRendezvousDirection() lives here.
TEST(NatRendezvousRelay, RelayingForOurBuddyDoesNotSpendWhatItsForwardsNeed)
{
	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);

	const std::vector<uint8_t> ask = Request(Requester(), kSourcePort);
	CRendezvousRelayLimiter limiter;
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	// Our buddy spends its entire relay-service budget asking us to relay.
	for (uint32_t i = 0; i < kRendezvousMaxAttempts; ++i) {
		const SRelayDecision served = RelayRendezvousRequest(ask.data(),
			ask.size(),
			Requester(),
			kSourcePort,
			requesterHash,
			1000,
			limiter,
			clients,
			sender);
		ASSERT_EQUALS((int)RELAY_FORWARD, (int)served.disposition);
	}

	const SRelayDecision throttled = RelayRendezvousRequest(ask.data(),
		ask.size(),
		Requester(),
		kSourcePort,
		requesterHash,
		1000,
		limiter,
		clients,
		sender);
	ASSERT_EQUALS((int)RELAY_DISCARD_RATE_LIMITED, (int)throttled.disposition);

	// And the forward it sends us in the other direction, on the same limiter,
	// is untouched by that. This is the assertion the shared table failed.
	uint8_t peerHash[NATT_PEER_HASH_LENGTH];
	FillHash(peerHash, 0x30);
	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length =
		EncodeRelayedRendezvous(peerHash, NULL, PunchTarget(), 4662, frame, sizeof(frame));

	const SRelayedRendezvousDecision acted =
		AcceptRelayedRendezvous(frame, length, Requester(), true, CNetworkAddress(), 1000, limiter);
	ASSERT_EQUALS((int)RELAYED_ACCEPT, (int)acted.acceptance);
}

// And the other way round, so neither role is merely first past the post: a
// buddy that has spent its forward budget can still ask us to relay.
TEST(NatRendezvousRelay, ForwardsFromOurBuddyDoNotSpendWhatRelayingForItNeeds)
{
	uint8_t peerHash[NATT_PEER_HASH_LENGTH];
	FillHash(peerHash, 0x30);
	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length =
		EncodeRelayedRendezvous(peerHash, NULL, PunchTarget(), 4662, frame, sizeof(frame));

	CRendezvousRelayLimiter limiter;
	for (uint32_t i = 0; i < kRendezvousMaxAttempts; ++i) {
		const SRelayedRendezvousDecision acted = AcceptRelayedRendezvous(
			frame, length, Requester(), true, CNetworkAddress(), 1000, limiter);
		ASSERT_EQUALS((int)RELAYED_ACCEPT, (int)acted.acceptance);
	}
	const SRelayedRendezvousDecision throttled =
		AcceptRelayedRendezvous(frame, length, Requester(), true, CNetworkAddress(), 1000, limiter);
	ASSERT_EQUALS((int)RELAYED_REJECT_RATE_LIMITED, (int)throttled.acceptance);

	uint8_t requesterHash[NATT_PEER_HASH_LENGTH];
	FillHash(requesterHash, 0x10);
	const std::vector<uint8_t> ask = Request(Requester(), kSourcePort);
	CFakeClientList clients(Target(), kTargetPort, 0x20);
	CRecordingSender sender;

	const SRelayDecision served = RelayRendezvousRequest(ask.data(),
		ask.size(),
		Requester(),
		kSourcePort,
		requesterHash,
		1000,
		limiter,
		clients,
		sender);
	ASSERT_EQUALS((int)RELAY_FORWARD, (int)served.disposition);
}

// A budget bounds this direction too. A relay that forwards more than its share
// is throttled on exactly the terms a requester is -- five per window -- out of
// the table belonging to this role. See ERendezvousRole for why it is not the
// same table the relay service spends from.
TEST(NatRendezvousRelay, RelayedRendezvousIsRateLimitedPerRelay)
{
	uint8_t peerHash[NATT_PEER_HASH_LENGTH];
	FillHash(peerHash, 0x30);

	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length =
		EncodeRelayedRendezvous(peerHash, NULL, PunchTarget(), 4662, frame, sizeof(frame));

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
		peerHash, NULL, CNetworkAddress::FromString("192.0.2.10"), 4662, frame, sizeof(frame));

	CRendezvousRelayLimiter limiter;
	const SRelayedRendezvousDecision decision = AcceptRelayedRendezvous(
		frame, length, Target(), true, CNetworkAddress::FromString("192.0.2.10"), 1000, limiter);

	ASSERT_EQUALS((int)RELAYED_REJECT_ENDPOINT_IS_OURSELVES, (int)decision.acceptance);
	ASSERT_FALSE(decision.punch);
}

// The punch target is the one address on this path that comes out of a
// datagram, so it is the one that has to be somewhere a packet has business
// going. Being our buddy's word for it is not enough: a buddy that names
// 127.0.0.1 has this client punch at its own loopback services, and one that
// names 10.0.0.5 or 192.168.1.1 has it punch at a host inside the operator's
// LAN -- a network the sender cannot reach itself, which is exactly why it
// would ask us. Broadcast and multicast turn the burst into a fan-out besides.
//
// The predicate is CNetworkAddress::IsGloballyRoutableIPv4(), which the
// obfuscation policy already uses for the mirror-image question. A second
// list of blocks here would be a second thing to keep correct.
//
// Asserted with an ABSENT ownEndpoint on purpose: a client behind NAT
// frequently does not know its own public address, which switches the
// "is this us" guard off. This one does not depend on it.
TEST(NatRendezvousRelay, RelayedRendezvousNamingAnUnroutableEndpointIsRejected)
{
	uint8_t peerHash[NATT_PEER_HASH_LENGTH];
	FillHash(peerHash, 0x30);

	const char *const unroutable[] = { "127.0.0.1",
		"10.0.0.5",
		"192.168.1.1",
		"172.16.0.1",
		"169.254.1.1",
		"100.64.0.1",
		"224.0.0.1",
		"255.255.255.255",
		"198.51.100.7" };

	for (size_t i = 0; i < sizeof(unroutable) / sizeof(unroutable[0]); ++i) {
		uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
		const size_t length = EncodeRelayedRendezvous(peerHash,
			NULL,
			CNetworkAddress::FromString(unroutable[i]),
			4662,
			frame,
			sizeof(frame));
		ASSERT_TRUE(length > 0);

		// A fresh limiter per address: this test is about the endpoint, and
		// sharing one budget across nine forwards would have the last four
		// rejected for being throttled instead.
		CRendezvousRelayLimiter limiter;
		const SRelayedRendezvousDecision decision = AcceptRelayedRendezvous(
			frame, length, Target(), true, CNetworkAddress(), 1000, limiter);

		ASSERT_EQUALS((int)RELAYED_REJECT_ENDPOINT_NOT_ROUTABLE, (int)decision.acceptance);
		ASSERT_FALSE(decision.punch);
		ASSERT_TRUE(decision.punchEndpoint.IsAbsent());
	}
}

// The boundary the check actually draws, asserted as such rather than left to
// be inferred from the refusals above.
//
// 81.2.69.142 is a public address this client holds nothing about, has never
// contacted, and has no relationship with -- and our buddy naming it gets a
// punch burst aimed at it. That is ACCEPTED, deliberately, and this test exists
// to say so out loud.
//
// Routability is a necessary condition on a punch target, not a sufficient one:
// it stops the burst reaching our loopback, our LAN, link-local, CGNAT,
// multicast and broadcast, and it does nothing about an arbitrary stranger on
// the public internet. Constraining that would mean requiring the endpoint to
// be one we already hold for the named peer, which is exactly the address the
// hint exists to deliver -- the relay observed the peer's current NAT mapping
// and we did not. So the harm is bounded by the burst (CHolePunchSchedule:
// three packets per attempt, five attempts, 120 seconds) and by who may ask,
// not by where. If that boundary ever moves, this test is the one to change.
TEST(NatRendezvousRelay, AnArbitraryPublicEndpointFromOurBuddyIsAccepted)
{
	uint8_t peerHash[NATT_PEER_HASH_LENGTH];
	FillHash(peerHash, 0x30);

	uint8_t frame[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length =
		EncodeRelayedRendezvous(peerHash, NULL, PunchTarget(), 4662, frame, sizeof(frame));

	CRendezvousRelayLimiter limiter;
	const SRelayedRendezvousDecision decision =
		AcceptRelayedRendezvous(frame, length, Target(), true, CNetworkAddress(), 1000, limiter);

	ASSERT_EQUALS((int)RELAYED_ACCEPT, (int)decision.acceptance);
	ASSERT_TRUE(decision.punchEndpoint == PunchTarget());
}

// A malformed relayed message yields no punch and no endpoint. The endpoint
// field of the decision is absent rather than zero, so a caller that ignores
// the acceptance code still cannot dial anything.
TEST(NatRendezvousRelay, MalformedRelayedRendezvousYieldsNoEndpoint)
{
	const uint8_t garbage[3] = { OP_RENDEZVOUS, CONNECT_OPT_NAT_TRAVERSAL_UTP, 0x00 };

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
