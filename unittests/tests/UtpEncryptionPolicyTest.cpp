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

// Whether an outbound NAT traversal frame is wrapped in aMule's eD2k UDP
// obfuscation.
//
// The bulk of this suite is about one input: the address this client believes
// is its own. That address is not a display value -- EncryptedDatagramSocket.cpp
// bakes it into the RC4 key -- and the peer derives its half of the key from
// the source address of the datagram it actually received. Get it wrong and
// every frame decrypts to noise at the far end, silently, because a frame that
// failed to deobfuscate looks exactly like a peer that sent plaintext. There is
// no log line and no error to find; the connection just never establishes.
//
// The way to get it wrong is one defaulted argument. CamuleApp::GetPublicIP()
// takes `bool ignorelocal = false`, and on the fall-through path -- no address
// from a server, Kad not connected -- the false answer is m_localip, which
// amule.cpp:654 fills from the machine's own hostname. A Debian host resolves
// its hostname through /etc/hosts to 127.0.1.1, so a gate spelled
// `GetPublicIP() != 0` reports a public address of 127.0.1.1 and opens.
//
// So the cases below feed the gate the addresses that a real deployment
// actually produces -- 127.0.1.1 above all, then the rest of loopback, the
// RFC1918 blocks, link-local, carrier-grade NAT, zero -- and require a refusal
// from each. They are regression tests for a defect that cannot be observed
// from the outside, which is the only reason to pin something this small this
// hard.

#include <muleunit/test.h>

#include <NetworkAddress.h>
#include <UtpEncryptionPolicy.h>

#include <QuicNattProtocol.h>
#include <UtpDatagramRouting.h>

#include <protocol/Protocols.h>

#include <cstring>
#include <vector>

using namespace muleunit;

DECLARE_SIMPLE(UtpEncryptionPolicy)

namespace
{

//! Anti-host order, the convention CamuleApp::GetPublicIP() returns and
//! SNattFrameObfuscationInputs::publicIpIgnoringLocal carries: the leading
//! octet of the dotted form is the least significant byte.
std::uint32_t Ip(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d)
{
	return static_cast<std::uint32_t>(a) | (static_cast<std::uint32_t>(b) << 8) |
	       (static_cast<std::uint32_t>(c) << 16) | (static_cast<std::uint32_t>(d) << 24);
}

//! One of the root name servers: an address that is genuinely reachable from
//! anywhere, and outside every block IsGloballyRoutableIPv4() excludes. Used
//! rather than a documentation-range literal precisely because the
//! documentation ranges are among the ones the gate has to refuse.
std::uint32_t RoutablePublicIp()
{
	return Ip(198, 41, 0, 4);
}

//! Every input other than the public address set so the gate would open. Each
//! test then changes exactly one field, so a failure names the field.
SNattFrameObfuscationInputs ReadyToObfuscate()
{
	SNattFrameObfuscationInputs inputs;
	inputs.frameType = OP_NATT_FRAME_UTP;
	inputs.publicIpIgnoringLocal = RoutablePublicIp();
	inputs.cryptLayerSupportedLocally = true;
	inputs.peerIdentified = true;
	inputs.peerHashKnown = true;
	inputs.peerSupportsCryptLayer = true;
	inputs.cryptLayerRequestedByEitherEnd = true;
	return inputs;
}

SNattFrameObfuscationInputs WithPublicIp(std::uint32_t ip)
{
	SNattFrameObfuscationInputs inputs = ReadyToObfuscate();
	inputs.publicIpIgnoringLocal = ip;
	return inputs;
}

} // namespace

// The baseline the rest of the suite is measured against. Without this one, a
// policy that refused everything would pass every test below.
TEST(UtpEncryptionPolicy, RoutablePublicAddressWithAWillingPeerObfuscates)
{
	const SNattFrameObfuscationDecision decision = DecideNattFrameObfuscation(ReadyToObfuscate());

	ASSERT_TRUE(decision.obfuscate);
	ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_APPLY);
}

// The defect itself, in the exact shape a Debian host produces it. 127.0.1.1 is
// not a hypothetical: it is the loopback entry /etc/hosts gives the hostname,
// so it is what StringHosttoUint32(::wxGetFullHostName()) resolves to and what
// m_localip therefore holds on the machines this daemon most often runs on.
TEST(UtpEncryptionPolicy, DebianHostnameLoopbackAddressIsRefused)
{
	const SNattFrameObfuscationDecision decision =
		DecideNattFrameObfuscation(WithPublicIp(Ip(127, 0, 1, 1)));

	ASSERT_FALSE(decision.obfuscate);
	ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_PUBLIC_ADDRESS_NOT_ROUTABLE);
}

// The rest of 127.0.0.0/8, so the rule is the block and not the two literals
// anybody would have thought to special-case.
TEST(UtpEncryptionPolicy, EveryLoopbackAddressIsRefused)
{
	const std::uint32_t loopback[] = {
		Ip(127, 0, 0, 1),
		Ip(127, 0, 0, 53),
		Ip(127, 1, 2, 3),
		Ip(127, 255, 255, 254),
	};

	for (const std::uint32_t ip : loopback) {
		const SNattFrameObfuscationDecision decision = DecideNattFrameObfuscation(WithPublicIp(ip));

		ASSERT_FALSE(decision.obfuscate);
		ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_PUBLIC_ADDRESS_NOT_ROUTABLE);
	}
}

// All three RFC1918 blocks, including both edges of the 172.16.0.0/12 range --
// 172.15.x and 172.32.x are outside it and must stay routable, which is the
// half of the boundary a mask written as `a == 172` would get wrong.
TEST(UtpEncryptionPolicy, EveryRfc1918PrivateAddressIsRefused)
{
	const std::uint32_t priv[] = {
		Ip(10, 0, 0, 1),
		Ip(10, 255, 255, 254),
		Ip(172, 16, 0, 1),
		Ip(172, 24, 5, 6),
		Ip(172, 31, 255, 254),
		Ip(192, 168, 0, 1),
		Ip(192, 168, 1, 100),
	};

	for (const std::uint32_t ip : priv) {
		const SNattFrameObfuscationDecision decision = DecideNattFrameObfuscation(WithPublicIp(ip));

		ASSERT_FALSE(decision.obfuscate);
		ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_PUBLIC_ADDRESS_NOT_ROUTABLE);
	}
}

// The other edge of the same boundary: 172.15.x and 172.32.x are ordinary
// public space. A gate that refused them would quietly stop obfuscating for
// everyone in two /8-sized neighbourhoods and nobody would notice.
TEST(UtpEncryptionPolicy, AddressesJustOutsideThe172PrivateBlockStillObfuscate)
{
	const std::uint32_t outside[] = {
		Ip(172, 15, 255, 254),
		Ip(172, 32, 0, 1),
	};

	for (const std::uint32_t ip : outside) {
		const SNattFrameObfuscationDecision decision = DecideNattFrameObfuscation(WithPublicIp(ip));

		ASSERT_TRUE(decision.obfuscate);
		ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_APPLY);
	}
}

// 169.254.0.0/16. What an interface holds when DHCP never answered, so it is
// the address a client on a broken network would key with.
TEST(UtpEncryptionPolicy, LinkLocalAddressIsRefused)
{
	const SNattFrameObfuscationDecision decision =
		DecideNattFrameObfuscation(WithPublicIp(Ip(169, 254, 3, 7)));

	ASSERT_FALSE(decision.obfuscate);
	ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_PUBLIC_ADDRESS_NOT_ROUTABLE);
}

// 100.64.0.0/10. Not in the brief's list and the one most likely to be met in
// the wild: a client behind a mobile or ISP-level NAT is handed one of these,
// it is neither loopback nor RFC1918, and it is never the address the peer
// sees. Non-zero has never meant routable.
TEST(UtpEncryptionPolicy, CarrierGradeNatAddressIsRefused)
{
	const std::uint32_t cgnat[] = {
		Ip(100, 64, 0, 1),
		Ip(100, 127, 255, 254),
	};

	for (const std::uint32_t ip : cgnat) {
		const SNattFrameObfuscationDecision decision = DecideNattFrameObfuscation(WithPublicIp(ip));

		ASSERT_FALSE(decision.obfuscate);
		ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_PUBLIC_ADDRESS_NOT_ROUTABLE);
	}
}

// The edges of 100.64.0.0/10, which is a /10 and not a /8: 100.63.x and 100.128.x
// are public.
TEST(UtpEncryptionPolicy, AddressesJustOutsideTheCarrierGradeNatBlockStillObfuscate)
{
	const std::uint32_t outside[] = {
		Ip(100, 63, 255, 254),
		Ip(100, 128, 0, 1),
	};

	for (const std::uint32_t ip : outside) {
		const SNattFrameObfuscationDecision decision = DecideNattFrameObfuscation(WithPublicIp(ip));

		ASSERT_TRUE(decision.obfuscate);
		ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_APPLY);
	}
}

// Zero is what GetPublicIP(true) returns when nothing is known yet -- the
// ordinary state of a client that has not finished firewall detection. It is
// also the value a bare GetPublicIP() would have replaced with the local
// address, so the refusal reported here is the one the defect turned into an
// approval.
TEST(UtpEncryptionPolicy, UnknownPublicAddressIsRefusedAsUnknownNotAsUnroutable)
{
	const SNattFrameObfuscationDecision decision = DecideNattFrameObfuscation(WithPublicIp(0));

	ASSERT_FALSE(decision.obfuscate);
	ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_NO_PUBLIC_ADDRESS);
}

// 0.0.0.0/8, multicast and the reserved top of the space. None of them can be a
// unicast source address, so none of them can be the address a peer replies to.
TEST(UtpEncryptionPolicy, NonUnicastAddressIsRefused)
{
	const std::uint32_t bogus[] = {
		Ip(0, 1, 2, 3),
		Ip(224, 0, 0, 1),
		Ip(239, 255, 255, 250),
		Ip(255, 255, 255, 255),
	};

	for (const std::uint32_t ip : bogus) {
		const SNattFrameObfuscationDecision decision = DecideNattFrameObfuscation(WithPublicIp(ip));

		ASSERT_FALSE(decision.obfuscate);
		ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_PUBLIC_ADDRESS_NOT_ROUTABLE);
	}
}

// QUIC frames stay plaintext whatever else is true. Stated against a set of
// inputs that would otherwise obfuscate, so this fails if the frame type check
// is ever moved below the rest: the payload is already TLS ciphertext, and
// wrapping it would also hide the frame type byte the peer uses to decide which
// transport the datagram belongs to.
TEST(UtpEncryptionPolicy, QuicFrameIsNeverObfuscatedEvenWhenEveryOtherInputAllowsIt)
{
	SNattFrameObfuscationInputs inputs = ReadyToObfuscate();
	inputs.frameType = OP_NATT_FRAME_QUIC;

	const SNattFrameObfuscationDecision decision = DecideNattFrameObfuscation(inputs);

	ASSERT_FALSE(decision.obfuscate);
	ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_FRAME_CARRIES_ITS_OWN_ENCRYPTION);
}

// A frame type this policy has no answer for keeps the behaviour that predates
// it, which is plaintext. Nothing new is obfuscated by accident when a frame
// type is added.
TEST(UtpEncryptionPolicy, UngovernedFrameTypeStaysPlaintext)
{
	SNattFrameObfuscationInputs inputs = ReadyToObfuscate();
	inputs.frameType = 0x7F;

	const SNattFrameObfuscationDecision decision = DecideNattFrameObfuscation(inputs);

	ASSERT_FALSE(decision.obfuscate);
	ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_FRAME_TYPE_NOT_GOVERNED);
}

// The user switched the crypt layer off. Their choice governs the NAT traversal
// frames exactly as it governs eD2k UDP.
TEST(UtpEncryptionPolicy, CryptLayerDisabledLocallySendsPlaintext)
{
	SNattFrameObfuscationInputs inputs = ReadyToObfuscate();
	inputs.cryptLayerSupportedLocally = false;

	const SNattFrameObfuscationDecision decision = DecideNattFrameObfuscation(inputs);

	ASSERT_FALSE(decision.obfuscate);
	ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_CRYPT_LAYER_DISABLED_LOCALLY);
}

// libutp emits datagrams from a callback holding an address and a port and
// nothing else, so "no client is recorded for this endpoint" is an ordinary
// outcome rather than an error. The frame still goes out -- in plaintext,
// because there is no user hash to key with.
TEST(UtpEncryptionPolicy, UnidentifiedPeerSendsPlaintextRatherThanNothing)
{
	SNattFrameObfuscationInputs inputs = ReadyToObfuscate();
	inputs.peerIdentified = false;

	const SNattFrameObfuscationDecision decision = DecideNattFrameObfuscation(inputs);

	ASSERT_FALSE(decision.obfuscate);
	ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_PEER_NOT_IDENTIFIED);
}

// The peer is in the list but its hash is not known yet. Same missing key,
// reported separately so a log line can tell the two apart.
TEST(UtpEncryptionPolicy, PeerWithoutAKnownHashSendsPlaintext)
{
	SNattFrameObfuscationInputs inputs = ReadyToObfuscate();
	inputs.peerHashKnown = false;

	const SNattFrameObfuscationDecision decision = DecideNattFrameObfuscation(inputs);

	ASSERT_FALSE(decision.obfuscate);
	ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_PEER_HASH_UNKNOWN);
}

// A peer that never advertised the crypt layer would not try to deobfuscate
// what it received, so obfuscating for it is the same as dropping the frame.
TEST(UtpEncryptionPolicy, PeerWithoutCryptLayerSupportSendsPlaintext)
{
	SNattFrameObfuscationInputs inputs = ReadyToObfuscate();
	inputs.peerSupportsCryptLayer = false;

	const SNattFrameObfuscationDecision decision = DecideNattFrameObfuscation(inputs);

	ASSERT_FALSE(decision.obfuscate);
	ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_PEER_DOES_NOT_SUPPORT_CRYPT_LAYER);
}

// Both ends can and neither asked. Same disjunction
// CUpDownClient::ShouldReceiveCryptUDPPackets() applies to eD2k UDP, so a peer
// pair that sends its eD2k datagrams in the clear sends its uTP frames in the
// clear too.
TEST(UtpEncryptionPolicy, CryptLayerNeitherRequestedNorRequiredSendsPlaintext)
{
	SNattFrameObfuscationInputs inputs = ReadyToObfuscate();
	inputs.cryptLayerRequestedByEitherEnd = false;

	const SNattFrameObfuscationDecision decision = DecideNattFrameObfuscation(inputs);

	ASSERT_FALSE(decision.obfuscate);
	ASSERT_TRUE(decision.refusal == NATT_OBFUSCATE_NOT_REQUESTED_BY_EITHER_END);
}

// The predicate the gate delegates to, exercised through CNetworkAddress
// directly so a change to it is caught here as well as through the policy. The
// mapped form has to answer the same way: an address that arrived as
// ::ffff:127.0.1.1 is still loopback.
TEST(UtpEncryptionPolicy, RoutabilityPredicateAgreesForMappedAndNativeIpv4)
{
	ASSERT_FALSE(CNetworkAddress::FromString("127.0.1.1").IsGloballyRoutableIPv4());
	ASSERT_FALSE(CNetworkAddress::FromString("::ffff:127.0.1.1").IsGloballyRoutableIPv4());
	ASSERT_TRUE(CNetworkAddress::FromString("198.41.0.4").IsGloballyRoutableIPv4());
	ASSERT_TRUE(CNetworkAddress::FromString("::ffff:198.41.0.4").IsGloballyRoutableIPv4());
}

// An IPv6 address is not an IPv4 one, and the predicate must not answer for it.
// uTP is IPv4-only in this build (UtpDialPolicy.h refuses anything else), so
// this is the "wrong question" case rather than a live path -- but a predicate
// that returned true here would open the gate for an address the eD2k key
// derivation has no room for.
TEST(UtpEncryptionPolicy, RoutabilityPredicateRefusesNativeIpv6AndAbsence)
{
	ASSERT_FALSE(CNetworkAddress::FromString("2001:db8::1").IsGloballyRoutableIPv4());
	ASSERT_FALSE(CNetworkAddress::Absent().IsGloballyRoutableIPv4());
	ASSERT_FALSE(CNetworkAddress::FromIPv4NetworkOrder(0).IsGloballyRoutableIPv4());
}

// The receive half of the round trip, at the layer this change actually owns.
//
// The obfuscation here wraps the whole datagram, not the payload inside the
// envelope: CMuleUDPSocket::SendControlData() hands the assembled
// [OP_UDPRESERVEDPROT2][frame type][payload] bytes to
// CEncryptedDatagramSocket::EncryptSendClient(), and
// CClientUDPSocket::OnPacketReceived() runs every arriving datagram back
// through DecryptReceivedClient() before anything looks at the first byte. So
// by the time the frame reaches RouteInboundDatagram() it is the same three
// parts it started as, whether it travelled obfuscated or in the clear -- which
// is the property that lets the gate be opportunistic without the receiver
// having to know which form it got.
//
// That is why the assertion below is stated once and holds for both forms: the
// bytes are identical after deobfuscation. The RC4 and MD5 steps between them
// are CEncryptedDatagramSocket's existing eD2k UDP contract, unchanged by this
// work and exercised by every obfuscated eD2k datagram this client already
// sends; there is no new cipher path here to pin.
TEST(UtpEncryptionPolicy, DeobfuscatedFrameRoutesToUtpCarryingTheOriginalPayload)
{
	const std::uint8_t payload[] = { 0x41, 0x00, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF };

	std::vector<std::uint8_t> datagram(UTP_FRAME_HEADER_LENGTH + sizeof(payload));
	WriteUtpFrameHeader(datagram.data());
	std::memcpy(datagram.data() + UTP_FRAME_HEADER_LENGTH, payload, sizeof(payload));

	// The first byte is what keeps the plaintext form intact end to end:
	// DecryptReceivedClient() returns a datagram whose leading byte is
	// OP_UDPRESERVEDPROT2 untouched instead of trying to deobfuscate it. Pinned
	// because the whole opportunistic scheme rests on it.
	ASSERT_TRUE(datagram[0] == OP_UDPRESERVEDPROT2);

	std::vector<std::uint8_t> delivered;
	bool reachedEd2k = false;

	const bool routed = RouteInboundDatagram(
		datagram.data(),
		datagram.size(),
		true,
		false,
		[&delivered](const std::uint8_t *utpPayload, std::size_t utpPayloadLength) {
			delivered.assign(utpPayload, utpPayload + utpPayloadLength);
			return true;
		},
		[](const std::uint8_t *, std::size_t) { return false; },
		[&reachedEd2k](const std::uint8_t *, std::size_t) { reachedEd2k = true; });

	ASSERT_TRUE(routed);
	ASSERT_FALSE(reachedEd2k);
	ASSERT_EQUALS((unsigned)sizeof(payload), (unsigned)delivered.size());
	ASSERT_TRUE(std::memcmp(delivered.data(), payload, sizeof(payload)) == 0);
}

// A QUIC frame reaches the QUIC context as it was sent, with its frame type
// byte still readable. This is the consequence the refusal above exists for:
// obfuscating the datagram would replace that byte with a random
// non-protocol marker, and the peer's demultiplexer would have no way to tell
// which transport the payload belonged to before deciding whether to decrypt.
TEST(UtpEncryptionPolicy, QuicFrameReachesTheQuicContextWithItsFrameTypeStillReadable)
{
	const std::uint8_t payload[] = { 0xC0, 0x00, 0x00, 0x00, 0x01, 0x08 };

	std::vector<std::uint8_t> datagram(QUIC_FRAME_HEADER_LENGTH + sizeof(payload));
	WriteQuicFrameHeader(datagram.data());
	std::memcpy(datagram.data() + QUIC_FRAME_HEADER_LENGTH, payload, sizeof(payload));

	ASSERT_TRUE(datagram[0] == OP_UDPRESERVEDPROT2);
	ASSERT_TRUE(datagram[1] == OP_NATT_FRAME_QUIC);

	std::vector<std::uint8_t> delivered;

	const bool routed = RouteInboundDatagram(
		datagram.data(),
		datagram.size(),
		false,
		true,
		[](const std::uint8_t *, std::size_t) { return false; },
		[&delivered](const std::uint8_t *quicPayload, std::size_t quicPayloadLength) {
			delivered.assign(quicPayload, quicPayload + quicPayloadLength);
			return true;
		},
		[](const std::uint8_t *, std::size_t) {});

	ASSERT_TRUE(routed);
	ASSERT_EQUALS((unsigned)sizeof(payload), (unsigned)delivered.size());
	ASSERT_TRUE(std::memcmp(delivered.data(), payload, sizeof(payload)) == 0);
}

// The bytes libutp is told to leave room for. Obfuscation grows every datagram
// by CRYPT_HEADER_WITHOUTPADDING, which is a #define private to
// EncryptedDatagramSocket.cpp and so has to be restated as a constant here --
// and a restated constant is one somebody can change on one side only. libutp
// is asked for its datagram size once per context, long before any peer is
// known, so the reservation cannot be conditional on whether a particular frame
// ends up obfuscated: it is subtracted from the MTU always
// (UtpLibraryAdapter.cpp, OnGetUdpMtu). Understating it would put every
// obfuscated datagram over the path MTU, and libutp would read the loss as
// congestion and throttle -- a symptom that points at the network, not here.
TEST(UtpEncryptionPolicy, ObfuscationHeaderReservationMatchesTheCipherHeaderSize)
{
	ASSERT_EQUALS(8u, (unsigned)UDP_OBFUSCATION_HEADER_LENGTH);
	ASSERT_EQUALS(2u, (unsigned)UTP_FRAME_HEADER_LENGTH);
}
