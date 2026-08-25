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

// The rendezvous and hole-punch wire format, byte for byte.
//
// Every value this suite asserts is a literal, because a description of a byte
// is not a byte. These three opcodes and two option bits come from eMuleAI's
// srchybrid/Opcodes.h and there is no negotiation about them: an opcode off by
// one is a frame the peer classifies as unknown and drops, and a drop on the
// far side of a NAT is indistinguishable from the NAT not opening. The whole
// change would read as "traversal does not work here" with nothing logged
// anywhere.
//
// The bounds are pinned in the same way and for a different reason. They are
// safety limits, not performance settings: the exchange asks a third party to
// send packets toward an address, so the attempt count and the total budget are
// what stop the mechanism being an amplifier. A test that accepted "about five"
// would let a later change raise them without anyone deciding to.
//
// The parsers are asserted on truncation at every field boundary rather than
// only on a whole valid frame. A parser that reads one byte past a short
// datagram produces a hole-punch target read out of adjacent heap, and the only
// symptom is punching at an address nobody chose.

#include <muleunit/test.h>

#include <NatRendezvousProtocol.h>
#include <NetworkAddress.h>

using namespace muleunit;

DECLARE_SIMPLE(NatRendezvousProtocol)

namespace
{

//! A recognisable 16-byte peer hash: 00 01 02 ... 0F.
void FillHash(uint8_t *out)
{
	for (uint8_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		out[i] = i;
	}
}

bool HashIsTheOne(const uint8_t *hash)
{
	for (uint8_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		if (hash[i] != i) {
			return false;
		}
	}
	return true;
}

} // namespace

// The five values the proposal pins. Literals on both sides: reading the
// constant back through its own name would assert nothing.
TEST(NatRendezvousProtocol, OpcodesAndOptionBitsAreTheirPinnedValues)
{
	ASSERT_EQUALS(0xA0, static_cast<int>(OP_RENDEZVOUS));
	ASSERT_EQUALS(0xA1, static_cast<int>(OP_HOLEPUNCH));
	ASSERT_EQUALS(0xAA, static_cast<int>(OP_NATT_ENDPOINT_HINT));
	ASSERT_EQUALS(0x20, static_cast<int>(CONNECT_OPT_NATT_ENDPOINT_HINT));
	ASSERT_EQUALS(0x80, static_cast<int>(CONNECT_OPT_NAT_TRAVERSAL_UTP));
}

// The safety limits. See the file comment: these are not tunable.
TEST(NatRendezvousProtocol, BoundsAreTheirPinnedValues)
{
	ASSERT_EQUALS(5u, kRendezvousMaxAttempts);
	ASSERT_EQUALS(120000u, kRendezvousTotalBudgetMs);
	ASSERT_EQUALS(60000u, kRendezvousBackoffMs);
	ASSERT_EQUALS(1500u, kNattFrameTypeFallbackWaitMs);
}

// The frame type this exchange rides on is the legacy uTP one, 0x00, which is
// the type the shipped transport already shares the ed2k UDP port with.
TEST(NatRendezvousProtocol, ControlMessagesRideTheLegacyUtpFrameType)
{
	ASSERT_EQUALS(0x00, static_cast<int>(OP_NATT_FRAME_UTP));
}

// An IPv4 endpoint hint, laid out byte by byte: opcode, family, four address
// octets most significant first, then the port big-endian.
TEST(NatRendezvousProtocol, IPv4EndpointHintEncodesExactBytes)
{
	uint8_t buffer[NATT_ENDPOINT_HINT_MAX_LENGTH] = { 0 };
	const size_t written =
		EncodeEndpointHint(CNetworkAddress::FromString("192.0.2.10"), 4662, buffer, sizeof(buffer));

	ASSERT_EQUALS(8u, written);
	ASSERT_EQUALS(0xAA, static_cast<int>(buffer[0]));
	ASSERT_EQUALS(0x04, static_cast<int>(buffer[1]));
	ASSERT_EQUALS(192, static_cast<int>(buffer[2]));
	ASSERT_EQUALS(0, static_cast<int>(buffer[3]));
	ASSERT_EQUALS(2, static_cast<int>(buffer[4]));
	ASSERT_EQUALS(10, static_cast<int>(buffer[5]));
	// 4662 == 0x1236.
	ASSERT_EQUALS(0x12, static_cast<int>(buffer[6]));
	ASSERT_EQUALS(0x36, static_cast<int>(buffer[7]));
}

// The IPv6 form: the same shape with family 0x06 and sixteen address bytes.
TEST(NatRendezvousProtocol, IPv6EndpointHintEncodesExactBytes)
{
	uint8_t buffer[NATT_ENDPOINT_HINT_MAX_LENGTH] = { 0 };
	const size_t written =
		EncodeEndpointHint(CNetworkAddress::FromString("2001:db8::1"), 4662, buffer, sizeof(buffer));

	ASSERT_EQUALS(20u, written);
	ASSERT_EQUALS(0xAA, static_cast<int>(buffer[0]));
	ASSERT_EQUALS(0x06, static_cast<int>(buffer[1]));
	ASSERT_EQUALS(0x20, static_cast<int>(buffer[2]));
	ASSERT_EQUALS(0x01, static_cast<int>(buffer[3]));
	ASSERT_EQUALS(0x0d, static_cast<int>(buffer[4]));
	ASSERT_EQUALS(0xb8, static_cast<int>(buffer[5]));
	for (int i = 6; i < 17; ++i) {
		ASSERT_EQUALS(0x00, static_cast<int>(buffer[i]));
	}
	ASSERT_EQUALS(0x01, static_cast<int>(buffer[17]));
	ASSERT_EQUALS(0x12, static_cast<int>(buffer[18]));
	ASSERT_EQUALS(0x36, static_cast<int>(buffer[19]));
}

// Absence is not an address, so it does not encode. Returning zero rather than
// eight zero bytes is the point: a hint of 0.0.0.0:0 would be forwarded and
// punched at.
TEST(NatRendezvousProtocol, AbsentEndpointEncodesNothing)
{
	uint8_t buffer[NATT_ENDPOINT_HINT_MAX_LENGTH] = { 0xFF };
	ASSERT_EQUALS(0u, EncodeEndpointHint(CNetworkAddress::Absent(), 4662, buffer, sizeof(buffer)));
	ASSERT_EQUALS(0xFF, static_cast<int>(buffer[0]));
}

// A port of zero is not an endpoint either -- nothing listens there, and a hint
// naming it costs a punch attempt to find that out.
TEST(NatRendezvousProtocol, ZeroPortEncodesNothing)
{
	uint8_t buffer[NATT_ENDPOINT_HINT_MAX_LENGTH] = { 0xFF };
	ASSERT_EQUALS(
		0u, EncodeEndpointHint(CNetworkAddress::FromString("192.0.2.10"), 0, buffer, sizeof(buffer)));
	ASSERT_EQUALS(0xFF, static_cast<int>(buffer[0]));
}

TEST(NatRendezvousProtocol, EndpointHintRoundTrips)
{
	uint8_t buffer[NATT_ENDPOINT_HINT_MAX_LENGTH] = { 0 };
	const size_t written =
		EncodeEndpointHint(CNetworkAddress::FromString("198.51.100.7"), 1234, buffer, sizeof(buffer));

	SNattEndpointHint hint;
	ASSERT_TRUE(ParseEndpointHint(buffer, written, hint));
	ASSERT_EQUALS(8u, hint.consumed);
	ASSERT_EQUALS(1234, static_cast<int>(hint.port));
	ASSERT_TRUE(hint.address == CNetworkAddress::FromString("198.51.100.7"));
}

// Truncation at every field boundary. Each of these is one byte short of a
// legal hint, and each must fail rather than read the byte that is not there.
TEST(NatRendezvousProtocol, TruncatedEndpointHintIsRejectedAtEveryBoundary)
{
	uint8_t buffer[NATT_ENDPOINT_HINT_MAX_LENGTH] = { 0 };
	const size_t written =
		EncodeEndpointHint(CNetworkAddress::FromString("192.0.2.10"), 4662, buffer, sizeof(buffer));

	for (size_t length = 0; length < written; ++length) {
		SNattEndpointHint hint;
		ASSERT_FALSE(ParseEndpointHint(buffer, length, hint));
	}

	SNattEndpointHint hint;
	ASSERT_FALSE(ParseEndpointHint(NULL, written, hint));
}

// A family byte that is neither 0x04 nor 0x06 is a malformed hint, not a hint
// of unknown length: guessing a length here is how a parser walks off the end
// of a datagram.
TEST(NatRendezvousProtocol, UnknownAddressFamilyByteIsRejected)
{
	uint8_t buffer[NATT_ENDPOINT_HINT_MAX_LENGTH] = { 0 };
	const size_t written =
		EncodeEndpointHint(CNetworkAddress::FromString("192.0.2.10"), 4662, buffer, sizeof(buffer));
	buffer[1] = 0x05;

	SNattEndpointHint hint;
	ASSERT_FALSE(ParseEndpointHint(buffer, written, hint));
}

// The wrong opcode in the first byte is not an endpoint hint, however well the
// rest of the bytes fit.
TEST(NatRendezvousProtocol, EndpointHintWithForeignOpcodeIsRejected)
{
	uint8_t buffer[NATT_ENDPOINT_HINT_MAX_LENGTH] = { 0 };
	const size_t written =
		EncodeEndpointHint(CNetworkAddress::FromString("192.0.2.10"), 4662, buffer, sizeof(buffer));
	buffer[0] = OP_HOLEPUNCH;

	SNattEndpointHint hint;
	ASSERT_FALSE(ParseEndpointHint(buffer, written, hint));
}

// A rendezvous request carrying a hint: opcode, options with both bits set, the
// sixteen-byte hash of the other side of the pair, then the hint element.
TEST(NatRendezvousProtocol, RendezvousRequestWithHintEncodesExactBytes)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written = EncodeRendezvousRequest(
		hash, CNetworkAddress::FromString("192.0.2.10"), 4662, buffer, sizeof(buffer));

	ASSERT_EQUALS(26u, written);
	ASSERT_EQUALS(0xA0, static_cast<int>(buffer[0]));
	// Both bits: a hint follows, and the traversal this asks for is uTP.
	ASSERT_EQUALS(0xA0, static_cast<int>(buffer[1]));
	for (int i = 0; i < 16; ++i) {
		ASSERT_EQUALS(i, static_cast<int>(buffer[2 + i]));
	}
	ASSERT_EQUALS(0xAA, static_cast<int>(buffer[18]));
	ASSERT_EQUALS(0x04, static_cast<int>(buffer[19]));
	ASSERT_EQUALS(192, static_cast<int>(buffer[20]));
	ASSERT_EQUALS(0x36, static_cast<int>(buffer[25]));
}

// Without an endpoint to name, the hint bit is clear and no hint element is
// written. A set bit with no element behind it is what makes a parser read
// past the end of a frame.
TEST(NatRendezvousProtocol, RendezvousRequestWithoutHintClearsTheHintBit)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written =
		EncodeRendezvousRequest(hash, CNetworkAddress::Absent(), 4662, buffer, sizeof(buffer));

	ASSERT_EQUALS(18u, written);
	ASSERT_EQUALS(0xA0, static_cast<int>(buffer[0]));
	ASSERT_EQUALS(0x80, static_cast<int>(buffer[1]));
}

TEST(NatRendezvousProtocol, RendezvousRequestRoundTrips)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written = EncodeRendezvousRequest(
		hash, CNetworkAddress::FromString("192.0.2.10"), 4662, buffer, sizeof(buffer));

	SNattRendezvousRequest request;
	ASSERT_TRUE(ParseRendezvousRequest(buffer, written, request));
	ASSERT_TRUE(HashIsTheOne(request.peerHash));
	ASSERT_TRUE(request.requestsUtpTraversal);
	ASSERT_TRUE(request.hasEndpointHint);
	ASSERT_EQUALS(4662, static_cast<int>(request.hintPort));
	ASSERT_TRUE(request.hintAddress == CNetworkAddress::FromString("192.0.2.10"));
}

// The bit says a hint follows and nothing follows. Rejected as malformed: the
// alternative is a parse that succeeds with a hint read from whatever is after
// the datagram.
TEST(NatRendezvousProtocol, RendezvousRequestClaimingAHintItDoesNotCarryIsRejected)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written =
		EncodeRendezvousRequest(hash, CNetworkAddress::Absent(), 4662, buffer, sizeof(buffer));
	buffer[1] |= CONNECT_OPT_NATT_ENDPOINT_HINT;

	SNattRendezvousRequest request;
	ASSERT_FALSE(ParseRendezvousRequest(buffer, written, request));
}

// A request with no hint bit parses, and reports no hint. This is the legal
// shape for a requester that does not know its external endpoint.
TEST(NatRendezvousProtocol, RendezvousRequestWithoutHintParsesWithNoHint)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written =
		EncodeRendezvousRequest(hash, CNetworkAddress::Absent(), 4662, buffer, sizeof(buffer));

	SNattRendezvousRequest request;
	ASSERT_TRUE(ParseRendezvousRequest(buffer, written, request));
	ASSERT_FALSE(request.hasEndpointHint);
	ASSERT_TRUE(request.hintAddress.IsAbsent());
	ASSERT_EQUALS(0, static_cast<int>(request.hintPort));
}

TEST(NatRendezvousProtocol, TruncatedRendezvousRequestIsRejectedAtEveryBoundary)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written = EncodeRendezvousRequest(
		hash, CNetworkAddress::FromString("192.0.2.10"), 4662, buffer, sizeof(buffer));

	for (size_t length = 0; length < written; ++length) {
		SNattRendezvousRequest request;
		ASSERT_FALSE(ParseRendezvousRequest(buffer, length, request));
	}
}

TEST(NatRendezvousProtocol, RendezvousRequestWithForeignOpcodeIsRejected)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written =
		EncodeRendezvousRequest(hash, CNetworkAddress::Absent(), 4662, buffer, sizeof(buffer));
	buffer[0] = OP_HOLEPUNCH;

	SNattRendezvousRequest request;
	ASSERT_FALSE(ParseRendezvousRequest(buffer, written, request));
}

// A hole punch is eighteen bytes: opcode, options, and the sender's own hash so
// the receiver can pair the packet with the rendezvous it agreed to.
TEST(NatRendezvousProtocol, HolePunchEncodesExactBytes)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_HOLEPUNCH_LENGTH] = { 0 };
	const size_t written = EncodeHolePunch(hash, buffer, sizeof(buffer));

	ASSERT_EQUALS(18u, written);
	ASSERT_EQUALS(0xA1, static_cast<int>(buffer[0]));
	ASSERT_EQUALS(0x80, static_cast<int>(buffer[1]));
	for (int i = 0; i < 16; ++i) {
		ASSERT_EQUALS(i, static_cast<int>(buffer[2 + i]));
	}
}

TEST(NatRendezvousProtocol, HolePunchRoundTrips)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_HOLEPUNCH_LENGTH] = { 0 };
	const size_t written = EncodeHolePunch(hash, buffer, sizeof(buffer));

	SNattHolePunch punch;
	ASSERT_TRUE(ParseHolePunch(buffer, written, punch));
	ASSERT_TRUE(HashIsTheOne(punch.senderHash));
	ASSERT_TRUE(punch.requestsUtpTraversal);
}

TEST(NatRendezvousProtocol, TruncatedHolePunchIsRejectedAtEveryBoundary)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_HOLEPUNCH_LENGTH] = { 0 };
	const size_t written = EncodeHolePunch(hash, buffer, sizeof(buffer));

	for (size_t length = 0; length < written; ++length) {
		SNattHolePunch punch;
		ASSERT_FALSE(ParseHolePunch(buffer, length, punch));
	}
}

// The demultiplexer the receive path uses before it knows which message it has.
// An opcode this protocol does not define is dropped rather than guessed at.
TEST(NatRendezvousProtocol, ControlMessageClassificationSeparatesTheThreeOpcodes)
{
	const uint8_t rendezvous[1] = { OP_RENDEZVOUS };
	const uint8_t holepunch[1] = { OP_HOLEPUNCH };
	const uint8_t hint[1] = { OP_NATT_ENDPOINT_HINT };
	const uint8_t foreign[1] = { 0x42 };

	ASSERT_EQUALS((int)NATT_CONTROL_RENDEZVOUS, (int)ClassifyNattControlMessage(rendezvous, 1));
	ASSERT_EQUALS((int)NATT_CONTROL_HOLEPUNCH, (int)ClassifyNattControlMessage(holepunch, 1));
	ASSERT_EQUALS((int)NATT_CONTROL_ENDPOINT_HINT, (int)ClassifyNattControlMessage(hint, 1));
	ASSERT_EQUALS((int)NATT_CONTROL_NOT_A_CONTROL_MESSAGE, (int)ClassifyNattControlMessage(foreign, 1));
	ASSERT_EQUALS(
		(int)NATT_CONTROL_NOT_A_CONTROL_MESSAGE, (int)ClassifyNattControlMessage(rendezvous, 0));
	ASSERT_EQUALS((int)NATT_CONTROL_NOT_A_CONTROL_MESSAGE, (int)ClassifyNattControlMessage(NULL, 1));
}

// A short output buffer is a caller bug, and the answer is to write nothing.
// Writing what fits would put a half-built frame on the wire.
TEST(NatRendezvousProtocol, EncodersRefuseAnOutputBufferThatIsTooSmall)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t small[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
	ASSERT_EQUALS(0u,
		EncodeEndpointHint(CNetworkAddress::FromString("192.0.2.10"), 4662, small, sizeof(small)));
	ASSERT_EQUALS(0u,
		EncodeRendezvousRequest(
			hash, CNetworkAddress::FromString("192.0.2.10"), 4662, small, sizeof(small)));
	ASSERT_EQUALS(0u, EncodeHolePunch(hash, small, sizeof(small)));
	ASSERT_EQUALS(0xFF, static_cast<int>(small[0]));
}

// The bit that separates the two directions of the exchange.
//
// A relay request (A to R) and a relayed rendezvous (R to B) are the same
// opcode carrying the same fields, and they must not be confused: a client that
// read a relay request as a relayed rendezvous would start punching toward the
// address in the datagram, which is the reflection the relay validation exists
// to prevent. So the direction is explicit rather than inferred from local
// state, and the ABSENCE of the bit is what the relay path requires.
//
// 0x40 is not a value the proposal pins, and eMuleAI's use of that bit is
// unknown to this tree. It travels only inside a message that only exists
// between peers that advertised MOD_MISCOPT_NAT_TRAVERSAL, so it widens nothing
// that an unaware client parses -- but it is the one value here that interop
// against eMuleAI could contradict.
TEST(NatRendezvousProtocol, RelayedBitIsItsPinnedValue)
{
	ASSERT_EQUALS(0x40, static_cast<int>(CONNECT_OPT_NATT_RELAYED));
}

TEST(NatRendezvousProtocol, RelayedRendezvousSetsTheRelayedBitAndAnOrdinaryRequestDoesNot)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t relayed[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t relayedLength = EncodeRelayedRendezvous(
		hash, CNetworkAddress::FromString("192.0.2.10"), 4662, relayed, sizeof(relayed));
	ASSERT_EQUALS(26u, relayedLength);
	// 0x80 traversal, 0x40 relayed, 0x20 a hint follows.
	ASSERT_EQUALS(0xE0, static_cast<int>(relayed[1]));

	SNattRendezvousRequest parsedRelayed;
	ASSERT_TRUE(ParseRendezvousRequest(relayed, relayedLength, parsedRelayed));
	ASSERT_TRUE(parsedRelayed.isRelayed);

	uint8_t request[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t requestLength = EncodeRendezvousRequest(
		hash, CNetworkAddress::FromString("192.0.2.10"), 4662, request, sizeof(request));
	ASSERT_EQUALS(0xA0, static_cast<int>(request[1]));

	SNattRendezvousRequest parsedRequest;
	ASSERT_TRUE(ParseRendezvousRequest(request, requestLength, parsedRequest));
	ASSERT_FALSE(parsedRequest.isRelayed);
}

// A relayed rendezvous with no endpoint in it is useless -- there is nothing to
// punch toward -- so it is not encoded at all rather than encoded empty.
TEST(NatRendezvousProtocol, RelayedRendezvousWithoutAnEndpointIsNotEncoded)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0xFF };
	ASSERT_EQUALS(
		0u, EncodeRelayedRendezvous(hash, CNetworkAddress::Absent(), 4662, buffer, sizeof(buffer)));
	ASSERT_EQUALS(0xFF, static_cast<int>(buffer[0]));
}
