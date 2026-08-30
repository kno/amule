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
// is not a byte. These three opcodes and three option bits come from eMuleAI's
// srchybrid/Opcodes.h and there is no negotiation about them: an opcode off by
// one is a frame the peer classifies as unknown and drops, and a drop on the
// far side of a NAT is indistinguishable from the NAT not opening. The whole
// change would read as "traversal does not work here" with nothing logged
// anywhere.
//
// The BODY layouts are pinned the same way and matter more than the opcodes,
// because the body has no length fields in it. eMuleAI detects each optional
// block by how many bytes are left, so a body one byte off does not fail to
// parse -- it parses into different fields. A file hash misread as an endpoint
// is a punch aimed at an address nobody chose, and nothing on either side logs
// a reason. So the offsets here are literals too.
//
// The bounds are pinned for a different reason. They are safety limits, not
// performance settings: the exchange asks a third party to send packets toward
// an address, so the attempt count and the total budget are what stop the
// mechanism being an amplifier. A test that accepted "about five" would let a
// later change raise them without anyone deciding to.
//
// The parsers are asserted on truncation at every field boundary rather than
// only on a whole valid body. A parser that reads one byte past a short
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

//! A file hash that cannot be confused with the peer hash above: F0 F1 ... FF.
void FillFileHash(uint8_t *out)
{
	for (uint8_t i = 0; i < NATT_FILE_HASH_LENGTH; ++i) {
		out[i] = static_cast<uint8_t>(0xF0 + i);
	}
}

bool FileHashIsTheOne(const uint8_t *hash)
{
	for (uint8_t i = 0; i < NATT_FILE_HASH_LENGTH; ++i) {
		if (hash[i] != static_cast<uint8_t>(0xF0 + i)) {
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

// The envelope. Control messages ride the eMule protocol byte with their opcode
// as the datagram's second byte, which is where eMuleAI v1.6 puts them -- not
// the 0xB2 reserved-protocol framing this tree used before, which no other
// client speaks. 0xB2 still carries uTP and QUIC transport data; it no longer
// carries any control message.
TEST(NatRendezvousProtocol, ControlMessagesRideTheEmuleProtocolByte)
{
	ASSERT_EQUALS(0xC5, static_cast<int>(NATT_CONTROL_PROTOCOL));
	ASSERT_EQUALS(0xC5, static_cast<int>(OP_EMULEPROT));
}

// The body lengths, which are what the remaining-length rule is arithmetic on.
// A fixed part of seventeen bytes, and three optional blocks after it.
TEST(NatRendezvousProtocol, BodyLengthsAreTheirPinnedValues)
{
	ASSERT_EQUALS(16u, NATT_PEER_HASH_LENGTH);
	ASSERT_EQUALS(16u, NATT_FILE_HASH_LENGTH);
	ASSERT_EQUALS(6u, NATT_ENDPOINT_TAIL_LENGTH);
	ASSERT_EQUALS(17u, NATT_RENDEZVOUS_FIXED_LENGTH);
	ASSERT_EQUALS(40u, NATT_RENDEZVOUS_MAX_LENGTH);
	ASSERT_EQUALS(17u, NATT_HOLEPUNCH_LENGTH);
}

// A rendezvous body with everything in it, laid out byte by byte: the peer
// hash, the options byte, the file hash, then the endpoint as four address
// octets most significant first and a big-endian port. No opcode byte -- the
// opcode is the datagram's second byte, outside the body -- and no family byte,
// because the endpoint slot in this format is IPv4 and only IPv4.
TEST(NatRendezvousProtocol, RendezvousRequestEncodesExactBytes)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);
	uint8_t fileHash[NATT_FILE_HASH_LENGTH];
	FillFileHash(fileHash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written = EncodeRendezvousRequest(
		hash, fileHash, CNetworkAddress::FromString("192.0.2.10"), 4662, buffer, sizeof(buffer));

	ASSERT_EQUALS(39u, written);
	for (int i = 0; i < 16; ++i) {
		ASSERT_EQUALS(i, static_cast<int>(buffer[i]));
	}
	// 0x80 the traversal is uTP, 0x20 an endpoint follows. Not relayed.
	ASSERT_EQUALS(0xA0, static_cast<int>(buffer[16]));
	for (int i = 0; i < 16; ++i) {
		ASSERT_EQUALS(0xF0 + i, static_cast<int>(buffer[17 + i]));
	}
	ASSERT_EQUALS(192, static_cast<int>(buffer[33]));
	ASSERT_EQUALS(0, static_cast<int>(buffer[34]));
	ASSERT_EQUALS(2, static_cast<int>(buffer[35]));
	ASSERT_EQUALS(10, static_cast<int>(buffer[36]));
	// 4662 == 0x1236.
	ASSERT_EQUALS(0x12, static_cast<int>(buffer[37]));
	ASSERT_EQUALS(0x36, static_cast<int>(buffer[38]));
}

// Without a file hash the endpoint moves up to offset 17, and that is a legal
// body rather than a trap. The greedy file-hash test is `remaining >= 16` and
// an endpoint tail is six bytes, so a body with no file hash can never be
// misread as one carrying it -- the arithmetic does not reach.
TEST(NatRendezvousProtocol, RendezvousWithoutAFileHashPutsTheEndpointAtSeventeen)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written = EncodeRendezvousRequest(
		hash, NULL, CNetworkAddress::FromString("192.0.2.10"), 4662, buffer, sizeof(buffer));

	ASSERT_EQUALS(23u, written);
	ASSERT_EQUALS(0xA0, static_cast<int>(buffer[16]));
	ASSERT_EQUALS(192, static_cast<int>(buffer[17]));
	ASSERT_EQUALS(0x36, static_cast<int>(buffer[22]));

	// And it reads back as an endpoint, not as sixteen bytes of file hash.
	SNattRendezvousRequest request;
	ASSERT_TRUE(ParseRendezvousRequest(buffer, written, request));
	ASSERT_FALSE(request.hasFileHash);
	ASSERT_TRUE(request.hasEndpointHint);
	ASSERT_EQUALS(4662, static_cast<int>(request.hintPort));
	ASSERT_TRUE(request.hintAddress == CNetworkAddress::FromString("192.0.2.10"));
}

// A file hash and no endpoint: seventeen plus sixteen, and the greedy test
// takes those sixteen bytes as the file hash, which is what they are.
TEST(NatRendezvousProtocol, RendezvousWithAFileHashAndNoEndpointRoundTrips)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);
	uint8_t fileHash[NATT_FILE_HASH_LENGTH];
	FillFileHash(fileHash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written = EncodeRendezvousRequest(
		hash, fileHash, CNetworkAddress::Absent(), 4662, buffer, sizeof(buffer));

	ASSERT_EQUALS(33u, written);
	// The endpoint bit is clear because no endpoint was encoded.
	ASSERT_EQUALS(0x80, static_cast<int>(buffer[16]));

	SNattRendezvousRequest request;
	ASSERT_TRUE(ParseRendezvousRequest(buffer, written, request));
	ASSERT_TRUE(request.hasFileHash);
	ASSERT_TRUE(FileHashIsTheOne(request.fileHash));
	ASSERT_FALSE(request.hasEndpointHint);
	ASSERT_TRUE(request.hintAddress.IsAbsent());
	ASSERT_EQUALS(0, static_cast<int>(request.hintPort));
}

TEST(NatRendezvousProtocol, RendezvousRequestRoundTrips)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);
	uint8_t fileHash[NATT_FILE_HASH_LENGTH];
	FillFileHash(fileHash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written = EncodeRendezvousRequest(
		hash, fileHash, CNetworkAddress::FromString("192.0.2.10"), 4662, buffer, sizeof(buffer));

	SNattRendezvousRequest request;
	ASSERT_TRUE(ParseRendezvousRequest(buffer, written, request));
	ASSERT_TRUE(HashIsTheOne(request.peerHash));
	ASSERT_TRUE(FileHashIsTheOne(request.fileHash));
	ASSERT_TRUE(request.hasFileHash);
	ASSERT_TRUE(request.requestsUtpTraversal);
	ASSERT_FALSE(request.isRelayed);
	ASSERT_TRUE(request.hasEndpointHint);
	ASSERT_EQUALS(4662, static_cast<int>(request.hintPort));
	ASSERT_TRUE(request.hintAddress == CNetworkAddress::FromString("192.0.2.10"));
	ASSERT_FALSE(request.hasTransportHint);
}

// The bare fixed part, with nothing optional after it. Legal, and the shape a
// requester that knows neither its endpoint nor a file sends.
TEST(NatRendezvousProtocol, RendezvousWithNothingOptionalParses)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written =
		EncodeRendezvousRequest(hash, NULL, CNetworkAddress::Absent(), 4662, buffer, sizeof(buffer));

	ASSERT_EQUALS(17u, written);
	ASSERT_EQUALS(0x80, static_cast<int>(buffer[16]));

	SNattRendezvousRequest request;
	ASSERT_TRUE(ParseRendezvousRequest(buffer, written, request));
	ASSERT_FALSE(request.hasFileHash);
	ASSERT_FALSE(request.hasEndpointHint);
	ASSERT_FALSE(request.hasTransportHint);
}

// The block detection is by remaining length and NOT by the options byte. This
// is the whole difference from the format this tree used before, so it is
// asserted from both sides: a body carrying an endpoint is read as carrying one
// even with the 0x20 bit cleared, and a body carrying none is read as carrying
// none even with the bit set.
//
// This is what replaces the old "the bit is set and no element follows, so
// reject the whole message" rule. That rule cannot survive here, because under
// a remaining-length format the bit asserts nothing a parser could contradict.
// What the rule protected -- never punching at an endpoint that was not really
// there -- is now protected by the length arithmetic itself and by the value
// check two tests below.
TEST(NatRendezvousProtocol, OptionalBlocksAreDetectedByLengthAndNotByTheOptionsBit)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t withEndpoint[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t withLength = EncodeRendezvousRequest(hash,
		NULL,
		CNetworkAddress::FromString("192.0.2.10"),
		4662,
		withEndpoint,
		sizeof(withEndpoint));
	withEndpoint[16] &= static_cast<uint8_t>(~CONNECT_OPT_NATT_ENDPOINT_HINT);

	SNattRendezvousRequest stillHasIt;
	ASSERT_TRUE(ParseRendezvousRequest(withEndpoint, withLength, stillHasIt));
	ASSERT_TRUE(stillHasIt.hasEndpointHint);
	ASSERT_EQUALS(4662, static_cast<int>(stillHasIt.hintPort));

	uint8_t withoutEndpoint[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t withoutLength = EncodeRendezvousRequest(
		hash, NULL, CNetworkAddress::Absent(), 4662, withoutEndpoint, sizeof(withoutEndpoint));
	withoutEndpoint[16] |= CONNECT_OPT_NATT_ENDPOINT_HINT;

	SNattRendezvousRequest stillHasNone;
	ASSERT_TRUE(ParseRendezvousRequest(withoutEndpoint, withoutLength, stillHasNone));
	ASSERT_FALSE(stillHasNone.hasEndpointHint);
	ASSERT_TRUE(stillHasNone.hintAddress.IsAbsent());
}

// The bit is still emitted, though nothing here reads it. eMuleAI's own use of
// 0x20 is unknown to this tree, so a client that does consult it sees the truth
// rather than a cleared bit next to an endpoint that is present.
TEST(NatRendezvousProtocol, TheEndpointBitStillStatesWhatWasActuallyEncoded)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t withEndpoint[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	EncodeRendezvousRequest(hash,
		NULL,
		CNetworkAddress::FromString("192.0.2.10"),
		4662,
		withEndpoint,
		sizeof(withEndpoint));
	ASSERT_EQUALS(0x20, static_cast<int>(withEndpoint[16] & 0x20));

	uint8_t withoutEndpoint[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	EncodeRendezvousRequest(
		hash, NULL, CNetworkAddress::Absent(), 4662, withoutEndpoint, sizeof(withoutEndpoint));
	ASSERT_EQUALS(0x00, static_cast<int>(withoutEndpoint[16] & 0x20));
}

// An endpoint slot that is present but names nothing -- a zero port, or
// 0.0.0.0 -- is a malformed message and not an endpoint-free one. This is the
// value check the old hint-bit validation used to carry: the endpoint in this
// message becomes a destination this client sends packets toward, so accepting
// it as "no endpoint" would silently convert a hostile body into a valid one.
TEST(NatRendezvousProtocol, AnEndpointSlotNamingNothingIsRejected)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written = EncodeRendezvousRequest(
		hash, NULL, CNetworkAddress::FromString("192.0.2.10"), 4662, buffer, sizeof(buffer));

	uint8_t zeroPort[NATT_RENDEZVOUS_MAX_LENGTH];
	for (size_t i = 0; i < written; ++i) {
		zeroPort[i] = buffer[i];
	}
	zeroPort[21] = 0;
	zeroPort[22] = 0;
	SNattRendezvousRequest parsedZeroPort;
	ASSERT_FALSE(ParseRendezvousRequest(zeroPort, written, parsedZeroPort));

	uint8_t zeroAddress[NATT_RENDEZVOUS_MAX_LENGTH];
	for (size_t i = 0; i < written; ++i) {
		zeroAddress[i] = buffer[i];
	}
	for (size_t i = 17; i < 21; ++i) {
		zeroAddress[i] = 0;
	}
	SNattRendezvousRequest parsedZeroAddress;
	ASSERT_FALSE(ParseRendezvousRequest(zeroAddress, written, parsedZeroAddress));
}

// A trailing transport-hint byte is recorded and does not disturb the endpoint
// in front of it. Recorded rather than acted on: eMuleAI's values for this byte
// are not known here, and a byte whose meaning is a guess must not select a
// transport.
TEST(NatRendezvousProtocol, ATrailingTransportHintIsReadWithoutDisturbingTheEndpoint)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);
	uint8_t fileHash[NATT_FILE_HASH_LENGTH];
	FillFileHash(fileHash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written = EncodeRendezvousRequest(
		hash, fileHash, CNetworkAddress::FromString("192.0.2.10"), 4662, buffer, sizeof(buffer));
	buffer[written] = 0x07;

	SNattRendezvousRequest request;
	ASSERT_TRUE(ParseRendezvousRequest(buffer, written + 1, request));
	ASSERT_TRUE(request.hasFileHash);
	ASSERT_TRUE(request.hasEndpointHint);
	ASSERT_EQUALS(4662, static_cast<int>(request.hintPort));
	ASSERT_TRUE(request.hasTransportHint);
	ASSERT_EQUALS(0x07, static_cast<int>(request.transportHint));
}

// Bytes past everything this build understands are ignored rather than
// rejected, so a later eMuleAI revision that appends a field is still parseable
// here. eMuleAI's own parser reads what it recognises and stops, and a stricter
// reader on this side would drop messages that client considers valid.
TEST(NatRendezvousProtocol, SurplusBytesAfterTheKnownBlocksAreIgnored)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);
	uint8_t fileHash[NATT_FILE_HASH_LENGTH];
	FillFileHash(fileHash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH + 8] = { 0 };
	const size_t written = EncodeRendezvousRequest(
		hash, fileHash, CNetworkAddress::FromString("192.0.2.10"), 4662, buffer, sizeof(buffer));
	for (size_t i = 0; i < 8; ++i) {
		buffer[written + i] = 0xEE;
	}

	SNattRendezvousRequest request;
	ASSERT_TRUE(ParseRendezvousRequest(buffer, written + 8, request));
	ASSERT_TRUE(request.hasEndpointHint);
	ASSERT_EQUALS(4662, static_cast<int>(request.hintPort));
	ASSERT_TRUE(request.hasTransportHint);
	ASSERT_EQUALS(0xEE, static_cast<int>(request.transportHint));
}

// Truncation at every boundary inside the fixed part. Each of these is short of
// a legal body and must fail rather than read the byte that is not there.
//
// Only the fixed part: past it, a shorter body is a body with fewer optional
// blocks, which is exactly what the remaining-length rule means. That is
// asserted separately below, because "short" and "malformed" stop being the
// same thing at offset seventeen.
TEST(NatRendezvousProtocol, TruncatedRendezvousFixedPartIsRejectedAtEveryBoundary)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);
	uint8_t fileHash[NATT_FILE_HASH_LENGTH];
	FillFileHash(fileHash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	EncodeRendezvousRequest(
		hash, fileHash, CNetworkAddress::FromString("192.0.2.10"), 4662, buffer, sizeof(buffer));

	for (size_t length = 0; length < NATT_RENDEZVOUS_FIXED_LENGTH; ++length) {
		SNattRendezvousRequest request;
		ASSERT_FALSE(ParseRendezvousRequest(buffer, length, request));
	}

	SNattRendezvousRequest request;
	ASSERT_FALSE(ParseRendezvousRequest(NULL, NATT_RENDEZVOUS_MAX_LENGTH, request));
}

// A body cut short inside an optional block parses as a body without that
// block, and never reads past its own end. Cutting the full body at every
// length from the fixed part upward must succeed, and must never report a block
// whose bytes are not all present.
TEST(NatRendezvousProtocol, ABodyCutInsideAnOptionalBlockDropsThatBlockRatherThanReadingPastIt)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);
	uint8_t fileHash[NATT_FILE_HASH_LENGTH];
	FillFileHash(fileHash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written = EncodeRendezvousRequest(
		hash, fileHash, CNetworkAddress::FromString("192.0.2.10"), 4662, buffer, sizeof(buffer));

	for (size_t length = NATT_RENDEZVOUS_FIXED_LENGTH; length <= written; ++length) {
		const size_t remaining = length - NATT_RENDEZVOUS_FIXED_LENGTH;

		SNattRendezvousRequest request;
		if (remaining >= NATT_FILE_HASH_LENGTH && remaining - NATT_FILE_HASH_LENGTH > 0 &&
			remaining - NATT_FILE_HASH_LENGTH < NATT_ENDPOINT_TAIL_LENGTH) {
			// The endpoint slot is not all there, so what is left of it is a
			// transport hint. That is the remaining-length rule, not an
			// accident of it: those bytes are read as the last block that
			// fits, never as a partial endpoint.
			ASSERT_TRUE(ParseRendezvousRequest(buffer, length, request));
			ASSERT_FALSE(request.hasEndpointHint);
			continue;
		}

		ASSERT_TRUE(ParseRendezvousRequest(buffer, length, request));
		ASSERT_EQUALS(remaining >= NATT_FILE_HASH_LENGTH, request.hasFileHash);
	}
}

// A hole punch is seventeen bytes: the sender's own hash so the receiver can
// pair the packet with the rendezvous it agreed to, then the options byte. Its
// opcode, like a rendezvous's, is the datagram's second byte and not part of
// the body.
TEST(NatRendezvousProtocol, HolePunchEncodesExactBytes)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_HOLEPUNCH_LENGTH] = { 0 };
	const size_t written = EncodeHolePunch(hash, buffer, sizeof(buffer));

	ASSERT_EQUALS(17u, written);
	for (int i = 0; i < 16; ++i) {
		ASSERT_EQUALS(i, static_cast<int>(buffer[i]));
	}
	ASSERT_EQUALS(0x80, static_cast<int>(buffer[16]));
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

// The demultiplexer the receive path uses. Its input is now the datagram's
// opcode byte rather than the body's first byte, because the body no longer has
// an opcode in it -- which is the whole point of the envelope change.
TEST(NatRendezvousProtocol, ControlMessageClassificationSeparatesTheThreeOpcodes)
{
	ASSERT_EQUALS((int)NATT_CONTROL_RENDEZVOUS, (int)ClassifyNattControlMessage(OP_RENDEZVOUS));
	ASSERT_EQUALS((int)NATT_CONTROL_HOLEPUNCH, (int)ClassifyNattControlMessage(OP_HOLEPUNCH));
	ASSERT_EQUALS(
		(int)NATT_CONTROL_ENDPOINT_HINT, (int)ClassifyNattControlMessage(OP_NATT_ENDPOINT_HINT));
	ASSERT_EQUALS((int)NATT_CONTROL_NOT_A_CONTROL_MESSAGE, (int)ClassifyNattControlMessage(0x42));
	// The ed2k client-to-client UDP opcodes that share this envelope. None of
	// them may be classified as a control message, or the NAT-T path would
	// swallow an upload-queue reask.
	ASSERT_EQUALS((int)NATT_CONTROL_NOT_A_CONTROL_MESSAGE, (int)ClassifyNattControlMessage(0x90));
	ASSERT_EQUALS((int)NATT_CONTROL_NOT_A_CONTROL_MESSAGE, (int)ClassifyNattControlMessage(0x95));
}

// A short output buffer is a caller bug, and the answer is to write nothing.
// Writing what fits would put a half-built body on the wire, which under a
// remaining-length format is not a truncated message but a different one.
TEST(NatRendezvousProtocol, EncodersRefuseAnOutputBufferThatIsTooSmall)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);
	uint8_t fileHash[NATT_FILE_HASH_LENGTH];
	FillFileHash(fileHash);

	uint8_t small[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
	ASSERT_EQUALS(0u,
		EncodeRendezvousRequest(hash,
			fileHash,
			CNetworkAddress::FromString("192.0.2.10"),
			4662,
			small,
			sizeof(small)));
	ASSERT_EQUALS(0u, EncodeHolePunch(hash, small, sizeof(small)));
	ASSERT_EQUALS(0xFF, static_cast<int>(small[0]));

	// One byte short of the whole body is still too small: the file hash and
	// the endpoint go out together or not at all.
	uint8_t almost[NATT_RENDEZVOUS_MAX_LENGTH - 2] = { 0xFF };
	ASSERT_EQUALS(0u,
		EncodeRendezvousRequest(
			hash, fileHash, CNetworkAddress::FromString("192.0.2.10"), 4662, almost, 38));
	ASSERT_EQUALS(0xFF, static_cast<int>(almost[0]));
}

// An IPv6 endpoint has no slot in this format at all, so it is not encoded --
// the message goes out with no endpoint rather than with a truncated or
// reinterpreted one. Nothing in production loses by that: every outbound
// control message is already narrowed to IPv4 by
// CClientUDPSocket::SendNattControlMessage(), which drops a native-IPv6
// destination outright.
TEST(NatRendezvousProtocol, AnIPv6EndpointIsNotEncoded)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written = EncodeRendezvousRequest(
		hash, NULL, CNetworkAddress::FromString("2001:db8::1"), 4662, buffer, sizeof(buffer));

	ASSERT_EQUALS(17u, written);
	ASSERT_EQUALS(0x80, static_cast<int>(buffer[16]));
}

// An IPv4-mapped IPv6 address is the same host as its IPv4 form, so it encodes
// as IPv4. The peer has to punch at an endpoint, and ::ffff:192.0.2.10 is not
// one an IPv4 socket can send to.
TEST(NatRendezvousProtocol, AnIPv4MappedEndpointEncodesAsIPv4)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t written = EncodeRendezvousRequest(
		hash, NULL, CNetworkAddress::FromString("::ffff:192.0.2.10"), 4662, buffer, sizeof(buffer));

	ASSERT_EQUALS(23u, written);
	ASSERT_EQUALS(192, static_cast<int>(buffer[17]));
	ASSERT_EQUALS(10, static_cast<int>(buffer[20]));
}

// Absence is not an address, and a port of zero is not an endpoint. Neither
// encodes, and the alternative -- six zero bytes -- would be an endpoint of
// 0.0.0.0:0 that the far side would dutifully punch at.
TEST(NatRendezvousProtocol, AnAbsentEndpointOrAZeroPortEncodesNoEndpoint)
{
	uint8_t hash[NATT_PEER_HASH_LENGTH];
	FillHash(hash);

	uint8_t absent[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	ASSERT_EQUALS(17u,
		EncodeRendezvousRequest(hash, NULL, CNetworkAddress::Absent(), 4662, absent, sizeof(absent)));

	uint8_t zeroPort[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	ASSERT_EQUALS(17u,
		EncodeRendezvousRequest(hash,
			NULL,
			CNetworkAddress::FromString("192.0.2.10"),
			0,
			zeroPort,
			sizeof(zeroPort)));
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
	uint8_t fileHash[NATT_FILE_HASH_LENGTH];
	FillFileHash(fileHash);

	uint8_t relayed[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t relayedLength = EncodeRelayedRendezvous(
		hash, fileHash, CNetworkAddress::FromString("192.0.2.10"), 4662, relayed, sizeof(relayed));
	ASSERT_EQUALS(39u, relayedLength);
	// 0x80 traversal, 0x40 relayed, 0x20 an endpoint follows.
	ASSERT_EQUALS(0xE0, static_cast<int>(relayed[16]));

	SNattRendezvousRequest parsedRelayed;
	ASSERT_TRUE(ParseRendezvousRequest(relayed, relayedLength, parsedRelayed));
	ASSERT_TRUE(parsedRelayed.isRelayed);

	uint8_t request[NATT_RENDEZVOUS_MAX_LENGTH] = { 0 };
	const size_t requestLength = EncodeRendezvousRequest(
		hash, fileHash, CNetworkAddress::FromString("192.0.2.10"), 4662, request, sizeof(request));
	ASSERT_EQUALS(0xA0, static_cast<int>(request[16]));

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
	uint8_t fileHash[NATT_FILE_HASH_LENGTH];
	FillFileHash(fileHash);

	uint8_t buffer[NATT_RENDEZVOUS_MAX_LENGTH] = { 0xFF };
	ASSERT_EQUALS(0u,
		EncodeRelayedRendezvous(
			hash, fileHash, CNetworkAddress::Absent(), 4662, buffer, sizeof(buffer)));
	ASSERT_EQUALS(0xFF, static_cast<int>(buffer[0]));
}
