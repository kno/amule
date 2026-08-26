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

// The wire identity of the QUIC NAT-T path, and the proof that ties a QUIC
// connection to the ed2k identity which negotiated it.
//
// Every value here is wire format shared with eMuleAI: the ALPN string, the
// 0xB2/0x01 framing, the `EAQN1` magic and the 37-byte proof layout. A
// mismatch in any of them produces no diagnostic on either side -- the peer
// simply never completes the handshake -- which is exactly why they are
// asserted as literals rather than as a restatement of the header.
//
// The proof half is the security-relevant one. An observer of the rendezvous
// exchange must not be able to complete the handshake in the peer's place, so
// what this suite pins is not that a good proof passes but that each of the
// four ways a bad one arrives is rejected, and rejected as an *authentication*
// failure rather than a transport one.

#include <muleunit/test.h>

#include <QuicNattProtocol.h>
#include <protocol/Protocols.h>

#include <cstring>

using namespace muleunit;

DECLARE_SIMPLE(QuicNattProtocol)

namespace
{
//! A recognisable identity and nonce, distinct from each other so a proof
//! builder that wrote the same value into both fields could not pass.
const uint8_t kUserHash[QUIC_NATT_PROOF_VALUE_LENGTH] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

const uint8_t kNonce[QUIC_NATT_PROOF_VALUE_LENGTH] = {
	0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F
};
} // namespace

// The four values a peer has to agree with byte for byte. Literals, because a
// test written as `ASSERT_EQUALS(QUIC_NATT_ALPN_LENGTH, strlen(QUIC_NATT_ALPN))`
// would pass for any string at all.
TEST(QuicNattProtocol, WireIdentityIsExact)
{
	ASSERT_TRUE(strcmp(QUIC_NATT_ALPN, "ed2k-ai-natt-quic-v1") == 0);
	ASSERT_EQUALS(20u, (unsigned)QUIC_NATT_ALPN_LENGTH);

	ASSERT_EQUALS(0xB2, (int)OP_UDPRESERVEDPROT2);
	ASSERT_EQUALS(0x01, (int)OP_NATT_FRAME_QUIC);

	ASSERT_TRUE(memcmp(QUIC_NATT_PROOF_MAGIC, "EAQN1", 5) == 0);
	ASSERT_EQUALS(5u, (unsigned)QUIC_NATT_PROOF_MAGIC_LENGTH);
	ASSERT_EQUALS(16u, (unsigned)QUIC_NATT_PROOF_VALUE_LENGTH);
	ASSERT_EQUALS(37u, (unsigned)QUIC_NATT_PROOF_LENGTH);
}

// Spec delta, "Peer offering a different ALPN": exactly one value is accepted.
// The near misses are the interesting cases -- a prefix, an extension, a case
// difference and the empty offer -- because a comparison written with strncmp
// or a case-insensitive compare would accept some of them.
TEST(QuicNattProtocol, OnlyTheOneAlpnIsAccepted)
{
	ASSERT_TRUE(IsAcceptedQuicAlpn((const uint8_t *)"ed2k-ai-natt-quic-v1", 20));

	// A prefix of the accepted value.
	ASSERT_FALSE(IsAcceptedQuicAlpn((const uint8_t *)"ed2k-ai-natt-quic-v", 19));
	// The accepted value with something appended.
	ASSERT_FALSE(IsAcceptedQuicAlpn((const uint8_t *)"ed2k-ai-natt-quic-v10", 21));
	// A later version of this same protocol is still not this one.
	ASSERT_FALSE(IsAcceptedQuicAlpn((const uint8_t *)"ed2k-ai-natt-quic-v2", 20));
	// Case matters: ALPN identifiers are byte strings, not names.
	ASSERT_FALSE(IsAcceptedQuicAlpn((const uint8_t *)"ED2K-AI-NATT-QUIC-V1", 20));
	// Somebody else's protocol on the same port.
	ASSERT_FALSE(IsAcceptedQuicAlpn((const uint8_t *)"h3", 2));

	// No offer at all. A length of zero must not read the pointer, and a
	// null pointer must not be a crash: both arrive from the network.
	ASSERT_FALSE(IsAcceptedQuicAlpn((const uint8_t *)"ed2k-ai-natt-quic-v1", 0));
	ASSERT_FALSE(IsAcceptedQuicAlpn(NULL, 0));
	ASSERT_FALSE(IsAcceptedQuicAlpn(NULL, 20));
}

// The frame header is the same two-byte shape uTP uses, with the type byte
// changed. Asserted rather than assumed because the two live side by side on
// one port and a copied-and-edited writer that kept 0x00 would put QUIC
// packets into libutp.
TEST(QuicNattProtocol, FrameHeaderIsTwoBytesEndingInTheQuicType)
{
	uint8_t header[QUIC_FRAME_HEADER_LENGTH] = { 0, 0 };
	WriteQuicFrameHeader(header);

	ASSERT_EQUALS(2u, (unsigned)QUIC_FRAME_HEADER_LENGTH);
	ASSERT_EQUALS(0xB2, (int)header[0]);
	ASSERT_EQUALS(0x01, (int)header[1]);

	const uint8_t quicFrame[4] = { OP_UDPRESERVEDPROT2, OP_NATT_FRAME_QUIC, 0x11, 0x22 };
	ASSERT_TRUE(IsQuicFrame(quicFrame, 4));
	ASSERT_TRUE(QuicFramePayload(quicFrame) == quicFrame + 2);
	ASSERT_EQUALS(2u, (unsigned)QuicFramePayloadLength(4));

	// The header alone is a QUIC frame with an empty payload: ngtcp2 rejects
	// a zero-length datagram on its own terms, and a minimum length invented
	// here would be a second parser nobody maintains. Same rule as IsUtpFrame().
	ASSERT_TRUE(IsQuicFrame(quicFrame, 2));
	ASSERT_EQUALS(0u, (unsigned)QuicFramePayloadLength(2));

	// A uTP frame is not a QUIC frame, and vice versa. This is the pair that
	// shares the port.
	const uint8_t utpFrame[4] = { OP_UDPRESERVEDPROT2, OP_NATT_FRAME_UTP, 0x11, 0x22 };
	ASSERT_FALSE(IsQuicFrame(utpFrame, 4));

	// Neither the wrong protocol byte nor a truncated datagram.
	const uint8_t wrongProtocol[4] = { 0xE3, OP_NATT_FRAME_QUIC, 0x11, 0x22 };
	ASSERT_FALSE(IsQuicFrame(wrongProtocol, 4));
	ASSERT_FALSE(IsQuicFrame(quicFrame, 1));
	ASSERT_FALSE(IsQuicFrame(NULL, 0));
}

// The proof aMule builds is the proof aMule accepts. Its layout is asserted
// field by field rather than by round-tripping alone: a builder and a
// validator that agreed on the wrong offsets would round-trip perfectly and
// interoperate with nothing.
TEST(QuicNattProtocol, ProofLayoutIsMagicThenIdentityThenNonce)
{
	uint8_t proof[QUIC_NATT_PROOF_LENGTH];
	memset(proof, 0xCC, sizeof(proof));

	ASSERT_TRUE(BuildQuicNattProof(kUserHash, kNonce, proof));

	ASSERT_TRUE(memcmp(proof, "EAQN1", 5) == 0);
	ASSERT_TRUE(memcmp(proof + 5, kUserHash, 16) == 0);
	ASSERT_TRUE(memcmp(proof + 21, kNonce, 16) == 0);

	ASSERT_EQUALS(
		(int)QUIC_PROOF_VALID, (int)ValidateQuicNattProof(proof, sizeof(proof), kUserHash, kNonce));
}

// Spec delta, "Missing or malformed proof". Each of the three shapes is
// rejected with its own reason, because a validator that collapsed them into
// one "invalid" answer would make a genuine protocol mismatch indistinguishable
// from an attack in the log.
TEST(QuicNattProtocol, AbsentTruncatedAndWrongMagicProofsAreRejected)
{
	uint8_t proof[QUIC_NATT_PROOF_LENGTH];
	ASSERT_TRUE(BuildQuicNattProof(kUserHash, kNonce, proof));

	// Absent: nothing arrived. A null pointer and a zero length are the same
	// condition and neither may read the pointer.
	ASSERT_EQUALS((int)QUIC_PROOF_ABSENT, (int)ValidateQuicNattProof(NULL, 0, kUserHash, kNonce));
	ASSERT_EQUALS((int)QUIC_PROOF_ABSENT, (int)ValidateQuicNattProof(proof, 0, kUserHash, kNonce));

	// Truncated: every length short of the full record, including lengths
	// that stop inside the magic and lengths that stop inside a value. The
	// sweep is the point -- an off-by-one bound only fails at one length.
	for (size_t length = 1; length < QUIC_NATT_PROOF_LENGTH; ++length) {
		ASSERT_EQUALS((int)QUIC_PROOF_TRUNCATED,
			(int)ValidateQuicNattProof(proof, length, kUserHash, kNonce));
	}

	// Longer than the record. The proof is a fixed-length field, not a
	// prefix, so trailing bytes mean the sender is speaking something else.
	uint8_t oversized[QUIC_NATT_PROOF_LENGTH + 1];
	memcpy(oversized, proof, QUIC_NATT_PROOF_LENGTH);
	oversized[QUIC_NATT_PROOF_LENGTH] = 0x00;
	ASSERT_EQUALS((int)QUIC_PROOF_OVERSIZED,
		(int)ValidateQuicNattProof(oversized, sizeof(oversized), kUserHash, kNonce));

	// Wrong magic, at each of the five positions. Checked before the identity
	// so that a peer speaking a different protocol is reported as such rather
	// than as an impostor.
	for (size_t i = 0; i < QUIC_NATT_PROOF_MAGIC_LENGTH; ++i) {
		uint8_t corrupted[QUIC_NATT_PROOF_LENGTH];
		memcpy(corrupted, proof, sizeof(corrupted));
		corrupted[i] = (uint8_t)(corrupted[i] ^ 0xFF);

		ASSERT_EQUALS((int)QUIC_PROOF_BAD_MAGIC,
			(int)ValidateQuicNattProof(corrupted, sizeof(corrupted), kUserHash, kNonce));
	}
}

// Spec delta, "Proof for a different identity". The whole point of the proof:
// a well-formed record carrying somebody else's identity, or the right
// identity with a nonce from a different rendezvous, must not pass. Every byte
// of both fields is swept, because a comparison that stopped at the first few
// bytes would pass most of these.
TEST(QuicNattProtocol, ProofForAnotherIdentityIsRejected)
{
	uint8_t proof[QUIC_NATT_PROOF_LENGTH];
	ASSERT_TRUE(BuildQuicNattProof(kUserHash, kNonce, proof));

	for (size_t i = 0; i < QUIC_NATT_PROOF_VALUE_LENGTH; ++i) {
		// One flipped byte of the identity.
		uint8_t otherIdentity[QUIC_NATT_PROOF_VALUE_LENGTH];
		memcpy(otherIdentity, kUserHash, sizeof(otherIdentity));
		otherIdentity[i] = (uint8_t)(otherIdentity[i] ^ 0xFF);
		ASSERT_EQUALS((int)QUIC_PROOF_WRONG_IDENTITY,
			(int)ValidateQuicNattProof(proof, sizeof(proof), otherIdentity, kNonce));

		// One flipped byte of the nonce: the right peer, but a proof
		// replayed from a rendezvous this connection did not negotiate.
		uint8_t otherNonce[QUIC_NATT_PROOF_VALUE_LENGTH];
		memcpy(otherNonce, kNonce, sizeof(otherNonce));
		otherNonce[i] = (uint8_t)(otherNonce[i] ^ 0xFF);
		ASSERT_EQUALS((int)QUIC_PROOF_WRONG_IDENTITY,
			(int)ValidateQuicNattProof(proof, sizeof(proof), kUserHash, otherNonce));
	}

	// The two fields must not be interchangeable: a proof whose identity and
	// nonce are swapped is a different proof.
	uint8_t swapped[QUIC_NATT_PROOF_LENGTH];
	ASSERT_TRUE(BuildQuicNattProof(kNonce, kUserHash, swapped));
	ASSERT_EQUALS((int)QUIC_PROOF_WRONG_IDENTITY,
		(int)ValidateQuicNattProof(swapped, sizeof(swapped), kUserHash, kNonce));
}

// Task 3.3: the log has to say which of the two happened. A dropped packet and
// a peer failing to prove who it is are different events -- one is the network,
// the other is somebody trying -- and a single "QUIC connection failed" line
// for both makes the second invisible. Everything short of a valid proof is an
// authentication failure; nothing in this enum is a transport one.
TEST(QuicNattProtocol, EveryProofRejectionIsAnAuthenticationFailure)
{
	ASSERT_FALSE(IsQuicAuthenticationFailure(QUIC_PROOF_VALID));

	ASSERT_TRUE(IsQuicAuthenticationFailure(QUIC_PROOF_ABSENT));
	ASSERT_TRUE(IsQuicAuthenticationFailure(QUIC_PROOF_TRUNCATED));
	ASSERT_TRUE(IsQuicAuthenticationFailure(QUIC_PROOF_OVERSIZED));
	ASSERT_TRUE(IsQuicAuthenticationFailure(QUIC_PROOF_BAD_MAGIC));
	ASSERT_TRUE(IsQuicAuthenticationFailure(QUIC_PROOF_WRONG_IDENTITY));

	// Each reason names itself, and no two share a name: the log line is the
	// only place these values are ever read by a person.
	const EQuicProofResult all[] = { QUIC_PROOF_VALID,
		QUIC_PROOF_ABSENT,
		QUIC_PROOF_TRUNCATED,
		QUIC_PROOF_OVERSIZED,
		QUIC_PROOF_BAD_MAGIC,
		QUIC_PROOF_WRONG_IDENTITY };

	for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); ++i) {
		ASSERT_TRUE(QuicProofResultName(all[i]) != NULL);
		for (size_t j = i + 1; j < sizeof(all) / sizeof(all[0]); ++j) {
			ASSERT_TRUE(strcmp(QuicProofResultName(all[i]), QuicProofResultName(all[j])) != 0);
		}
	}
}

// A builder handed nowhere to write, or nothing to write, must say so rather
// than dereferencing. These arguments come from a connection whose peer state
// may not have been established yet.
TEST(QuicNattProtocol, ProofBuilderRefusesNullArguments)
{
	uint8_t proof[QUIC_NATT_PROOF_LENGTH];
	memset(proof, 0xCC, sizeof(proof));

	ASSERT_FALSE(BuildQuicNattProof(NULL, kNonce, proof));
	ASSERT_FALSE(BuildQuicNattProof(kUserHash, NULL, proof));
	ASSERT_FALSE(BuildQuicNattProof(kUserHash, kNonce, NULL));

	// Nothing was written on the way to refusing.
	for (size_t i = 0; i < sizeof(proof); ++i) {
		ASSERT_EQUALS(0xCC, (int)proof[i]);
	}
}

// A validator with nothing to validate against cannot answer "valid". This is
// the fail-closed direction: an unestablished expectation must reject, not
// wave the connection through.
TEST(QuicNattProtocol, ValidatorWithoutAnExpectationRejects)
{
	uint8_t proof[QUIC_NATT_PROOF_LENGTH];
	ASSERT_TRUE(BuildQuicNattProof(kUserHash, kNonce, proof));

	ASSERT_EQUALS((int)QUIC_PROOF_WRONG_IDENTITY,
		(int)ValidateQuicNattProof(proof, sizeof(proof), NULL, kNonce));
	ASSERT_EQUALS((int)QUIC_PROOF_WRONG_IDENTITY,
		(int)ValidateQuicNattProof(proof, sizeof(proof), kUserHash, NULL));
}
