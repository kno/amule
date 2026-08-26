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

// The 16-byte peer identity value the QUIC proof's second field carries, and
// the direction question of which end's value goes in it.
//
// This suite exists because every property below is invisible at runtime. A
// value stored from a wrong-length tag, a value used in the wrong direction, an
// absent value silently treated as sixteen zero bytes -- none of them produces
// a diagnostic. The QUIC handshake simply never completes, on either side, with
// nothing logged anywhere. That is the same failure mode the wire constants in
// QuicNattProtocolTest are pinned against, and it is why these are asserted
// rather than read off the header.

#include <muleunit/test.h>

#include <QuicProofValue.h>

#include <cstring>

using namespace muleunit;

DECLARE_SIMPLE(QuicProofValue)

namespace
{

//! Sixteen distinguishable bytes. Not a hash of anything -- a test that
//! depended on the derivation would stop testing the container.
const std::uint8_t kSixteenA[QUIC_NATT_PROOF_VALUE_LENGTH] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x0F
};

const std::uint8_t kSixteenB[QUIC_NATT_PROOF_VALUE_LENGTH] = {
	0xF0, 0x0F, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
};

} // namespace

// A default-constructed value is absent, and absent is not "sixteen zeroes".
//
// The distinction is the whole safety property of this change. FindExpectation()
// must keep returning NULL for a peer that advertised nothing, and it decides
// that by asking this object. A container that reported present-and-zero would
// hand the validator a comparable expectation and turn "we learned nothing about
// this peer" into "this peer must send sixteen zero bytes" -- which any third
// party can send.
TEST(QuicProofValue, ADefaultValueIsAbsentAndExposesNoBytes)
{
	CQuicProofValue value;

	ASSERT_FALSE(value.IsPresent());
	ASSERT_TRUE(value.Bytes() == NULL);
}

TEST(QuicProofValue, SixteenBytesAreStoredVerbatim)
{
	CQuicProofValue value;

	ASSERT_TRUE(value.SetFromWire(kSixteenA, QUIC_NATT_PROOF_VALUE_LENGTH));
	ASSERT_TRUE(value.IsPresent());
	ASSERT_TRUE(value.Bytes() != NULL);
	ASSERT_EQUALS(0, memcmp(value.Bytes(), kSixteenA, QUIC_NATT_PROOF_VALUE_LENGTH));
}

// Every wrong length is refused, and refused *without storing*: a peer must not
// be able to install a partial expectation. Zero is included because a tag with
// no payload is the shape a truncated packet takes, and NULL because the tag
// reader hands back a null pointer for a tag it could not read.
TEST(QuicProofValue, EveryWrongLengthIsRefusedWithoutStoring)
{
	for (std::size_t length = 0; length <= (2 * QUIC_NATT_PROOF_VALUE_LENGTH); ++length) {
		if (length == QUIC_NATT_PROOF_VALUE_LENGTH) {
			continue;
		}

		CQuicProofValue value;
		ASSERT_FALSE(value.SetFromWire(kSixteenA, length));
		ASSERT_FALSE(value.IsPresent());
		ASSERT_TRUE(value.Bytes() == NULL);
	}

	CQuicProofValue nullValue;
	ASSERT_FALSE(nullValue.SetFromWire(NULL, QUIC_NATT_PROOF_VALUE_LENGTH));
	ASSERT_FALSE(nullValue.IsPresent());
}

// A refused write must not disturb a value already learned. A peer that sent a
// good tag in its hello and a malformed one in a later handshake keeps the good
// one; the alternative would let a malformed tag erase an expectation and so
// downgrade every subsequent QUIC connection to a refusal.
TEST(QuicProofValue, ARefusedWriteLeavesAnEarlierValueIntact)
{
	CQuicProofValue value;
	ASSERT_TRUE(value.SetFromWire(kSixteenA, QUIC_NATT_PROOF_VALUE_LENGTH));

	ASSERT_FALSE(value.SetFromWire(kSixteenB, QUIC_NATT_PROOF_VALUE_LENGTH - 1));

	ASSERT_TRUE(value.IsPresent());
	ASSERT_EQUALS(0, memcmp(value.Bytes(), kSixteenA, QUIC_NATT_PROOF_VALUE_LENGTH));
}

TEST(QuicProofValue, ResetReturnsToAbsentRatherThanToZeroes)
{
	CQuicProofValue value;
	ASSERT_TRUE(value.SetFromWire(kSixteenA, QUIC_NATT_PROOF_VALUE_LENGTH));

	value.Reset();

	ASSERT_FALSE(value.IsPresent());
	ASSERT_TRUE(value.Bytes() == NULL);
}

// --- The direction ----------------------------------------------------------
//
// Which end's value the proof's second field carries. Both ends' values are
// unguessable to a third party that never saw the corresponding hello, so both
// directions are defensible as authentication -- but only one interoperates,
// and nothing observable distinguishes a wrong choice from a peer that is
// offline. So the choice is a named constant with a test, not a call-site
// decision.

TEST(QuicProofValue, TheProofCarriesTheSendersOwnAdvertisedValue)
{
	// Pins the shipped decision. Mirrors the proof's first field, which
	// carries the sender's own ed2k user hash (BuildQuicNattProof) -- a record
	// whose two fields described different ends would be a record neither end
	// could describe in one sentence.
	ASSERT_TRUE(kQuicProofValueDirection == QUIC_PROOF_VALUE_SENDER_ADVERTISED);
}

TEST(QuicProofValue, SelectionFollowsTheDirectionAndNothingElse)
{
	CQuicProofValue local;
	CQuicProofValue peer;
	ASSERT_TRUE(local.SetFromWire(kSixteenA, QUIC_NATT_PROOF_VALUE_LENGTH));
	ASSERT_TRUE(peer.SetFromWire(kSixteenB, QUIC_NATT_PROOF_VALUE_LENGTH));

	ASSERT_TRUE(SelectQuicProofValue(local, peer, QUIC_PROOF_VALUE_SENDER_ADVERTISED) == local.Bytes());
	ASSERT_TRUE(SelectQuicProofValue(local, peer, QUIC_PROOF_VALUE_RECIPIENT_ADVERTISED) == peer.Bytes());
}

// Selection fails closed on absence, in both directions. This is the property
// that keeps an unlearned value from becoming an empty proof field: the caller
// gets NULL, BuildQuicNattProof() refuses, and no proof goes out at all.
TEST(QuicProofValue, SelectionOfAnAbsentValueIsNull)
{
	CQuicProofValue absent;
	CQuicProofValue present;
	ASSERT_TRUE(present.SetFromWire(kSixteenA, QUIC_NATT_PROOF_VALUE_LENGTH));

	ASSERT_TRUE(SelectQuicProofValue(absent, present, QUIC_PROOF_VALUE_SENDER_ADVERTISED) == NULL);
	ASSERT_TRUE(SelectQuicProofValue(present, absent, QUIC_PROOF_VALUE_RECIPIENT_ADVERTISED) == NULL);
}

// The expectation an inbound connection is checked against is entirely
// peer-side under the shipped direction: the peer's user hash and the peer's
// own advertised value, both learned from its ed2k hello over TCP. Asserted as
// one statement because it is the safety claim of this whole change -- nothing
// in the expectation may come from the QUIC connection being validated.
TEST(QuicProofValue, TheInboundExpectationIsBuiltOnlyFromWhatThePeerAdvertised)
{
	CQuicProofValue local;
	CQuicProofValue peer;
	ASSERT_TRUE(local.SetFromWire(kSixteenA, QUIC_NATT_PROOF_VALUE_LENGTH));
	ASSERT_TRUE(peer.SetFromWire(kSixteenB, QUIC_NATT_PROOF_VALUE_LENGTH));

	// The sender of an inbound connection is the peer, so the value expected
	// in the proof is the peer's -- never ours, and never the connection's.
	ASSERT_TRUE(ExpectedQuicProofValueFromPeer(local, peer) == peer.Bytes());
}

// --- Deriving this client's own value ---------------------------------------

// Stability across calls is the property a restart depends on. A peer learns
// this value from one hello and checks it against a proof that may arrive
// minutes later, so a derivation that varied would refuse every connection --
// and would do so silently.
TEST(QuicProofValue, DerivationIsStableForOneKey)
{
	const std::uint8_t key[] = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE };

	std::uint8_t first[QUIC_NATT_PROOF_VALUE_LENGTH] = {};
	std::uint8_t second[QUIC_NATT_PROOF_VALUE_LENGTH] = {};

	ASSERT_TRUE(DeriveLocalQuicProofValue(key, sizeof(key), first));
	ASSERT_TRUE(DeriveLocalQuicProofValue(key, sizeof(key), second));

	ASSERT_EQUALS(0, memcmp(first, second, QUIC_NATT_PROOF_VALUE_LENGTH));
}

// Two installs must not collide: the value is what distinguishes them, so a
// derivation that ignored part of its input would hand every client the same
// identity. A one-byte difference is the smallest input change there is.
TEST(QuicProofValue, DifferentKeysDeriveDifferentValues)
{
	std::uint8_t keyA[] = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE };
	std::uint8_t keyB[] = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCF };

	std::uint8_t valueA[QUIC_NATT_PROOF_VALUE_LENGTH] = {};
	std::uint8_t valueB[QUIC_NATT_PROOF_VALUE_LENGTH] = {};

	ASSERT_TRUE(DeriveLocalQuicProofValue(keyA, sizeof(keyA), valueA));
	ASSERT_TRUE(DeriveLocalQuicProofValue(keyB, sizeof(keyB), valueB));

	ASSERT_TRUE(memcmp(valueA, valueB, QUIC_NATT_PROOF_VALUE_LENGTH) != 0);
}

// No key is a real state -- secure identification may never have produced one
// -- and it must yield no value rather than a value derived from nothing. A
// derivation that hashed an empty input would give every keyless client the
// same identity, which is an identity any of them could claim.
TEST(QuicProofValue, WithoutAKeyThereIsNoValue)
{
	std::uint8_t out[QUIC_NATT_PROOF_VALUE_LENGTH];
	memset(out, 0xA5, sizeof(out));

	const std::uint8_t key[] = { 0x01 };

	ASSERT_FALSE(DeriveLocalQuicProofValue(NULL, 0, out));
	ASSERT_FALSE(DeriveLocalQuicProofValue(NULL, sizeof(key), out));
	ASSERT_FALSE(DeriveLocalQuicProofValue(key, 0, out));
	ASSERT_FALSE(DeriveLocalQuicProofValue(key, sizeof(key), NULL));

	// The output buffer was not touched by any refusal.
	for (std::size_t i = 0; i < sizeof(out); ++i) {
		ASSERT_EQUALS(0xA5, (int)out[i]);
	}
}

// The derived value is not the key, nor a prefix of it. Not a security claim --
// the key is public -- but a derivation that copied its input would be a
// derivation nobody had noticed was missing, and it would break the moment a
// key shorter than 16 bytes arrived.
TEST(QuicProofValue, TheValueIsADigestRatherThanTheKeyItself)
{
	const std::uint8_t key[QUIC_NATT_PROOF_VALUE_LENGTH] = {
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A
	};

	std::uint8_t value[QUIC_NATT_PROOF_VALUE_LENGTH] = {};
	ASSERT_TRUE(DeriveLocalQuicProofValue(key, sizeof(key), value));

	ASSERT_TRUE(memcmp(value, key, QUIC_NATT_PROOF_VALUE_LENGTH) != 0);
}
