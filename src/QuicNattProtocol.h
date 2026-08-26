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

#ifndef QUICNATTPROTOCOL_H
#define QUICNATTPROTOCOL_H

#include <cstddef>
#include <cstdint>

#include <protocol/Protocols.h> // Needed for OP_UDPRESERVEDPROT2 / OP_NATT_FRAME_QUIC

/**
 * The wire identity of the QUIC NAT-T path, and the proof that authenticates
 * it.
 *
 * Four values here are shared with eMuleAI byte for byte: the ALPN string, the
 * 0xB2/0x01 framing, the `EAQN1` magic and the 37-byte proof layout. None of
 * them produces a diagnostic when it is wrong -- the peer simply never
 * completes the handshake, on either side, with nothing logged anywhere -- so
 * they are pinned as literals in QuicNattProtocolTest rather than left to be
 * read off this file.
 *
 * Header-only and free of ngtcp2, GnuTLS, wxWidgets and theApp, for the same
 * reason as ReservedProtocolFrames.h and UtpDialPolicy.h: this is the part of
 * the QUIC path that can be decided without a TLS handshake, and it has to be
 * assertable in a build configured with -DENABLE_QUIC=NO -- which is the
 * default build and the only one macOS gets. The crypto half lives behind
 * IQuicLibrary (QuicContext.h) and reaches ngtcp2 in exactly one translation
 * unit (QuicLibraryAdapter.cpp).
 */

// --- ALPN -------------------------------------------------------------------

/**
 * The only ALPN identifier this path offers or accepts.
 *
 * ALPN identifiers are byte strings, not names: the comparison below is exact
 * and case-sensitive, which is what the spec delta means by "no other ALPN
 * value MUST be offered or accepted". Accepting a near miss would not be a
 * kindness to an older peer -- there is no older peer -- it would be accepting
 * a connection whose other end believes it negotiated a different protocol.
 */
constexpr char QUIC_NATT_ALPN[] = "ed2k-ai-natt-quic-v1";

//! Its length in bytes, without the terminator. ALPN travels length-prefixed,
//! so the terminator is never on the wire.
constexpr std::size_t QUIC_NATT_ALPN_LENGTH = sizeof(QUIC_NATT_ALPN) - 1;

/**
 * Is this the ALPN identifier this path speaks?
 *
 * @param alpn  the offered identifier, not terminated. May be NULL when
 *              length is 0 -- a peer that offered nothing.
 * @param length  its length in bytes.
 *
 * Length is compared first, so a prefix of the accepted value and the accepted
 * value with something appended are both rejected without reading past either
 * buffer.
 */
inline bool IsAcceptedQuicAlpn(const std::uint8_t *alpn, std::size_t length)
{
	if (alpn == nullptr || length != QUIC_NATT_ALPN_LENGTH) {
		return false;
	}

	for (std::size_t i = 0; i < QUIC_NATT_ALPN_LENGTH; ++i) {
		if (alpn[i] != static_cast<std::uint8_t>(QUIC_NATT_ALPN[i])) {
			return false;
		}
	}

	return true;
}

// --- Framing on the shared port ---------------------------------------------

//! The two framing bytes in front of every QUIC datagram on the shared port.
//! The same shape uTP uses, with the type byte changed -- see
//! UtpDatagramRouting.h for why the port is shared at all.
constexpr std::size_t QUIC_FRAME_HEADER_LENGTH = 2;

//! Write the QUIC frame header. `out` must have room for
//! QUIC_FRAME_HEADER_LENGTH bytes.
inline void WriteQuicFrameHeader(std::uint8_t *out)
{
	out[0] = OP_UDPRESERVEDPROT2;
	out[1] = OP_NATT_FRAME_QUIC;
}

/**
 * Is this datagram a QUIC frame?
 *
 * The header alone with no payload still is one: ngtcp2 rejects a zero-length
 * datagram on its own terms, and a minimum length invented here would be a
 * second parser nobody maintains. Identical rule to IsUtpFrame().
 *
 * @param datagram  the whole datagram, protocol byte first. May be NULL when
 *                  length is 0.
 * @param length    bytes available from `datagram`.
 */
inline bool IsQuicFrame(const std::uint8_t *datagram, std::size_t length)
{
	if (datagram == nullptr || length < QUIC_FRAME_HEADER_LENGTH) {
		return false;
	}

	return datagram[0] == OP_UDPRESERVEDPROT2 && datagram[1] == OP_NATT_FRAME_QUIC;
}

//! The QUIC payload window: everything after the two framing bytes. Only
//! meaningful when IsQuicFrame() is true.
inline const std::uint8_t *QuicFramePayload(const std::uint8_t *datagram)
{
	return datagram + QUIC_FRAME_HEADER_LENGTH;
}

//! Length of that window, for a datagram of `length` bytes.
inline std::size_t QuicFramePayloadLength(std::size_t length)
{
	return length - QUIC_FRAME_HEADER_LENGTH;
}

// --- Peer proof -------------------------------------------------------------

/**
 * The 37-byte proof: magic, then the sender's ed2k user hash, then the sender's
 * 16-byte identity value.
 *
 * TLS authenticates the *connection*; it says nothing about which ed2k client
 * is on the other end, because neither side has a certificate the other can
 * check. The proof is what ties the two together. Without it, anyone who
 * observed the rendezvous exchange -- which travels in the clear over UDP --
 * could complete the QUIC handshake in the peer's place and be handed the
 * connection.
 *
 * The second field is what makes the record worth more than the user hash
 * alone. A user hash is on the wire in every hello and every source exchange,
 * so a proof carrying only that could be assembled by anyone who has ever heard
 * of the peer. The identity value cannot: it reaches this end only through the
 * peer's ed2k hello over TCP (tag CT_MOD_QUIC_IDENT), while the attack this
 * proof exists to stop -- hijacking a punched UDP mapping -- gives an attacker
 * the UDP half and not the TCP one.
 *
 * This field was read as a per-exchange nonce until a real eMuleAI v1.6.0 was
 * measured on 2026-08-26 and sent a byte-identical value across three separate
 * sessions. It is a stable per-install identity, not a nonce, and the
 * difference matters twice: it is what gives the field a wire source at all,
 * and it is what bounds how much the proof proves. A stable value is not a
 * challenge, so a captured proof does replay -- against an attacker who already
 * had the peer's hello. See QuicProofValue.h, which owns the value and the
 * question of which end's belongs here.
 */
constexpr char QUIC_NATT_PROOF_MAGIC[] = "EAQN1";
constexpr std::size_t QUIC_NATT_PROOF_MAGIC_LENGTH = sizeof(QUIC_NATT_PROOF_MAGIC) - 1;

//! Both proof fields are 16 bytes: an ed2k user hash is an MD4 digest, and the
//! identity value is sized to match it -- which is how the CT_MOD_QUIC_IDENT tag
//! was recognised as this field's source, since eMuleAI sends it as a 16-byte
//! hash-typed tag.
constexpr std::size_t QUIC_NATT_PROOF_VALUE_LENGTH = 16;

//! 5 + 16 + 16. A fixed-length record, not a prefix of a longer one.
constexpr std::size_t QUIC_NATT_PROOF_LENGTH =
	QUIC_NATT_PROOF_MAGIC_LENGTH + (2 * QUIC_NATT_PROOF_VALUE_LENGTH);

//! Byte offsets of the two values inside the record.
constexpr std::size_t QUIC_NATT_PROOF_IDENTITY_OFFSET = QUIC_NATT_PROOF_MAGIC_LENGTH;
constexpr std::size_t QUIC_NATT_PROOF_VALUE_OFFSET =
	QUIC_NATT_PROOF_IDENTITY_OFFSET + QUIC_NATT_PROOF_VALUE_LENGTH;

/**
 * Why a proof was accepted or refused.
 *
 * Five distinct refusals rather than one "invalid", because the log line these
 * feed is the only place a person ever reads them, and "a peer speaking a
 * different protocol" and "a peer claiming to be somebody else" call for
 * different reactions. Every value except QUIC_PROOF_VALID is an
 * authentication failure -- see IsQuicAuthenticationFailure().
 */
enum EQuicProofResult
{
	//! Magic, identity and nonce all matched.
	QUIC_PROOF_VALID,
	//! Nothing arrived where a proof was expected.
	QUIC_PROOF_ABSENT,
	//! Shorter than the record. Includes lengths that stop inside the magic.
	QUIC_PROOF_TRUNCATED,
	//! Longer than the record. The field is fixed-length, so trailing bytes
	//! mean the sender is framing something this end does not speak.
	QUIC_PROOF_OVERSIZED,
	//! The right length, but not this protocol's magic.
	QUIC_PROOF_BAD_MAGIC,
	//! Well-formed, but for a different ed2k identity, or carrying an identity
	//! value this end never learned from that peer. This is the one that means
	//! somebody tried.
	QUIC_PROOF_WRONG_IDENTITY
};

/**
 * Build the proof this end sends.
 *
 * Both fields describe the *sender*, which is what lets the record be read as
 * one sentence: "I am this ed2k identity, and this is the identity value that
 * identity published." A record whose two fields described different ends would
 * be one neither end could describe at all. See kQuicProofValueDirection in
 * QuicProofValue.h, which is where that decision is recorded and where it would
 * be reversed.
 *
 * @param userHash    16 bytes: this client's ed2k user hash.
 * @param proofValue  16 bytes: the identity value the direction selects, from
 *                    SelectQuicProofValue().
 * @param out         receives QUIC_NATT_PROOF_LENGTH bytes. Untouched unless
 *                    true is returned.
 * @return false when any argument is NULL. A NULL is the ordinary answer for a
 *         value that was never learned, and it must produce no proof at all
 *         rather than a proof with an empty field -- so refusing here is the
 *         fail-closed path, not defensive coding against a caller bug.
 */
inline bool BuildQuicNattProof(
	const std::uint8_t *userHash, const std::uint8_t *proofValue, std::uint8_t *out)
{
	if (userHash == nullptr || proofValue == nullptr || out == nullptr) {
		return false;
	}

	for (std::size_t i = 0; i < QUIC_NATT_PROOF_MAGIC_LENGTH; ++i) {
		out[i] = static_cast<std::uint8_t>(QUIC_NATT_PROOF_MAGIC[i]);
	}
	for (std::size_t i = 0; i < QUIC_NATT_PROOF_VALUE_LENGTH; ++i) {
		out[QUIC_NATT_PROOF_IDENTITY_OFFSET + i] = userHash[i];
		out[QUIC_NATT_PROOF_VALUE_OFFSET + i] = proofValue[i];
	}

	return true;
}

/**
 * Compare two 16-byte values without an early exit.
 *
 * A comparison that returned at the first differing byte would leak how many
 * leading bytes a guess got right. The identity value is stable rather than
 * per-exchange, which makes that leak worse rather than better: an attacker gets
 * as many attempts as it likes against a target that never rotates, so an oracle
 * it can query is an oracle it can finish. The whole record is 32 bytes -- there
 * is no cost to reading all of it.
 */
inline bool QuicNattValuesEqual(const std::uint8_t *a, const std::uint8_t *b)
{
	std::uint8_t difference = 0;
	for (std::size_t i = 0; i < QUIC_NATT_PROOF_VALUE_LENGTH; ++i) {
		difference = static_cast<std::uint8_t>(difference | (a[i] ^ b[i]));
	}

	return difference == 0;
}

/**
 * Validate a proof received from a peer.
 *
 * The order of the checks is the order of the reasons: length, then magic,
 * then identity. A peer speaking a different protocol is reported as such and
 * not as an impostor, which keeps the one refusal that means somebody tried
 * distinguishable in the log.
 *
 * Both expectations must have come from the peer's ed2k hello and neither may
 * come from the connection being validated. That is not enforceable from inside
 * this function -- it is a property of the caller -- so it is stated at the one
 * place a caller reads: see SQuicPeerExpectation in QuicContext.h, which is the
 * only thing in the tree that fills these two arguments in.
 *
 * @param proof   what the peer sent. May be NULL when length is 0.
 * @param length  its length in bytes.
 * @param expectedUserHash  16 bytes: the user hash of the ed2k identity this
 *        connection is supposed to belong to. NULL means this end has no
 *        expectation, which refuses -- an unestablished expectation must never
 *        wave a connection through.
 * @param expectedValue  16 bytes: the identity value that peer advertised in its
 *        hello. NULL refuses, for the same reason, and it is the ordinary
 *        answer for a peer that advertised none.
 */
inline EQuicProofResult ValidateQuicNattProof(const std::uint8_t *proof,
	std::size_t length,
	const std::uint8_t *expectedUserHash,
	const std::uint8_t *expectedValue)
{
	if (proof == nullptr || length == 0) {
		return QUIC_PROOF_ABSENT;
	}
	if (length < QUIC_NATT_PROOF_LENGTH) {
		return QUIC_PROOF_TRUNCATED;
	}
	if (length > QUIC_NATT_PROOF_LENGTH) {
		return QUIC_PROOF_OVERSIZED;
	}

	for (std::size_t i = 0; i < QUIC_NATT_PROOF_MAGIC_LENGTH; ++i) {
		if (proof[i] != static_cast<std::uint8_t>(QUIC_NATT_PROOF_MAGIC[i])) {
			return QUIC_PROOF_BAD_MAGIC;
		}
	}

	if (expectedUserHash == nullptr || expectedValue == nullptr) {
		return QUIC_PROOF_WRONG_IDENTITY;
	}

	// Both halves are compared even when the first already failed: the
	// refusal is the same either way, and branching on the first would
	// reintroduce the early exit QuicNattValuesEqual() exists to avoid.
	const bool identityMatches =
		QuicNattValuesEqual(proof + QUIC_NATT_PROOF_IDENTITY_OFFSET, expectedUserHash);
	const bool valueMatches = QuicNattValuesEqual(proof + QUIC_NATT_PROOF_VALUE_OFFSET, expectedValue);

	return (identityMatches && valueMatches) ? QUIC_PROOF_VALID : QUIC_PROOF_WRONG_IDENTITY;
}

/**
 * Is this result an authentication failure rather than a transport one?
 *
 * The spec delta requires the distinction in the log, and it is not cosmetic:
 * a transport failure is the network -- a dropped datagram, a NAT that did not
 * hold -- while every refusal in EQuicProofResult is a peer that reached this
 * end and failed to prove who it is. One "QUIC connection failed" line for both
 * makes the second invisible inside the ordinary noise of the first.
 */
inline bool IsQuicAuthenticationFailure(EQuicProofResult result)
{
	return result != QUIC_PROOF_VALID;
}

//! The reason as it appears in a log line. Distinct for every value -- a
//! shared string would put two different events under one name.
inline const char *QuicProofResultName(EQuicProofResult result)
{
	switch (result) {
	case QUIC_PROOF_VALID:
		return "valid";
	case QUIC_PROOF_ABSENT:
		return "no proof sent";
	case QUIC_PROOF_TRUNCATED:
		return "proof truncated";
	case QUIC_PROOF_OVERSIZED:
		return "proof longer than the record";
	case QUIC_PROOF_BAD_MAGIC:
		return "proof magic mismatch";
	case QUIC_PROOF_WRONG_IDENTITY:
		return "proof for a different identity";
	}

	// Unreachable for any declared value; a new one added without a case
	// here reads as unknown rather than borrowing another reason's name.
	return "unknown";
}

#endif // QUICNATTPROTOCOL_H
