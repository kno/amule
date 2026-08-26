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

#include "QuicProofValue.h" // Interface declarations

// CryptoPP_Inc.h is the one place that knows how to include cryptopp under this
// tree's warning gates. It is free of wxWidgets and of theApp, which is what
// lets this translation unit link into a unit test without dragging in an app.
#include "CryptoPP_Inc.h"

#include <cstring>

namespace
{

/**
 * Domain separator, hashed in front of the key material.
 *
 * Without it, the value published here would be the plain fingerprint of the
 * secure-identification public key -- and any other protocol that ever
 * fingerprints that same key the same way would produce the same 16 bytes.
 * Prefixing a purpose string means this value can only ever be replayed as
 * *this* value, which costs one hash block and removes a whole class of
 * cross-protocol confusion before it can exist.
 *
 * The string is this end's own choice and never appears on the wire: only the
 * digest does. It is not an interop constant and eMuleAI does not need to know
 * it -- a peer checks our value against what we advertised, never against a
 * derivation of its own.
 */
const char kQuicProofValueDomain[] = "aMule QUIC NAT-T peer identity v1";

} // namespace

/**
 * SHA-256 over a domain separator and this client's secure-identification
 * public key, truncated to the proof field's 16 bytes.
 *
 * ## Why the public key, and why publishing a fingerprint of it is safe
 *
 * The value has to be stable across restarts, or a peer that learned it from
 * one hello would refuse the next connection -- and it must not be invented per
 * session for the same reason. aMule already keeps exactly one long-lived
 * per-install secret, the secure-identification RSA key in cryptkey.dat, and
 * the *public* half of it is the natural stable identifier: it is already sent
 * in the clear to every peer that completes a secure-identification exchange,
 * so a fingerprint of it discloses nothing that peer did not already have.
 *
 * The private half never enters this function. Nothing here is reversible into
 * key material either, and that is not the load-bearing property -- the input
 * is public -- it just means a captured value cannot be turned into anything
 * else.
 *
 * The corollary is stated in QuicProofValue.h and is worth repeating where the
 * derivation lives: because the input is public and the output is stable, this
 * value is an *identity*, not a secret. It authenticates in the sense that an
 * attacker on the punched UDP hole must have obtained the impersonated peer's
 * ed2k hello over TCP. It does not authenticate in the sense of a fresh
 * challenge, and no derivation from a stable input could.
 *
 * SHA-256 rather than the MD5 aMule uses for its obfuscation keys: nothing on
 * the wire fixes the algorithm -- the peer checks our value against the one we
 * advertised, never against a derivation of its own -- so the choice is free,
 * and there is no reason to pick a broken hash when the input is attacker-known
 * and a preimage or collision would let one install claim another's identity.
 *
 * Truncation to 16 bytes is the proof field's width
 * (QUIC_NATT_PROOF_VALUE_LENGTH), and truncating a SHA-256 digest is a
 * supported construction: the leading 128 bits of the digest are what a
 * 128-bit-output SHA-256 variant would produce.
 */
bool DeriveLocalQuicProofValue(const std::uint8_t *publicKey, std::size_t publicKeyLength, std::uint8_t *out)
{
	if (publicKey == nullptr || publicKeyLength == 0 || out == nullptr) {
		// No key means secure identification never produced one, which is a
		// real state rather than an error: the client then advertises no
		// identity value, no peer can form an expectation for it, and every
		// inbound QUIC connection is refused. That is the fail-closed
		// direction and it costs only the faster path -- the peer falls back
		// to uTP.
		return false;
	}

	CryptoPP::SHA256 hash;
	hash.Update(reinterpret_cast<const CryptoPP::byte *>(kQuicProofValueDomain),
		sizeof(kQuicProofValueDomain) - 1);
	hash.Update(reinterpret_cast<const CryptoPP::byte *>(publicKey), publicKeyLength);

	CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
	hash.Final(digest);

	static_assert(QUIC_NATT_PROOF_VALUE_LENGTH <= CryptoPP::SHA256::DIGESTSIZE,
		"the proof value must fit inside one SHA-256 digest, or the truncation below "
		"would read past it");
	std::memcpy(out, digest, QUIC_NATT_PROOF_VALUE_LENGTH);
	return true;
}
