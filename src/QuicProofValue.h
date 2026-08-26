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

#ifndef QUICPROOFVALUE_H
#define QUICPROOFVALUE_H

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "QuicNattProtocol.h" // Needed for QUIC_NATT_PROOF_VALUE_LENGTH

/**
 * The 16-byte peer identity value that the QUIC proof's second field carries,
 * and the one decision about which end's value goes in it.
 *
 * ## Where the value comes from, and why that is what makes the proof work
 *
 * The proof (QuicNattProtocol.h) is 5 magic bytes plus two 16-byte fields. The
 * first is an ed2k user hash. The second was read, in this change's earlier
 * phase, as a per-exchange nonce -- and that reading is what left
 * CQuicEndpoint::FindExpectation() with no source, because the rendezvous
 * message has no field a nonce could travel in. A real eMuleAI v1.6.0 was then
 * measured on 2026-08-26 and contradicted the nonce reading: in its
 * OP_HELLOANSWER, and only once the peer has advertised CT_MOD_MISCOPTIONS, it
 * sends a tag 0xBF carrying exactly 16 bytes of high-entropy data -- and the
 * bytes were byte-identical across three separate sessions. A nonce is not
 * stable across sessions. A key fingerprint is.
 *
 * So the second field is a *stable peer identity value* that travels in the
 * ed2k hello, and this object is that value, learned per peer.
 *
 * What makes it authentication rather than theatre is that it is
 * **cross-channel**. The value is learned over the ed2k TCP hello; the peer
 * must then reproduce it inside the QUIC proof over UDP. A third party that
 * hijacks a punched hole -- the exact attack this proof exists to stop -- has
 * seen the UDP side and not the TCP one, and cannot guess 16 bytes of entropy.
 *
 * ## What it is NOT, stated because a reader will otherwise assume more
 *
 * A value that is stable per install is not a secret and this proof is not a
 * challenge-response. Anyone who has ever handshaked with a peer, or observed
 * one of its cleartext hellos, knows that peer's value for good. So the
 * property is "the attacker must have seen a hello from the peer it is
 * impersonating", not "the attacker must break a fresh challenge". A
 * per-exchange nonce would have been strictly stronger, and if the rendezvous
 * ever grows a field for one, this is where that change lands.
 *
 * That weaker property is what eMuleAI implements, and interoperating with
 * eMuleAI is what this change exists for -- a stronger proof neither side could
 * complete would authenticate nothing at all. It is also strictly better than
 * the state it replaces, which was that no inbound QUIC connection could
 * authenticate under any circumstances.
 *
 * Header-only and free of ngtcp2, GnuTLS, wxWidgets and theApp, for the same
 * reason as QuicNattProtocol.h: this is decidable without a TLS handshake and
 * has to be assertable in a -DENABLE_QUIC=NO build, which is the default build
 * and the only one macOS gets. Deriving *this* client's own value needs a hash
 * function and therefore a translation unit -- see QuicProofValue.cpp.
 */
class CQuicProofValue
{
public:
	CQuicProofValue() = default;

	/**
	 * Store a value read off the wire.
	 *
	 * @param bytes  the tag payload. May be NULL.
	 * @param length its length. Anything but QUIC_NATT_PROOF_VALUE_LENGTH is
	 *        refused.
	 * @return false when nothing was stored.
	 *
	 * A refusal leaves any value already learned untouched. That direction is
	 * deliberate: a malformed tag in a later handshake must not be able to
	 * erase a good value learned earlier, because erasing it would downgrade
	 * every subsequent QUIC connection from that peer to an authentication
	 * refusal -- a peer could do that to itself by accident, and a third party
	 * spoofing a hello could do it on purpose.
	 */
	bool SetFromWire(const std::uint8_t *bytes, std::size_t length)
	{
		if (bytes == nullptr || length != QUIC_NATT_PROOF_VALUE_LENGTH) {
			return false;
		}

		std::memcpy(m_bytes, bytes, QUIC_NATT_PROOF_VALUE_LENGTH);
		m_present = true;
		return true;
	}

	/**
	 * Whether a value was ever learned.
	 *
	 * Absence is a state of its own and not sixteen zero bytes. That is the
	 * fail-closed property the whole change rests on: a peer that advertised
	 * nothing must produce no expectation at all, because an expectation of
	 * sixteen zeroes is one any third party can satisfy.
	 */
	bool IsPresent() const { return m_present; }

	//! The 16 bytes, or NULL when absent. NULL rather than a zero buffer so
	//! that a caller which forgets to test IsPresent() reaches
	//! BuildQuicNattProof()/ValidateQuicNattProof(), both of which refuse a
	//! NULL -- the mistake fails closed instead of validating.
	const std::uint8_t *Bytes() const { return m_present ? m_bytes : nullptr; }

	void Reset()
	{
		m_present = false;
		std::memset(m_bytes, 0, QUIC_NATT_PROOF_VALUE_LENGTH);
	}

private:
	std::uint8_t m_bytes[QUIC_NATT_PROOF_VALUE_LENGTH] = {};
	bool m_present = false;
};

/**
 * Whose value the proof's second field carries.
 *
 * This is the one genuine ambiguity in the measured evidence, and it is
 * recorded as an enumeration rather than resolved inline because nothing
 * observable distinguishes a wrong answer from a peer that is simply offline:
 * a mismatched second field is an authentication refusal, which looks exactly
 * like the QUIC handshake never completing. Both values are unguessable to a
 * third party that never saw the corresponding hello, so both are defensible as
 * authentication; only one interoperates.
 */
enum EQuicProofValueDirection
{
	//! The proof carries the value its *sender* advertised in its own hello.
	QUIC_PROOF_VALUE_SENDER_ADVERTISED,
	//! The proof carries the value its *recipient* advertised, i.e. the sender
	//! echoes back what it learned from the other end.
	QUIC_PROOF_VALUE_RECIPIENT_ADVERTISED
};

/**
 * The shipped choice: the sender's own advertised value.
 *
 * The reason is the proof's other field. BuildQuicNattProof() takes "this
 * client's ed2k user hash" -- the sender's own identity, not the recipient's --
 * and a 37-byte record whose two fields described different ends would be a
 * record neither end could describe in one sentence. Read as sender-side
 * throughout, the proof says one thing: "I am this ed2k identity, and here is
 * the identity value that identity published." The recipient checks both
 * against what it learned from that peer's hello, so the expectation is
 * entirely peer-side and nothing in it comes from the connection being
 * validated.
 *
 * The evidence does not settle it and the interop test may contradict it. That
 * is why this is a constant and every call site goes through
 * SelectQuicProofValue(): flipping the decision is changing this one
 * initialiser, and QuicProofValueTest asserts both branches of the selection so
 * the other direction is not untested code the day it is needed.
 */
constexpr EQuicProofValueDirection kQuicProofValueDirection = QUIC_PROOF_VALUE_SENDER_ADVERTISED;

/**
 * The bytes to put in the proof this end is about to send.
 *
 * @param locallyAdvertised  the value this client published in its own hello.
 * @param peerAdvertised     the value the peer published in its hello.
 * @return the 16 bytes, or NULL when the value the direction selects was never
 *         learned. NULL is the fail-closed answer and it propagates:
 *         BuildQuicNattProof() refuses a NULL, so no proof goes out at all
 *         rather than a proof with an empty field.
 */
inline const std::uint8_t *SelectQuicProofValue(const CQuicProofValue &locallyAdvertised,
	const CQuicProofValue &peerAdvertised,
	EQuicProofValueDirection direction)
{
	return (direction == QUIC_PROOF_VALUE_SENDER_ADVERTISED) ? locallyAdvertised.Bytes()
								 : peerAdvertised.Bytes();
}

/**
 * The bytes an inbound connection's proof must match.
 *
 * The sender of an inbound connection is the peer, so this is
 * SelectQuicProofValue() with the two arguments swapped -- and it is a named
 * function rather than that swap spelled out at the call site, because getting
 * the swap backwards would produce an expectation this end could satisfy
 * itself. That is precisely the "validator that passes everything while looking
 * like authentication" this change is required not to build.
 *
 * @param locallyAdvertised  what this client published. Used only under the
 *        recipient-advertised direction.
 * @param peerAdvertised     what the peer published in its ed2k hello. This is
 *        the value under the shipped direction.
 */
inline const std::uint8_t *ExpectedQuicProofValueFromPeer(
	const CQuicProofValue &locallyAdvertised, const CQuicProofValue &peerAdvertised)
{
	return SelectQuicProofValue(peerAdvertised, locallyAdvertised, kQuicProofValueDirection);
}

/**
 * Derive this client's own stable identity value.
 *
 * Implemented in QuicProofValue.cpp: it needs a hash function, which a header
 * that must stay includable in a build with no crypto dependency cannot have.
 * See that file for what it hashes and why publishing the result is safe.
 *
 * @param publicKey  this client's secure-identification public key, from
 *        CClientCreditsList::GetPublicKey(). May be NULL.
 * @param publicKeyLength its length. Zero refuses.
 * @param out  receives QUIC_NATT_PROOF_VALUE_LENGTH bytes. Untouched unless
 *        true is returned.
 * @return false when there is no key to derive from -- which is a real state,
 *         not an error: secure identification can be off, and a client with no
 *         key advertises no identity value and so serves no QUIC connection.
 */
bool DeriveLocalQuicProofValue(const std::uint8_t *publicKey, std::size_t publicKeyLength, std::uint8_t *out);

#endif // QUICPROOFVALUE_H
