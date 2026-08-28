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

#ifndef UTPENCRYPTIONPOLICY_H
#define UTPENCRYPTIONPOLICY_H

#include <cstdint>

#include <protocol/Protocols.h> // Needed for OP_NATT_FRAME_UTP / OP_NATT_FRAME_QUIC

#include "NetworkAddress.h" // Needed for CNetworkAddress::IsGloballyRoutableIPv4

/**
 * Whether one outbound OP_UDPRESERVEDPROT2 frame is wrapped in aMule's eD2k UDP
 * obfuscation before it leaves the shared client UDP socket.
 *
 * The receive path in CClientUDPSocket::OnPacketReceived() has always run every
 * datagram through CEncryptedDatagramSocket::DecryptReceivedClient(), so this
 * client already accepts an obfuscated NAT-traversal frame from a peer. The
 * send path did not produce one: SendUtpDatagram() passed @c bEncrypt=false and
 * said "never obfuscated". This function is the missing half, and it is a
 * function with a test rather than a condition inside the socket because of
 * what a wrong answer looks like.
 *
 * @par Why a wrong answer is invisible
 * The eD2k UDP obfuscation key is not symmetric in the way "encrypt with the
 * peer's hash" suggests. EncryptedDatagramSocket.cpp derives the sending key as
 * MD5(<receiver user hash 16><@b sender @b IP 4><0x5B><random key part 2>) and
 * the receiving key as MD5(<@b own @b user @b hash 16><@b source @b IP @b of
 * @b the @b datagram 4><0x5B><the same random key part 2>). The two agree only
 * when the sender's idea of its own address is the address the peer observes.
 * When they disagree the RC4 stream differs, the magic value never matches,
 * DecryptReceivedClient() returns the buffer untouched, and the frame reaches
 * libutp as noise. Nothing is logged at either end, because a frame that failed
 * to deobfuscate is byte-for-byte indistinguishable from a peer that chose to
 * send plaintext. The connection simply never establishes.
 *
 * @par The address that must not be used
 * CamuleApp::GetPublicIP(bool ignorelocal) defaults @c ignorelocal to @b false,
 * and on that path -- no address from a server, Kad not connected -- it returns
 * @c m_localip, which amule.cpp:654 sets from @c StringHosttoUint32(
 * ::wxGetFullHostName()). On a Debian host that resolves through /etc/hosts to
 * @c 127.0.1.1. A bare @c GetPublicIP() therefore answers "yes, 127.0.1.1" to
 * the question "do I know my public address", the gate opens, and every frame
 * is obfuscated with a key no peer on earth can reproduce.
 *
 * So this policy takes @c GetPublicIP(true) -- absence reported as zero rather
 * than as the local address -- and then asks separately whether the address is
 * one a stranger could send a reply to. The second question is not redundant:
 * @c m_dwPublicIP itself is only asserted to be a high ID
 * (CamuleApp::SetPublicIP), and a LAN-local ed2k server or a carrier-grade NAT
 * deployment can put a private or shared address in it. Non-zero has never
 * meant routable.
 *
 * @note aMule's own eD2k UDP path carries the same hazard in
 *       CMuleUDPSocket::SendControlData() and in
 *       CUpDownClient::ShouldReceiveCryptUDPPackets(), both of which read the
 *       bare form. That is upstream behaviour affecting eD2k traffic and is
 *       deliberately left alone here; this policy only governs the NAT
 *       traversal frames, and it is strictly stricter than the socket's own
 *       gate, so opening it can never conflict with the check below it.
 */

//! Why the frame went out the way it did. Recorded so a log line -- and a
//! failing test -- can name the reason rather than saying "not obfuscated" for
//! seven different situations.
enum ENattFrameObfuscationRefusal
{
	//! The obfuscation is applied to this frame.
	NATT_OBFUSCATE_APPLY,
	//! QUIC. Never obfuscated, whatever the rest of the inputs say: the
	//! payload is already TLS ciphertext, so wrapping it buys nothing, and the
	//! frame type byte would stop being readable by a peer that has to decide
	//! which transport the datagram belongs to.
	NATT_OBFUSCATE_FRAME_CARRIES_ITS_OWN_ENCRYPTION,
	//! A frame type this policy does not carry an answer for. Plaintext, which
	//! is what every OP_UDPRESERVEDPROT2 frame was before this change.
	NATT_OBFUSCATE_FRAME_TYPE_NOT_GOVERNED,
	//! This client has the crypt layer switched off in its preferences.
	NATT_OBFUSCATE_CRYPT_LAYER_DISABLED_LOCALLY,
	//! No CUpDownClient is recorded for this endpoint, so there is no user
	//! hash to key with. Ordinary rather than exceptional: libutp emits
	//! datagrams from a callback that knows an address and a port and nothing
	//! else, and a peer can leave the list while frames are still in flight.
	NATT_OBFUSCATE_PEER_NOT_IDENTIFIED,
	//! The peer is known but its user hash is not, which is the same missing
	//! key by another route.
	NATT_OBFUSCATE_PEER_HASH_UNKNOWN,
	//! The peer never advertised the crypt layer, so it would not try to
	//! deobfuscate what it received.
	NATT_OBFUSCATE_PEER_DOES_NOT_SUPPORT_CRYPT_LAYER,
	//! Both ends can, but neither asked for it.
	NATT_OBFUSCATE_NOT_REQUESTED_BY_EITHER_END,
	//! No public address is known yet -- the ordinary state of a client that
	//! has not finished firewall detection, and the state a bare
	//! GetPublicIP() hides behind the local address.
	NATT_OBFUSCATE_NO_PUBLIC_ADDRESS,
	//! An address is known but it is not one a peer could reply to: loopback,
	//! RFC1918, link-local, carrier-grade NAT, a documentation block, or
	//! anything above the unicast space. Keying with it would produce frames
	//! that decrypt to noise at the far end with nothing logged anywhere.
	NATT_OBFUSCATE_PUBLIC_ADDRESS_NOT_ROUTABLE
};

/**
 * Everything the decision reads, in one struct rather than as eight positional
 * arguments. The neighbouring policies in this tree (UtpDialPolicy.h,
 * NatTraversalPolicy.h) pass their inputs positionally because they have three
 * or four; at this width a caller that transposes two booleans would still
 * compile and would silently obfuscate for the wrong reason, which is exactly
 * the class of mistake this whole file exists to prevent.
 */
struct SNattFrameObfuscationInputs
{
	//! The byte after OP_UDPRESERVEDPROT2: OP_NATT_FRAME_UTP or
	//! OP_NATT_FRAME_QUIC.
	std::uint8_t frameType = OP_NATT_FRAME_UTP;

	/**
	 * @c theApp->GetPublicIP(true), in aMule's anti-host order.
	 *
	 * The @c true is the whole point and must not be dropped: see the class
	 * comment above. Zero means "not known", which is what the argument buys.
	 */
	std::uint32_t publicIpIgnoringLocal = 0;

	//! @c thePrefs::IsClientCryptLayerSupported().
	bool cryptLayerSupportedLocally = false;

	//! A CUpDownClient was found for this endpoint by
	//! CClientList::FindClientByUDPEndpoint().
	bool peerIdentified = false;

	//! @c CUpDownClient::HasValidHash() -- the key the obfuscation needs.
	bool peerHashKnown = false;

	//! @c CUpDownClient::SupportsCryptLayer().
	bool peerSupportsCryptLayer = false;

	//! @c thePrefs::IsClientCryptLayerRequested() @c || @c
	//! CUpDownClient::RequestsCryptLayer(). The same disjunction
	//! CUpDownClient::ShouldReceiveCryptUDPPackets() uses for eD2k UDP, so a
	//! peer pair that obfuscates its eD2k datagrams obfuscates its NAT
	//! traversal frames too.
	bool cryptLayerRequestedByEitherEnd = false;
};

/** The answer, and the reason for it. */
struct SNattFrameObfuscationDecision
{
	//! Pass @c bEncrypt=true and the peer's user hash to
	//! CMuleUDPSocket::SendPacket().
	bool obfuscate = false;
	ENattFrameObfuscationRefusal refusal = NATT_OBFUSCATE_FRAME_TYPE_NOT_GOVERNED;
};

/**
 * Decide whether one NAT traversal frame is obfuscated on the way out.
 *
 * Opportunistic in both directions and deliberately so. Every refusal below
 * yields plaintext rather than a dropped frame, because the receiving half of
 * this protocol accepts both forms: DecryptReceivedClient() passes a datagram
 * whose first byte is OP_UDPRESERVEDPROT2 straight through, so a plaintext
 * frame arrives intact at a peer that would have been happy to decrypt one.
 * Refusing to send at all would turn a privacy improvement into a
 * connectivity regression.
 */
inline SNattFrameObfuscationDecision DecideNattFrameObfuscation(const SNattFrameObfuscationInputs &inputs)
{
	SNattFrameObfuscationDecision decision;

	// Frame type first, because for QUIC no other input can change the answer.
	// Obfuscating a QUIC frame would encrypt ciphertext to no end and would
	// hide the frame type byte from the peer's transport demultiplexer.
	if (inputs.frameType == OP_NATT_FRAME_QUIC) {
		decision.refusal = NATT_OBFUSCATE_FRAME_CARRIES_ITS_OWN_ENCRYPTION;
		return decision;
	}
	if (inputs.frameType != OP_NATT_FRAME_UTP) {
		// A frame type added later, or the rendezvous control frames, which
		// this policy has no answer for. Plaintext is the behaviour that
		// predates this file, so an unhandled type keeps it.
		decision.refusal = NATT_OBFUSCATE_FRAME_TYPE_NOT_GOVERNED;
		return decision;
	}

	if (!inputs.cryptLayerSupportedLocally) {
		decision.refusal = NATT_OBFUSCATE_CRYPT_LAYER_DISABLED_LOCALLY;
		return decision;
	}

	if (!inputs.peerIdentified) {
		decision.refusal = NATT_OBFUSCATE_PEER_NOT_IDENTIFIED;
		return decision;
	}

	if (!inputs.peerHashKnown) {
		decision.refusal = NATT_OBFUSCATE_PEER_HASH_UNKNOWN;
		return decision;
	}

	if (!inputs.peerSupportsCryptLayer) {
		decision.refusal = NATT_OBFUSCATE_PEER_DOES_NOT_SUPPORT_CRYPT_LAYER;
		return decision;
	}

	if (!inputs.cryptLayerRequestedByEitherEnd) {
		decision.refusal = NATT_OBFUSCATE_NOT_REQUESTED_BY_EITHER_END;
		return decision;
	}

	// The two questions about our own address, in this order so the reason
	// distinguishes "we do not know it yet" from "we know it and it is
	// useless". Both are ordinary; only the second is the one that used to
	// pass.
	if (inputs.publicIpIgnoringLocal == 0) {
		decision.refusal = NATT_OBFUSCATE_NO_PUBLIC_ADDRESS;
		return decision;
	}

	// The routability test lives on CNetworkAddress rather than as octet
	// comparisons here, next to the IPv6 rule it mirrors, so that a range added
	// to one is not forgotten by the other.
	if (!CNetworkAddress::FromIPv4NetworkOrder(inputs.publicIpIgnoringLocal).IsGloballyRoutableIPv4()) {
		decision.refusal = NATT_OBFUSCATE_PUBLIC_ADDRESS_NOT_ROUTABLE;
		return decision;
	}

	decision.obfuscate = true;
	decision.refusal = NATT_OBFUSCATE_APPLY;
	return decision;
}

#endif // UTPENCRYPTIONPOLICY_H
