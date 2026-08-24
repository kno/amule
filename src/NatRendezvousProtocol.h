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

#ifndef NATRENDEZVOUSPROTOCOL_H
#define NATRENDEZVOUSPROTOCOL_H

#include <cstddef>
#include <cstdint>

#include <protocol/Protocols.h> // Needed for OP_UDPRESERVEDPROT2 / OP_NATT_FRAME_UTP

#include "NetworkAddress.h" // Needed for CNetworkAddress

/**
 * The rendezvous and hole-punch control messages, and their bounds.
 *
 * ## Where these bytes sit in a datagram
 *
 * A control message is not a datagram of its own. It rides the frame type the
 * uTP transport already shares the ed2k UDP port with:
 *
 *     [0] 0xB2  OP_UDPRESERVEDPROT2
 *     [1] 0x00  OP_NATT_FRAME_UTP
 *     [2] ..    one control message, first byte an opcode below
 *
 * That is deliberate rather than economical. The NAT mapping a punch opens is
 * the mapping the ed2k UDP port already has, so the hole that is punched is the
 * hole uTP will use -- a control message on a port of its own would open a
 * mapping the transport cannot reach through.
 *
 * The two parsers on that port do not collide, because libutp is offered every
 * 0xB2/0x00 datagram first (see UtpDatagramRouting.h) and declines these. A
 * libutp v1 header's first byte is `type << 4 | version` with version 1 and
 * type 0..4, so the legal first bytes are 0x01, 0x11, 0x21, 0x31 and 0x41.
 * None of the three opcodes below can be one of those: 0xA0, 0xA1 and 0xAA all
 * decode to version 0 or version 10, which libutp rejects. So the classification
 * is unambiguous in both directions and neither side has to know about the
 * other's payloads.
 *
 * ## Why the numbers are literals and not settings
 *
 * The opcodes and option bits are eMuleAI's (srchybrid/Opcodes.h) and are wire
 * format: an opcode off by one is a frame the peer drops, and a drop behind a
 * NAT looks exactly like the NAT not opening.
 *
 * The four bounds are a different kind of fixed. A rendezvous asks a third
 * party to send packets toward an address the requester named, which is the
 * shape of a reflector. The attempt count and the total budget are what stop
 * that being unbounded, and the backoff is what stops a failed traversal
 * costing the source. They are safety limits, not performance knobs; raising
 * them is a change to the security argument, not a tuning decision.
 *
 * Header-only and free of theApp and of wxWidgets, for the same reason as
 * ReservedProtocolFrames.h: the socket classes that carry these bytes cannot be
 * linked into a unit test, and every byte here has to be assertable.
 */

//! Control opcodes carried inside an OP_NATT_FRAME_UTP frame. A separate
//! namespace from Protocols and from the ed2k opcodes -- 0xA0 is
//! OP_SERVER_LIST_REQ as a Client2Server UDP opcode and OP_BUDDYPONG as a
//! Client2Client TCP one, and neither has anything to do with this.
enum ENattControlOpcodes : uint8_t
{
	//! A → R: relay a rendezvous to the named peer.
	OP_RENDEZVOUS = 0xA0,
	//! A → B: a packet whose only job is to open the mapping in A's NAT.
	OP_HOLEPUNCH = 0xA1,
	//! The observed external endpoint of the sender, as a candidate.
	OP_NATT_ENDPOINT_HINT = 0xAA
};

//! Bits in the connect-options byte that follows a control opcode.
enum ENattConnectOptions : uint8_t
{
	//! An OP_NATT_ENDPOINT_HINT element follows the fixed part of the message.
	CONNECT_OPT_NATT_ENDPOINT_HINT = 0x20,
	/**
	 * This OP_RENDEZVOUS was forwarded by a relay: act on it, do not relay it
	 * on.
	 *
	 * A relay request (A to R) and a relayed rendezvous (R to B) carry the same
	 * opcode and the same fields and mean opposite things. Confusing them is
	 * not a cosmetic error: a client that read a relay request as a forward
	 * would start punching toward the address inside the datagram, which is
	 * exactly the reflection the relay validation exists to prevent. So the
	 * direction is explicit, and the *absence* of this bit is what the relay
	 * path requires -- a crafted request cannot reach the acting path at all.
	 *
	 * 0x40 is the one value in this header the proposal does not pin, and
	 * eMuleAI's use of that bit is unknown to this tree. It travels only inside
	 * a message that exists only between peers that advertised
	 * MOD_MISCOPT_NAT_TRAVERSAL, so no unaware client parses it -- but it is
	 * the value an interop check against eMuleAI could contradict, and the
	 * alternative (inferring the direction from local state) would have left
	 * the acting path reachable by a crafted request.
	 */
	CONNECT_OPT_NATT_RELAYED = 0x40,
	//! The traversal being asked for is the uTP one. Set on every message this
	//! build sends, because uTP is the only transport it can serve.
	CONNECT_OPT_NAT_TRAVERSAL_UTP = 0x80
};

//! At most five hole-punch attempts for one pair. A safety limit: see above.
constexpr uint32_t kRendezvousMaxAttempts = 5;

//! And at most 120 seconds of them, whichever comes first.
constexpr uint32_t kRendezvousTotalBudgetMs = 120000;

//! After exhaustion, wait a minute before trying that pair again. The source
//! stays queued throughout -- that is what the backoff is for.
constexpr uint32_t kRendezvousBackoffMs = 60000;

//! How long a peer that advertised QUIC NAT-T is given to answer on the QUIC
//! frame type before the exchange falls back to the legacy uTP frame type
//! (OP_NATT_FRAME_UTP, 0x00).
constexpr uint32_t kNattFrameTypeFallbackWaitMs = 1500;

//! An ed2k user hash, the identity a control message names.
constexpr size_t NATT_PEER_HASH_LENGTH = 16;

//! Family byte values inside an endpoint hint. The value is the address family
//! number as humans write it, not AF_INET/AF_INET6, whose numbering differs
//! between operating systems and would make the wire format host-dependent.
enum ENattAddressFamilyByte : uint8_t
{
	NATT_FAMILY_IPV4 = 0x04,
	NATT_FAMILY_IPV6 = 0x06
};

//! Encoded lengths. Fixed per family, so nothing here needs a length prefix.
constexpr size_t NATT_ENDPOINT_HINT_IPV4_LENGTH = 8;  // opcode, family, 4, port
constexpr size_t NATT_ENDPOINT_HINT_IPV6_LENGTH = 20; // opcode, family, 16, port
constexpr size_t NATT_ENDPOINT_HINT_MAX_LENGTH = NATT_ENDPOINT_HINT_IPV6_LENGTH;

//! opcode, options, hash.
constexpr size_t NATT_RENDEZVOUS_FIXED_LENGTH = 2 + NATT_PEER_HASH_LENGTH;
constexpr size_t NATT_RENDEZVOUS_MAX_LENGTH =
	NATT_RENDEZVOUS_FIXED_LENGTH + NATT_ENDPOINT_HINT_MAX_LENGTH;

//! opcode, options, hash. A hole punch carries no hint: the mapping it opens is
//! observed by the receiver, which is worth more than anything the sender could
//! claim about it.
constexpr size_t NATT_HOLEPUNCH_LENGTH = 2 + NATT_PEER_HASH_LENGTH;

//! Which control message a frame carries.
enum ENattControlKind
{
	NATT_CONTROL_RENDEZVOUS,
	NATT_CONTROL_HOLEPUNCH,
	NATT_CONTROL_ENDPOINT_HINT,
	//! Not one of the three. Drop it; do not guess at a length.
	NATT_CONTROL_NOT_A_CONTROL_MESSAGE
};

//! A parsed endpoint hint.
struct SNattEndpointHint
{
	CNetworkAddress address;
	uint16_t port = 0;
	//! Bytes the hint occupied, so a caller parsing a message that embeds one
	//! knows where the hint ended without recomputing the family's length.
	size_t consumed = 0;
};

//! A parsed OP_RENDEZVOUS message.
struct SNattRendezvousRequest
{
	//! The other side of the pair: the peer to relay to when this arrives at a
	//! relay, and the peer that asked when the relay forwards it on.
	uint8_t peerHash[NATT_PEER_HASH_LENGTH] = { 0 };
	//! CONNECT_OPT_NAT_TRAVERSAL_UTP was set.
	bool requestsUtpTraversal = false;
	//! CONNECT_OPT_NATT_RELAYED was set: a relay forwarded this, so it is to be
	//! acted on rather than relayed on.
	bool isRelayed = false;
	//! CONNECT_OPT_NATT_ENDPOINT_HINT was set *and* a well-formed hint
	//! followed. The two are never reported apart: a set bit with nothing
	//! behind it is a malformed message and ParseRendezvousRequest() rejects
	//! the whole thing rather than reporting a hint it did not read.
	bool hasEndpointHint = false;
	//! Absent unless hasEndpointHint. Never fabricated, never all-zero: an
	//! unspecified address is not an endpoint, and CNetworkAddress keeps the
	//! two distinguishable.
	CNetworkAddress hintAddress;
	uint16_t hintPort = 0;
};

//! A parsed OP_HOLEPUNCH message.
struct SNattHolePunch
{
	//! Who sent it, so the receiver can pair the packet with the rendezvous it
	//! agreed to rather than with the address it arrived from -- which is
	//! precisely the thing a NAT rewrites.
	uint8_t senderHash[NATT_PEER_HASH_LENGTH] = { 0 };
	bool requestsUtpTraversal = false;
};

/**
 * Classify the first byte of an OP_NATT_FRAME_UTP payload.
 *
 * Reads frame[0] and nothing else. An opcode this protocol does not define is
 * NATT_CONTROL_NOT_A_CONTROL_MESSAGE -- which is also what a uTP data payload
 * that reached here would be, so the caller drops it either way.
 */
inline ENattControlKind ClassifyNattControlMessage(const uint8_t *frame, size_t frameLength)
{
	if (frame == nullptr || frameLength == 0) {
		return NATT_CONTROL_NOT_A_CONTROL_MESSAGE;
	}

	switch (frame[0]) {
	case OP_RENDEZVOUS:
		return NATT_CONTROL_RENDEZVOUS;
	case OP_HOLEPUNCH:
		return NATT_CONTROL_HOLEPUNCH;
	case OP_NATT_ENDPOINT_HINT:
		return NATT_CONTROL_ENDPOINT_HINT;
	default:
		return NATT_CONTROL_NOT_A_CONTROL_MESSAGE;
	}
}

/**
 * Write an OP_NATT_ENDPOINT_HINT element.
 *
 * @return bytes written, or 0 when nothing was written. Zero on an absent
 *         address, on a zero port, and on an output buffer too small -- in
 *         every one of those cases the buffer is left untouched. Writing what
 *         fits would put a half-built element on the wire, and encoding an
 *         absent address as eight zero bytes would produce a hint of
 *         0.0.0.0:0 that the far side would dutifully punch at.
 */
inline size_t EncodeEndpointHint(
	const CNetworkAddress &address, uint16_t port, uint8_t *out, size_t outLength)
{
	if (out == nullptr || port == 0 || address.IsAbsent() || address.IsUnspecified()) {
		return 0;
	}

	// A mapped IPv4 address goes out as IPv4: the peer has to punch at an
	// endpoint, and ::ffff:192.0.2.10 is not one an IPv4 socket can send to.
	const CNetworkAddress unmapped = address.Unmapped();

	if (unmapped.IsIPv4()) {
		if (outLength < NATT_ENDPOINT_HINT_IPV4_LENGTH) {
			return 0;
		}
		uint32_t hostOrder = 0;
		if (!unmapped.ToIPv4HostOrder(hostOrder)) {
			return 0;
		}
		out[0] = OP_NATT_ENDPOINT_HINT;
		out[1] = NATT_FAMILY_IPV4;
		out[2] = static_cast<uint8_t>((hostOrder >> 24) & 0xFF);
		out[3] = static_cast<uint8_t>((hostOrder >> 16) & 0xFF);
		out[4] = static_cast<uint8_t>((hostOrder >> 8) & 0xFF);
		out[5] = static_cast<uint8_t>(hostOrder & 0xFF);
		out[6] = static_cast<uint8_t>((port >> 8) & 0xFF);
		out[7] = static_cast<uint8_t>(port & 0xFF);
		return NATT_ENDPOINT_HINT_IPV4_LENGTH;
	}

	if (!unmapped.IsIPv6() || outLength < NATT_ENDPOINT_HINT_IPV6_LENGTH) {
		return 0;
	}

	uint8_t bytes[16];
	if (!unmapped.ToIPv6Bytes(bytes)) {
		return 0;
	}
	out[0] = OP_NATT_ENDPOINT_HINT;
	out[1] = NATT_FAMILY_IPV6;
	for (size_t i = 0; i < 16; ++i) {
		out[2 + i] = bytes[i];
	}
	out[18] = static_cast<uint8_t>((port >> 8) & 0xFF);
	out[19] = static_cast<uint8_t>(port & 0xFF);
	return NATT_ENDPOINT_HINT_IPV6_LENGTH;
}

/**
 * Read an OP_NATT_ENDPOINT_HINT element.
 *
 * @param frame points at the hint's opcode byte.
 * @param frameLength bytes available from there. Every field boundary is
 *        checked before the field is read: a hint is the one part of this
 *        protocol whose payload becomes a destination address, so a parser that
 *        reads one byte past a short datagram punches at whatever was next in
 *        memory.
 * @param out written only on success.
 * @return false for a truncated element, a foreign opcode, an unknown family
 *         byte, a zero port or an unspecified address. An unknown family is
 *         malformed rather than "a hint of unknown length": the length is a
 *         function of the family and there is nothing to skip past.
 */
inline bool ParseEndpointHint(const uint8_t *frame, size_t frameLength, SNattEndpointHint &out)
{
	if (frame == nullptr || frameLength < 2 || frame[0] != OP_NATT_ENDPOINT_HINT) {
		return false;
	}

	if (frame[1] == NATT_FAMILY_IPV4) {
		if (frameLength < NATT_ENDPOINT_HINT_IPV4_LENGTH) {
			return false;
		}
		const uint32_t hostOrder = (static_cast<uint32_t>(frame[2]) << 24) |
					   (static_cast<uint32_t>(frame[3]) << 16) |
					   (static_cast<uint32_t>(frame[4]) << 8) |
					   static_cast<uint32_t>(frame[5]);
		const uint16_t port = static_cast<uint16_t>((frame[6] << 8) | frame[7]);
		const CNetworkAddress address = CNetworkAddress::FromIPv4HostOrder(hostOrder);
		if (port == 0 || address.IsUnspecified()) {
			return false;
		}
		out.address = address;
		out.port = port;
		out.consumed = NATT_ENDPOINT_HINT_IPV4_LENGTH;
		return true;
	}

	if (frame[1] == NATT_FAMILY_IPV6) {
		if (frameLength < NATT_ENDPOINT_HINT_IPV6_LENGTH) {
			return false;
		}
		// FromIPv6Bytes() answers absent for all-zero, which is `::` and not
		// an endpoint. That is the check, so it is not repeated here.
		const CNetworkAddress address = CNetworkAddress::FromIPv6Bytes(frame + 2);
		const uint16_t port = static_cast<uint16_t>((frame[18] << 8) | frame[19]);
		if (port == 0 || address.IsAbsent()) {
			return false;
		}
		out.address = address;
		out.port = port;
		out.consumed = NATT_ENDPOINT_HINT_IPV6_LENGTH;
		return true;
	}

	return false;
}

/**
 * Write an OP_RENDEZVOUS message.
 *
 * @param peerHash NATT_PEER_HASH_LENGTH bytes naming the other side of the
 *        pair.
 * @param ownEndpoint this end's believed external address, or an absent
 *        address when it is not known. When it cannot be encoded the hint bit
 *        is left clear -- a set bit with no element behind it is what makes the
 *        receiving parser read past the end of the datagram.
 * @return bytes written, 0 on failure with the buffer untouched.
 */
inline size_t EncodeRendezvousMessage(const uint8_t *peerHash,
	const CNetworkAddress &endpoint,
	uint16_t port,
	bool relayed,
	uint8_t *out,
	size_t outLength)
{
	if (out == nullptr || peerHash == nullptr || outLength < NATT_RENDEZVOUS_FIXED_LENGTH) {
		return 0;
	}

	// The hint is encoded into a local buffer first, so the options byte can
	// state what is actually there rather than what the caller intended.
	uint8_t hint[NATT_ENDPOINT_HINT_MAX_LENGTH];
	const size_t hintLength = EncodeEndpointHint(endpoint, port, hint, sizeof(hint));
	if (outLength < NATT_RENDEZVOUS_FIXED_LENGTH + hintLength) {
		return 0;
	}
	if (relayed && hintLength == 0) {
		// A forward with no endpoint in it gives the receiver nothing to punch
		// toward, so it is not encoded at all rather than encoded empty.
		return 0;
	}

	out[0] = OP_RENDEZVOUS;
	out[1] = static_cast<uint8_t>(CONNECT_OPT_NAT_TRAVERSAL_UTP |
		(relayed ? CONNECT_OPT_NATT_RELAYED : 0) |
		(hintLength != 0 ? CONNECT_OPT_NATT_ENDPOINT_HINT : 0));
	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		out[2 + i] = peerHash[i];
	}
	for (size_t i = 0; i < hintLength; ++i) {
		out[NATT_RENDEZVOUS_FIXED_LENGTH + i] = hint[i];
	}
	return NATT_RENDEZVOUS_FIXED_LENGTH + hintLength;
}

//! A rendezvous request: A asking a relay to reach the peer named by
//! @a peerHash, and stating its own believed external endpoint.
inline size_t EncodeRendezvousRequest(const uint8_t *peerHash,
	const CNetworkAddress &ownEndpoint,
	uint16_t ownPort,
	uint8_t *out,
	size_t outLength)
{
	return EncodeRendezvousMessage(peerHash, ownEndpoint, ownPort, false, out, outLength);
}

/**
 * A relayed rendezvous: a relay telling @a peerHash's counterpart where the
 * requester was observed to be.
 *
 * @param peerHash the requester's identity, from the relay's own client list.
 * @param observedEndpoint the endpoint the relay OBSERVED the request arrive
 *        from -- never one the request claimed.
 */
inline size_t EncodeRelayedRendezvous(const uint8_t *peerHash,
	const CNetworkAddress &observedEndpoint,
	uint16_t observedPort,
	uint8_t *out,
	size_t outLength)
{
	return EncodeRendezvousMessage(peerHash, observedEndpoint, observedPort, true, out, outLength);
}

/**
 * Read an OP_RENDEZVOUS message.
 *
 * Bytes after the message this build understands are ignored rather than
 * rejected, so a later eMuleAI revision that appends a field is still parseable
 * here. A *missing* field is the opposite case and is rejected.
 *
 * @return false for a truncated message, a foreign opcode, or a hint bit whose
 *         element is absent or malformed.
 */
inline bool ParseRendezvousRequest(
	const uint8_t *frame, size_t frameLength, SNattRendezvousRequest &out)
{
	if (frame == nullptr || frameLength < NATT_RENDEZVOUS_FIXED_LENGTH ||
		frame[0] != OP_RENDEZVOUS) {
		return false;
	}

	SNattRendezvousRequest parsed;
	parsed.requestsUtpTraversal = (frame[1] & CONNECT_OPT_NAT_TRAVERSAL_UTP) != 0;
	parsed.isRelayed = (frame[1] & CONNECT_OPT_NATT_RELAYED) != 0;
	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		parsed.peerHash[i] = frame[2 + i];
	}

	if ((frame[1] & CONNECT_OPT_NATT_ENDPOINT_HINT) != 0) {
		SNattEndpointHint hint;
		if (!ParseEndpointHint(frame + NATT_RENDEZVOUS_FIXED_LENGTH,
			    frameLength - NATT_RENDEZVOUS_FIXED_LENGTH,
			    hint)) {
			// The message says a hint follows and none does. Rejected
			// whole: reporting "no hint" here would silently accept a
			// truncated datagram, and reporting a hint would mean
			// reporting bytes that were never read.
			return false;
		}
		parsed.hasEndpointHint = true;
		parsed.hintAddress = hint.address;
		parsed.hintPort = hint.port;
	}

	out = parsed;
	return true;
}

/**
 * Write an OP_HOLEPUNCH message.
 *
 * @param ownHash this end's own user hash, so the receiver pairs the packet by
 *        identity rather than by the address it arrived from -- the address is
 *        exactly what the NAT under test rewrites.
 * @return bytes written, 0 on failure with the buffer untouched.
 */
inline size_t EncodeHolePunch(const uint8_t *ownHash, uint8_t *out, size_t outLength)
{
	if (out == nullptr || ownHash == nullptr || outLength < NATT_HOLEPUNCH_LENGTH) {
		return 0;
	}

	out[0] = OP_HOLEPUNCH;
	out[1] = CONNECT_OPT_NAT_TRAVERSAL_UTP;
	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		out[2 + i] = ownHash[i];
	}
	return NATT_HOLEPUNCH_LENGTH;
}

//! Read an OP_HOLEPUNCH message. Same trailing-bytes rule as
//! ParseRendezvousRequest().
inline bool ParseHolePunch(const uint8_t *frame, size_t frameLength, SNattHolePunch &out)
{
	if (frame == nullptr || frameLength < NATT_HOLEPUNCH_LENGTH || frame[0] != OP_HOLEPUNCH) {
		return false;
	}

	out.requestsUtpTraversal = (frame[1] & CONNECT_OPT_NAT_TRAVERSAL_UTP) != 0;
	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		out.senderHash[i] = frame[2 + i];
	}
	return true;
}

#endif // NATRENDEZVOUSPROTOCOL_H
