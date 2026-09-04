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

#include <protocol/Protocols.h> // Needed for OP_EMULEPROT

#include "NetworkAddress.h" // Needed for CNetworkAddress

/**
 * The rendezvous and hole-punch control messages, and their bounds.
 *
 * ## Where these bytes sit in a datagram
 *
 * A control message is not a datagram of its own. It rides the eMule protocol
 * byte, with its opcode where every other eMule UDP message keeps one:
 *
 *     [0] 0xC5  OP_EMULEPROT
 *     [1] ..    the control opcode
 *     [2] ..    the body, which carries no opcode of its own
 *
 * That is eMuleAI v1.6's framing, and the older envelope this tree used --
 * 0xB2 OP_UDPRESERVEDPROT2 with a 0x00 frame type and the opcode inline -- was
 * worse than merely private. eMuleAI uses BOTH protocol bytes, for different
 * jobs: 0xC5 for this signalling, and 0xB2 for transport data and capability
 * negotiation, where frame type 0x00 is its uTP DATA frame. So the old framing
 * did not just fail to be understood -- it put control messages on the frame
 * type the peer hands straight to its uTP parser. A rendezvous that reaches no
 * peer is indistinguishable from a NAT that does not open, which is how this
 * went unnoticed.
 *
 * The move costs nothing on the transport side, because the *transport* frames
 * stay where they were: 0xB2/0x00 still carries uTP and 0xB2/0x01 still carries
 * QUIC. The NAT mapping a punch opens is the mapping the ed2k UDP port already
 * has, and 0xC5 arrives on that same port -- so the hole punched is still the
 * hole the transport will use. Only the signalling changed envelope.
 *
 * Sharing 0xC5 with the ed2k client-to-client UDP opcodes is safe by
 * inspection: those are 0x90..0x95 and 0xFE (see
 * protocol/ed2k/Client2Client/UDP.h and kad2/Client2Client/UDP.h), and the
 * three opcodes below are 0xA0, 0xA1 and 0xAA. ClassifyNattControlMessage() is
 * where that separation is enforced, and its test asserts it against the ed2k
 * values as literals rather than trusting the comment.
 *
 * ## The body, and why it has no length fields
 *
 * eMuleAI detects each optional block by how many bytes are LEFT, not by a flag
 * in the options byte:
 *
 *     hash(16)
 *     options(1)
 *     if (remaining >= 16) fileHash(16)      // greedy
 *     if (remaining >=  6) IPv4(4) port(2)
 *     if (remaining >   0) transportHint(1)
 *
 * Two consequences follow, and both shape everything below.
 *
 * The first is that a body one byte off does not fail to parse -- it parses
 * into *different fields*. There is no framing error to detect and nothing to
 * log. So the encoders here write a body whole or not at all: a short output
 * buffer produces zero bytes rather than a prefix, because a prefix of this
 * format is a valid message that means something else.
 *
 * The second is that the options byte no longer *decides* anything a parser
 * reads. CONNECT_OPT_NATT_ENDPOINT_HINT is still emitted to state what was
 * encoded -- eMuleAI's own use of 0x20 is unknown to this tree, and a client
 * that does consult it should see the truth -- but ParseRendezvousRequest()
 * ignores it entirely and goes by length. The validation the old format had
 * ("the bit is set and no element follows, so reject the whole message") could
 * not survive that, because under this format the bit asserts nothing a parser
 * could contradict. What that validation protected is protected instead by the
 * length arithmetic, which cannot claim a block whose bytes are absent, and by
 * the value check in ParseEndpointTail(): an endpoint slot that is present but
 * names 0.0.0.0 or port 0 rejects the whole message, because that slot becomes
 * an address this client sends packets toward.
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

//! The protocol byte every control message rides. Named rather than used
//! inline, because "these are eMule-protocol messages now" is the decision this
//! change turns on and it should be greppable.
constexpr uint8_t NATT_CONTROL_PROTOCOL = OP_EMULEPROT;

//! Control opcodes, carried as the datagram's second byte under
//! NATT_CONTROL_PROTOCOL. A separate namespace from the ed2k opcodes -- 0xA0 is
//! OP_SERVER_LIST_REQ as a Client2Server UDP opcode and OP_BUDDYPONG as a
//! Client2Client TCP one, and neither has anything to do with this. Within the
//! client-to-client UDP space these three collide with nothing; see the file
//! comment.
enum ENattControlOpcodes : uint8_t
{
	//! A → R: relay a rendezvous to the named peer.
	OP_RENDEZVOUS = 0xA0,
	//! A → B: a packet whose only job is to open the mapping in A's NAT.
	OP_HOLEPUNCH = 0xA1,
	//! The observed external endpoint of the sender, as a candidate.
	OP_NATT_ENDPOINT_HINT = 0xAA
};

/**
 * Bits in the connect-options byte. Emitted to describe the body; never read to
 * decide what the body contains -- see the file comment.
 *
 * The byte is eMuleAI's, whole. Their GetMyConnectOptions()
 * (srchybrid/OtherFunctions.cpp) builds ONE byte carrying the crypt-layer bits
 * and the NAT-T bits together, and BaseClient.cpp writes exactly that byte into
 * the rendezvous body. There is no separate namespace for this message, so a
 * bit taken here is a bit taken from them. Their allocation, in full
 * (srchybrid/Opcodes.h):
 *
 *     0x01  CONNECT_OPT_CRYPT_SUPPORTED
 *     0x02  CONNECT_OPT_CRYPT_REQUESTED
 *     0x04  CONNECT_OPT_CRYPT_REQUIRED
 *     0x08  CONNECT_OPT_DIRECT_UDP_CALLBACK
 *     0x10  reserved, and reserved is not free
 *     0x20  CONNECT_OPT_NATT_ENDPOINT_HINT
 *     0x40  CONNECT_OPT_NAT_TRAVERSAL_QUIC
 *     0x80  CONNECT_OPT_NAT_TRAVERSAL_UTP
 *
 * Check that table before taking a bit. This tree already took 0x40 once, for a
 * "this was forwarded by a relay" flag, and 0x40 is their QUIC capability: they
 * would have read our forwards as "peer supports QUIC" and spent a capability
 * window on it, and we would have read a QUIC-capable peer's request as "already
 * relayed, act on it" and punched toward the address in the datagram -- which is
 * precisely the reflection the relay validation exists to prevent. The flag is
 * gone rather than relocated: see CClientUDPSocket::ProcessNattControlFrame()
 * for where the direction of a rendezvous is decided now, and why it is not
 * decided by anything the sender writes.
 */
enum ENattConnectOptions : uint8_t
{
	//! An endpoint was encoded into the tail. Informational only on receipt.
	//! Kept, and not deleted as redundant under the length rule: this is
	//! eMuleAI's 0x20 with eMuleAI's meaning, and their buddy-forward path
	//! gates on it (srchybrid/ClientUDPSocket.cpp). Their standalone parser
	//! goes by remaining length while that path goes by the flag, so a
	//! receiver has to honour whichever mechanism the frame it is reading uses.
	CONNECT_OPT_NATT_ENDPOINT_HINT = 0x20,
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
//! frame type before the transport falls back to the legacy uTP frame type
//! (OP_NATT_FRAME_UTP, 0x00). A transport question, not a signalling one: the
//! control messages ride 0xC5 either way.
constexpr uint32_t kNattFrameTypeFallbackWaitMs = 1500;

//! An ed2k user hash, the identity a control message names.
constexpr size_t NATT_PEER_HASH_LENGTH = 16;

//! An ed2k file hash, the file a rendezvous is about.
constexpr size_t NATT_FILE_HASH_LENGTH = 16;

//! The endpoint tail: four address octets then a big-endian port. IPv4 and only
//! IPv4 -- there is no family byte and no IPv6 slot in this format. See
//! EncodeEndpointTail() for what that costs.
constexpr size_t NATT_ENDPOINT_TAIL_LENGTH = 6;

//! The trailing transport-hint byte. Parsed and recorded, never emitted: see
//! SNattRendezvousRequest::transportHint.
constexpr size_t NATT_TRANSPORT_HINT_LENGTH = 1;

/**
 * Values for that byte. These are eMuleAI's ENatTraversalTransport
 * (srchybrid/UpdownClient.h), not a numbering of this tree's own.
 *
 * Pinned here because the obvious wrong move is to reuse one of the option bits
 * above: CONNECT_OPT_NAT_TRAVERSAL_UTP is 0x80, and eMuleAI's parser accepts
 * only 0x01 and 0x02 and silently discards everything else. A hint byte of 0x80
 * would therefore be dropped without a word on either side, which is the
 * failure mode this whole file exists to avoid.
 */
enum ENattTransportHint : uint8_t
{
	NATT_TRANSPORT_HINT_NONE = 0x00,
	NATT_TRANSPORT_HINT_UTP = 0x01,
	NATT_TRANSPORT_HINT_QUIC = 0x02
};

//! Whether a received hint byte is one eMuleAI would have acted on. Their
//! parser takes only UTP and QUIC -- NONE included, it rejects -- so a byte
//! outside that pair is worth logging and nothing else.
inline bool IsRecognisedNattTransportHint(uint8_t hint)
{
	return hint == NATT_TRANSPORT_HINT_UTP || hint == NATT_TRANSPORT_HINT_QUIC;
}

//! hash, options. Everything after this is optional and detected by length.
constexpr size_t NATT_RENDEZVOUS_FIXED_LENGTH = NATT_PEER_HASH_LENGTH + 1;

//! The largest body this build can produce or make sense of: the fixed part,
//! a file hash, an endpoint, and a transport hint.
constexpr size_t NATT_RENDEZVOUS_MAX_LENGTH = NATT_RENDEZVOUS_FIXED_LENGTH + NATT_FILE_HASH_LENGTH +
					      NATT_ENDPOINT_TAIL_LENGTH + NATT_TRANSPORT_HINT_LENGTH;

//! hash, options. A hole punch carries nothing optional: the mapping it opens
//! is observed by the receiver, which is worth more than anything the sender
//! could claim about it.
constexpr size_t NATT_HOLEPUNCH_LENGTH = NATT_PEER_HASH_LENGTH + 1;

//! Which control message a datagram carries.
enum ENattControlKind
{
	NATT_CONTROL_RENDEZVOUS,
	NATT_CONTROL_HOLEPUNCH,
	NATT_CONTROL_ENDPOINT_HINT,
	//! Not one of the three. Not ours; leave it to the ed2k opcode handlers.
	NATT_CONTROL_NOT_A_CONTROL_MESSAGE
};

//! A parsed endpoint tail.
struct SNattEndpointHint
{
	CNetworkAddress address;
	uint16_t port = 0;
};

//! A parsed OP_RENDEZVOUS body.
struct SNattRendezvousRequest
{
	//! The other side of the pair: the peer to relay to when this arrives at a
	//! relay, and the peer that asked when the relay forwards it on.
	uint8_t peerHash[NATT_PEER_HASH_LENGTH] = { 0 };
	//! CONNECT_OPT_NAT_TRAVERSAL_UTP was set.
	bool requestsUtpTraversal = false;
	/**
	 * A file hash was present AND named a file.
	 *
	 * Absent is legal twice over. Structurally, the greedy test is
	 * `remaining >= 16` and the longest endpoint-and-hint tail is seven bytes,
	 * so a body without a file hash can never be misread as one carrying it.
	 * Semantically, eMuleAI's handler gates only two source-enrichment blocks
	 * on it and processes the rendezvous either way -- a message naming no file
	 * is not an error there.
	 *
	 * eMuleAI's own encoder always writes the field, using an all-zero hash
	 * when it has no file, and its parser calls that absent via isnulmd4().
	 * This parser reaches the same answer from either spelling: an all-zero
	 * hash reports false here, exactly as a missing field does. Encoding is the
	 * other way round -- see EncodeRendezvousMessage().
	 */
	bool hasFileHash = false;
	//! The file the rendezvous is about. Zero unless hasFileHash, and never
	//! fabricated: a wrong file hash on the wire is worse than none.
	uint8_t fileHash[NATT_FILE_HASH_LENGTH] = { 0 };
	//! An endpoint tail was present AND named a real endpoint. The two are
	//! never reported apart: a slot naming 0.0.0.0 or port 0 rejects the whole
	//! message rather than reporting no endpoint, because reporting no endpoint
	//! would quietly turn a hostile body into an acceptable one.
	bool hasEndpointHint = false;
	//! Absent unless hasEndpointHint. Never fabricated, never all-zero: an
	//! unspecified address is not an endpoint, and CNetworkAddress keeps the
	//! two distinguishable.
	CNetworkAddress hintAddress;
	uint16_t hintPort = 0;
	//! A trailing transport-hint byte was present.
	bool hasTransportHint = false;
	/**
	 * Its raw value, recorded and not acted on. See ENattTransportHint for the
	 * two values eMuleAI defines, and IsRecognisedNattTransportHint() for the
	 * test their own parser applies.
	 *
	 * Kept raw rather than filtered so a byte outside that pair survives into a
	 * log line instead of vanishing into a zero, which is the one place the
	 * next revision of their format would first show up.
	 *
	 * Not acted on because there is nothing here for it to decide. This build
	 * serves one transport, and a peer's preference cannot conjure the other:
	 * a hint of QUIC would have to be refused anyway
	 * (LocalCanServeQuicNatTraversal()). This build emits no hint for the
	 * mirror-image reason -- the transport it can serve is already stated by
	 * CONNECT_OPT_NAT_TRAVERSAL_UTP, which eMuleAI reads.
	 */
	uint8_t transportHint = 0;
};

//! A parsed OP_HOLEPUNCH body.
struct SNattHolePunch
{
	/**
	 * Whether the punch named its sender at all.
	 *
	 * False for eMuleAI's punches, which carry an EMPTY body: their sender
	 * builds `new Packet(OP_EMULEPROT)` with only the opcode set, and their
	 * receiver matches by the address the datagram arrived from rather than by
	 * anything inside it. A punch from an eMuleAI peer is therefore a valid
	 * message with no identity in it, and a caller that needs one has to say so
	 * rather than reading a zeroed hash.
	 */
	bool hasSenderHash = false;
	//! Who sent it, so the receiver can pair the packet with the rendezvous it
	//! agreed to rather than with the address it arrived from -- which is
	//! precisely the thing a NAT rewrites. Zero unless hasSenderHash.
	uint8_t senderHash[NATT_PEER_HASH_LENGTH] = { 0 };
	bool requestsUtpTraversal = false;
};

//! An all-zero ed2k hash, which names no file and no peer. eMuleAI spells an
//! absent file hash this way (isnulmd4()), so a parser that did not test for it
//! would report a file context of sixteen zero bytes as if it were a file.
inline bool IsNullNattHash(const uint8_t *hash)
{
	if (hash == nullptr) {
		return true;
	}
	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		if (hash[i] != 0) {
			return false;
		}
	}
	return true;
}

/**
 * Classify a datagram's control opcode.
 *
 * Its input is the datagram's SECOND byte, not the body's first: under this
 * envelope the body carries no opcode. An opcode this protocol does not define
 * is NATT_CONTROL_NOT_A_CONTROL_MESSAGE, which is also what every ed2k
 * client-to-client UDP opcode is -- so the caller passes those on rather than
 * dropping them.
 */
inline ENattControlKind ClassifyNattControlMessage(uint8_t opcode)
{
	switch (opcode) {
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
 * Write the endpoint tail: four address octets most significant first, then a
 * big-endian port.
 *
 * There is no family byte and no IPv6 form. That is the format, not an
 * omission, and what it costs is a future capability rather than a working one:
 * CClientUDPSocket::SendNattControlMessage() already narrows every outbound
 * control message to IPv4 and drops a native-IPv6 destination outright, so no
 * IPv6 endpoint reaches an encoder in production today. Giving IPv6 a slot
 * needs a length-prefixed element, which is a wire-format proposal of its own
 * and not this change.
 *
 * @return NATT_ENDPOINT_TAIL_LENGTH, or 0 when nothing was written. Zero on an
 *         absent address, on an address that is not IPv4, on a zero port, and
 *         on an output buffer too small -- in every one of those cases the
 *         buffer is left untouched. Encoding an absent address as six zero
 *         bytes would produce an endpoint of 0.0.0.0:0 that the far side would
 *         dutifully punch at.
 */
inline size_t EncodeEndpointTail(
	const CNetworkAddress &address, uint16_t port, uint8_t *out, size_t outLength)
{
	if (out == nullptr || port == 0 || outLength < NATT_ENDPOINT_TAIL_LENGTH || address.IsAbsent() ||
		address.IsUnspecified()) {
		return 0;
	}

	// A mapped IPv4 address goes out as IPv4: the peer has to punch at an
	// endpoint, and ::ffff:192.0.2.10 is not one an IPv4 socket can send to.
	const CNetworkAddress unmapped = address.Unmapped();
	uint32_t hostOrder = 0;
	if (!unmapped.IsIPv4() || !unmapped.ToIPv4HostOrder(hostOrder)) {
		return 0;
	}

	out[0] = static_cast<uint8_t>((hostOrder >> 24) & 0xFF);
	out[1] = static_cast<uint8_t>((hostOrder >> 16) & 0xFF);
	out[2] = static_cast<uint8_t>((hostOrder >> 8) & 0xFF);
	out[3] = static_cast<uint8_t>(hostOrder & 0xFF);
	out[4] = static_cast<uint8_t>((port >> 8) & 0xFF);
	out[5] = static_cast<uint8_t>(port & 0xFF);
	return NATT_ENDPOINT_TAIL_LENGTH;
}

/**
 * Read the endpoint tail.
 *
 * @param tail points at the first address octet. The caller has already
 *        established that NATT_ENDPOINT_TAIL_LENGTH bytes are there; this
 *        function is the value check, not the bounds check.
 * @return false for a zero port or an unspecified address. Those are not
 *         endpoints, and this is the one part of the message whose payload
 *         becomes a destination -- so a caller must not be able to treat them
 *         as "no endpoint given" and carry on.
 */
inline bool ParseEndpointTail(const uint8_t *tail, SNattEndpointHint &out)
{
	if (tail == nullptr) {
		return false;
	}

	const uint32_t hostOrder = (static_cast<uint32_t>(tail[0]) << 24) |
				   (static_cast<uint32_t>(tail[1]) << 16) |
				   (static_cast<uint32_t>(tail[2]) << 8) | static_cast<uint32_t>(tail[3]);
	const uint16_t port = static_cast<uint16_t>((tail[4] << 8) | tail[5]);
	const CNetworkAddress address = CNetworkAddress::FromIPv4HostOrder(hostOrder);
	if (port == 0 || address.IsUnspecified()) {
		return false;
	}

	out.address = address;
	out.port = port;
	return true;
}

/**
 * Write an OP_RENDEZVOUS body.
 *
 * Whole or nothing. Under a remaining-length format a prefix is not a truncated
 * message, it is a different one, so every optional block that was asked for
 * must fit before a single byte is written.
 *
 * @param peerHash NATT_PEER_HASH_LENGTH bytes naming the other side of the
 *        pair.
 * @param fileHash NATT_FILE_HASH_LENGTH bytes naming the file this rendezvous
 *        is about, or NULL when the caller holds none.
 *
 *        NULL is a legal body and not a degraded one. eMuleAI's handler gates
 *        only two source-enrichment blocks on the file hash and processes the
 *        rendezvous either way, so omitting it costs the enrichment and nothing
 *        else; and the greedy test cannot misread the shorter body, because it
 *        needs sixteen bytes of tail and the longest endpoint-and-hint tail is
 *        seven.
 *
 *        eMuleAI itself writes an all-zero hash here rather than omitting the
 *        field, and its parser calls that absent. Both spellings reach the same
 *        conclusion at both ends, and this encoder picks omission for a reason
 *        that outlives the compatibility: sixteen zero bytes are still a hash
 *        to any reader that does not know the convention, while a field that is
 *        not there cannot be misread as one naming a file. Never a borrowed
 *        hash either -- that would name a file this rendezvous is not about,
 *        which is worse than naming none.
 * @param endpoint this end's believed external address, or an absent address
 *        when it is not known.
 * @return bytes written, 0 on failure with the buffer untouched.
 */
inline size_t EncodeRendezvousMessage(const uint8_t *peerHash,
	const uint8_t *fileHash,
	const CNetworkAddress &endpoint,
	uint16_t port,
	bool endpointRequired,
	uint8_t *out,
	size_t outLength)
{
	if (out == nullptr || peerHash == nullptr || outLength < NATT_RENDEZVOUS_FIXED_LENGTH) {
		return 0;
	}

	// Both optional blocks are built into locals first, so the options byte can
	// state what is actually there rather than what the caller intended, and so
	// the length is known before anything is written.
	const size_t fileHashLength = fileHash != nullptr ? NATT_FILE_HASH_LENGTH : 0;
	uint8_t tail[NATT_ENDPOINT_TAIL_LENGTH];
	const size_t tailLength = EncodeEndpointTail(endpoint, port, tail, sizeof(tail));

	if (endpointRequired && tailLength == 0) {
		// A forward with no endpoint in it gives the receiver nothing to punch
		// toward, so it is not encoded at all rather than encoded empty.
		return 0;
	}

	const size_t total = NATT_RENDEZVOUS_FIXED_LENGTH + fileHashLength + tailLength;
	if (outLength < total) {
		return 0;
	}

	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		out[i] = peerHash[i];
	}
	// Nothing here states which direction the message travels. The two
	// directions are byte-identical on the wire, deliberately: a receiver that
	// took the sender's word for the direction would let a crafted request onto
	// the path that punches at the address in the datagram. See
	// CClientUDPSocket::ProcessNattControlFrame().
	// CONNECT_OPT_NATT_ENDPOINT_HINT is deliberately NOT set, even when a tail
	// follows. The bit is eMuleAI's and it does not mean what the name suggests
	// here: on their buddy-forward path it is a *request* -- "buddy, reply with
	// the target's live endpoint" -- answered with a standalone
	// OP_NATT_ENDPOINT_HINT datagram (ClientUDPSocket.cpp, their tree), not a
	// marker that this body carries one. Setting it would ask a service of a
	// peer, get an answer this build recognises and drops, and claim something
	// we did not mean. Presence of the tail is signalled by remaining length,
	// which is the rule their parser actually applies.
	//
	// Receiving is the other way round: a peer that sets it is honoured, since
	// ParseRendezvousRequest() ignores the bit and goes by length either way.
	out[NATT_PEER_HASH_LENGTH] = static_cast<uint8_t>(CONNECT_OPT_NAT_TRAVERSAL_UTP);

	size_t cursor = NATT_RENDEZVOUS_FIXED_LENGTH;
	for (size_t i = 0; i < fileHashLength; ++i) {
		out[cursor + i] = fileHash[i];
	}
	cursor += fileHashLength;
	for (size_t i = 0; i < tailLength; ++i) {
		out[cursor + i] = tail[i];
	}
	return total;
}

/**
 * A rendezvous request: A asking a relay to reach the peer named by
 * @a peerHash, about the file named by @a fileHash, and stating its own
 * believed external endpoint.
 *
 * The bytes are indistinguishable from EncodeRelayedRendezvous()' output, and
 * the two functions exist for the caller's sake rather than the wire's: they
 * differ only in whether an endpoint is mandatory. What separates the two
 * directions is not in the message at all -- see
 * CClientUDPSocket::ProcessNattControlFrame().
 *
 * The endpoint is optional HERE because a request without one is a request the
 * relay will discard for want of anything to validate against the source, which
 * is a decision for RelayRendezvousRequest() and not for this encoder. The
 * caller that has no endpoint to name declines to send instead; see
 * CClientUDPSocket::SendRendezvousRequest().
 */
inline size_t EncodeRendezvousRequest(const uint8_t *peerHash,
	const uint8_t *fileHash,
	const CNetworkAddress &ownEndpoint,
	uint16_t ownPort,
	uint8_t *out,
	size_t outLength)
{
	return EncodeRendezvousMessage(peerHash, fileHash, ownEndpoint, ownPort, false, out, outLength);
}

/**
 * A relayed rendezvous: a relay telling @a peerHash's counterpart where the
 * requester was observed to be.
 *
 * @param peerHash the requester's identity, from the relay's own client list.
 * @param fileHash the file hash the REQUEST carried, forwarded verbatim, or
 *        NULL when it carried none. Taken from the datagram deliberately, and
 *        it is the one field here that may be: the relay's "never from the
 *        datagram" rule exists for the identity and the endpoint, which are the
 *        reflection vectors -- a file hash names no host and is never dialled.
 *        The relay has no other source for it and must not invent one.
 * @param observedEndpoint the endpoint the relay OBSERVED the request arrive
 *        from -- never one the request claimed. Mandatory here, unlike in a
 *        request: a forward with no endpoint gives its receiver nothing to
 *        punch toward, so it is not sent at all rather than sent empty.
 */
inline size_t EncodeRelayedRendezvous(const uint8_t *peerHash,
	const uint8_t *fileHash,
	const CNetworkAddress &observedEndpoint,
	uint16_t observedPort,
	uint8_t *out,
	size_t outLength)
{
	return EncodeRendezvousMessage(
		peerHash, fileHash, observedEndpoint, observedPort, true, out, outLength);
}

/**
 * Read an OP_RENDEZVOUS body.
 *
 * @param body points past the 0xC5 and the opcode byte.
 * @param bodyLength bytes available from there.
 *
 * Each optional block is claimed only when all of its bytes are present, which
 * is what keeps this from reading past a short datagram: there is no field
 * whose length comes from the data. Bytes after everything this build
 * understands are ignored rather than rejected, so a later eMuleAI revision
 * that appends a field is still parseable here -- and eMuleAI's own parser does
 * the same, so a stricter reader on this side would drop messages that client
 * considers valid.
 *
 * @return false only for a body shorter than the fixed part, or for an endpoint
 *         slot that is present and names nothing. Nothing else in this format
 *         is malformed: a shorter body is a body with fewer blocks.
 */
inline bool ParseRendezvousRequest(const uint8_t *body, size_t bodyLength, SNattRendezvousRequest &out)
{
	if (body == nullptr || bodyLength < NATT_RENDEZVOUS_FIXED_LENGTH) {
		return false;
	}

	SNattRendezvousRequest parsed;
	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		parsed.peerHash[i] = body[i];
	}
	const uint8_t options = body[NATT_PEER_HASH_LENGTH];
	parsed.requestsUtpTraversal = (options & CONNECT_OPT_NAT_TRAVERSAL_UTP) != 0;

	// From here it is length arithmetic and nothing else. CONNECT_OPT_NATT_-
	// ENDPOINT_HINT is deliberately not consulted: see the file comment.
	size_t cursor = NATT_RENDEZVOUS_FIXED_LENGTH;
	size_t remaining = bodyLength - NATT_RENDEZVOUS_FIXED_LENGTH;

	// Greedy, as eMuleAI's parser is. Sixteen bytes left mean a file hash, even
	// though six of them could also spell an endpoint -- which is why an
	// encoder must never leave a sixteen-byte-or-longer tail that is not one.
	if (remaining >= NATT_FILE_HASH_LENGTH) {
		// The bytes are consumed either way -- they occupy the slot and the
		// endpoint's position depends on it -- but an all-zero hash is reported
		// as no file, which is how eMuleAI spells "I have no file context".
		// Consuming without reporting is the whole distinction: skipping the
		// advance would push the endpoint read sixteen bytes early.
		if (!IsNullNattHash(body + cursor)) {
			for (size_t i = 0; i < NATT_FILE_HASH_LENGTH; ++i) {
				parsed.fileHash[i] = body[cursor + i];
			}
			parsed.hasFileHash = true;
		}
		cursor += NATT_FILE_HASH_LENGTH;
		remaining -= NATT_FILE_HASH_LENGTH;
	}

	if (remaining >= NATT_ENDPOINT_TAIL_LENGTH) {
		SNattEndpointHint hint;
		if (!ParseEndpointTail(body + cursor, hint)) {
			// The slot is there and names nothing. Rejected whole: this is
			// the one field that becomes a destination, and reporting "no
			// endpoint" would let a body that named 0.0.0.0:0 through as if
			// it had been well formed.
			return false;
		}
		parsed.hasEndpointHint = true;
		parsed.hintAddress = hint.address;
		parsed.hintPort = hint.port;
		cursor += NATT_ENDPOINT_TAIL_LENGTH;
		remaining -= NATT_ENDPOINT_TAIL_LENGTH;
	}

	if (remaining > 0) {
		parsed.hasTransportHint = true;
		parsed.transportHint = body[cursor];
	}

	out = parsed;
	return true;
}

/**
 * Write an OP_HOLEPUNCH body.
 *
 * @param ownHash this end's own user hash, so the receiver pairs the packet by
 *        identity rather than by the address it arrived from -- the address is
 *        exactly what the NAT under test rewrites.
 * @return bytes written, 0 on failure with the buffer untouched.
 *
 * The field ORDER here -- hash then options -- mirrors the rendezvous body,
 * which is the only field order this tree has observed from eMuleAI v1.6. A
 * punch carries nothing optional, so there is no length arithmetic to get wrong
 * and the only interop risk is that order itself.
 */
inline size_t EncodeHolePunch(const uint8_t *ownHash, uint8_t *out, size_t outLength)
{
	if (out == nullptr || ownHash == nullptr || outLength < NATT_HOLEPUNCH_LENGTH) {
		return 0;
	}

	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		out[i] = ownHash[i];
	}
	out[NATT_PEER_HASH_LENGTH] = CONNECT_OPT_NAT_TRAVERSAL_UTP;
	return NATT_HOLEPUNCH_LENGTH;
}

/**
 * Read an OP_HOLEPUNCH body. Same trailing-bytes rule as
 * ParseRendezvousRequest().
 *
 * An EMPTY body is valid and is the shape eMuleAI actually sends -- see
 * SNattHolePunch::hasSenderHash. Demanding the full fixed part here would drop
 * every punch a real eMuleAI peer emits, and a dropped punch behind a NAT looks
 * exactly like the NAT not opening, so the failure would have been invisible.
 *
 * A body that is present but shorter than the fixed part is still rejected.
 * Nobody emits one, and half a user hash is not a user hash: accepting it would
 * mean pairing a punch against an identity read partly out of adjacent memory.
 *
 * @return false only for that partial case. On success, check hasSenderHash
 *         before using senderHash.
 */
inline bool ParseHolePunch(const uint8_t *body, size_t bodyLength, SNattHolePunch &out)
{
	if (bodyLength == 0) {
		out = SNattHolePunch();
		return true;
	}

	if (body == nullptr || bodyLength < NATT_HOLEPUNCH_LENGTH) {
		return false;
	}

	for (size_t i = 0; i < NATT_PEER_HASH_LENGTH; ++i) {
		out.senderHash[i] = body[i];
	}
	out.hasSenderHash = true;
	out.requestsUtpTraversal = (body[NATT_PEER_HASH_LENGTH] & CONNECT_OPT_NAT_TRAVERSAL_UTP) != 0;
	return true;
}

#endif // NATRENDEZVOUSPROTOCOL_H
