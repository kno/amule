//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2026 aMule Team ( https://amule-org.github.io )
// Copyright (c) 2002-2011 Merkur ( devs@emule-project.net / http://www.emule-project.net )
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

#ifndef ED2KPROTOCOLS_H
#define ED2KPROTOCOLS_H

// For MuleInfoPacket (OLD - DEPRECATED.)
#define EMULE_PROTOCOL 0x01

// Known protocols
enum Protocols
{
	OP_EDONKEYHEADER = 0xE3,
	OP_EDONKEYPROT = OP_EDONKEYHEADER,
	OP_PACKEDPROT = 0xD4,
	OP_EMULEPROT = 0xC5,

	// Reserved for later UDP headers (important for EncryptedDatagramSocket)
	OP_UDPRESERVEDPROT1 = 0xA3,
	OP_UDPRESERVEDPROT2 = 0xB2,

	// Kademlia 1/2
	OP_KADEMLIAHEADER = 0xE4,
	OP_KADEMLIAPACKEDPROT = 0xE5,

	// Kry tests
	OP_ED2KV2HEADER = 0xF4,
	OP_ED2KV2PACKEDPROT = 0xF5,

	OP_MLDONKEYPROT = 0x00
};

// OP_UDPRESERVEDPROT2 frame types.
//
// 0xB2 is the one UDP protocol byte that is not followed by an eD2k opcode:
// the next byte selects a frame type and the rest is that frame's payload.
// These are the types eMuleAI defines, and they are a separate namespace from
// Protocols above -- OP_NATT_FRAME_UTP and OP_MLDONKEYPROT are both 0x00 and
// mean unrelated things at different offsets.
//
// See src/ReservedProtocolFrames.h for the classification, which is what makes
// a frame type aMule does not serve a recognised drop rather than malformed
// traffic.
//
// OP_NATT_FRAME_UTP is served: it carries uTP (src/UtpDatagramRouting.h) and,
// for the payloads libutp declines, the rendezvous and hole-punch control
// messages. Those three opcodes -- OP_RENDEZVOUS 0xA0, OP_HOLEPUNCH 0xA1,
// OP_NATT_ENDPOINT_HINT 0xAA -- are NOT in this file, and deliberately: they
// are a third namespace, at a third offset, and every one of them collides with
// an eD2k opcode that has nothing to do with NAT traversal. 0xA0 alone is
// OP_SERVER_LIST_REQ as a Client2Server UDP opcode and OP_BUDDYPONG as a
// Client2Client TCP one. They live in src/NatRendezvousProtocol.h with the
// codec that reads them and the bounds that limit them.
//
// The transports behind the remaining types do not exist here. QUIC is
// amule-quic-transport; the capability and key frames have nothing to
// negotiate while that is true.
enum ReservedProt2FrameTypes
{
	//! Legacy uTP NAT-T frame.
	OP_NATT_FRAME_UTP = 0x00,
	//! QUIC NAT-T frame.
	OP_NATT_FRAME_QUIC = 0x01,
	//! Direct peer NAT-T capability negotiation.
	OP_NATT_FRAME_CAPS = 0x02,
	//! Direct peer NAT-T capability negotiation acknowledgement.
	OP_NATT_FRAME_CAPS_ACK = 0x03,
	//! NAT-T key frame.
	OP_NATT_FRAME_KEY = 0xFF
};

#endif // ED2KPROTOCOLS_H
