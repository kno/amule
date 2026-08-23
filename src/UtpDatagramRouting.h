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

#ifndef UTPDATAGRAMROUTING_H
#define UTPDATAGRAMROUTING_H

#include <cstddef>
#include <cstdint>

#include <protocol/Protocols.h> // Needed for OP_UDPRESERVEDPROT2 / OP_NATT_FRAME_UTP

/**
 * Inbound classification for the port uTP and ed2k UDP share.
 *
 * uTP does not get a port of its own: its datagrams arrive on the ed2k UDP
 * port, wrapped in OP_UDPRESERVEDPROT2 (0xB2) with frame type
 * OP_NATT_FRAME_UTP (0x00), exactly as eMuleAI sends them
 * (srchybrid/ClientUDPSocket.cpp:410) and reads them back (:991). Sharing the
 * port is not an economy: the NAT hole punched for ed2k UDP is the hole uTP
 * uses, which is what makes uTP usable for NAT traversal later.
 *
 * Two parsers therefore want the same datagram, and the order is load-bearing:
 *
 *   1. The uTP context is offered the datagram first.
 *   2. Only a datagram it declines continues to the ed2k UDP parser, whole and
 *      unmodified -- including the 0xB2 protocol byte, because the ed2k side
 *      has its own demultiplexer for the other frame types
 *      (ReservedProtocolFrames.h) and expects the datagram it always got.
 *
 * Inverting that breaks exactly one of the two and never says so: offer the
 * ed2k parser everything first and uTP never sees a packet; offer the uTP
 * context datagrams it has no business seeing and ed2k UDP depends on libutp
 * declining them. RouteInboundDatagram() is where the order lives so that
 * CClientUDPSocket cannot express it any other way, and
 * UtpDatagramRoutingTest asserts it in both directions.
 *
 * Header-only and free of theApp for the same reason as
 * ReservedProtocolFrames.h: CClientUDPSocket cannot be linked into a unit
 * test.
 */

//! The two framing bytes in front of every uTP datagram on the shared port.
constexpr std::size_t UTP_FRAME_HEADER_LENGTH = 2;

//! Write the uTP frame header. `out` must have room for
//! UTP_FRAME_HEADER_LENGTH bytes.
inline void WriteUtpFrameHeader(std::uint8_t *out)
{
	out[0] = OP_UDPRESERVEDPROT2;
	out[1] = OP_NATT_FRAME_UTP;
}

/**
 * Is this datagram a uTP frame?
 *
 * The header alone with no payload still is one: libutp rejects a zero-length
 * datagram on its own terms, and a minimum length invented here would be a
 * second parser nobody maintains.
 *
 * @param datagram  the whole datagram, protocol byte first. May be NULL when
 *                  length is 0.
 * @param length    bytes available from `datagram`.
 */
inline bool IsUtpFrame(const std::uint8_t *datagram, std::size_t length)
{
	if (datagram == nullptr || length < UTP_FRAME_HEADER_LENGTH) {
		return false;
	}

	return datagram[0] == OP_UDPRESERVEDPROT2 && datagram[1] == OP_NATT_FRAME_UTP;
}

//! The uTP payload window: everything after the two framing bytes. Only
//! meaningful when IsUtpFrame() is true.
inline const std::uint8_t *UtpFramePayload(const std::uint8_t *datagram)
{
	return datagram + UTP_FRAME_HEADER_LENGTH;
}

//! Length of that window, for a datagram of `length` bytes.
inline std::size_t UtpFramePayloadLength(std::size_t length)
{
	return length - UTP_FRAME_HEADER_LENGTH;
}

/**
 * Route one inbound datagram: uTP first, then ed2k.
 *
 * @param datagram  the whole datagram, protocol byte first. Never written
 *                  through, and never advanced before the ed2k parser sees it.
 * @param length    bytes available from `datagram`.
 * @param utpAvailable  whether a uTP context exists at all. False in every
 *                  build configured with -DENABLE_UTP=NO, and the shared port
 *                  must behave exactly as it did before uTP in that case.
 * @param offerToUtp  bool(const uint8_t *payload, size_t payloadLength) --
 *                  returns true when the context claimed the datagram.
 * @param parseAsEd2k  void(const uint8_t *datagram, size_t length) -- the
 *                  existing ed2k UDP path, handed the datagram unmodified.
 *
 * @return true when uTP consumed the datagram, i.e. the ed2k parser was not
 *         and must not be entered.
 */
template <class UtpOffer, class Ed2kParser>
inline bool RouteInboundDatagram(const std::uint8_t *datagram,
	std::size_t length,
	bool utpAvailable,
	UtpOffer offerToUtp,
	Ed2kParser parseAsEd2k)
{
	if (datagram == nullptr || length == 0) {
		return false;
	}

	if (utpAvailable && IsUtpFrame(datagram, length)) {
		if (offerToUtp(UtpFramePayload(datagram), UtpFramePayloadLength(length))) {
			return true;
		}
		// Declined: fall through with the original pointer and length.
		// Not the payload window -- the ed2k side is entitled to the
		// datagram it has always received.
	}

	parseAsEd2k(datagram, length);
	return false;
}

#endif // UTPDATAGRAMROUTING_H
