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

// uTP, QUIC and ed2k UDP share one port, so one datagram arrives and three
// parsers want it. The design pins the order: the uTP context is offered the
// datagram first, a datagram it declines is offered to the QUIC context next,
// and only a datagram both decline continues to the ed2k UDP parser.
//
// Inverting any part of that breaks exactly one of the three, and which one
// depends on the direction of the inversion -- ed2k UDP if a transport context
// is offered nothing, a transport if the ed2k parser is allowed to consume 0xB2
// first, and QUIC if it is offered before uTP rather than after. None of those
// failures produces a message. So the order is asserted by recording which
// sides were actually called and in what sequence, rather than by trusting that
// reading the code the right way round is enough.

#include <muleunit/test.h>

#include <QuicNattProtocol.h>
#include <UtpDatagramRouting.h>
#include <protocol/Protocols.h>

#include <cstring>
#include <string>
#include <vector>

using namespace muleunit;

DECLARE_SIMPLE(UtpDatagramRouting)

namespace
{

//! Records what was called, with what, and in which order.
struct SRouteRecorder
{
	//! "utp" / "quic" / "ed2k" in call order. More than one entry means a
	//! fall-through, and the sequence is the classification order itself.
	std::vector<std::string> calls;
	//! Whether the uTP side claims the datagram it is offered.
	bool utpConsumes = false;
	//! Whether the QUIC side claims the datagram it is offered.
	bool quicConsumes = false;

	const uint8_t *utpPayload = nullptr;
	size_t utpPayloadLength = 0;
	const uint8_t *quicPayload = nullptr;
	size_t quicPayloadLength = 0;
	const uint8_t *ed2kDatagram = nullptr;
	size_t ed2kLength = 0;

	bool OfferToUtp(const uint8_t *payload, size_t payloadLength)
	{
		calls.push_back("utp");
		utpPayload = payload;
		utpPayloadLength = payloadLength;
		return utpConsumes;
	}

	bool OfferToQuic(const uint8_t *payload, size_t payloadLength)
	{
		calls.push_back("quic");
		quicPayload = payload;
		quicPayloadLength = payloadLength;
		return quicConsumes;
	}

	void ParseAsEd2k(const uint8_t *datagram, size_t length)
	{
		calls.push_back("ed2k");
		ed2kDatagram = datagram;
		ed2kLength = length;
	}
};

//! A uTP frame on the shared port: protocol byte, frame type, payload.
std::vector<uint8_t> MakeUtpFrame(const std::vector<uint8_t> &payload)
{
	std::vector<uint8_t> datagram(UTP_FRAME_HEADER_LENGTH + payload.size());
	WriteUtpFrameHeader(&datagram[0]);
	if (!payload.empty()) {
		memcpy(&datagram[UTP_FRAME_HEADER_LENGTH], &payload[0], payload.size());
	}
	return datagram;
}

//! A QUIC frame on the same port: protocol byte, frame type 0x01, payload.
std::vector<uint8_t> MakeQuicFrame(const std::vector<uint8_t> &payload)
{
	std::vector<uint8_t> datagram(QUIC_FRAME_HEADER_LENGTH + payload.size());
	WriteQuicFrameHeader(&datagram[0]);
	if (!payload.empty()) {
		memcpy(&datagram[QUIC_FRAME_HEADER_LENGTH], &payload[0], payload.size());
	}
	return datagram;
}

bool Route(SRouteRecorder &recorder,
	std::vector<uint8_t> &datagram,
	bool utpAvailable,
	bool quicAvailable = false)
{
	return RouteInboundDatagram(
		&datagram[0],
		datagram.size(),
		utpAvailable,
		quicAvailable,
		[&recorder](const uint8_t *payload, size_t length) {
			return recorder.OfferToUtp(payload, length);
		},
		[&recorder](const uint8_t *payload, size_t length) {
			return recorder.OfferToQuic(payload, length);
		},
		[&recorder](const uint8_t *whole, size_t length) { recorder.ParseAsEd2k(whole, length); });
}

} // namespace

// The two header bytes are wire format: eMuleAI wraps every outbound uTP
// datagram in OP_UDPRESERVEDPROT2 + OP_NATT_FRAME_UTP
// (srchybrid/ClientUDPSocket.cpp:410) and unwraps inbound ones by the same two
// bytes (:991). Literal values, so a renumbering cannot pass.
TEST(UtpDatagramRouting, FrameHeaderIsExact)
{
	uint8_t header[UTP_FRAME_HEADER_LENGTH] = { 0xFF, 0xFF };
	WriteUtpFrameHeader(header);

	ASSERT_EQUALS(2u, (unsigned)UTP_FRAME_HEADER_LENGTH);
	ASSERT_EQUALS(0xB2, (int)header[0]);
	ASSERT_EQUALS(0x00, (int)header[1]);
	ASSERT_EQUALS((int)OP_UDPRESERVEDPROT2, (int)header[0]);
	ASSERT_EQUALS((int)OP_NATT_FRAME_UTP, (int)header[1]);
}

// Spec delta, "Inbound datagram classification": a uTP packet must reach the
// uTP context and must NOT reach the ed2k UDP parser. The recorder proves both
// halves -- one call, and it is the uTP one.
TEST(UtpDatagramRouting, UtpFrameGoesToTheContextAndNoFurther)
{
	std::vector<uint8_t> datagram = MakeUtpFrame({ 0x21, 0x00, 0x00, 0x01, 0xAB });

	SRouteRecorder recorder;
	recorder.utpConsumes = true;

	ASSERT_TRUE(Route(recorder, datagram, true));

	ASSERT_EQUALS(1u, (unsigned)recorder.calls.size());
	ASSERT_TRUE(recorder.calls[0] == "utp");
	// libutp is handed the payload, not the two framing bytes.
	ASSERT_TRUE(recorder.utpPayload == &datagram[0] + UTP_FRAME_HEADER_LENGTH);
	ASSERT_EQUALS(5u, (unsigned)recorder.utpPayloadLength);
	ASSERT_EQUALS(0x21, (int)recorder.utpPayload[0]);
}

// Spec delta, "Non-uTP datagram": a datagram the uTP context declines must
// continue to the ed2k UDP parser unmodified. "Unmodified" is asserted as
// byte-identity of the whole buffer plus the original pointer and length --
// the ed2k parser must see the 0xB2 protocol byte it always saw, not a window
// somebody advanced past it.
TEST(UtpDatagramRouting, DeclinedFrameContinuesToTheEd2kParserUntouched)
{
	std::vector<uint8_t> datagram = MakeUtpFrame({ 0x41, 0x42, 0x43 });
	const std::vector<uint8_t> before = datagram;

	SRouteRecorder recorder;
	recorder.utpConsumes = false;

	ASSERT_FALSE(Route(recorder, datagram, true));

	// Order, both entries: uTP was asked first, ed2k got it afterwards.
	ASSERT_EQUALS(2u, (unsigned)recorder.calls.size());
	ASSERT_TRUE(recorder.calls[0] == "utp");
	ASSERT_TRUE(recorder.calls[1] == "ed2k");

	ASSERT_TRUE(recorder.ed2kDatagram == &datagram[0]);
	ASSERT_EQUALS(before.size(), recorder.ed2kLength);
	for (size_t i = 0; i < before.size(); ++i) {
		ASSERT_EQUALS((int)before[i], (int)datagram[i]);
	}
}

// The other direction of the inversion: an ordinary ed2k UDP datagram must not
// be offered to the uTP context at all. Offering it would be harmless only for
// as long as libutp keeps declining everything it does not recognise, which is
// not a property to depend on -- and it would put every ed2k datagram through
// a second parser for nothing.
TEST(UtpDatagramRouting, Ed2kDatagramIsNeverOfferedToTheContext)
{
	// OP_EMULEPROT + an opcode: the shape CClientUDPSocket has always
	// parsed. Then the other two protocol bytes that share this port.
	const uint8_t protocols[3] = { OP_EMULEPROT, OP_KADEMLIAHEADER, OP_KADEMLIAPACKEDPROT };

	for (int i = 0; i < 3; ++i) {
		std::vector<uint8_t> datagram = { protocols[i], 0x9B, 0x01, 0x02 };

		SRouteRecorder recorder;
		recorder.utpConsumes = true; // would consume if it were ever asked

		ASSERT_FALSE(Route(recorder, datagram, true));

		ASSERT_EQUALS(1u, (unsigned)recorder.calls.size());
		ASSERT_TRUE(recorder.calls[0] == "ed2k");
		ASSERT_TRUE(recorder.utpPayload == nullptr);
		ASSERT_TRUE(recorder.ed2kDatagram == &datagram[0]);
		ASSERT_EQUALS(4u, (unsigned)recorder.ed2kLength);
	}
}

// A 0xB2 datagram carrying some other NAT-T frame type is not uTP. It has to
// keep reaching the ed2k side, which is where the frame demultiplexer that
// serves the other four types lives (ReservedProtocolFrames.h).
TEST(UtpDatagramRouting, OtherNatTraversalFrameTypesAreNotUtp)
{
	const uint8_t others[4] = {
		OP_NATT_FRAME_QUIC, OP_NATT_FRAME_CAPS, OP_NATT_FRAME_CAPS_ACK, OP_NATT_FRAME_KEY
	};

	for (int i = 0; i < 4; ++i) {
		std::vector<uint8_t> datagram = { OP_UDPRESERVEDPROT2, others[i], 0x77 };

		SRouteRecorder recorder;
		recorder.utpConsumes = true;

		ASSERT_FALSE(Route(recorder, datagram, true));
		ASSERT_EQUALS(1u, (unsigned)recorder.calls.size());
		ASSERT_TRUE(recorder.calls[0] == "ed2k");
	}
}

// Two datagrams too short to be a uTP frame: the protocol byte alone, and an
// empty one. Both must reach the ed2k parser -- that is where the truncation
// guard already is -- and neither may cause a read of the missing type byte.
TEST(UtpDatagramRouting, TruncatedDatagramIsNotUtp)
{
	std::vector<uint8_t> protocolByteOnly = { OP_UDPRESERVEDPROT2 };

	SRouteRecorder recorder;
	recorder.utpConsumes = true;

	ASSERT_FALSE(Route(recorder, protocolByteOnly, true));
	ASSERT_EQUALS(1u, (unsigned)recorder.calls.size());
	ASSERT_TRUE(recorder.calls[0] == "ed2k");
	ASSERT_EQUALS(1u, (unsigned)recorder.ed2kLength);

	// A null datagram is the same condition, not a crash. Nothing is
	// routed anywhere, because there is nothing to route.
	SRouteRecorder empty;
	ASSERT_FALSE(RouteInboundDatagram(
		nullptr,
		0,
		true,
		true,
		[&empty](const uint8_t *p, size_t l) { return empty.OfferToUtp(p, l); },
		[&empty](const uint8_t *p, size_t l) { return empty.OfferToQuic(p, l); },
		[&empty](const uint8_t *p, size_t l) { empty.ParseAsEd2k(p, l); }));
	ASSERT_EQUALS(0u, (unsigned)empty.calls.size());
}

// A build without libutp, or one whose context has not come up, must leave the
// shared port exactly as it was: the uTP frame reaches the ed2k side and is
// dropped there as a known-but-unserved frame type. This is the state every
// build configured with -DENABLE_UTP=NO is in, so it is the one that must not
// regress ed2k UDP.
TEST(UtpDatagramRouting, WithoutAContextEverythingGoesToEd2k)
{
	std::vector<uint8_t> datagram = MakeUtpFrame({ 0x21, 0x00 });

	SRouteRecorder recorder;
	recorder.utpConsumes = true;

	ASSERT_FALSE(Route(recorder, datagram, false));

	ASSERT_EQUALS(1u, (unsigned)recorder.calls.size());
	ASSERT_TRUE(recorder.calls[0] == "ed2k");
	ASSERT_TRUE(recorder.utpPayload == nullptr);
	ASSERT_EQUALS(4u, (unsigned)recorder.ed2kLength);
}

// The classification on its own, without the fall-through: this is what the
// client UDP socket reads to decide whether it has a uTP candidate at all.
TEST(UtpDatagramRouting, ClassificationIsExact)
{
	const std::vector<uint8_t> utpFrame = MakeUtpFrame({ 0x21 });
	ASSERT_TRUE(IsUtpFrame(&utpFrame[0], utpFrame.size()));

	// The header with no payload: still a uTP frame. libutp is handed a
	// zero-length datagram and rejects it on its own terms; inventing a
	// minimum length here would be a second, undocumented parser.
	const std::vector<uint8_t> headerOnly = MakeUtpFrame({});
	ASSERT_TRUE(IsUtpFrame(&headerOnly[0], headerOnly.size()));
	ASSERT_EQUALS(0u, (unsigned)UtpFramePayloadLength(headerOnly.size()));

	const uint8_t notUtp[2] = { OP_UDPRESERVEDPROT2, OP_NATT_FRAME_QUIC };
	ASSERT_FALSE(IsUtpFrame(notUtp, 2));

	const uint8_t ed2k[2] = { OP_EMULEPROT, 0x00 };
	ASSERT_FALSE(IsUtpFrame(ed2k, 2));

	ASSERT_FALSE(IsUtpFrame(&utpFrame[0], 1));
	ASSERT_FALSE(IsUtpFrame(nullptr, 2));
}

// Spec delta, "Shared port classification order": QUIC sits between uTP and the
// ed2k UDP parser. A QUIC frame therefore reaches the QUIC context, and the
// uTP context is asked first and declines -- both halves matter, because the
// order is only observable when a consumer that could have claimed the datagram
// is asked before one that did.
TEST(UtpDatagramRouting, QuicFrameReachesTheQuicContextAfterUtpDeclines)
{
	std::vector<uint8_t> datagram = MakeQuicFrame({ 0xC3, 0x00, 0x00, 0x00, 0x01 });

	SRouteRecorder recorder;
	recorder.utpConsumes = true;  // Would claim anything it is offered...
	recorder.quicConsumes = true; // ...but a QUIC frame is not offered to it.

	ASSERT_TRUE(Route(recorder, datagram, true, true));

	ASSERT_EQUALS(1u, (unsigned)recorder.calls.size());
	ASSERT_TRUE(recorder.calls[0] == "quic");

	// The QUIC context is handed the payload window, not the framing bytes:
	// ngtcp2 parses a QUIC packet, and the two bytes in front of it are
	// aMule's envelope.
	ASSERT_TRUE(recorder.quicPayload == &datagram[QUIC_FRAME_HEADER_LENGTH]);
	ASSERT_EQUALS(5u, (unsigned)recorder.quicPayloadLength);
}

// The full three-way order, asserted on one datagram that every consumer is
// willing to look at. A datagram neither transport claims must reach the ed2k
// parser whole -- including its 0xB2 protocol byte, because the ed2k side owns
// the other OP_UDPRESERVEDPROT2 frame types.
TEST(UtpDatagramRouting, DeclinedDatagramVisitsUtpThenQuicThenEd2k)
{
	std::vector<uint8_t> datagram = MakeUtpFrame({ 0x21, 0x00 });

	SRouteRecorder recorder;
	recorder.utpConsumes = false;
	recorder.quicConsumes = false;

	ASSERT_FALSE(Route(recorder, datagram, true, true));

	// uTP first. QUIC is not offered a datagram that is framed as uTP: the
	// frame type is what selects the transport, and offering 0x00 bytes to
	// ngtcp2 would have it parse somebody else's protocol.
	ASSERT_EQUALS(2u, (unsigned)recorder.calls.size());
	ASSERT_TRUE(recorder.calls[0] == "utp");
	ASSERT_TRUE(recorder.calls[1] == "ed2k");
	ASSERT_TRUE(recorder.ed2kDatagram == &datagram[0]);
	ASSERT_EQUALS(datagram.size(), recorder.ed2kLength);

	// And the mirror: a QUIC-framed datagram the QUIC context declines
	// continues to ed2k, again whole. The uTP context is never offered it.
	std::vector<uint8_t> quicDatagram = MakeQuicFrame({ 0xC3, 0x00 });
	SRouteRecorder second;
	second.utpConsumes = true;
	second.quicConsumes = false;

	ASSERT_FALSE(Route(second, quicDatagram, true, true));

	ASSERT_EQUALS(2u, (unsigned)second.calls.size());
	ASSERT_TRUE(second.calls[0] == "quic");
	ASSERT_TRUE(second.calls[1] == "ed2k");
	ASSERT_TRUE(second.ed2kDatagram == &quicDatagram[0]);
	ASSERT_EQUALS(quicDatagram.size(), second.ed2kLength);
}

// The default build, and the only one macOS gets: -DENABLE_QUIC=NO. The QUIC
// context does not exist, so a QUIC frame from an eMuleAI peer must reach the
// ed2k side and be dropped there as a recognised-but-unserved frame type
// (ReservedProtocolFrames.h) -- never be silently consumed by a context that is
// not there, and never disturb uTP.
TEST(UtpDatagramRouting, WithoutAQuicContextQuicFramesFallThroughToEd2k)
{
	std::vector<uint8_t> datagram = MakeQuicFrame({ 0xC3, 0x00 });

	SRouteRecorder recorder;
	recorder.utpConsumes = true;
	recorder.quicConsumes = true;

	ASSERT_FALSE(Route(recorder, datagram, true, false));

	ASSERT_EQUALS(1u, (unsigned)recorder.calls.size());
	ASSERT_TRUE(recorder.calls[0] == "ed2k");
	ASSERT_TRUE(recorder.quicPayload == nullptr);
	ASSERT_TRUE(recorder.ed2kDatagram == &datagram[0]);
	ASSERT_EQUALS(datagram.size(), recorder.ed2kLength);
}

// Neither transport compiled in. Every datagram goes straight to the ed2k
// parser, which is the shared port behaving exactly as it did before either
// transport existed. Task 1.3 rests on this case.
TEST(UtpDatagramRouting, WithNeitherTransportEverythingIsEd2k)
{
	std::vector<std::vector<uint8_t>> datagrams = { MakeUtpFrame({ 0x21, 0x00 }),
		MakeQuicFrame({ 0xC3, 0x00 }),
		{ OP_UDPRESERVEDPROT2, OP_NATT_FRAME_KEY, 0x01 },
		{ 0xE3, 0x9A, 0x01 } };

	for (std::vector<uint8_t> &datagram : datagrams) {
		SRouteRecorder recorder;
		recorder.utpConsumes = true;
		recorder.quicConsumes = true;

		ASSERT_FALSE(Route(recorder, datagram, false, false));

		ASSERT_EQUALS(1u, (unsigned)recorder.calls.size());
		ASSERT_TRUE(recorder.calls[0] == "ed2k");
		ASSERT_EQUALS(datagram.size(), recorder.ed2kLength);
	}
}

// A datagram declined by all three is dropped without error, which the router
// expresses by returning false and touching nothing: it has no error channel
// of its own, and the drop -- with its reason -- belongs to the ed2k side's
// frame demultiplexer.
TEST(UtpDatagramRouting, DatagramDeclinedByAllThreeIsDroppedWithoutError)
{
	std::vector<uint8_t> datagram = MakeQuicFrame({ 0xC3 });

	SRouteRecorder recorder;
	recorder.utpConsumes = false;
	recorder.quicConsumes = false;

	ASSERT_FALSE(Route(recorder, datagram, true, true));

	ASSERT_EQUALS(2u, (unsigned)recorder.calls.size());
	ASSERT_TRUE(recorder.calls[1] == "ed2k");
}
