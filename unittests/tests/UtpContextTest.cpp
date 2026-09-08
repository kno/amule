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

// The uTP context: one per client instance, fed by inbound datagrams, driven
// by a periodic tick, and sending through the ed2k UDP socket it shares a port
// with.
//
// The tick is the part with no visible failure mode. libutp does its
// retransmission and congestion control in utp_check_timeouts(); a context
// that is only serviced when a packet arrives cannot recover a lost packet on
// an otherwise idle connection, because the packet that would drive it is the
// one that was lost. The connection then sits there until something unrelated
// happens on the same context. So the test that matters here drives ticks with
// no inbound traffic at all and asserts the timeout check still fires.
//
// The library is behind IUtpLibrary so this test needs neither libutp nor a
// network: the fake counts calls and answers on command, which is also what
// lets "the context declined this datagram" be exercised in both directions.

#include <muleunit/test.h>

#include <NetworkAddress.h>
#include <UtpContext.h>

#include <string>
#include <vector>

using namespace muleunit;

DECLARE_SIMPLE(UtpContext)

namespace
{

//! A stand-in for libutp: counts every call and answers as instructed.
class CFakeUtpLibrary : public IUtpLibrary
{
public:
	void *CreateContext() override
	{
		++createCalls;
		lastHandle = reinterpret_cast<void *>(0xC0FFEEu + createCalls);
		return lastHandle;
	}

	void DestroyContext(void *context) override
	{
		++destroyCalls;
		destroyedHandle = context;
	}

	bool ProcessDatagram(void *context,
		const uint8_t *payload,
		size_t length,
		const CNetworkAddress &from,
		uint16_t port) override
	{
		++processCalls;
		processedOnHandle = context;
		processedLength = length;
		processedFirstByte = length != 0 ? payload[0] : 0;
		processedFrom = from;
		processedPort = port;
		return consumes;
	}

	void IssueDeferredAcks(void *context) override
	{
		++deferredAckCalls;
		acksOnHandle = context;
	}

	void CheckTimeouts(void *context) override
	{
		++timeoutCalls;
		timeoutsOnHandle = context;
	}

	//! Not exercised here: the per-connection write path is CUtpStream's, and
	//! UtpStreamTest drives it.
	long WriteToSocket(void *, const uint8_t *, size_t length) override { return (long)length; }

	//! The dial and the per-connection teardown are CUtpSocketTransport's, and
	//! UtpSocketTransportTest drives them. Present here because IUtpLibrary is
	//! one interface: inert answers keep this fake honest about what it does
	//! not stand in for.
	void *CreateOutboundSocket(void *, void *, const CNetworkAddress &, uint16_t) override
	{
		return nullptr;
	}

	void CloseSocket(void *) override {}
	void NotifyReadDrained(void *) override {}

	//! Stands in for "UTP_ON_ACCEPT is registered on this context". The real
	//! adapter answers from its own registration; the fake answers on command
	//! so both sides of the gate are reachable in one build.
	bool AcceptsInboundConnections(void *context) const override
	{
		return context != nullptr && acceptsInbound;
	}

	unsigned createCalls = 0;
	unsigned destroyCalls = 0;
	unsigned processCalls = 0;
	unsigned deferredAckCalls = 0;
	unsigned timeoutCalls = 0;

	bool consumes = true;
	bool acceptsInbound = false;

	void *lastHandle = nullptr;
	void *destroyedHandle = nullptr;
	void *processedOnHandle = nullptr;
	void *acksOnHandle = nullptr;
	void *timeoutsOnHandle = nullptr;

	size_t processedLength = 0;
	uint8_t processedFirstByte = 0;
	CNetworkAddress processedFrom;
	uint16_t processedPort = 0;
};

//! Stands in for the ed2k UDP socket the context sends through.
class CFakeDatagramSink : public IUtpDatagramSink
{
public:
	void SendUtpDatagram(
		const uint8_t *payload, size_t length, const CNetworkAddress &to, uint16_t port) override
	{
		++sendCalls;
		sent.assign(payload, payload + length);
		sentTo = to;
		sentPort = port;
	}

	unsigned sendCalls = 0;
	std::vector<uint8_t> sent;
	CNetworkAddress sentTo;
	uint16_t sentPort = 0;
};

const CNetworkAddress Peer4()
{
	return CNetworkAddress::FromString("192.0.2.10");
}

const CNetworkAddress Peer6()
{
	return CNetworkAddress::FromString("2001:db8::1");
}

} // namespace

// Design, "Shape": one utp_context per client instance, not per connection.
// libutp keeps its own socket table inside the context, so a context per
// connection would give every connection its own congestion state on one port
// -- and the accept path would have nowhere to land.
TEST(UtpContext, OneContextPerClientInstance)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	context.Configure(&library, &sink);

	const uint8_t datagram[3] = { 0x21, 0x00, 0x01 };

	for (int i = 0; i < 3; ++i) {
		context.ProcessDatagram(datagram, 3, Peer4(), 4662);
	}
	for (int i = 0; i < 5; ++i) {
		context.Tick();
	}

	ASSERT_EQUALS(1u, library.createCalls);
	ASSERT_EQUALS(3u, library.processCalls);
	// Every call went to that one handle, which is the whole point.
	ASSERT_TRUE(library.processedOnHandle == library.lastHandle);
	ASSERT_TRUE(library.timeoutsOnHandle == library.lastHandle);
}

// Spec delta, "Idle connection with pending retransmission": with no inbound
// traffic whatsoever, the tick alone must keep driving the context. Asserted
// as one timeout check per tick with a process count of exactly zero -- if the
// implementation ever only serviced timers off the receive path, the process
// count could not stay at zero while the timeout count rose.
TEST(UtpContext, IdleRetransmissionFiresOnTheTickAlone)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	context.Configure(&library, &sink);

	for (int i = 0; i < 4; ++i) {
		context.Tick();
	}

	ASSERT_EQUALS(0u, library.processCalls);
	ASSERT_EQUALS(4u, library.timeoutCalls);
	// Deferred acks go out on the same tick: an ack held back for
	// coalescing and never flushed stalls the peer's window just as
	// effectively as a missing retransmission.
	ASSERT_EQUALS(4u, library.deferredAckCalls);
	// The tick brought the context up on its own. Retransmission must not
	// wait for a first inbound packet to create it.
	ASSERT_EQUALS(1u, library.createCalls);
}

// The context's answer is libutp's answer, both ways: consumed means the ed2k
// parser must not run, declined means it must. Anything that hardcoded one of
// the two would leave one of these two cases failing.
TEST(UtpContext, TheContextsAnswerIsTheLibrarysAnswer)
{
	const uint8_t datagram[2] = { 0x41, 0x00 };

	CFakeUtpLibrary consuming;
	CFakeDatagramSink sink;
	CUtpContext consumingContext;
	consuming.consumes = true;
	consumingContext.Configure(&consuming, &sink);
	ASSERT_TRUE(consumingContext.ProcessDatagram(datagram, 2, Peer4(), 4662));

	CFakeUtpLibrary declining;
	CUtpContext decliningContext;
	declining.consumes = false;
	decliningContext.Configure(&declining, &sink);
	ASSERT_FALSE(decliningContext.ProcessDatagram(datagram, 2, Peer4(), 4662));

	// Either way the payload and the peer reached the library intact.
	ASSERT_EQUALS(2u, (unsigned)declining.processedLength);
	ASSERT_EQUALS(0x41, (int)declining.processedFirstByte);
	ASSERT_TRUE(declining.processedFrom == Peer4());
	ASSERT_EQUALS(4662, (int)declining.processedPort);
}

// Design, "Shape": outbound datagrams leave through the same UDP socket, which
// is what lets uTP reuse the NAT hole ed2k UDP already has. The context hands
// the sink the uTP payload; the sink is what wraps it in the 0xB2/0x00 frame.
TEST(UtpContext, OutboundDatagramLeavesThroughTheSharedSocket)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	context.Configure(&library, &sink);

	const uint8_t payload[4] = { 0x21, 0x00, 0x00, 0x07 };
	ASSERT_TRUE(context.SendDatagram(payload, 4, Peer4(), 4672));

	ASSERT_EQUALS(1u, sink.sendCalls);
	ASSERT_EQUALS(4u, (unsigned)sink.sent.size());
	ASSERT_EQUALS(0x07, (int)sink.sent[3]);
	ASSERT_TRUE(sink.sentTo == Peer4());
	ASSERT_EQUALS(4672, (int)sink.sentPort);
}

// Proposal, "Staging": IPv4 only ships first, deliberately, even though
// address widening has landed. The interface stays family-generic -- it takes
// a CNetworkAddress, not a uint32 -- so enabling IPv6 later is a change to
// this guard and not to every signature. Until then an IPv6 peer must be
// declined rather than handed to a library that was never exercised over it in
// this tree.
TEST(UtpContext, Ipv6PeerIsDeclinedWhileStagingIsIpv4Only)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	context.Configure(&library, &sink);

	const uint8_t datagram[2] = { 0x21, 0x00 };

	ASSERT_FALSE(context.ProcessDatagram(datagram, 2, Peer6(), 4662));
	ASSERT_EQUALS(0u, library.processCalls);

	ASSERT_FALSE(context.SendDatagram(datagram, 2, Peer6(), 4662));
	ASSERT_EQUALS(0u, sink.sendCalls);

	// An absent address is the same refusal, not a crash.
	ASSERT_FALSE(context.ProcessDatagram(datagram, 2, CNetworkAddress::Absent(), 4662));
	ASSERT_EQUALS(0u, library.processCalls);

	// And the IPv4 peer still works, so the guard is a family test and not
	// a blanket refusal.
	ASSERT_TRUE(context.ProcessDatagram(datagram, 2, Peer4(), 4662));
	ASSERT_EQUALS(1u, library.processCalls);
}

// A build configured with -DENABLE_UTP=NO has no library at all. Nothing may
// be created, nothing may be sent, and neither the receive path nor the tick
// may fault -- both run on every datagram and every core timer tick in a
// perfectly ordinary build.
TEST(UtpContext, WithoutALibraryTheContextIsUnavailableAndInert)
{
	CFakeDatagramSink sink;
	CUtpContext context;
	context.Configure(nullptr, &sink);

	const uint8_t datagram[2] = { 0x21, 0x00 };

	ASSERT_FALSE(context.IsAvailable());
	ASSERT_FALSE(context.ProcessDatagram(datagram, 2, Peer4(), 4662));
	ASSERT_FALSE(context.SendDatagram(datagram, 2, Peer4(), 4662));
	context.Tick();

	ASSERT_EQUALS(0u, sink.sendCalls);

	// An unconfigured context is the same state: this is what a socket
	// looks like between construction and Configure().
	CUtpContext unconfigured;
	ASSERT_FALSE(unconfigured.IsAvailable());
	ASSERT_FALSE(unconfigured.ProcessDatagram(datagram, 2, Peer4(), 4662));
	unconfigured.Tick();
}

// The context belongs to the client instance and dies with it. libutp holds
// per-context allocations, so leaking one across a socket close/open cycle --
// which OnCoreTimer does on a lost Kad connection (amule.cpp) -- would leak
// them for the life of the process.
TEST(UtpContext, ContextIsDestroyedWithTheClientInstance)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;

	{
		CUtpContext context;
		context.Configure(&library, &sink);
		context.Tick();
		ASSERT_EQUALS(1u, library.createCalls);
		ASSERT_EQUALS(0u, library.destroyCalls);
	}

	ASSERT_EQUALS(1u, library.destroyCalls);
	ASSERT_TRUE(library.destroyedHandle == library.lastHandle);
}

// What gates the advertised MOD_MISCOPT_NAT_TRAVERSAL bit.
//
// Compiled in and configured is the equivalent of a bound socket: necessary and
// not sufficient. libutp drops an inbound connection outright unless
// UTP_ON_ACCEPT is registered on the context, so a build that has libutp, has a
// context and has no accept callback cannot serve a single uTP connection --
// and if it advertised the capability anyway, every peer that read the bit
// would spend its connection attempts on a client that silently discards them.
// Nothing logs on either side; the only symptom is a source that never
// transfers. That is why this question is asked of the library rather than
// answered by "a context exists".
//
// The same distinction is already precedent in this tree: the IPv6 capability
// bit follows *verified* inbound connectivity, not a bound socket.
TEST(UtpContext, CannotServeConnectionsWhileInboundAcceptIsUnwired)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	context.Configure(&library, &sink);

	library.acceptsInbound = false;

	ASSERT_TRUE(context.IsAvailable());
	ASSERT_FALSE(context.CanServeConnections());
}

// The other side of the same gate: once the accept path is wired, this end can
// serve and the capability becomes honest to advertise. Asserted here rather
// than only in the production adapter because only one of the two answers
// exists in any given build, and the wrong one produces no symptom.
TEST(UtpContext, ServesConnectionsOnceInboundAcceptIsWired)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	context.Configure(&library, &sink);

	library.acceptsInbound = true;

	ASSERT_TRUE(context.CanServeConnections());
	// The question had to create the context to be answerable at all: the
	// answer must not depend on whether a tick happened to run first, or the
	// advertised capability would flap for one core-timer period after every
	// socket reopen.
	ASSERT_EQUALS(1u, library.createCalls);
}

// A default build -- ENABLE_UTP off, no library, no context -- serves nothing,
// so it advertises nothing. This is the assertion that keeps the default build
// byte-identical on the wire to what it was before uTP existed.
TEST(UtpContext, CannotServeConnectionsWithoutALibrary)
{
	CFakeDatagramSink sink;
	CUtpContext context;
	context.Configure(nullptr, &sink);

	ASSERT_FALSE(context.CanServeConnections());

	CUtpContext unconfigured;
	ASSERT_FALSE(unconfigured.CanServeConnections());
}
