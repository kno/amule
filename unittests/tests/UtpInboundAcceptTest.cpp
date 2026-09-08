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

// The inbound half, and the capability bit that follows it.
//
// libutp drops an inbound connection outright unless UTP_ON_ACCEPT is
// registered on its context. So "this end can serve a uTP connection" is not
// "libutp is linked" and not "a context exists" -- it is "an inbound attempt
// would be handled". That distinction is the whole reason the advertised
// MOD_MISCOPT_NAT_TRAVERSAL bit is gated on CanServeConnections() rather than on
// the build configuration: a client advertising a capability it cannot serve
// makes every peer that reads the bit spend its connection attempts on a socket
// that silently discards them, with nothing logged on either side and no symptom
// except a source that never transfers.
//
// The registration therefore follows the acceptor, and not the other way round.
// libutp answers an inbound SYN as soon as the callback exists, so registering
// it with nowhere to put the connection would complete a handshake and then drop
// it -- worse for the peer than never answering, because it looks like a working
// client.
//
// This suite pins the composed answer -- the capability word absent before the
// accept path is wired and carrying the bit after -- because that is the
// observable that reaches the wire, and neither half of it is observable in a
// build that has only one of the two answers.

#include <muleunit/test.h>

#include <NetworkAddress.h>
#include <PeerCapabilities.h>
#include <UtpContext.h>
#include <UtpSocketTransport.h>

#include <vector>

using namespace muleunit;

DECLARE_SIMPLE(UtpInboundAccept)

namespace
{

/**
 * A stand-in for libutp that behaves the way the real adapter does about the
 * accept callback: the registration follows the owning context's acceptor, and
 * the claim is set at the point of registration and nowhere else.
 */
class CFakeUtpLibrary : public IUtpLibrary
{
public:
	//! Set after both objects exist, because the declaration order matters
	//! for their destruction: the context tears its libutp context down
	//! through this library, so the library has to outlive it, while an
	//! accepted transport has to die before the context it is registered with.
	//! Hence library, then context, then acceptor -- and a setter rather than a
	//! constructor argument.
	void SetOwner(CUtpContext *owner) { m_owner = owner; }

	void *CreateContext() override
	{
		++createCalls;
		// Exactly CUtpLibraryAdapter::CreateContext()'s rule.
		acceptCallbackRegistered = m_owner != nullptr && m_owner->HasInboundAcceptor();
		return reinterpret_cast<void *>(0xC0FFEEu);
	}

	void DestroyContext(void *) override {}

	bool ProcessDatagram(void *, const uint8_t *, size_t, const CNetworkAddress &, uint16_t) override
	{
		return true;
	}

	bool AcceptsInboundConnections(void *context) const override
	{
		return context != nullptr && acceptCallbackRegistered;
	}

	void IssueDeferredAcks(void *) override {}
	void CheckTimeouts(void *) override {}
	long WriteToSocket(void *, const uint8_t *, size_t length) override { return (long)length; }

	void *CreateOutboundSocket(void *, void *, const CNetworkAddress &, uint16_t) override
	{
		return reinterpret_cast<void *>(0xBEEFu);
	}

	void CloseSocket(void *socket) override { closedSockets.push_back(socket); }
	void NotifyReadDrained(void *) override {}

	unsigned createCalls = 0;
	bool acceptCallbackRegistered = false;
	std::vector<void *> closedSockets;

private:
	CUtpContext *m_owner = nullptr;
};

class CFakeDatagramSink : public IUtpDatagramSink
{
public:
	void SendUtpDatagram(const uint8_t *, size_t, const CNetworkAddress &, uint16_t) override {}
};

//! Stands in for CUtpInboundAcceptor. The production one builds a
//! CClientTCPSocket, which needs theApp; what is assertable without one is the
//! contract around it -- who is offered the connection, and who closes it when
//! it is refused.
class CFakeAcceptor : public IUtpConnectionAcceptor
{
public:
	CUtpSocketTransport *AcceptUtpConnection(
		CUtpContext &context, void *socket, const CNetworkAddress &from, std::uint16_t port) override
	{
		++calls;
		offeredSocket = socket;
		offeredFrom = from;
		offeredPort = port;

		if (!accepts) {
			// The production acceptor owns the socket from the moment it is
			// called, refusal included, so a refusal closes it here.
			context.CloseSocket(socket);
			return nullptr;
		}

		taken = new CUtpSocketTransport(context, from, port);
		taken->AttachSocket(socket, true);
		return taken;
	}

	~CFakeAcceptor() { delete taken; }

	bool accepts = true;
	unsigned calls = 0;
	void *offeredSocket = nullptr;
	CNetworkAddress offeredFrom;
	std::uint16_t offeredPort = 0;
	CUtpSocketTransport *taken = nullptr;
};

const CNetworkAddress Peer4()
{
	return CNetworkAddress::FromString("198.51.100.7");
}

const CNetworkAddress Peer6()
{
	return CNetworkAddress::FromString("2001:db8::2");
}

void *const INBOUND_SOCKET = reinterpret_cast<void *>(0x51F0u);

} // namespace

// The state this change started from: libutp linked, a context created, and no
// accept path. Nothing may be advertised, because nothing can be served.
TEST(UtpInboundAccept, WithoutAnAcceptorNothingIsServedAndNothingIsAdvertised)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	library.SetOwner(&context);
	context.Configure(&library, &sink);

	ASSERT_TRUE(context.IsAvailable());
	ASSERT_FALSE(context.HasInboundAcceptor());
	ASSERT_FALSE(context.CanServeConnections());
	// The accept callback was never registered, which is what makes the
	// refusal libutp's own behaviour rather than a decision taken later.
	ASSERT_FALSE(library.acceptCallbackRegistered);

	// The composed answer: this is the word that reaches the wire. The QUIC
	// half is false throughout this suite -- what is under test here is the
	// uTP gate, and QUIC has a gate of its own that must not be able to set
	// this bit. PeerCapabilitiesTest pins the composition of the two.
	ASSERT_EQUALS(0u, (unsigned)AdvertisedModMiscOptions(context.CanServeConnections(), false));
}

// The state after this change: an acceptor exists, so the callback is
// registered, so an inbound attempt is handled -- and the bit becomes honest.
TEST(UtpInboundAccept, WithAnAcceptorTheCapabilityBitIsAdvertised)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	CFakeAcceptor acceptor;
	library.SetOwner(&context);
	context.Configure(&library, &sink, &acceptor);

	ASSERT_TRUE(context.HasInboundAcceptor());
	ASSERT_TRUE(context.CanServeConnections());
	ASSERT_TRUE(library.acceptCallbackRegistered);

	ASSERT_EQUALS((unsigned)MOD_MISCOPT_NAT_TRAVERSAL,
		(unsigned)AdvertisedModMiscOptions(context.CanServeConnections(), false));
	ASSERT_EQUALS(0x00000002u, (unsigned)MOD_MISCOPT_NAT_TRAVERSAL);
}

// A default build -- ENABLE_UTP off, so no library and no context -- serves
// nothing whatever else is configured, and advertises nothing. This is the
// assertion that keeps the default build's handshake identical to the one that
// predates uTP.
TEST(UtpInboundAccept, WithoutALibraryTheAcceptorChangesNothing)
{
	CUtpContext context;
	CFakeDatagramSink sink;
	CFakeAcceptor acceptor;
	context.Configure(nullptr, &sink, &acceptor);

	ASSERT_FALSE(context.CanServeConnections());
	ASSERT_EQUALS(0u, (unsigned)AdvertisedModMiscOptions(context.CanServeConnections(), false));
}

// An inbound connection reaches the acceptor with the peer intact, and the
// transport it produces is what the callback hands back to libutp as the
// socket's user data.
TEST(UtpInboundAccept, AnInboundConnectionIsOfferedToTheAcceptor)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	CFakeAcceptor acceptor;
	library.SetOwner(&context);
	context.Configure(&library, &sink, &acceptor);

	CUtpSocketTransport *taken = context.OnInboundConnection(INBOUND_SOCKET, Peer4(), 4662);

	ASSERT_EQUALS(1u, acceptor.calls);
	ASSERT_TRUE(taken != NULL);
	ASSERT_TRUE(taken == acceptor.taken);
	ASSERT_TRUE(acceptor.offeredSocket == INBOUND_SOCKET);
	ASSERT_TRUE(acceptor.offeredFrom == Peer4());
	ASSERT_EQUALS(4662, (int)acceptor.offeredPort);
	// Accepted connections are up on arrival: libutp handshook it before
	// telling us.
	ASSERT_TRUE(taken->IsConnected());
}

// A refused connection is closed exactly once, by whoever refused it. libutp's
// utp_close() is not safe to call twice on one socket, so splitting that
// ownership would make a double close a matter of which refusal path was taken.
TEST(UtpInboundAccept, ARefusedConnectionIsClosedOnceByTheAcceptor)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	CFakeAcceptor acceptor;
	library.SetOwner(&context);
	acceptor.accepts = false;
	context.Configure(&library, &sink, &acceptor);

	ASSERT_TRUE(context.OnInboundConnection(INBOUND_SOCKET, Peer4(), 4662) == NULL);
	ASSERT_EQUALS(1u, acceptor.calls);
	ASSERT_EQUALS(1u, (unsigned)library.closedSockets.size());
	ASSERT_TRUE(library.closedSockets[0] == INBOUND_SOCKET);
}

// Refused before the acceptor is reached -- an address family this transport
// does not carry yet -- and the context closes it, because nothing else has
// taken it. Still exactly once.
TEST(UtpInboundAccept, AnIpv6InboundConnectionIsDeclinedAndClosedByTheContext)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	CFakeAcceptor acceptor;
	library.SetOwner(&context);
	context.Configure(&library, &sink, &acceptor);

	ASSERT_TRUE(context.OnInboundConnection(INBOUND_SOCKET, Peer6(), 4662) == NULL);
	ASSERT_EQUALS(0u, acceptor.calls);
	ASSERT_EQUALS(1u, (unsigned)library.closedSockets.size());
}

// And with no acceptor at all, an inbound connection that somehow arrived is
// closed rather than leaked: libutp had already answered the SYN, so leaving it
// open would keep a connection in its table nobody reads.
TEST(UtpInboundAccept, AnInboundConnectionWithNoAcceptorIsClosed)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	library.SetOwner(&context);
	context.Configure(&library, &sink);

	ASSERT_TRUE(context.OnInboundConnection(INBOUND_SOCKET, Peer4(), 4662) == NULL);
	ASSERT_EQUALS(1u, (unsigned)library.closedSockets.size());
}

// The gate must not depend on whether a tick happened to run first, or the
// advertised capability would flap for one core-timer period after every socket
// reopen. Asking creates the context.
TEST(UtpInboundAccept, TheAnswerDoesNotDependOnATickHavingRun)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	CFakeAcceptor acceptor;
	library.SetOwner(&context);
	context.Configure(&library, &sink, &acceptor);

	ASSERT_EQUALS(0u, library.createCalls);
	ASSERT_TRUE(context.CanServeConnections());
	ASSERT_EQUALS(1u, library.createCalls);

	// And it is stable: the same context, the same answer.
	ASSERT_TRUE(context.CanServeConnections());
	ASSERT_EQUALS(1u, library.createCalls);
}
