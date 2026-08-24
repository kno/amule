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

// The substitution: a uTP connection wearing the shape CLibSocket presents to
// everything above it.
//
// CUtpStream already presented aMule's Write/Read convention over libutp before
// this, and nothing put it underneath a socket -- so uTP carried no data at all.
// This suite drives what closed that gap, and the assertions are chosen for the
// two things that would fail silently:
//
//   - **The would-block contract.** CEMSocket checks BlocksRead() and
//     BlocksWrite() *before* LastError() (EMSocket.cpp:240, :658). "Nothing
//     right now" therefore has to be a zero return with the blocks flag set and
//     LastError() still zero. Report an error there instead and every closed
//     send window becomes a dropped connection, which looks exactly like a bad
//     peer.
//
//   - **Whose fault a failure is.** A refusal is about the peer; a timeout or a
//     reset is about the path. Read the second as the first and every peer
//     behind one UDP-blocking middlebox is marked dead, with nothing in any log
//     to say so.
//
// No libutp and no network: the library is behind IUtpLibrary and the fake here
// answers on command, which is the only way to reach both sides of those
// questions in one build.

#include <muleunit/test.h>

#include <NetworkAddress.h>
#include <UtpSocketTransport.h>

#include <cstring>
#include <string>
#include <vector>

using namespace muleunit;

DECLARE_SIMPLE(UtpSocketTransport)

namespace
{

//! A stand-in for libutp: records every call and answers as instructed.
class CFakeUtpLibrary : public IUtpLibrary
{
public:
	void *CreateContext() override
	{
		++createCalls;
		return reinterpret_cast<void *>(0xC0FFEEu);
	}

	void DestroyContext(void *) override { ++destroyCalls; }

	bool ProcessDatagram(
		void *, const uint8_t *, size_t, const CNetworkAddress &, uint16_t) override
	{
		return true;
	}

	bool AcceptsInboundConnections(void *context) const override
	{
		return context != nullptr && acceptsInbound;
	}

	void IssueDeferredAcks(void *) override { ++deferredAckCalls; }
	void CheckTimeouts(void *) override { ++timeoutCalls;

	}

	//! The send window. `windowOpen == false` makes utp_write answer zero,
	//! which is the ordinary case under load and must never read as an error.
	long WriteToSocket(void *socket, const uint8_t *data, size_t length) override
	{
		++writeCalls;
		wroteOnSocket = socket;
		if (!windowOpen) {
			return 0;
		}
		const size_t taken = length < windowBytes ? length : windowBytes;
		written.insert(written.end(), data, data + taken);
		return (long)taken;
	}

	void *CreateOutboundSocket(
		void *, void *userData, const CNetworkAddress &to, uint16_t port) override
	{
		++dialCalls;
		dialledTo = to;
		dialledPort = port;
		dialUserData = userData;
		if (!dialSucceeds) {
			return nullptr;
		}
		return reinterpret_cast<void *>(0xBEEF0000u + dialCalls);
	}

	void CloseSocket(void *socket) override
	{
		++closeCalls;
		closedSockets.push_back(socket);
	}

	void NotifyReadDrained(void *socket) override
	{
		++readDrainedCalls;
		readDrainedOnSocket = socket;
	}

	unsigned createCalls = 0;
	unsigned destroyCalls = 0;
	unsigned deferredAckCalls = 0;
	unsigned timeoutCalls = 0;
	unsigned writeCalls = 0;
	unsigned dialCalls = 0;
	unsigned closeCalls = 0;
	unsigned readDrainedCalls = 0;

	bool acceptsInbound = false;
	bool windowOpen = true;
	size_t windowBytes = 64u * 1024u;
	bool dialSucceeds = true;

	std::vector<uint8_t> written;
	void *wroteOnSocket = nullptr;
	void *dialUserData = nullptr;
	void *readDrainedOnSocket = nullptr;
	std::vector<void *> closedSockets;
	CNetworkAddress dialledTo;
	uint16_t dialledPort = 0;
};

class CFakeDatagramSink : public IUtpDatagramSink
{
public:
	void SendUtpDatagram(const uint8_t *, size_t, const CNetworkAddress &, uint16_t) override {}
};

//! Stands in for the socket wrapper above: counts the four events the asio
//! reactor posts, which is exactly what the production sink turns them into.
class CFakeSocketEvents : public IUtpSocketEvents
{
public:
	void OnUtpSocketConnected() override { ++connected; }
	void OnUtpSocketReadable() override { ++readable; }
	void OnUtpSocketWritable() override { ++writable; }
	void OnUtpSocketLost() override { ++lost; }

	unsigned connected = 0;
	unsigned readable = 0;
	unsigned writable = 0;
	unsigned lost = 0;
};

const CNetworkAddress Peer4()
{
	return CNetworkAddress::FromString("192.0.2.10");
}

const CNetworkAddress Peer6()
{
	return CNetworkAddress::FromString("2001:db8::1");
}

//! A live outbound transport, already attached, not yet connected.
struct SDialled
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	CFakeSocketEvents events;
	CUtpSocketTransport *transport = nullptr;

	SDialled()
	{
		context.Configure(&library, &sink);
		transport = DialUtp(context, Peer4(), 4662);
		if (transport != nullptr) {
			transport->SetEventSink(&events);
		}
	}

	~SDialled() { delete transport; }
};

} // namespace

// The dial itself: a utp_socket is created and connected, and the transport is
// its user data from before the SYN leaves -- otherwise the connection's first
// callback has nothing to resolve and the handshake completes into a void.
TEST(UtpSocketTransport, DialCreatesAConnectionOwnedByTheTransport)
{
	SDialled dialled;

	ASSERT_TRUE(dialled.transport != NULL);
	ASSERT_EQUALS(1u, dialled.library.dialCalls);
	ASSERT_TRUE(dialled.library.dialUserData == dialled.transport);
	ASSERT_TRUE(dialled.library.dialledTo == Peer4());
	ASSERT_EQUALS(4662, (int)dialled.library.dialledPort);
	ASSERT_TRUE(dialled.transport->IsAttached());
	// Registered for ticks: libutp accepts a write only while its own window
	// allows, so a connection nobody ticks never drains its queue.
	ASSERT_EQUALS(1u, (unsigned)dialled.context.GetTickableCount());
}

// A dial that could not start leaks nothing -- no transport, and nothing left
// registered on the context to be ticked forever.
TEST(UtpSocketTransport, AFailedDialLeavesNothingBehind)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	context.Configure(&library, &sink);
	library.dialSucceeds = false;

	ASSERT_TRUE(DialUtp(context, Peer4(), 4662) == NULL);
	ASSERT_EQUALS(0u, (unsigned)context.GetTickableCount());
}

// IPv4-only staging: an IPv6 peer is refused before libutp is asked, so the
// family rule stays the one predicate CUtpContext::IsUsableEndpoint() states.
TEST(UtpSocketTransport, AnIpv6PeerIsNotDialledWhileStagingIsIpv4Only)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	context.Configure(&library, &sink);

	ASSERT_TRUE(DialUtp(context, Peer6(), 4662) == NULL);
	ASSERT_EQUALS(0u, library.dialCalls);
}

// A build with no libutp cannot dial, and must not fault trying.
TEST(UtpSocketTransport, WithoutALibraryThereIsNoDial)
{
	CFakeDatagramSink sink;
	CUtpContext context;
	context.Configure(nullptr, &sink);

	ASSERT_TRUE(DialUtp(context, Peer4(), 4662) == NULL);
}

// Before the handshake completes a write is blocked, not failed. This is the
// contract CEMSocket reads: BlocksWrite() true with LastError() zero means
// "retry on the send event", and anything else here tears down a connection
// that was merely still being established.
TEST(UtpSocketTransport, WritesBlockBeforeTheHandshakeCompletes)
{
	SDialled dialled;
	const uint8_t payload[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

	ASSERT_FALSE(dialled.transport->IsConnected());
	ASSERT_EQUALS(0u, dialled.transport->Write(payload, 8));
	ASSERT_TRUE(dialled.transport->BlocksWrite());
	ASSERT_EQUALS(0, dialled.transport->LastError());
	ASSERT_EQUALS(0u, dialled.library.writeCalls);
}

// The whole point of the change: application bytes cross a uTP connection.
// Queued by Write(), handed to libutp on the tick, byte-for-byte.
TEST(UtpSocketTransport, ApplicationBytesReachTheLibraryOnTheTick)
{
	SDialled dialled;
	const uint8_t payload[5] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x2A };

	dialled.transport->OnUtpStateChange(UTP_SOCKET_CONNECTED);
	ASSERT_EQUALS(1u, dialled.events.connected);
	ASSERT_TRUE(dialled.transport->IsConnected());
	ASSERT_TRUE(dialled.transport->IsOk());

	ASSERT_EQUALS(5u, dialled.transport->Write(payload, 5));
	ASSERT_FALSE(dialled.transport->BlocksWrite());

	dialled.context.Tick(1000);

	ASSERT_EQUALS(5u, (unsigned)dialled.library.written.size());
	ASSERT_EQUALS(0, memcmp(&dialled.library.written[0], payload, 5));
	ASSERT_EQUALS(0u, (unsigned)dialled.transport->GetPendingWriteBytes());
}

// The other direction. libutp delivers on its own callback, the socket above is
// woken, and Read() hands the bytes over with the drain reported back -- libutp
// derives the receive window it advertises from what is still buffered here, so
// a drain that is not reported stalls the peer.
TEST(UtpSocketTransport, PeerBytesReachTheApplicationAndTheDrainIsReported)
{
	SDialled dialled;
	const uint8_t inbound[4] = { 0x11, 0x22, 0x33, 0x44 };
	uint8_t out[4] = { 0, 0, 0, 0 };

	dialled.transport->OnUtpStateChange(UTP_SOCKET_CONNECTED);

	// Nothing has arrived: blocked, not failed.
	ASSERT_EQUALS(0u, dialled.transport->Read(out, 4));
	ASSERT_TRUE(dialled.transport->BlocksRead());
	ASSERT_EQUALS(0, dialled.transport->LastError());

	dialled.transport->OnUtpDataReceived(inbound, 4);
	ASSERT_EQUALS(1u, dialled.events.readable);
	ASSERT_EQUALS(4u, (unsigned)dialled.transport->GetPendingReadBytes());

	ASSERT_EQUALS(4u, dialled.transport->Read(out, 4));
	ASSERT_EQUALS(0, memcmp(out, inbound, 4));
	ASSERT_FALSE(dialled.transport->BlocksRead());
	ASSERT_EQUALS(1u, dialled.library.readDrainedCalls);
	ASSERT_EQUALS(0u, (unsigned)dialled.transport->GetPendingReadBytes());
}

// A closed send window is the ordinary case under load. utp_write answering
// zero must leave the connection healthy and the queue intact, and the socket
// above must be told when the window reopens -- without that notification the
// send queue above stops being drained and the transfer stalls with nothing
// wrong anywhere.
TEST(UtpSocketTransport, AClosedWindowBlocksAndTheReopenIsAnnounced)
{
	SDialled dialled;
	const uint8_t payload[16] = { 0 };

	dialled.transport->OnUtpStateChange(UTP_SOCKET_CONNECTED);
	dialled.library.windowOpen = false;

	ASSERT_EQUALS(16u, dialled.transport->Write(payload, 16));
	dialled.context.Tick(1000);

	// libutp said no. Healthy, and the bytes are still ours.
	ASSERT_EQUALS(0, dialled.transport->LastError());
	ASSERT_EQUALS(16u, (unsigned)dialled.transport->GetPendingWriteBytes());
	ASSERT_EQUALS(0u, (unsigned)dialled.library.written.size());

	dialled.library.windowOpen = true;
	dialled.transport->OnUtpStateChange(UTP_SOCKET_WRITABLE);

	ASSERT_EQUALS(16u, (unsigned)dialled.library.written.size());
	ASSERT_EQUALS(0u, (unsigned)dialled.transport->GetPendingWriteBytes());
}

// A timeout is a fact about the path, never about the peer. This is the
// assertion that keeps a UDP-blocking middlebox from costing every source
// behind it.
TEST(UtpSocketTransport, ATimeoutIsATransportFailureAndNotThePeersFault)
{
	SDialled dialled;

	dialled.transport->OnUtpError(UTP_SOCKET_TIMEDOUT);

	ASSERT_TRUE(dialled.transport->GetOutcome() == UTP_ATTEMPT_TRANSPORT_FAILED);
	ASSERT_TRUE(dialled.transport->HasTransportFailed());
	ASSERT_EQUALS(1u, dialled.events.lost);
	// Now, and only now, LastError() is non-zero.
	ASSERT_TRUE(dialled.transport->LastError() != 0);

	// And the disposition the client path reads keeps the source.
	const SUtpAttemptDisposition disposition =
		DisposeUtpAttempt(dialled.transport->GetOutcome(), false);
	ASSERT_TRUE(disposition.tryTcp);
	ASSERT_FALSE(disposition.markPeerDead);
	ASSERT_FALSE(disposition.dropFromSourceList);
}

// A reset is equally unattributable: it says the connection died, not that the
// peer refused it.
TEST(UtpSocketTransport, AResetIsATransportFailureToo)
{
	SDialled dialled;

	dialled.transport->OnUtpError(UTP_SOCKET_RESET);

	ASSERT_TRUE(dialled.transport->GetOutcome() == UTP_ATTEMPT_TRANSPORT_FAILED);
	ASSERT_FALSE(DisposeUtpAttempt(dialled.transport->GetOutcome(), false).markPeerDead);
}

// A refusal is the one outcome that IS about the peer, and it goes down the
// rules that predate uTP -- including marking it dead. Asserted alongside the
// two above because only the pair proves the mapping distinguishes them.
TEST(UtpSocketTransport, ARefusalIsThePeersAnswerAndKeepsThePreUtpRules)
{
	SDialled dialled;

	dialled.transport->OnUtpError(UTP_SOCKET_REFUSED);

	ASSERT_TRUE(dialled.transport->GetOutcome() == UTP_ATTEMPT_PEER_REFUSED);
	ASSERT_FALSE(dialled.transport->HasTransportFailed());

	const SUtpAttemptDisposition disposition =
		DisposeUtpAttempt(dialled.transport->GetOutcome(), false);
	ASSERT_FALSE(disposition.tryTcp);
	ASSERT_TRUE(disposition.markPeerDead);
}

// An ordinary close is neither: a closed connection and a failed one must be
// different answers, or every disconnect would start shielding the peer.
TEST(UtpSocketTransport, AnOrdinaryCloseIsNotAFailure)
{
	SDialled dialled;

	dialled.transport->OnUtpStateChange(UTP_SOCKET_CONNECTED);
	dialled.transport->Close();

	ASSERT_FALSE(dialled.transport->HasTransportFailed());
	ASSERT_TRUE(dialled.transport->GetOutcome() == UTP_ATTEMPT_CONNECTED);
	ASSERT_EQUALS(0, dialled.transport->LastError());
	ASSERT_FALSE(dialled.transport->IsOk());
	// The libutp socket went with it, exactly once.
	ASSERT_EQUALS(1u, dialled.library.closeCalls);
}

// UTP_STATE_DESTROYING means nothing may refer to the socket again -- including
// this object's own destructor. A second utp_close() on a socket libutp has
// freed is a use-after-free, so the count here is the assertion.
TEST(UtpSocketTransport, DestroyingReleasesTheSocketWithoutClosingItAgain)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	context.Configure(&library, &sink);

	{
		CUtpSocketTransport *transport = DialUtp(context, Peer4(), 4662);
		ASSERT_TRUE(transport != NULL);
		transport->OnUtpStateChange(UTP_SOCKET_DESTROYING);
		delete transport;
	}

	ASSERT_EQUALS(0u, library.closeCalls);
	ASSERT_EQUALS(0u, (unsigned)context.GetTickableCount());
}

// The peer's identity comes from the transport, because there is no TCP
// connection to ask. CClientTCPSocket::InitNetworkData() reads both of these on
// every accepted connection.
TEST(UtpSocketTransport, ThePeerIsAnsweredByTheTransport)
{
	SDialled dialled;

	ASSERT_TRUE(dialled.transport->GetPeerAddress() == Peer4());
	ASSERT_EQUALS(4662, (int)dialled.transport->GetPeerPort());
}

// A destroyed transport stops being ticked. It is registered by raw pointer, so
// a missed deregistration is a dangling call on the next core timer tick.
TEST(UtpSocketTransport, ADestroyedTransportIsNoLongerTicked)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	context.Configure(&library, &sink);

	CUtpSocketTransport *first = DialUtp(context, Peer4(), 4662);
	CUtpSocketTransport *second = DialUtp(context, Peer4(), 4663);
	ASSERT_EQUALS(2u, (unsigned)context.GetTickableCount());

	delete first;
	ASSERT_EQUALS(1u, (unsigned)context.GetTickableCount());

	delete second;
	ASSERT_EQUALS(0u, (unsigned)context.GetTickableCount());
}

// An accepted connection is up on arrival: libutp completes the handshake
// before it hands it over, and there is no UTP_STATE_CONNECT to wait for. A
// transport that waited for one would refuse every write for the life of the
// connection -- an inbound peer that connects and then never receives a byte.
TEST(UtpSocketTransport, AnAcceptedConnectionIsConnectedOnArrival)
{
	CFakeUtpLibrary library;
	CFakeDatagramSink sink;
	CUtpContext context;
	context.Configure(&library, &sink);

	CUtpSocketTransport transport(context, Peer4(), 4662);
	transport.AttachSocket(reinterpret_cast<void *>(0xABCDu), true);

	ASSERT_TRUE(transport.IsConnected());
	ASSERT_TRUE(transport.IsOk());

	const uint8_t payload[4] = { 9, 9, 9, 9 };
	ASSERT_EQUALS(4u, transport.Write(payload, 4));
	context.Tick(500);
	ASSERT_EQUALS(4u, (unsigned)library.written.size());
}
