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

// The QUIC byte-stream transport, driven by a fake IQuicStreamWriter.
//
// This is the piece task 2.1 was missing and 3.1 was blocking: the adapter could
// complete a handshake and validate a peer proof, and then had nowhere to put the
// bytes. The behaviours asserted here are the ones the layers above the socket
// already depend on and were never told there was a choice about:
//
//   - the would-block contract, which CEMSocket reads *before* LastError(), so
//     "nothing right now" must be zero bytes with the flag set and no error;
//   - that ngtcp2 is entered only from the tick, because Write() arrives on the
//     upload throttler's thread and a call into the library from there corrupts
//     its per-connection state with no reliable symptom;
//   - that the write queue is bounded, because the throttler produces bytes at
//     the configured upload rate indefinitely and a peer that stops reading must
//     not turn that into unbounded memory.
//
// None of it needs ngtcp2: the library sits behind IQuicStreamWriter, which is
// what makes every branch reachable in the default -DENABLE_QUIC=NO build.

#include <muleunit/test.h>

#include <NetworkAddress.h>
#include <QuicSocketTransport.h>

#include <cstring>
#include <string>
#include <vector>

using namespace muleunit;

DECLARE_SIMPLE(QuicSocketTransport)

namespace
{

//! Records what the transport handed to ngtcp2, and accepts as configured.
class CFakeStreamWriter : public IQuicStreamWriter
{
public:
	//! How many bytes each WriteQuicStream() accepts. A negative meaning is not
	//! needed: zero is "window closed", which is the case that must block rather
	//! than fail.
	std::size_t acceptsPerCall = 64 * 1024;

	std::vector<std::uint8_t> written;
	int writeCalls = 0;
	int closeCalls = 0;
	int detachCalls = 0;

	std::size_t WriteQuicStream(const std::uint8_t *data, std::size_t length) override
	{
		++writeCalls;
		const std::size_t taken = (length < acceptsPerCall) ? length : acceptsPerCall;
		written.insert(written.end(), data, data + taken);
		return taken;
	}

	void CloseQuicStream() override { ++closeCalls; }
	void DetachStreamTransport() override { ++detachCalls; }
};

class CFakeStreamEvents : public IStreamTransportEvents
{
public:
	int connected = 0;
	int readable = 0;
	int writable = 0;
	int lost = 0;

	void OnStreamTransportConnected() override { ++connected; }
	void OnStreamTransportReadable() override { ++readable; }
	void OnStreamTransportWritable() override { ++writable; }
	void OnStreamTransportLost() override { ++lost; }
};

CNetworkAddress Peer()
{
	return CNetworkAddress::FromString("192.0.2.10");
}

} // namespace

// A transport with no writer is not connected and refuses to write. This is the
// state between construction and the accept path binding the connection, and it
// must not look usable: CUpDownClient dials only when IsOk() is false, so a
// transport that claimed to be up would suppress the connection attempt that
// should have replaced it.
TEST(QuicSocketTransport, WithoutAConnectionItIsNotUsable)
{
	CQuicSocketTransport transport(Peer(), 4672);

	ASSERT_FALSE(transport.IsConnected());
	ASSERT_FALSE(transport.IsOk());

	const char payload[] = "hello";
	ASSERT_EQUALS(0u, (unsigned)transport.Write(payload, 5));
	ASSERT_TRUE(transport.BlocksWrite());
	// Blocked, not failed: the caller retries on the send event, exactly as it
	// does for a TCP connect in flight.
	ASSERT_EQUALS(0, transport.LastError());
}

// Connected on arrival. A QUIC connection reaches this object only after its
// handshake completed and its peer proof validated, so there is no state left to
// wait for -- and a transport that waited for one would refuse every write for
// the life of the connection.
TEST(QuicSocketTransport, AttachingAConnectionMakesItConnected)
{
	CFakeStreamWriter writer;
	CQuicSocketTransport transport(Peer(), 4672);

	transport.AttachWriter(&writer);

	ASSERT_TRUE(transport.IsConnected());
	ASSERT_TRUE(transport.IsOk());
	ASSERT_EQUALS(0, transport.LastError());
}

// The exact would-block contract on the read side. CEMSocket checks BlocksRead()
// before LastError() (EMSocket.cpp:240), so an empty queue must be zero bytes
// with the flag set and LastError() still zero. Reporting an error there instead
// turns an idle connection into a dropped one.
TEST(QuicSocketTransport, AnEmptyReadBlocksWithoutError)
{
	CFakeStreamWriter writer;
	CQuicSocketTransport transport(Peer(), 4672);
	transport.AttachWriter(&writer);

	char buffer[16];
	ASSERT_EQUALS(0u, (unsigned)transport.Read(buffer, sizeof(buffer)));
	ASSERT_TRUE(transport.BlocksRead());
	ASSERT_EQUALS(0, transport.LastError());
}

// Bytes from the peer are delivered in order and the socket above is woken. In
// order matters and is free here rather than earned: QUIC delivers stream bytes
// with no gaps, so this is a plain queue and needs none of CUtpStream's
// reassembly.
TEST(QuicSocketTransport, PeerBytesAreReadableInOrder)
{
	CFakeStreamWriter writer;
	CFakeStreamEvents events;
	CQuicSocketTransport transport(Peer(), 4672);
	transport.AttachWriter(&writer);
	transport.SetEventSink(&events);

	const std::uint8_t first[] = { 'a', 'b', 'c' };
	const std::uint8_t second[] = { 'd', 'e' };
	transport.OnQuicStreamData(first, sizeof(first));
	transport.OnQuicStreamData(second, sizeof(second));

	ASSERT_EQUALS(2, events.readable);
	ASSERT_EQUALS(5u, (unsigned)transport.GetPendingReadBytes());
	ASSERT_FALSE(transport.BlocksRead());

	char buffer[8];
	memset(buffer, 0, sizeof(buffer));
	ASSERT_EQUALS(5u, (unsigned)transport.Read(buffer, sizeof(buffer)));
	ASSERT_EQUALS(0, memcmp(buffer, "abcde", 5));
	// Drained, so the next read blocks -- and still reports no error.
	ASSERT_TRUE(transport.BlocksRead());
	ASSERT_EQUALS(0, transport.LastError());
}

// A partial read leaves the remainder queued and does not block: the caller asked
// for less than there is, which is not the same as there being nothing.
TEST(QuicSocketTransport, APartialReadKeepsTheRemainder)
{
	CFakeStreamWriter writer;
	CQuicSocketTransport transport(Peer(), 4672);
	transport.AttachWriter(&writer);

	const std::uint8_t bytes[] = { 1, 2, 3, 4, 5, 6 };
	transport.OnQuicStreamData(bytes, sizeof(bytes));

	char buffer[4];
	ASSERT_EQUALS(4u, (unsigned)transport.Read(buffer, sizeof(buffer)));
	ASSERT_EQUALS(2u, (unsigned)transport.GetPendingReadBytes());
	ASSERT_FALSE(transport.BlocksRead());
}

// **The threading rule, expressed as a behaviour.** Write() must not enter
// ngtcp2: it arrives on the upload throttler's thread as well as the core thread,
// and a call into the library from the wrong thread corrupts its per-connection
// state with no reliable symptom -- which is precisely why this has to be
// asserted rather than reviewed.
TEST(QuicSocketTransport, WriteQueuesAndOnlyTheTickReachesTheLibrary)
{
	CFakeStreamWriter writer;
	CQuicSocketTransport transport(Peer(), 4672);
	transport.AttachWriter(&writer);

	const char payload[] = "0123456789";
	ASSERT_EQUALS(10u, (unsigned)transport.Write(payload, 10));

	// Nothing has reached the library yet.
	ASSERT_EQUALS(0, writer.writeCalls);
	ASSERT_EQUALS(10u, (unsigned)transport.GetPendingWriteBytes());

	transport.OnQuicTick();

	ASSERT_EQUALS(1, writer.writeCalls);
	ASSERT_EQUALS(10u, (unsigned)writer.written.size());
	ASSERT_EQUALS(0, memcmp(writer.written.data(), payload, 10));
	ASSERT_EQUALS(0u, (unsigned)transport.GetPendingWriteBytes());
}

// A closed window takes nothing and loses nothing. Zero from the library is flow
// control, not failure: dropping the queue there would silently lose bytes the
// layers above believe were accepted.
TEST(QuicSocketTransport, AClosedWindowLeavesTheQueueIntact)
{
	CFakeStreamWriter writer;
	writer.acceptsPerCall = 0;
	CQuicSocketTransport transport(Peer(), 4672);
	transport.AttachWriter(&writer);

	ASSERT_EQUALS(4u, (unsigned)transport.Write("abcd", 4));
	transport.OnQuicTick();

	ASSERT_EQUALS(4u, (unsigned)transport.GetPendingWriteBytes());
	ASSERT_EQUALS(0, transport.LastError());
}

// A partial acceptance is ordinary rather than an error: the stream's
// flow-control window is finite, and the remainder goes on the next tick.
TEST(QuicSocketTransport, APartialAcceptanceDrainsAcrossTicks)
{
	CFakeStreamWriter writer;
	writer.acceptsPerCall = 3;
	CQuicSocketTransport transport(Peer(), 4672);
	transport.AttachWriter(&writer);

	ASSERT_EQUALS(9u, (unsigned)transport.Write("abcdefghi", 9));

	transport.OnQuicTick();
	ASSERT_EQUALS(6u, (unsigned)transport.GetPendingWriteBytes());
	transport.OnQuicTick();
	ASSERT_EQUALS(3u, (unsigned)transport.GetPendingWriteBytes());
	transport.OnQuicTick();
	ASSERT_EQUALS(0u, (unsigned)transport.GetPendingWriteBytes());

	ASSERT_EQUALS(9u, (unsigned)writer.written.size());
	ASSERT_EQUALS(0, memcmp(writer.written.data(), "abcdefghi", 9));
}

// The write queue is bounded, and over the bound the write blocks rather than
// grows. The upload throttler produces bytes at the configured rate for as long
// as the connection lives, so a peer that stops reading would otherwise turn a
// stalled transfer into unbounded memory.
TEST(QuicSocketTransport, TheWriteQueueIsBoundedAndBlocksRatherThanGrows)
{
	CFakeStreamWriter writer;
	writer.acceptsPerCall = 0; // Nothing drains, so the bound is reachable.
	CQuicSocketTransport transport(Peer(), 4672);
	transport.AttachWriter(&writer);

	const std::vector<char> chunk(64 * 1024, 'x');
	std::size_t queued = 0;
	for (int i = 0; i < 16; ++i) {
		queued += transport.Write(chunk.data(), (std::uint32_t)chunk.size());
	}

	ASSERT_EQUALS((unsigned)CQuicSocketTransport::kMaxWriteQueueBytes, (unsigned)queued);
	ASSERT_EQUALS((unsigned)CQuicSocketTransport::kMaxWriteQueueBytes,
		(unsigned)transport.GetPendingWriteBytes());
	ASSERT_TRUE(transport.BlocksWrite());
	// Still not a failure. A full send buffer is the TCP convention the layers
	// above already implement, and reporting an error would drop the connection.
	ASSERT_EQUALS(0, transport.LastError());
}

// Draining below the bound reopens the window and announces it once. Without the
// announcement the connection would idle until something else woke it, because
// CEMSocket retries on the send event rather than by polling.
TEST(QuicSocketTransport, DrainingBelowTheBoundAnnouncesWritability)
{
	CFakeStreamWriter writer;
	writer.acceptsPerCall = 0;
	CFakeStreamEvents events;
	CQuicSocketTransport transport(Peer(), 4672);
	transport.AttachWriter(&writer);
	transport.SetEventSink(&events);

	const std::vector<char> chunk(64 * 1024, 'x');
	for (int i = 0; i < 16; ++i) {
		transport.Write(chunk.data(), (std::uint32_t)chunk.size());
	}
	ASSERT_TRUE(transport.BlocksWrite());
	ASSERT_EQUALS(0, events.writable);

	writer.acceptsPerCall = 1024;
	transport.OnQuicTick();

	ASSERT_FALSE(transport.BlocksWrite());
	ASSERT_EQUALS(1, events.writable);
}

// An ordinary close closes the connection and does NOT set a failure. A closed
// connection and a failed one are different answers, and only the second must
// keep the peer blameless -- see UtpTransportFailure.h for what depends on that
// distinction on the uTP side.
TEST(QuicSocketTransport, CloseIsNotAFailure)
{
	CFakeStreamWriter writer;
	CQuicSocketTransport transport(Peer(), 4672);
	transport.AttachWriter(&writer);

	transport.Close();

	ASSERT_EQUALS(1, writer.closeCalls);
	ASSERT_FALSE(transport.IsConnected());
	ASSERT_EQUALS(0, transport.LastError());

	// Idempotent: the socket above closes on more than one teardown path, and a
	// second CloseQuicStream() would reach a connection that may already be gone.
	transport.Close();
	ASSERT_EQUALS(1, writer.closeCalls);
}

// A lost connection wakes the socket above and stops the transport calling back
// into the connection, which is being destroyed by its own owner.
TEST(QuicSocketTransport, ALostConnectionIsAnnouncedAndTheWriterIsDropped)
{
	CFakeStreamWriter writer;
	CFakeStreamEvents events;
	CQuicSocketTransport transport(Peer(), 4672);
	transport.AttachWriter(&writer);
	transport.SetEventSink(&events);

	transport.OnQuicStreamLost(true);

	ASSERT_EQUALS(1, events.lost);
	ASSERT_FALSE(transport.IsConnected());
	ASSERT_TRUE(transport.LastError() != 0);

	// Nothing further reaches the connection: Close() and the tick both find a
	// NULL writer, which is what keeps a destroyed connection from being called.
	transport.Close();
	transport.OnQuicTick();
	ASSERT_EQUALS(0, writer.closeCalls);
	ASSERT_EQUALS(0, writer.writeCalls);
}

// The destructor detaches both ways. The two objects point at each other and
// either may die first -- the transport belongs to a CClientTCPSocket, the
// connection to the QUIC endpoint -- so a single direction would leave a
// dangling pointer on whichever path was not taken.
TEST(QuicSocketTransport, TheDestructorDetachesAndClosesTheConnection)
{
	CFakeStreamWriter writer;

	{
		CQuicSocketTransport transport(Peer(), 4672);
		transport.AttachWriter(&writer);
	}

	ASSERT_EQUALS(1, writer.detachCalls);
	ASSERT_EQUALS(1, writer.closeCalls);
}

// After the connection is gone, the destructor must not reach it. This is the
// other order of the same teardown, and it is the one that crashes if only the
// transport's side of the detach exists.
TEST(QuicSocketTransport, ADestructorAfterTheConnectionIsGoneTouchesNothing)
{
	CFakeStreamWriter writer;

	{
		CQuicSocketTransport transport(Peer(), 4672);
		transport.AttachWriter(&writer);
		transport.OnQuicStreamLost(false);
	}

	ASSERT_EQUALS(0, writer.detachCalls);
	ASSERT_EQUALS(0, writer.closeCalls);
}

// The peer accessors answer from the transport, because the asio socket
// underneath was never opened. CClientTCPSocket stores the address in network
// order, so this is the one place the conversion has to be right.
TEST(QuicSocketTransport, ThePeerAccessorsAnswerFromTheTransport)
{
	CQuicSocketTransport transport(Peer(), 4672);

	ASSERT_TRUE(transport.GetPeerAddress() == Peer());
	ASSERT_EQUALS(4672, (int)transport.GetPeerPort());
}
