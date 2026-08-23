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

// The stream face of uTP: Write/Read with the same convention as
// CEncryptedStreamSocket (bytes transferred, 0 for would-block), so the client
// path consumes a uTP connection the way it consumes a TCP one.
//
// What is worth testing here is not the copying, it is the drain: libutp
// accepts a write only when its own window allows, so the buffer in front of it
// has to be emptied under a budget. Without the budget one connection with a
// large buffer monopolises a pump pass; without the backoff a closed window
// turns into a busy loop that calls utp_write thousands of times a second and
// gets zero every time.

#include <muleunit/test.h>

#include <UtpStream.h>

#include <vector>

using namespace muleunit;

DECLARE_SIMPLE(UtpStream)

namespace
{

const size_t k64K = 64u * 1024u;
const size_t k256K = 256u * 1024u;

//! Answers utp_write with a scripted result and records what it was given.
class CFakeWriteLibrary : public IUtpLibrary
{
public:
	void *CreateContext() override { return reinterpret_cast<void *>(0xC1u); }
	void DestroyContext(void *) override {}
	bool ProcessDatagram(void *, const uint8_t *, size_t, const CNetworkAddress &, uint16_t) override
	{
		return false;
	}
	void IssueDeferredAcks(void *) override {}
	void CheckTimeouts(void *) override {}
	//! Not exercised here: the accept path gates the advertised capability,
	//! and UtpContextTest drives it. The write path is what this suite is for.
	bool AcceptsInboundConnections(void *) const override { return false; }

	long WriteToSocket(void *, const uint8_t *data, size_t length) override
	{
		++writeCalls;
		lastLength = length;
		if (result == 0) {
			return 0;
		}
		if (result < 0) {
			return result;
		}
		const size_t accepted = length < (size_t)result ? length : (size_t)result;
		acceptedTotal += accepted;
		firstByteOfLastWrite = length != 0 ? data[0] : 0;
		return (long)accepted;
	}

	//! Bytes utp_write will take per call. 0 means "window closed",
	//! negative means an error.
	long result = (long)k64K;

	unsigned writeCalls = 0;
	size_t acceptedTotal = 0;
	size_t lastLength = 0;
	uint8_t firstByteOfLastWrite = 0;
};

CUtpStream MakeConnectedStream(CFakeWriteLibrary &library)
{
	CUtpStream stream;
	stream.Attach(&library, reinterpret_cast<void *>(0x5Cu));
	stream.OnConnected();
	return stream;
}

std::vector<uint8_t> Payload(size_t length, uint8_t first)
{
	std::vector<uint8_t> data(length, 0x5A);
	if (length != 0) {
		data[0] = first;
	}
	return data;
}

} // namespace

// The interface the client already consumes for TCP: a write returns the byte
// count it took, and zero means "retry later" rather than an error.
TEST(UtpStream, WriteReportsWhatItAcceptedAndReadReturnsIt)
{
	CFakeWriteLibrary library;
	CUtpStream stream = MakeConnectedStream(library);

	ASSERT_TRUE(stream.IsConnected());

	const std::vector<uint8_t> data = Payload(1000, 0xAB);
	ASSERT_EQUALS(1000, stream.Write(&data[0], data.size(), 1000));

	// Inbound direction: what libutp delivered is what Read hands back, in
	// order, and a partial read leaves the rest queued.
	const std::vector<uint8_t> inbound = Payload(10, 0x11);
	stream.OnDataReceived(&inbound[0], inbound.size());

	uint8_t out[4] = { 0, 0, 0, 0 };
	ASSERT_EQUALS(4, stream.Read(out, 4));
	ASSERT_EQUALS(0x11, (int)out[0]);
	ASSERT_EQUALS(0x5A, (int)out[1]);
	ASSERT_EQUALS(4, stream.Read(out, 4));
	// Ten bytes delivered, eight read: the remainder is what is left, and
	// then nothing.
	ASSERT_EQUALS(2, stream.Read(out, 4));
	ASSERT_EQUALS(0, stream.Read(out, 4));
}

// A write that finds the buffer full returns zero rather than blocking or
// growing without limit -- and the buffer's own promotion accounting is what
// decides whether the retry fits.
TEST(UtpStream, WriteBlocksAtTheBufferCeilingRatherThanGrowingForever)
{
	CFakeWriteLibrary library;
	library.result = 0; // window closed: nothing drains
	CUtpStream stream = MakeConnectedStream(library);

	const std::vector<uint8_t> chunk = Payload(k64K, 0x01);

	size_t total = 0;
	int accepted = 0;
	while ((accepted = stream.Write(&chunk[0], chunk.size(), 1000)) != 0) {
		total += (size_t)accepted;
	}

	// The first blocked write promoted 64 KB -> 512 KB, so that is what it
	// took before it started refusing.
	ASSERT_EQUALS(512u * 1024u, total);
	ASSERT_EQUALS(0, stream.Write(&chunk[0], chunk.size(), 1000));
	ASSERT_EQUALS(512u * 1024u, stream.GetWriteBufferCapacity());
}

// The drain budget: at most UTP_WRITE_MAX_ATTEMPTS_PER_PASS calls to utp_write
// per pump pass. One connection with a full buffer must not hold the pump.
TEST(UtpStream, PumpStopsAfterTheAttemptBudget)
{
	CFakeWriteLibrary library;
	library.result = 1024; // small window: every attempt takes a little
	CUtpStream stream = MakeConnectedStream(library);

	const std::vector<uint8_t> data = Payload(k64K, 0x02);
	stream.Write(&data[0], data.size(), 1000);

	const size_t written = stream.PumpWrites(1000);

	ASSERT_EQUALS(UTP_WRITE_MAX_ATTEMPTS_PER_PASS, library.writeCalls);
	ASSERT_EQUALS(1024u * UTP_WRITE_MAX_ATTEMPTS_PER_PASS, (unsigned)written);
	// The rest is still queued for the next pass -- nothing was dropped.
	ASSERT_EQUALS(k64K - written, stream.GetPendingWriteBytes());
}

// The other half of the budget: at most UTP_WRITE_MAX_BYTES_PER_PASS bytes, and
// no single utp_write larger than UTP_WRITE_MAX_ATTEMPT_SIZE.
TEST(UtpStream, PumpStopsAfterTheByteBudget)
{
	CFakeWriteLibrary library;
	library.result = (long)k256K; // a wide-open window
	CUtpStream stream = MakeConnectedStream(library);

	// Queue well past the per-pass budget.
	const std::vector<uint8_t> chunk = Payload(k64K, 0x03);
	for (int i = 0; i < 8; ++i) {
		stream.Write(&chunk[0], chunk.size(), 1000);
	}
	ASSERT_TRUE(stream.GetPendingWriteBytes() > UTP_WRITE_MAX_BYTES_PER_PASS);

	const size_t written = stream.PumpWrites(1000);

	ASSERT_EQUALS(UTP_WRITE_MAX_BYTES_PER_PASS, written);
	ASSERT_TRUE(library.lastLength <= UTP_WRITE_MAX_ATTEMPT_SIZE);

	// A second pass carries on from where the first stopped.
	const size_t remaining = stream.GetPendingWriteBytes();
	ASSERT_TRUE(remaining != 0);
	ASSERT_TRUE(stream.PumpWrites(1001) != 0);
	ASSERT_TRUE(stream.GetPendingWriteBytes() < remaining);
}

// A closed window must not become a busy loop. After a zero-byte write the
// stream backs off, and the backoff grows with the burst up to a cap.
TEST(UtpStream, ZeroWriteBacksOffAndTheDelayIsCapped)
{
	CFakeWriteLibrary library;
	library.result = 0;
	CUtpStream stream = MakeConnectedStream(library);

	const std::vector<uint8_t> data = Payload(k64K, 0x04);
	stream.Write(&data[0], data.size(), 1000);

	ASSERT_EQUALS(0u, (unsigned)stream.PumpWrites(1000));
	ASSERT_EQUALS(1u, library.writeCalls);

	// Inside the backoff window nothing is attempted at all.
	ASSERT_EQUALS(0u, (unsigned)stream.PumpWrites(1000 + UTP_ZERO_WRITE_RETRY_BASE_MS));
	ASSERT_EQUALS(1u, library.writeCalls);

	// Past it, exactly one more attempt.
	const uint64_t firstDelay = UTP_ZERO_WRITE_RETRY_BASE_MS + UTP_ZERO_WRITE_RETRY_STEP_MS;
	ASSERT_EQUALS(0u, (unsigned)stream.PumpWrites(1000 + firstDelay));
	ASSERT_EQUALS(2u, library.writeCalls);

	// Keep failing and the delay climbs, then stops at the cap rather than
	// backing off toward never retrying.
	uint64_t now = 1000 + firstDelay;
	for (int i = 0; i < 60; ++i) {
		now += UTP_ZERO_WRITE_RETRY_MAX_MS;
		stream.PumpWrites(now);
	}
	ASSERT_EQUALS(UTP_ZERO_WRITE_RETRY_MAX_MS, stream.GetZeroWriteBackoffMs());

	// A window that reopens clears the backoff immediately: the next pass
	// must not sit out a delay earned while it was closed.
	library.result = (long)k64K;
	ASSERT_TRUE(stream.PumpWrites(now + UTP_ZERO_WRITE_RETRY_MAX_MS) != 0);
	ASSERT_EQUALS(0u, (unsigned)stream.GetZeroWriteBackoffMs());
}

// The duplex trim reaches the stream: a connection carrying traffic both ways
// gets the duplex ceiling, and the queued bytes survive the trim.
TEST(UtpStream, DuplexTransferTrimsTheStreamsBuffer)
{
	CFakeWriteLibrary library;
	library.result = 0;
	CUtpStream stream = MakeConnectedStream(library);

	// Grow the buffer past the duplex ceiling the hard way, with the window
	// closed: fill to 512 KB, then earn the second promotion with sustained
	// blocked writes.
	const std::vector<uint8_t> chunk = Payload(k64K, 0x05);
	while (stream.Write(&chunk[0], chunk.size(), 1000) != 0) {
	}
	ASSERT_EQUALS(512u * 1024u, stream.GetWriteBufferCapacity());

	for (unsigned i = 0; i < UTP_WRITE_BUFFER_PROMOTION_BLOCKS; ++i) {
		stream.Write(&chunk[0], chunk.size(), 1000);
	}
	ASSERT_EQUALS(2u * 1024u * 1024u, stream.GetWriteBufferCapacity());

	// Now the connection turns out to be carrying traffic both ways. The
	// ceiling drops immediately -- but the buffer cannot follow while more
	// is queued than the duplex ceiling would hold, because the trim must
	// not drop bytes the application believes were accepted.
	const size_t queued = stream.GetPendingWriteBytes();
	ASSERT_TRUE(queued > 512u * 1024u);

	stream.SetDuplexTransfer(true);
	ASSERT_EQUALS(512u * 1024u, stream.GetWriteBufferMaxCapacity());
	ASSERT_EQUALS(2u * 1024u * 1024u, stream.GetWriteBufferCapacity());

	stream.Write(&chunk[0], chunk.size(), 1001);
	ASSERT_EQUALS(2u * 1024u * 1024u, stream.GetWriteBufferCapacity());
	ASSERT_EQUALS(queued, stream.GetPendingWriteBytes());

	// Drain under the ceiling and the next write takes the trim, with every
	// queued byte still there.
	library.result = (long)k256K;
	ASSERT_EQUALS(k256K, stream.PumpWrites(1002));
	const size_t stillQueued = stream.GetPendingWriteBytes();
	ASSERT_TRUE(stillQueued < 512u * 1024u);
	ASSERT_EQUALS(2u * 1024u * 1024u, stream.GetWriteBufferCapacity());

	ASSERT_EQUALS((int)k64K, stream.Write(&chunk[0], chunk.size(), 1003));
	ASSERT_EQUALS(512u * 1024u, stream.GetWriteBufferCapacity());
	ASSERT_EQUALS(stillQueued + k64K, stream.GetPendingWriteBytes());
}

// Transport failure is visible on the stream, because that is where the client
// path reads it -- and it is not the same thing as a closed connection.
TEST(UtpStream, TransportFailureIsVisibleAndDistinctFromClose)
{
	CFakeWriteLibrary library;
	CUtpStream stream = MakeConnectedStream(library);

	ASSERT_FALSE(stream.HasTransportFailed());

	stream.OnTransportFailure();
	ASSERT_TRUE(stream.HasTransportFailed());
	ASSERT_FALSE(stream.IsConnected());
	ASSERT_EQUALS((int)UTP_FALLBACK_TRY_TCP, (int)DecideFallback(stream.GetOutcome(), false));

	// A stream closed in the ordinary way has not failed, so it must not
	// trigger a fallback.
	CUtpStream closing = MakeConnectedStream(library);
	closing.Close();
	ASSERT_FALSE(closing.HasTransportFailed());
	ASSERT_FALSE(closing.IsConnected());
	ASSERT_EQUALS((int)UTP_FALLBACK_NONE, (int)DecideFallback(closing.GetOutcome(), false));
}

// A stream with no libutp socket behind it -- an unattached one, or one whose
// socket has gone -- accepts nothing and pumps nothing, rather than writing
// through a null handle.
TEST(UtpStream, DetachedStreamIsInert)
{
	CUtpStream stream;
	const std::vector<uint8_t> data = Payload(16, 0x06);

	ASSERT_FALSE(stream.IsConnected());
	ASSERT_EQUALS(0, stream.Write(&data[0], data.size(), 1000));
	ASSERT_EQUALS(0u, (unsigned)stream.PumpWrites(1000));
	ASSERT_EQUALS(0u, (unsigned)stream.GetPendingWriteBytes());
}
