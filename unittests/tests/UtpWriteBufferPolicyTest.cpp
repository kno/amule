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

// The write-buffer heuristics ported from eMuleAI's CUtpSocket
// (srchybrid/eMuleAI/UtpSocket.cpp:1263-1372).
//
// These are the part of the uTP port that a single-direction test cannot see.
// A buffer that only ever grows works perfectly for one download; the moment
// the same socket is also uploading, two multi-megabyte buffers sit on one
// connection and the transfer stalls waiting on memory it is not using. A
// buffer that only ever shrinks stalls a one-directional bulk transfer at
// 64 KB. The growth thresholds and the duplex trim are one mechanism and the
// proposal says as much: ship them together or the port "will appear to work
// in single-direction tests and stall under real load".
//
// So every threshold is pinned here as a literal byte count, and each of the
// three behaviours -- growth on sustained blocking, the duplex trim, and the
// ceiling -- is asserted separately, including the interactions between them.

#include <muleunit/test.h>

#include <UtpWriteBufferPolicy.h>

using namespace muleunit;

DECLARE_SIMPLE(UtpWriteBufferPolicy)

namespace
{

const size_t k64K = 64u * 1024u;
const size_t k512K = 512u * 1024u;
const size_t k2M = 2u * 1024u * 1024u;
const size_t k4M = 4u * 1024u * 1024u;

//! Fill the buffer to its usable capacity, then report the accepted total.
size_t FillToCapacity(CUtpWriteBufferPolicy &policy, uint64_t nowMs)
{
	size_t total = 0;
	size_t accepted = 0;
	// One 64 KB chunk at a time: a single huge write would be clamped to the
	// free space in one call, which is the same end state by a less
	// realistic route.
	while ((accepted = policy.Enqueue(k64K, nowMs)) != 0) {
		total += accepted;
	}
	return total;
}

} // namespace

// Every threshold is a ported constant, not a judgement call. Literal values,
// so a "tidy-up" that halves one of them cannot pass.
TEST(UtpWriteBufferPolicy, ThresholdsAreTheOnesThatWerePorted)
{
	ASSERT_EQUALS(k64K, UTP_WRITE_BUFFER_INITIAL);
	ASSERT_EQUALS(k512K, UTP_WRITE_BUFFER_FIRST_ADAPTIVE);
	ASSERT_EQUALS(k2M, UTP_WRITE_BUFFER_SECOND_ADAPTIVE);
	ASSERT_EQUALS(k4M, UTP_WRITE_BUFFER_MAX_ADAPTIVE);
	// The duplex ceiling is the first adaptive step, not a separate number:
	// a duplex connection is allowed the first promotion and no more.
	ASSERT_EQUALS(k512K, UTP_WRITE_BUFFER_DUPLEX_MAX);
	ASSERT_EQUALS(UTP_WRITE_BUFFER_FIRST_ADAPTIVE, UTP_WRITE_BUFFER_DUPLEX_MAX);
	ASSERT_EQUALS(64u, UTP_WRITE_BUFFER_PROMOTION_BLOCKS);
	ASSERT_EQUALS(30000u, UTP_WRITE_BUFFER_IDLE_SHRINK_MS);
}

// A fresh connection gets the small buffer: handshake traffic is tiny, and a
// client with hundreds of connections cannot afford a megabyte each up front.
TEST(UtpWriteBufferPolicy, StartsAtTheInitialCapacityWithNothingQueued)
{
	CUtpWriteBufferPolicy policy;

	ASSERT_EQUALS(k64K, policy.GetCapacity());
	ASSERT_EQUALS(0u, (unsigned)policy.GetPendingBytes());
	ASSERT_EQUALS(k4M, policy.GetMaxCapacity());
	ASSERT_FALSE(policy.IsDuplexTransfer());
	ASSERT_FALSE(policy.HasGrown());
}

// Spec delta, "Sustained blocked writes", first half: the promotion out of the
// initial buffer happens on the FIRST block. Waiting 64 blocked writes to
// leave 64 KB would throttle every bulk transfer through a buffer sized for a
// handshake -- and the blocked write itself is then served, so the caller sees
// a promotion rather than a refusal.
TEST(UtpWriteBufferPolicy, FirstBlockAtTheInitialCapacityPromotesImmediately)
{
	CUtpWriteBufferPolicy policy;

	ASSERT_EQUALS(k64K, policy.Enqueue(k64K, 1000));
	ASSERT_EQUALS(k64K, policy.GetCapacity());
	ASSERT_EQUALS(k64K, (size_t)policy.GetPendingBytes());

	// The write that found it full promotes the buffer and is then served
	// out of the space that promotion opened.
	ASSERT_EQUALS(1u, (unsigned)policy.Enqueue(1, 1001));
	ASSERT_EQUALS(k512K, policy.GetCapacity());
	ASSERT_TRUE(policy.HasGrown());
	// The promotion resets the block accounting: the next step has to earn
	// its own 64 blocked writes.
	ASSERT_EQUALS(0u, policy.GetBlockedWritesAtCapacity());
}

// Spec delta, "Sustained blocked writes", second half: past the first
// promotion, growth costs 64 blocked writes per step. One blocked write is
// noise -- the peer's window closed for a moment -- and promoting on it would
// walk every connection up to 4 MB.
TEST(UtpWriteBufferPolicy, PastTheFirstStepGrowthNeedsSustainedBlocking)
{
	CUtpWriteBufferPolicy policy;

	// Fills through the immediate first promotion and stops at 512 KB with
	// one blocked write already counted.
	ASSERT_EQUALS(k512K, FillToCapacity(policy, 1000));
	ASSERT_EQUALS(k512K, policy.GetCapacity());
	ASSERT_EQUALS(k512K, (size_t)policy.GetPendingBytes());
	ASSERT_EQUALS(1u, policy.GetBlockedWritesAtCapacity());

	// Blocked writes 2 to 63 move the counter and nothing else.
	for (unsigned i = 2; i < UTP_WRITE_BUFFER_PROMOTION_BLOCKS; ++i) {
		ASSERT_EQUALS(0u, (unsigned)policy.Enqueue(k64K, 1000));
		ASSERT_EQUALS(k512K, policy.GetCapacity());
		ASSERT_EQUALS(i, policy.GetBlockedWritesAtCapacity());
	}

	// The 64th crosses the threshold, grows one step, and is served.
	ASSERT_EQUALS(k64K, policy.Enqueue(k64K, 1000));
	ASSERT_EQUALS(k2M, policy.GetCapacity());
	ASSERT_EQUALS(0u, policy.GetBlockedWritesAtCapacity());
}

// Spec delta, "Sustained blocked writes", the ceiling: growth stops at the
// documented maximum rather than growing unbounded. Blocked writes at 4 MB
// must not produce an 8 MB buffer, and must not keep a counter climbing
// either -- an unbounded counter is a slower leak of the same kind.
TEST(UtpWriteBufferPolicy, GrowthStopsAtTheMaximum)
{
	CUtpWriteBufferPolicy policy;

	// Walk it up to the ceiling the way a real transfer would: fill, block
	// repeatedly, fill again.
	ASSERT_TRUE(policy.GrowTo(k2M));
	FillToCapacity(policy, 1000);
	for (unsigned i = 0; i < UTP_WRITE_BUFFER_PROMOTION_BLOCKS; ++i) {
		policy.Enqueue(k64K, 1000);
	}
	ASSERT_EQUALS(k4M, policy.GetCapacity());
	FillToCapacity(policy, 1000);
	ASSERT_EQUALS(k4M, (size_t)policy.GetPendingBytes());

	// At the ceiling: any number of further blocked writes changes nothing,
	// counter included.
	for (unsigned i = 0; i < UTP_WRITE_BUFFER_PROMOTION_BLOCKS * 2; ++i) {
		ASSERT_EQUALS(0u, (unsigned)policy.Enqueue(k64K, 1000));
	}
	ASSERT_EQUALS(k4M, policy.GetCapacity());
	ASSERT_EQUALS(0u, policy.GetBlockedWritesAtCapacity());

	// And asking directly for more is clamped, not honoured.
	ASSERT_TRUE(policy.GrowTo(k4M * 4));
	ASSERT_EQUALS(k4M, policy.GetCapacity());
	ASSERT_EQUALS(k4M, policy.GetNextCapacity());
}

// Spec delta, "Simultaneous upload and download": once the connection is
// carrying traffic both ways the buffer is trimmed toward the duplex capacity,
// so that one socket does not hold a multi-megabyte buffer in each direction.
TEST(UtpWriteBufferPolicy, DuplexTransferTrimsTheBufferBackToTheDuplexCeiling)
{
	CUtpWriteBufferPolicy policy;
	ASSERT_TRUE(policy.GrowTo(k2M));
	ASSERT_EQUALS(k2M, policy.GetCapacity());

	policy.SetDuplexTransfer(true);

	// The ceiling moves first: that is what makes the trim a bounded
	// consequence rather than an arbitrary shrink.
	ASSERT_EQUALS(k512K, policy.GetMaxCapacity());
	ASSERT_TRUE(policy.TrimForDuplex());
	ASSERT_EQUALS(k512K, policy.GetCapacity());

	// Neither direction stalls for lack of buffer: the trimmed buffer is
	// still writable, up to the duplex capacity.
	ASSERT_EQUALS(k512K, FillToCapacity(policy, 2000));
}

// The trim must never discard queued bytes. With more queued than the duplex
// ceiling there is nothing safe to do yet, so the capacity stays where it is
// until the queue drains far enough.
TEST(UtpWriteBufferPolicy, TrimWaitsForTheQueueRatherThanDroppingData)
{
	CUtpWriteBufferPolicy policy;
	ASSERT_TRUE(policy.GrowTo(k2M));
	ASSERT_EQUALS(k2M, FillToCapacity(policy, 1000));

	policy.SetDuplexTransfer(true);
	ASSERT_FALSE(policy.TrimForDuplex());
	ASSERT_EQUALS(k2M, policy.GetCapacity());
	ASSERT_EQUALS(k2M, (size_t)policy.GetPendingBytes());

	// Drain to just above the duplex ceiling: still not trimmable.
	policy.Drain(k2M - k512K - k64K);
	ASSERT_EQUALS(k512K + k64K, (size_t)policy.GetPendingBytes());
	ASSERT_FALSE(policy.TrimForDuplex());
	ASSERT_EQUALS(k2M, policy.GetCapacity());

	// Once the queue fits under the ceiling the trim happens -- and the
	// send path takes it without being asked, which is eMuleAI's
	// "duplex-send" trim. The write that follows it is then blocked at the
	// duplex capacity rather than served out of a 2 MB buffer.
	policy.Drain(k64K);
	ASSERT_EQUALS(k512K, (size_t)policy.GetPendingBytes());
	ASSERT_EQUALS(0u, (unsigned)policy.Enqueue(1, 1000));
	ASSERT_EQUALS(k512K, policy.GetCapacity());
}

// The other trim call site: a buffer that drains completely while the transfer
// is duplex is trimmed on the drain ("duplex-drained"). Without it the buffer
// would sit at its grown size until the next write happened to notice.
TEST(UtpWriteBufferPolicy, FullyDrainedDuplexBufferTrimsOnTheDrain)
{
	CUtpWriteBufferPolicy policy;
	ASSERT_TRUE(policy.GrowTo(k2M));
	ASSERT_EQUALS(k64K, policy.Enqueue(k64K, 1000));

	policy.SetDuplexTransfer(true);
	ASSERT_EQUALS(k2M, policy.GetCapacity());

	policy.Drain(k64K);

	ASSERT_EQUALS(0u, (unsigned)policy.GetPendingBytes());
	ASSERT_EQUALS(k512K, policy.GetCapacity());
}

// While the connection is duplex, a blocked write must not promote past the
// duplex ceiling. This is the interaction a growth-only port gets wrong: the
// trim brings the buffer down and the very next blocked write puts it back.
TEST(UtpWriteBufferPolicy, DuplexCeilingSurvivesSustainedBlocking)
{
	CUtpWriteBufferPolicy policy;
	policy.SetDuplexTransfer(true);

	// The first promotion is still allowed -- it lands exactly on the
	// duplex ceiling, which is why the two numbers are the same constant.
	ASSERT_EQUALS(k512K, FillToCapacity(policy, 1000));
	ASSERT_EQUALS(k512K, policy.GetCapacity());

	for (unsigned i = 0; i < UTP_WRITE_BUFFER_PROMOTION_BLOCKS * 2; ++i) {
		ASSERT_EQUALS(0u, (unsigned)policy.Enqueue(k64K, 1000));
	}

	ASSERT_EQUALS(k512K, policy.GetCapacity());
	ASSERT_EQUALS(k512K, policy.GetMaxCapacity());
	// At the ceiling the counter is not even entered, so it cannot run away
	// while a duplex transfer is blocked.
	ASSERT_EQUALS(0u, policy.GetBlockedWritesAtCapacity());

	// When the transfer stops being duplex the ceiling comes back, and only
	// then can the buffer grow again.
	policy.SetDuplexTransfer(false);
	ASSERT_EQUALS(k4M, policy.GetMaxCapacity());
	for (unsigned i = 0; i < UTP_WRITE_BUFFER_PROMOTION_BLOCKS; ++i) {
		policy.Enqueue(k64K, 1000);
	}
	ASSERT_EQUALS(k2M, policy.GetCapacity());
}

// A grown buffer that has been idle for the shrink interval goes back to the
// initial size. Without this, one burst per connection is enough to leave a
// client holding megabytes per peer for the rest of the session.
TEST(UtpWriteBufferPolicy, GrownBufferShrinksAfterTheIdleInterval)
{
	CUtpWriteBufferPolicy policy;
	ASSERT_EQUALS(k512K, FillToCapacity(policy, 10000));
	ASSERT_EQUALS(k512K, policy.GetCapacity());

	// Still queued: nothing may shrink under queued data, however idle the
	// connection looks.
	ASSERT_FALSE(policy.ShrinkIfIdle(10000 + UTP_WRITE_BUFFER_IDLE_SHRINK_MS + 1));
	ASSERT_EQUALS(k512K, policy.GetCapacity());

	policy.Drain(policy.GetPendingBytes());

	// Drained, but not yet idle long enough.
	ASSERT_FALSE(policy.ShrinkIfIdle(10000 + UTP_WRITE_BUFFER_IDLE_SHRINK_MS));
	ASSERT_EQUALS(k512K, policy.GetCapacity());

	ASSERT_TRUE(policy.ShrinkIfIdle(10000 + UTP_WRITE_BUFFER_IDLE_SHRINK_MS + 1));
	ASSERT_EQUALS(k64K, policy.GetCapacity());
	ASSERT_FALSE(policy.HasGrown());

	// A buffer that never grew has nothing to give back, so the idle check
	// is a no-op rather than a second code path.
	ASSERT_FALSE(policy.ShrinkIfIdle(10000 + (UTP_WRITE_BUFFER_IDLE_SHRINK_MS * 10)));
	ASSERT_EQUALS(k64K, policy.GetCapacity());
}

// Shrinking is refused rather than lossy, and growing to a size that is
// already there is a no-op success rather than a reallocation.
TEST(UtpWriteBufferPolicy, ResizeRefusesToLoseQueuedBytes)
{
	CUtpWriteBufferPolicy policy;
	ASSERT_TRUE(policy.GrowTo(k2M));
	ASSERT_EQUALS(k2M, FillToCapacity(policy, 1000));

	ASSERT_FALSE(policy.ShrinkTo(k64K));
	ASSERT_EQUALS(k2M, policy.GetCapacity());

	// Growing to at-or-below the current capacity succeeds and changes
	// nothing, which is what keeps callers free of "did it move?" tests.
	ASSERT_TRUE(policy.GrowTo(k512K));
	ASSERT_EQUALS(k2M, policy.GetCapacity());

	policy.Drain(k2M);
	ASSERT_TRUE(policy.ShrinkTo(k64K));
	ASSERT_EQUALS(k64K, policy.GetCapacity());
}

// The accepted byte count is what the caller needs: a partial accept is normal
// (the buffer takes what fits), zero means blocked, and neither may exceed the
// usable capacity.
TEST(UtpWriteBufferPolicy, EnqueueAcceptsWhatFitsAndReportsIt)
{
	CUtpWriteBufferPolicy policy;

	// A write far larger than the buffer is clamped to the free space.
	ASSERT_EQUALS(k64K, policy.Enqueue(k4M, 500));
	ASSERT_EQUALS(k64K, (size_t)policy.GetPendingBytes());

	// Full at the initial capacity: promoted, then served.
	ASSERT_EQUALS(1u, (unsigned)policy.Enqueue(1, 500));
	ASSERT_EQUALS(k512K, policy.GetCapacity());
	ASSERT_EQUALS(k64K + 1u, (unsigned)policy.GetPendingBytes());

	// Draining frees exactly what was drained, no more.
	policy.Drain(k64K);
	ASSERT_EQUALS(1u, (unsigned)policy.GetPendingBytes());
}
