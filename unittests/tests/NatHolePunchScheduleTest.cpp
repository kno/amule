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

// What bounds a hole punch, and what happens to the source when it fails.
//
// Three separate things are pinned here and each has its own failure with no
// symptom:
//
//   - **The bounds.** Five attempts, 120 seconds, whichever comes first. A
//     punch that is not bounded keeps sending toward an endpoint that will
//     never answer, which for a symmetric-to-symmetric pair is forever. The
//     design says that case is out of scope; the budget is what makes "out of
//     scope" mean something at runtime.
//   - **Cancellation on success.** A punch that succeeded on the third attempt
//     must not send a fourth. The remaining packets would arrive on a
//     connection that is already up and be read as unsolicited traffic by the
//     far side.
//   - **Source retention across the backoff.** This is the one that costs
//     something invisibly. A failed traversal is a fact about two NATs, not
//     about the peer, so during the 60-second backoff the source stays queued.
//     Deleting it turns a transient NAT condition into a permanently lost peer,
//     and the only symptom is a download with fewer sources than it should
//     have.
//
// The retention rule has a specific trap in this tree that the disposition type
// exists to keep callers out of: CUpDownClient::Connect() returning false means
// "the client was deleted" to CUpDownClient::TryToConnect(), which then calls
// Safe_Delete(). So the natural-looking way to report "I could not connect
// right now" destroys exactly the source this requirement protects.

#include <muleunit/test.h>

#include <NatHolePunchSchedule.h>
#include <NatRendezvousProtocol.h>

using namespace muleunit;

DECLARE_SIMPLE(NatHolePunchSchedule)

namespace
{

//! Drive the schedule from `startMs` for as long as it wants to send, obeying
//! the spacing it asks for, and count the packets. Advances the clock to
//! whatever the schedule says is next rather than by a fixed step, so the
//! spacing the schedule asks for is the spacing the test uses.
uint32_t DrainPunches(CHolePunchSchedule &schedule, uint64_t startMs, uint64_t &endMs)
{
	uint32_t sent = 0;
	uint64_t now = startMs;
	for (int guard = 0; guard < 1000; ++guard) {
		const EHolePunchAction action = schedule.Poll(now);
		if (action == HOLEPUNCH_SEND) {
			++sent;
			now = schedule.NextDueMs();
			continue;
		}
		if (action == HOLEPUNCH_WAIT) {
			now = schedule.NextDueMs();
			continue;
		}
		break;
	}
	endMs = now;
	return sent;
}

} // namespace

// The derived spacing. Five attempts must fit inside the 120-second budget, so
// the attempt spacing is the budget divided by the attempt count rather than a
// fourth number somebody chose.
TEST(NatHolePunchSchedule, AttemptSpacingIsDerivedFromTheTwoPinnedBounds)
{
	ASSERT_EQUALS(24000u, kHolePunchAttemptSpacingMs);
	ASSERT_EQUALS(kRendezvousTotalBudgetMs / kRendezvousMaxAttempts, kHolePunchAttemptSpacingMs);
	// A burst, not a flood: three packets a quarter second apart is enough to
	// cross a NAT that drops the first one, and is well under any rate a peer
	// could mistake for an attack.
	ASSERT_EQUALS(3u, kHolePunchPacketsPerAttempt);
	ASSERT_EQUALS(250u, kHolePunchPacketSpacingMs);
}

// A schedule nobody started sends nothing. The state before Start() is not
// "attempt zero in progress".
TEST(NatHolePunchSchedule, UnstartedScheduleSendsNothing)
{
	CHolePunchSchedule schedule;

	ASSERT_EQUALS((int)HOLEPUNCH_IDLE, (int)schedule.Poll(1000));
	ASSERT_EQUALS(0u, schedule.PacketsSent());
	ASSERT_EQUALS(0u, schedule.AttemptsMade());
}

// The exhaustion path. Five attempts of three packets, then the budget is spent
// and the schedule stops -- inside the 120-second cap, because the spacing was
// derived from it.
TEST(NatHolePunchSchedule, ExhaustsAfterFiveAttemptsAndStopsSending)
{
	CHolePunchSchedule schedule;
	schedule.Start(1000);

	uint64_t endMs = 0;
	const uint32_t sent = DrainPunches(schedule, 1000, endMs);

	ASSERT_EQUALS(kRendezvousMaxAttempts * kHolePunchPacketsPerAttempt, sent);
	ASSERT_EQUALS(kRendezvousMaxAttempts, schedule.AttemptsMade());
	ASSERT_TRUE(schedule.IsExhausted());
	ASSERT_EQUALS((int)HOLEPUNCH_EXHAUSTED, (int)schedule.Poll(endMs));
	// Every attempt fitted inside the total budget.
	ASSERT_TRUE(endMs - 1000 <= kRendezvousTotalBudgetMs);

	// And it stays stopped. Polling again, at any time inside the backoff,
	// never yields another packet.
	const uint32_t before = schedule.PacketsSent();
	for (uint32_t offset = 0; offset < kRendezvousBackoffMs; offset += 5000) {
		ASSERT_TRUE(schedule.Poll(endMs + offset) != HOLEPUNCH_SEND);
	}
	ASSERT_EQUALS(before, schedule.PacketsSent());
}

// The 120-second cap is a second, independent bound, and it is the one that
// bites when the core timer is slow or the process was suspended. Five attempts
// have not been made here; the budget is spent anyway.
TEST(NatHolePunchSchedule, ExhaustsOnTheTotalBudgetEvenWithAttemptsRemaining)
{
	CHolePunchSchedule schedule;
	schedule.Start(1000);

	ASSERT_EQUALS((int)HOLEPUNCH_SEND, (int)schedule.Poll(1000));

	const EHolePunchAction late = schedule.Poll(1000 + kRendezvousTotalBudgetMs);
	ASSERT_EQUALS((int)HOLEPUNCH_EXHAUSTED, (int)late);
	ASSERT_TRUE(schedule.IsExhausted());
	ASSERT_TRUE(schedule.AttemptsMade() < kRendezvousMaxAttempts);
	ASSERT_EQUALS(1u, schedule.PacketsSent());
}

// Cancellation on success, and it is permanent. The punch succeeded on the
// third attempt; not one further packet leaves for this pair.
TEST(NatHolePunchSchedule, SuccessCancelsEveryRemainingAttempt)
{
	CHolePunchSchedule schedule;
	schedule.Start(1000);

	// Two whole attempts and one packet of the third.
	uint64_t now = 1000;
	uint32_t sent = 0;
	while (schedule.AttemptsMade() < 2 || sent % kHolePunchPacketsPerAttempt != 1) {
		const EHolePunchAction action = schedule.Poll(now);
		if (action == HOLEPUNCH_SEND) {
			++sent;
		}
		now = schedule.NextDueMs();
	}

	const uint32_t sentBeforeSuccess = schedule.PacketsSent();
	ASSERT_TRUE(sentBeforeSuccess > 0);
	ASSERT_TRUE(sentBeforeSuccess < kRendezvousMaxAttempts * kHolePunchPacketsPerAttempt);

	schedule.OnConnectionEstablished();

	ASSERT_TRUE(schedule.IsCancelled());
	ASSERT_FALSE(schedule.IsExhausted());

	// Not at the next due time, not at the end of the budget, not after it.
	ASSERT_EQUALS((int)HOLEPUNCH_SUCCEEDED, (int)schedule.Poll(now));
	ASSERT_EQUALS((int)HOLEPUNCH_SUCCEEDED, (int)schedule.Poll(now + kHolePunchAttemptSpacingMs));
	ASSERT_EQUALS((int)HOLEPUNCH_SUCCEEDED, (int)schedule.Poll(1000 + kRendezvousTotalBudgetMs));
	ASSERT_EQUALS((int)HOLEPUNCH_SUCCEEDED,
		(int)schedule.Poll(1000 + kRendezvousTotalBudgetMs + kRendezvousBackoffMs));
	ASSERT_EQUALS(sentBeforeSuccess, schedule.PacketsSent());
}

// Success after exhaustion still cancels. A punch that lands as the budget runs
// out is a success, and the schedule must not go on to report a backoff for a
// pair that is connected.
TEST(NatHolePunchSchedule, SuccessAfterExhaustionStillCancels)
{
	CHolePunchSchedule schedule;
	schedule.Start(1000);

	uint64_t endMs = 0;
	DrainPunches(schedule, 1000, endMs);
	ASSERT_TRUE(schedule.IsExhausted());

	schedule.OnConnectionEstablished();

	ASSERT_TRUE(schedule.IsCancelled());
	ASSERT_EQUALS((int)HOLEPUNCH_SUCCEEDED, (int)schedule.Poll(endMs + kRendezvousBackoffMs));
}

// The requirement the source list depends on. Every field of the disposition is
// asserted, including the two that must be false, because the cost of either
// being true is a source that quietly disappears.
TEST(NatHolePunchSchedule, ExhaustionKeepsTheSourceQueuedAndBlamesNobody)
{
	const SHolePunchDisposition disposition = DisposeExhaustedHolePunch();

	ASSERT_TRUE(disposition.keepSourceQueued);
	ASSERT_FALSE(disposition.markPeerDead);
	ASSERT_FALSE(disposition.dropFromSourceList);
	ASSERT_FALSE(disposition.countAsDeadSource);
	ASSERT_EQUALS(kRendezvousBackoffMs, disposition.retryAfterMs);
	// And the fallback the spec requires instead of giving up on the peer.
	ASSERT_TRUE(disposition.fallBackToCallbackOrBuddy);
}

// The backoff is a wait, not a ban. Before it elapses the pair is not retried;
// after it, a fresh rendezvous may be started.
TEST(NatHolePunchSchedule, BackoffElapsesAfterSixtySecondsAndThenAllowsARestart)
{
	CHolePunchSchedule schedule;
	schedule.Start(1000);

	uint64_t endMs = 0;
	DrainPunches(schedule, 1000, endMs);

	ASSERT_FALSE(schedule.MayRestart(endMs));
	ASSERT_FALSE(schedule.MayRestart(endMs + kRendezvousBackoffMs - 1));
	ASSERT_TRUE(schedule.MayRestart(endMs + kRendezvousBackoffMs));
	ASSERT_EQUALS((int)HOLEPUNCH_BACKOFF_ELAPSED, (int)schedule.Poll(endMs + kRendezvousBackoffMs));

	// A restart is a fresh budget, not a continuation of the old one.
	schedule.Start(endMs + kRendezvousBackoffMs);
	ASSERT_FALSE(schedule.IsExhausted());
	ASSERT_EQUALS(0u, schedule.AttemptsMade());
	ASSERT_EQUALS(0u, schedule.PacketsSent());
	ASSERT_EQUALS((int)HOLEPUNCH_SEND, (int)schedule.Poll(endMs + kRendezvousBackoffMs));
}

// A cancelled schedule is not restarted by Start(). The pair is connected; a
// caller that starts punching again is a bug, and honouring it would put
// packets on the wire for a live connection.
TEST(NatHolePunchSchedule, StartDoesNotReviveACancelledSchedule)
{
	CHolePunchSchedule schedule;
	schedule.Start(1000);
	schedule.OnConnectionEstablished();

	schedule.Start(2000);

	ASSERT_TRUE(schedule.IsCancelled());
	ASSERT_EQUALS((int)HOLEPUNCH_SUCCEEDED, (int)schedule.Poll(2000));
	ASSERT_EQUALS(0u, schedule.PacketsSent());
}

// A tick count that moved backwards must not buy extra packets. The spacing is
// there to keep a burst a burst; a clock adjustment is not permission to send
// the whole budget at once.
TEST(NatHolePunchSchedule, BackwardsClockDoesNotSendEarly)
{
	CHolePunchSchedule schedule;
	schedule.Start(100000);

	ASSERT_EQUALS((int)HOLEPUNCH_SEND, (int)schedule.Poll(100000));
	ASSERT_EQUALS((int)HOLEPUNCH_WAIT, (int)schedule.Poll(1));
	ASSERT_EQUALS(1u, schedule.PacketsSent());
}

// Within one attempt the packets are spaced, and between attempts the gap is
// the wider one. Asserted through the times the schedule itself reports, so a
// caller that honours NextDueMs() cannot produce a flood.
TEST(NatHolePunchSchedule, SpacingIsTightWithinABurstAndWideBetweenAttempts)
{
	CHolePunchSchedule schedule;
	schedule.Start(1000);

	ASSERT_EQUALS((int)HOLEPUNCH_SEND, (int)schedule.Poll(1000));
	ASSERT_EQUALS(1000u + kHolePunchPacketSpacingMs, schedule.NextDueMs());

	ASSERT_EQUALS((int)HOLEPUNCH_SEND, (int)schedule.Poll(schedule.NextDueMs()));
	ASSERT_EQUALS(1000u + (2u * kHolePunchPacketSpacingMs), schedule.NextDueMs());

	// The third packet completes the first attempt, so the next due time is a
	// whole attempt spacing from where the attempt began.
	ASSERT_EQUALS((int)HOLEPUNCH_SEND, (int)schedule.Poll(schedule.NextDueMs()));
	ASSERT_EQUALS(1u, schedule.AttemptsMade());
	ASSERT_EQUALS(1000u + kHolePunchAttemptSpacingMs, schedule.NextDueMs());
}
