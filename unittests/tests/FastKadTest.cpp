//								-*- C++ -*-
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

#include <muleunit/test.h>
#include <kademlia/net/FastKad.h>

using namespace muleunit;
using Kademlia::CFastKad;

DECLARE_SIMPLE(FastKad)

// Wall-clock zero for these tests; every call passes "now" explicitly, so no
// test here depends on a real clock.
static const uint64_t T0 = 1000000;

TEST(FastKad, ColdStartFallsBackToTheDocumentedDefault)
{
	CFastKad kad;
	ASSERT_EQUALS(0u, (unsigned)kad.GetSampleCount());
	// With no sample at all the estimate must be usable, not zero: a zero
	// timeout would drop every contact the instant it was asked.
	ASSERT_EQUALS((unsigned)CFastKad::DEFAULT_RESPONSE_TIME_MS, (unsigned)kad.GetEstMaxResponseTime());
}

TEST(FastKad, SingleSampleDoesNotDivideByZero)
{
	CFastKad kad;
	kad.AddResponseTime(0x01020304, 50, T0);
	ASSERT_EQUALS(1u, (unsigned)kad.GetSampleCount());

	// One fast sample must not collapse the ceiling: the unfilled window
	// still counts as default-speed, so the estimate stays near the default.
	const uint32_t est = kad.GetEstMaxResponseTime();
	ASSERT_TRUE(est > 0);
	ASSERT_TRUE(est <= CFastKad::MAX_RESPONSE_TIME_MS);
	ASSERT_TRUE(est >= CFastKad::DEFAULT_RESPONSE_TIME_MS / 2);
}

TEST(FastKad, RisingDistributionRaisesTheCeiling)
{
	CFastKad kad;
	// Fill the whole window with fast responses to get a low baseline.
	for (unsigned i = 0; i < CFastKad::MAX_SAMPLES; ++i) {
		kad.AddResponseTime(0x0A000000 + i, 100, T0);
	}
	const uint32_t fastEstimate = kad.GetEstMaxResponseTime();

	// Now the same nodes get steadily slower.
	for (unsigned i = 0; i < CFastKad::MAX_SAMPLES; ++i) {
		kad.AddResponseTime(0x0A000000 + i, 100 + i * 10, T0 + 1);
	}
	const uint32_t risingEstimate = kad.GetEstMaxResponseTime();

	ASSERT_TRUE(risingEstimate > fastEstimate);
	// And it must stay inside the documented absolute maximum.
	ASSERT_TRUE(risingEstimate <= CFastKad::MAX_RESPONSE_TIME_MS);
}

TEST(FastKad, FallingDistributionLowersTheCeiling)
{
	CFastKad kad;
	for (unsigned i = 0; i < CFastKad::MAX_SAMPLES; ++i) {
		kad.AddResponseTime(0x0B000000 + i, 2000, T0);
	}
	const uint32_t slowEstimate = kad.GetEstMaxResponseTime();

	for (unsigned i = 0; i < CFastKad::MAX_SAMPLES; ++i) {
		kad.AddResponseTime(0x0B000000 + i, 120, T0 + 1);
	}
	const uint32_t fastEstimate = kad.GetEstMaxResponseTime();

	ASSERT_TRUE(fastEstimate < slowEstimate);
	ASSERT_TRUE(fastEstimate > 0);
}

TEST(FastKad, EstimateNeverExceedsTheDocumentedMaximum)
{
	CFastKad kad;
	// A pathological window: half the nodes answer instantly, half take
	// minutes. The variance is enormous, so the raw formula would produce a
	// timeout far past anything usable.
	for (unsigned i = 0; i < CFastKad::MAX_SAMPLES; ++i) {
		kad.AddResponseTime(0x0C000000 + i, (i % 2) ? 1 : 600000, T0);
	}
	ASSERT_EQUALS((unsigned)CFastKad::MAX_RESPONSE_TIME_MS, (unsigned)kad.GetEstMaxResponseTime());
}

TEST(FastKad, WindowIsBoundedAtMaxSamples)
{
	CFastKad kad;
	for (unsigned i = 0; i < CFastKad::MAX_SAMPLES * 3; ++i) {
		// Every address is fresh, so nothing is old enough to evict once
		// the window is full: memory use must stop growing regardless.
		kad.AddResponseTime(0x0D000000 + i, 200, T0);
	}
	ASSERT_EQUALS((unsigned)CFastKad::MAX_SAMPLES, (unsigned)kad.GetSampleCount());
}

TEST(FastKad, StaleSamplesAreEvictedToMakeRoom)
{
	CFastKad kad;
	for (unsigned i = 0; i < CFastKad::MAX_SAMPLES; ++i) {
		kad.AddResponseTime(0x0E000000 + i, 200, T0);
	}
	ASSERT_EQUALS((unsigned)CFastKad::MAX_SAMPLES, (unsigned)kad.GetSampleCount());

	// Long enough later, the window is all stale and a new address gets in
	// by evicting the least recently referenced entry.
	const uint64_t later = T0 + CFastKad::MIN_EVICTION_AGE_MS + 1;
	kad.AddResponseTime(0xFFFFFFFF, 250, later);
	ASSERT_EQUALS((unsigned)CFastKad::MAX_SAMPLES, (unsigned)kad.GetSampleCount());
	// The new sample changed the estimate, which is only possible if it was
	// actually admitted.
	kad.AddResponseTime(0xFFFFFFFF, 2500, later + 1);
	ASSERT_TRUE(kad.GetEstMaxResponseTime() > 0);
}

TEST(FastKad, RepeatedSamplesFromOneAddressReplaceRatherThanAccumulate)
{
	CFastKad kad;
	for (unsigned i = 0; i < 10; ++i) {
		kad.AddResponseTime(0x7F000001, 100 + i, T0 + i);
	}
	ASSERT_EQUALS(1u, (unsigned)kad.GetSampleCount());
}

TEST(FastKad, ClearReturnsToColdStart)
{
	CFastKad kad;
	for (unsigned i = 0; i < CFastKad::MAX_SAMPLES; ++i) {
		kad.AddResponseTime(0x10000000 + i, 2500, T0);
	}
	ASSERT_TRUE(kad.GetEstMaxResponseTime() != CFastKad::DEFAULT_RESPONSE_TIME_MS);

	kad.Clear();
	ASSERT_EQUALS(0u, (unsigned)kad.GetSampleCount());
	ASSERT_EQUALS((unsigned)CFastKad::DEFAULT_RESPONSE_TIME_MS, (unsigned)kad.GetEstMaxResponseTime());
}
