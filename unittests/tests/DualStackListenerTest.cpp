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

// The listener side of amule-dual-stack-reachability: which sockets aMule tries
// to bind, in which order, what it falls back to when a platform refuses a
// dual-stack socket, and how many times a failure to bind a family may be
// logged.
//
// All of it is decision logic over the configured family set, deliberately
// separated from the socket calls themselves so the three cases the spec names
// -- both families available, IPv6 unavailable, dual-stack socket rejected --
// are reachable without a host that has each of those network stacks.

#include <muleunit/test.h>

#include <AddressFamilyPolicy.h>
#include <DualStackListeners.h>

using namespace muleunit;
using namespace DualStack;

DECLARE_SIMPLE(DualStackListener)

TEST(DualStackListener, DualStackConfigurationTriesOneSocketFirst)
{
	const CListenPlan plan(AddressFamilyPolicy::Families::DualStack);

	// One socket serving both families is the first thing attempted: it is the
	// only arrangement that needs no second port reservation and no second
	// acceptor, so it is preferred wherever the platform allows it.
	const std::vector<SBindAttempt> first = plan.FirstAttempts();
	ASSERT_EQUALS(1u, (unsigned)first.size());
	ASSERT_TRUE(first[0].family == EFamily::IPv6);
	ASSERT_TRUE(first[0].servesBothFamilies);
	ASSERT_FALSE(first[0].v6Only);

	// And the fallback is one socket per family, with the IPv6 one explicitly
	// restricted so the two cannot fight over the same mapped-v4 traffic.
	const std::vector<SBindAttempt> fallback = plan.FallbackAttempts();
	ASSERT_EQUALS(2u, (unsigned)fallback.size());
	ASSERT_TRUE(fallback[0].family == EFamily::IPv4);
	ASSERT_FALSE(fallback[0].servesBothFamilies);
	ASSERT_TRUE(fallback[1].family == EFamily::IPv6);
	ASSERT_FALSE(fallback[1].servesBothFamilies);
	ASSERT_TRUE(fallback[1].v6Only);
}

TEST(DualStackListener, SingleFamilyConfigurationsHaveNothingToFallBackTo)
{
	const CListenPlan v4(AddressFamilyPolicy::Families::IPv4Only);
	ASSERT_EQUALS(1u, (unsigned)v4.FirstAttempts().size());
	ASSERT_TRUE(v4.FirstAttempts()[0].family == EFamily::IPv4);
	ASSERT_FALSE(v4.FirstAttempts()[0].servesBothFamilies);
	// A configuration with one family in it cannot be arranged a second way.
	ASSERT_TRUE(v4.FallbackAttempts().empty());

	const CListenPlan v6(AddressFamilyPolicy::Families::IPv6Only);
	ASSERT_EQUALS(1u, (unsigned)v6.FirstAttempts().size());
	ASSERT_TRUE(v6.FirstAttempts()[0].family == EFamily::IPv6);
	ASSERT_TRUE(v6.FirstAttempts()[0].v6Only);
	ASSERT_TRUE(v6.FallbackAttempts().empty());
}

TEST(DualStackListener, DualStackSocketRejectionFallsBackToOnePerFamily)
{
	// GIVEN a platform that rejects a dual-stack listening socket
	CListenerState state;
	const CListenPlan plan(AddressFamilyPolicy::Families::DualStack);

	const std::vector<SBindAttempt> first = plan.FirstAttempts();
	state.RecordFailure(first[0].family);
	ASSERT_FALSE(state.IsAnyListening());

	// THEN it falls back to one listening socket per family...
	const std::vector<SBindAttempt> fallback = plan.FallbackAttempts();
	for (const SBindAttempt &attempt : fallback) {
		state.RecordBound(attempt.family, attempt.servesBothFamilies);
	}

	// ... and reports itself reachable on both.
	ASSERT_TRUE(state.IsListening(EFamily::IPv4));
	ASSERT_TRUE(state.IsListening(EFamily::IPv6));
	ASSERT_TRUE(state.IsAnyListening());
}

TEST(DualStackListener, OneDualStackSocketCountsAsListeningOnBothFamilies)
{
	CListenerState state;
	state.RecordBound(EFamily::IPv6, true);

	// A single socket with IPV6_V6ONLY off accepts IPv4 peers in mapped form,
	// so the client is reachable on IPv4 even though no IPv4 socket exists.
	ASSERT_TRUE(state.IsListening(EFamily::IPv4));
	ASSERT_TRUE(state.IsListening(EFamily::IPv6));
}

TEST(DualStackListener, SingleFamilyHostKeepsTheOtherFamilyListening)
{
	// GIVEN a host with no routable IPv6 address
	CListenerState state;
	state.RecordBound(EFamily::IPv4, false);
	state.RecordFailure(EFamily::IPv6);

	// THEN IPv4 operation is unaffected, and the client MUST NOT report itself
	// unreachable while either socket is listening.
	ASSERT_TRUE(state.IsListening(EFamily::IPv4));
	ASSERT_FALSE(state.IsListening(EFamily::IPv6));
	ASSERT_TRUE(state.IsAnyListening());
	ASSERT_FALSE(state.IsUnreachable());
}

TEST(DualStackListener, NoFamilyListeningIsTheOnlyUnreachableState)
{
	CListenerState state;
	ASSERT_TRUE(state.IsUnreachable());
	state.RecordFailure(EFamily::IPv4);
	state.RecordFailure(EFamily::IPv6);
	ASSERT_TRUE(state.IsUnreachable());
	state.RecordBound(EFamily::IPv6, false);
	ASSERT_FALSE(state.IsUnreachable());
}

TEST(DualStackListener, BindFailureIsReportedOncePerFamilyPerStart)
{
	CListenerState state;

	// The failure to bind IPv6 MUST be logged once, not per retry. The retry
	// loop is the caller's; the latch that keeps it quiet is here.
	ASSERT_TRUE(state.ShouldReportFailure(EFamily::IPv6));
	for (int retry = 0; retry < 20; ++retry) {
		state.RecordFailure(EFamily::IPv6);
		ASSERT_FALSE(state.ShouldReportFailure(EFamily::IPv6));
	}

	// The other family keeps its own latch: a v4 failure is a different fact
	// and is still worth one line.
	ASSERT_TRUE(state.ShouldReportFailure(EFamily::IPv4));
	ASSERT_FALSE(state.ShouldReportFailure(EFamily::IPv4));

	// A start is the latch's scope, so a restart says it again -- otherwise a
	// user who fixed their network would never see it fail after a reconfigure.
	state.Reset();
	ASSERT_TRUE(state.ShouldReportFailure(EFamily::IPv6));
	ASSERT_FALSE(state.ShouldReportFailure(EFamily::IPv6));
}

TEST(DualStackListener, ResetClearsBoundFamiliesToo)
{
	CListenerState state;
	state.RecordBound(EFamily::IPv4, false);
	state.RecordBound(EFamily::IPv6, false);
	ASSERT_TRUE(state.IsAnyListening());

	// ReinitializeNetwork() runs this more than once per process. A stale
	// "listening" flag from the previous configuration would make a client that
	// bound nothing believe it is reachable.
	state.Reset();
	ASSERT_FALSE(state.IsListening(EFamily::IPv4));
	ASSERT_FALSE(state.IsListening(EFamily::IPv6));
	ASSERT_TRUE(state.IsUnreachable());
}

TEST(DualStackListener, FamilyNamesAreStableForTheLog)
{
	// The bind lines are the observable evidence that both families came up,
	// so the family word in them is pinned rather than left to a caller's
	// spelling.
	ASSERT_EQUALS(wxString("IPv4"), wxString(FamilyName(EFamily::IPv4)));
	ASSERT_EQUALS(wxString("IPv6"), wxString(FamilyName(EFamily::IPv6)));
}
