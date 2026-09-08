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

// The outbound side of amule-dual-stack-reachability: which of a peer's
// advertised addresses is dialled, in which order, and when the peer has run
// out of families and may finally be counted as dead.
//
// The dead-peer accounting is the part with teeth. aMule's existing failure
// handling assumes one address per peer, so a peer advertising two would be
// written off after the first connect error -- losing every IPv4-reachable
// eMuleAI peer the moment it also advertised an IPv6 address we cannot reach.

#include <muleunit/test.h>

#include <NetworkAddress.h>
#include <PeerFamilyAttempts.h>

using namespace muleunit;
using namespace DualStack;

DECLARE_SIMPLE(OutboundFamilyFallback)

static CNetworkAddress V4()
{
	return CNetworkAddress::FromString("192.0.2.7");
}

static CNetworkAddress V6()
{
	return CNetworkAddress::FromString("2001:db8::7");
}

TEST(OutboundFamilyFallback, FamilyComesFromTheTargetEndpoint)
{
	// The family is a property of the address being dialled, never of a global
	// default: that is the whole point of the policy call this delegates to.
	ASSERT_TRUE(FamilyOf(V4()) == EFamily::IPv4);
	ASSERT_TRUE(FamilyOf(V6()) == EFamily::IPv6);
	// A mapped address narrows losslessly, so it is dialled as IPv4.
	ASSERT_TRUE(FamilyOf(CNetworkAddress::FromString("::ffff:192.0.2.7")) == EFamily::IPv4);
}

TEST(OutboundFamilyFallback, BothFamiliesAdvertisedTriesIPv6First)
{
	CPeerConnectAttempts attempts;
	attempts.Reset(V4(), V6());

	ASSERT_EQUALS(2u, (unsigned)attempts.CandidateCount());
	// IPv6 first: it is the family with no NAT between the peers, so when it
	// works it works better, and when it does not the IPv4 address is still
	// there to fall back to.
	ASSERT_TRUE(attempts.Current() == V6());
	ASSERT_FALSE(attempts.MayMarkDead());
}

TEST(OutboundFamilyFallback, IPv6FailureFallsBackToIPv4)
{
	CPeerConnectAttempts attempts;
	attempts.Reset(V4(), V6());

	// WHEN the IPv6 attempt fails at connect time
	ASSERT_TRUE(attempts.RecordFailureAndAdvance());
	// THEN the client attempts the IPv4 address
	ASSERT_TRUE(attempts.Current() == V4());
	// AND the peer is not dead yet
	ASSERT_FALSE(attempts.MayMarkDead());

	// Only when that one fails too is every advertised family exhausted.
	ASSERT_FALSE(attempts.RecordFailureAndAdvance());
	ASSERT_TRUE(attempts.MayMarkDead());
	ASSERT_TRUE(attempts.Current().IsAbsent());
}

TEST(OutboundFamilyFallback, SingleFamilyPeerIsDeadAfterOneFailure)
{
	CPeerConnectAttempts attempts;
	attempts.Reset(V4(), CNetworkAddress::Absent());

	ASSERT_EQUALS(1u, (unsigned)attempts.CandidateCount());
	ASSERT_TRUE(attempts.Current() == V4());
	// Nothing to fall back to, so behaviour is exactly what it was before this
	// change: one failure and the peer is done.
	ASSERT_FALSE(attempts.RecordFailureAndAdvance());
	ASSERT_TRUE(attempts.MayMarkDead());
}

TEST(OutboundFamilyFallback, PeerWithNoAddressIsNotDialledAndIsNotHeldOpen)
{
	CPeerConnectAttempts attempts;
	attempts.Reset(CNetworkAddress::Absent(), CNetworkAddress::Absent());

	ASSERT_EQUALS(0u, (unsigned)attempts.CandidateCount());
	ASSERT_TRUE(attempts.Current().IsAbsent());
	// A peer with no address at all cannot be kept alive by this accounting --
	// there is no family left to try, so it must not block the caller's
	// existing dead-peer handling.
	ASSERT_TRUE(attempts.MayMarkDead());
}

TEST(OutboundFamilyFallback, SuccessOnTheSecondFamilyClearsTheAccounting)
{
	CPeerConnectAttempts attempts;
	attempts.Reset(V4(), V6());
	ASSERT_TRUE(attempts.RecordFailureAndAdvance());
	ASSERT_TRUE(attempts.Current() == V4());

	// A connection that came up resets the sequence: the next time this peer is
	// dialled it gets both families again, because a transient IPv6 failure is
	// not a permanent verdict on the family.
	attempts.RecordSuccess();
	ASSERT_TRUE(attempts.Current() == V6());
	ASSERT_FALSE(attempts.MayMarkDead());
	ASSERT_EQUALS(0u, (unsigned)attempts.FailedFamilyCount());
}

TEST(OutboundFamilyFallback, FailuresAreCountedPerFamilyNotPerAttempt)
{
	CPeerConnectAttempts attempts;
	attempts.Reset(V4(), V6());

	attempts.RecordFailureAndAdvance();
	ASSERT_EQUALS(1u, (unsigned)attempts.FailedFamilyCount());
	ASSERT_TRUE(attempts.HasFamilyFailed(EFamily::IPv6));
	ASSERT_FALSE(attempts.HasFamilyFailed(EFamily::IPv4));

	attempts.RecordFailureAndAdvance();
	ASSERT_EQUALS(2u, (unsigned)attempts.FailedFamilyCount());
	ASSERT_TRUE(attempts.HasFamilyFailed(EFamily::IPv4));
}

TEST(OutboundFamilyFallback, MappedAddressDoesNotCountAsASecondFamily)
{
	CPeerConnectAttempts attempts;
	// A peer whose "IPv6" address is really its IPv4 address in mapped form is
	// reachable on one family, not two. Treating it as two would keep a dead
	// peer alive for one extra pointless attempt against the same host.
	attempts.Reset(V4(), CNetworkAddress::FromString("::ffff:192.0.2.7"));

	ASSERT_EQUALS(1u, (unsigned)attempts.CandidateCount());
	ASSERT_TRUE(attempts.Current() == V4());
	ASSERT_FALSE(attempts.RecordFailureAndAdvance());
	ASSERT_TRUE(attempts.MayMarkDead());
}
