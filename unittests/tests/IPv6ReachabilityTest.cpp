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

// What aMule may claim about its own IPv6 reachability, and when.
//
// The distinction this pins is the one the spec is explicit about: a bound
// socket is not reachability. A host can bind :: and still be behind a firewall
// that drops every inbound IPv6 packet, and a client that advertises IPv6 on
// the strength of a successful bind sends peers to an address that never
// answers -- the peer opens a handshake, nothing completes, and neither side
// logs a reason. Verification means an inbound connection actually arrived over
// IPv6.
//
// The second half of the file covers the reachability display: the core and the
// remote GUI render the same two lines from one function here, so a state added
// later cannot say one thing locally and another over EC.

#include <muleunit/test.h>

#include <IPv6Reachability.h>
#include <PeerCapabilities.h>

using namespace muleunit;
using namespace DualStack;

DECLARE_SIMPLE(IPv6Reachability)

TEST(IPv6Reachability, NothingBoundClaimsNothing)
{
	CLocalReachability reachability;

	ASSERT_TRUE(reachability.State(EFamily::IPv4) == EReachability::Unavailable);
	ASSERT_TRUE(reachability.State(EFamily::IPv6) == EReachability::Unavailable);
	ASSERT_FALSE(reachability.IsVerified(EFamily::IPv6));
	ASSERT_EQUALS(0u, reachability.AdvertisedModMiscOptions());
	ASSERT_FALSE(reachability.MayAdvertiseIPv6());
}

TEST(IPv6Reachability, BoundIsNotVerified)
{
	// GIVEN the client has bound an IPv6 socket but has received no inbound
	// IPv6 connection
	CLocalReachability reachability;
	reachability.SetBound(EFamily::IPv6, true);

	ASSERT_TRUE(reachability.State(EFamily::IPv6) == EReachability::Bound);
	ASSERT_TRUE(reachability.IsBound(EFamily::IPv6));
	ASSERT_FALSE(reachability.IsVerified(EFamily::IPv6));

	// WHEN it builds a hello packet
	// THEN it MUST NOT claim verified IPv6 reachability: no capability bit, and
	// no address tag either.
	ASSERT_EQUALS(0u, reachability.AdvertisedModMiscOptions());
	ASSERT_FALSE(reachability.MayAdvertiseIPv6());
}

TEST(IPv6Reachability, VerificationComesFromAnInboundConnection)
{
	CLocalReachability reachability;
	reachability.SetBound(EFamily::IPv6, true);
	reachability.RecordInboundConnection(EFamily::IPv6);

	ASSERT_TRUE(reachability.State(EFamily::IPv6) == EReachability::Verified);
	ASSERT_TRUE(reachability.IsVerified(EFamily::IPv6));
	// Only now does the capability bit go on the wire, and only bit 2.
	ASSERT_EQUALS((uint32_t)MOD_MISCOPT_IPV6, reachability.AdvertisedModMiscOptions());
	ASSERT_TRUE(reachability.MayAdvertiseIPv6());
}

TEST(IPv6Reachability, AdvertisedWordCarriesOnlyTheIPv6Bit)
{
	// The other four vendor bits belong to changes that ship those transports.
	// This change must not turn any of them on as a side effect.
	CLocalReachability reachability;
	reachability.SetBound(EFamily::IPv6, true);
	reachability.RecordInboundConnection(EFamily::IPv6);

	const uint32_t word = reachability.AdvertisedModMiscOptions();
	ASSERT_EQUALS(0u, word & (uint32_t)MOD_MISCOPT_EXTENDED_XS);
	ASSERT_EQUALS(0u, word & (uint32_t)MOD_MISCOPT_NAT_TRAVERSAL);
	ASSERT_EQUALS(0u, word & (uint32_t)MOD_MISCOPT_SERVING_BUDDY_PULL);
	ASSERT_EQUALS(0u, word & (uint32_t)MOD_MISCOPT_NAT_TRAVERSAL_QUIC);
	ASSERT_EQUALS(0u, word & ~(uint32_t)MOD_MISCOPT_KNOWN_MASK);
	// Bit 2, as pinned by PeerCapabilitiesTest.
	ASSERT_EQUALS(0x00000004u, word);
}

TEST(IPv6Reachability, VerificationOverIPv4NeverEnablesTheIPv6Claim)
{
	// An inbound IPv4 connection is the overwhelmingly common case, and it says
	// nothing about IPv6. Crediting it to IPv6 would make every reachable
	// client advertise an address it may not have.
	CLocalReachability reachability;
	reachability.SetBound(EFamily::IPv4, true);
	reachability.SetBound(EFamily::IPv6, true);
	reachability.RecordInboundConnection(EFamily::IPv4);

	ASSERT_TRUE(reachability.State(EFamily::IPv4) == EReachability::Verified);
	ASSERT_TRUE(reachability.State(EFamily::IPv6) == EReachability::Bound);
	ASSERT_EQUALS(0u, reachability.AdvertisedModMiscOptions());
	ASSERT_FALSE(reachability.MayAdvertiseIPv6());
}

TEST(IPv6Reachability, VerificationWithoutABoundSocketIsIgnored)
{
	// Defensive: an inbound connection cannot arrive on a family with no
	// socket, so this is a bug if it happens. It must not be the way a client
	// talks itself into advertising IPv6.
	CLocalReachability reachability;
	reachability.RecordInboundConnection(EFamily::IPv6);

	ASSERT_TRUE(reachability.State(EFamily::IPv6) == EReachability::Unavailable);
	ASSERT_FALSE(reachability.MayAdvertiseIPv6());
}

TEST(IPv6Reachability, LosingTheSocketDropsTheClaimAgain)
{
	CLocalReachability reachability;
	reachability.SetBound(EFamily::IPv6, true);
	reachability.RecordInboundConnection(EFamily::IPv6);
	ASSERT_TRUE(reachability.MayAdvertiseIPv6());

	// A reconfiguration that no longer binds IPv6 must not leave a verified
	// flag behind: the address would still be advertised with nothing
	// listening on it.
	reachability.SetBound(EFamily::IPv6, false);
	ASSERT_TRUE(reachability.State(EFamily::IPv6) == EReachability::Unavailable);
	ASSERT_FALSE(reachability.MayAdvertiseIPv6());
	ASSERT_EQUALS(0u, reachability.AdvertisedModMiscOptions());
}

TEST(IPv6Reachability, ReachableWhileEitherFamilyIsListening)
{
	CLocalReachability reachability;
	reachability.SetBound(EFamily::IPv4, true);
	ASSERT_TRUE(reachability.IsAnyFamilyListening());

	reachability.SetBound(EFamily::IPv4, false);
	reachability.SetBound(EFamily::IPv6, true);
	ASSERT_TRUE(reachability.IsAnyFamilyListening());

	reachability.SetBound(EFamily::IPv6, false);
	ASSERT_FALSE(reachability.IsAnyFamilyListening());
}

TEST(IPv6Reachability, StateLabelsAreTheOneSourceForBothDisplays)
{
	// The local GUI reads these through theApp; the remote GUI reads the same
	// states out of EC and renders them with this same function. Two tables
	// would drift the first time a state is added.
	ASSERT_EQUALS(wxString("Unavailable"), wxString(ReachabilityLabel(EReachability::Unavailable)));
	ASSERT_EQUALS(wxString("Listening"), wxString(ReachabilityLabel(EReachability::Bound)));
	ASSERT_EQUALS(wxString("Verified"), wxString(ReachabilityLabel(EReachability::Verified)));
}

TEST(IPv6Reachability, ECWordRoundTripsBothFamilies)
{
	CLocalReachability core;
	core.SetBound(EFamily::IPv4, true);
	core.RecordInboundConnection(EFamily::IPv4);
	core.SetBound(EFamily::IPv6, true);

	// The core packs both families into one EC value; the remote side unpacks
	// it and must land on exactly the same two states.
	const uint8_t wire = core.ToECWord();
	const CLocalReachability mirrored = CLocalReachability::FromECWord(wire);

	ASSERT_TRUE(mirrored.State(EFamily::IPv4) == EReachability::Verified);
	ASSERT_TRUE(mirrored.State(EFamily::IPv6) == EReachability::Bound);
	ASSERT_EQUALS(wxString(ReachabilityLabel(core.State(EFamily::IPv4))),
		wxString(ReachabilityLabel(mirrored.State(EFamily::IPv4))));
	ASSERT_EQUALS(wxString(ReachabilityLabel(core.State(EFamily::IPv6))),
		wxString(ReachabilityLabel(mirrored.State(EFamily::IPv6))));

	// And the advertisement decision survives the trip, so a remote GUI cannot
	// show "verified IPv6" for a daemon that is only listening.
	ASSERT_FALSE(mirrored.MayAdvertiseIPv6());
}

TEST(IPv6Reachability, ECWordIsStableAcrossEveryStateCombination)
{
	// Nine combinations, packed two bits per family. Pinned as literals: this
	// is a value crossing a version boundary, so a renumbering has to be a
	// deliberate act with a protocol note, not a silent one.
	const EReachability states[3] = {
		EReachability::Unavailable, EReachability::Bound, EReachability::Verified
	};
	for (int v4 = 0; v4 < 3; ++v4) {
		for (int v6 = 0; v6 < 3; ++v6) {
			CLocalReachability built;
			built.SetState(EFamily::IPv4, states[v4]);
			built.SetState(EFamily::IPv6, states[v6]);
			const uint8_t wire = built.ToECWord();
			ASSERT_EQUALS((unsigned)(v4 | (v6 << 2)), (unsigned)wire);
			const CLocalReachability back = CLocalReachability::FromECWord(wire);
			ASSERT_TRUE(back.State(EFamily::IPv4) == states[v4]);
			ASSERT_TRUE(back.State(EFamily::IPv6) == states[v6]);
		}
	}
}

TEST(IPv6Reachability, UnknownECWordBitsAreIgnoredRatherThanTrusted)
{
	// Bits 4-7 are reserved. A newer daemon that starts using them must not
	// make an older client read a state it does not know as "verified".
	const CLocalReachability mirrored = CLocalReachability::FromECWord(0xF0u | 0x06u);
	ASSERT_TRUE(mirrored.State(EFamily::IPv4) == EReachability::Verified);
	ASSERT_TRUE(mirrored.State(EFamily::IPv6) == EReachability::Bound);
}
