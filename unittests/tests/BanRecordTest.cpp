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

#include <muleunit/test.h>

#include "BanRecord.h"
#include "NetworkAddress.h" // Needed for CNetworkAddress

using namespace muleunit;

DECLARE_SIMPLE(BanRecord)

namespace
{
// A tick well clear of zero, so an expiry comparison cannot pass by accident
// on an uninitialised value.
const uint64 T0 = 1000000;
const CNetworkAddress IP_A = CNetworkAddress::FromString("127.0.0.1");
const CNetworkAddress IP_B = CNetworkAddress::FromString("127.0.0.2");
} // namespace

// The whole point of the class: the caller increments a counter when this
// returns true, so a second ban of the same address must answer false or the
// statistic drifts. CUpDownClient::SetSpammer(true) calls Ban() with no
// IsBanned() check, which is how that second call happens in practice.
TEST(BanRecord, BanningTheSameAddressTwiceCountsOnce)
{
	CBanRecord record;

	ASSERT_TRUE(record.Ban(IP_A, T0));
	ASSERT_EQUALS(1u, (unsigned)record.Size());

	ASSERT_FALSE(record.Ban(IP_A, T0 + 10));
	ASSERT_EQUALS(1u, (unsigned)record.Size());

	// The tick is still refreshed, so the ban is extended rather than left to
	// expire on the first one's schedule.
	ASSERT_TRUE(record.IsBanned(IP_A, T0 + 10 + CBanRecord::BAN_DURATION_MS - 1));
	ASSERT_FALSE(record.IsBanned(IP_A, T0 + 10 + CBanRecord::BAN_DURATION_MS));
}

// The mirror. Unbanning an address that is not banned must answer false, or
// the same counter drifts the other way.
TEST(BanRecord, UnbanningAnAddressThatIsNotBannedCountsNothing)
{
	CBanRecord record;

	ASSERT_FALSE(record.Unban(IP_A));
	ASSERT_EQUALS(0u, (unsigned)record.Size());

	ASSERT_TRUE(record.Ban(IP_A, T0));
	ASSERT_TRUE(record.Unban(IP_A));
	ASSERT_EQUALS(0u, (unsigned)record.Size());

	// And again, now that it is genuinely gone.
	ASSERT_FALSE(record.Unban(IP_A));
}

// An address we do not have is not a key. CUpDownClient holds an absent
// address until it has a socket, so one entry under that key would make every
// such client read back as banned.
TEST(BanRecord, AnAbsentAddressIsNeverBannedAndNeverAKey)
{
	CBanRecord record;
	const CNetworkAddress absent = CNetworkAddress::Absent();

	ASSERT_FALSE(record.Ban(absent, T0));
	ASSERT_EQUALS(0u, (unsigned)record.Size());
	ASSERT_FALSE(record.IsBanned(absent, T0));

	// A real ban does not make the absent key readable either.
	ASSERT_TRUE(record.Ban(IP_A, T0));
	ASSERT_FALSE(record.IsBanned(absent, T0));

	// And nothing was inserted to lift, which is what lets Unban() answer
	// false for it without a guard of its own.
	ASSERT_FALSE(record.Unban(absent));
}

// Absence is the whole of the rule, and 0.0.0.0 is not absence. The 32-bit
// record could not tell the two apart -- it read a missing address as the
// literal 0 -- so this pins which of them disqualifies a peer now that the
// type can express both.
TEST(BanRecord, TheUnspecifiedAddressIsBannableBecauseItIsAnAddress)
{
	CBanRecord record;
	const CNetworkAddress unspecified = CNetworkAddress::FromString("0.0.0.0");
	ASSERT_TRUE(unspecified.IsPresent());

	ASSERT_TRUE(record.Ban(unspecified, T0));
	ASSERT_TRUE(record.IsBanned(unspecified, T0 + 1));
	ASSERT_EQUALS(1u, (unsigned)record.Size());

	// It is its own peer: banning it says nothing about a peer we have no
	// address for.
	ASSERT_FALSE(record.IsBanned(CNetworkAddress::Absent(), T0 + 1));
}

// The reason the record is keyed on an address at all: a 32-bit key had no
// value that could name an IPv6 peer, so such a peer could not be banned.
TEST(BanRecord, AnIPv6PeerIsBannedAndReadBack)
{
	CBanRecord record;
	const CNetworkAddress v6 = CNetworkAddress::FromString("2001:db8::1");
	const CNetworkAddress otherV6 = CNetworkAddress::FromString("2001:db8::2");

	ASSERT_TRUE(record.Ban(v6, T0));
	ASSERT_EQUALS(1u, (unsigned)record.Size());
	ASSERT_TRUE(record.IsBanned(v6, T0 + 1));

	// Two peers in the same /64 are two peers, banned independently.
	ASSERT_FALSE(record.IsBanned(otherV6, T0 + 1));
	ASSERT_TRUE(record.Ban(otherV6, T0));
	ASSERT_EQUALS(2u, (unsigned)record.Size());

	// The expiry rules are the address family's business as little as the
	// counting rules are.
	ASSERT_FALSE(record.IsBanned(v6, T0 + CBanRecord::BAN_DURATION_MS));
	ASSERT_TRUE(record.Unban(otherV6));
	ASSERT_EQUALS(0u, (unsigned)record.Size());
}

// One peer, one ban, however it dials. A peer that arrives as 192.0.2.1 and
// later as ::ffff:192.0.2.1 must not get a second ban state to hide behind --
// which is what PeerAddressing::IndexKey() is for.
TEST(BanRecord, AMappedAddressAndItsNativeFormAreOnePeer)
{
	CBanRecord record;
	const CNetworkAddress native = CNetworkAddress::FromString("192.0.2.1");
	const CNetworkAddress mapped = CNetworkAddress::FromString("::ffff:192.0.2.1");

	// Distinct values, deliberately: CNetworkAddress does not normalise on
	// comparison, so it is the record's key that has to collapse them.
	ASSERT_TRUE(native != mapped);

	ASSERT_TRUE(record.Ban(native, T0));
	ASSERT_TRUE(record.IsBanned(mapped, T0 + 1));

	// The second form is a refresh, not a second banned peer.
	ASSERT_FALSE(record.Ban(mapped, T0 + 10));
	ASSERT_EQUALS(1u, (unsigned)record.Size());

	// And lifting it through either form lifts the one ban.
	ASSERT_TRUE(record.Unban(mapped));
	ASSERT_EQUALS(0u, (unsigned)record.Size());
	ASSERT_FALSE(record.IsBanned(native, T0 + 11));
}

// Expiry is read at the lookup rather than swept, so a lapsed ban must answer
// false the moment it lapses -- and must stop being counted, because the
// caller decrements on the transition.
TEST(BanRecord, ALapsedBanIsForgottenOnLookup)
{
	CBanRecord record;
	ASSERT_TRUE(record.Ban(IP_A, T0));

	const uint64 lapsed = T0 + CBanRecord::BAN_DURATION_MS;
	ASSERT_FALSE(record.IsBanned(IP_A, lapsed));
	// Forgotten, not merely reported false: the entry is gone, so the caller
	// that decremented on this transition will not decrement again.
	ASSERT_EQUALS(0u, (unsigned)record.Size());
	ASSERT_FALSE(record.Unban(IP_A));
}

// The lookup reports whether it dropped an entry, so the caller knows whether
// to decrement. Reporting the drop is the only way it can: it has no other
// view of the map.
TEST(BanRecord, TheLookupReportsWhetherItDroppedALapsedEntry)
{
	CBanRecord record;
	ASSERT_TRUE(record.Ban(IP_A, T0));

	bool dropped = false;
	ASSERT_TRUE(record.IsBanned(IP_A, T0 + 1, &dropped));
	ASSERT_FALSE(dropped);

	ASSERT_FALSE(record.IsBanned(IP_A, T0 + CBanRecord::BAN_DURATION_MS, &dropped));
	ASSERT_TRUE(dropped);

	// Nothing left to drop the second time.
	ASSERT_FALSE(record.IsBanned(IP_A, T0 + CBanRecord::BAN_DURATION_MS, &dropped));
	ASSERT_FALSE(dropped);
}

// Two addresses are two bans. Trivial, but it is what makes Size() a
// meaningful stand-in for the statistic the caller keeps.
TEST(BanRecord, DistinctAddressesAreCountedSeparately)
{
	CBanRecord record;

	ASSERT_TRUE(record.Ban(IP_A, T0));
	ASSERT_TRUE(record.Ban(IP_B, T0));
	ASSERT_EQUALS(2u, (unsigned)record.Size());

	ASSERT_TRUE(record.Unban(IP_A));
	ASSERT_EQUALS(1u, (unsigned)record.Size());
	ASSERT_TRUE(record.IsBanned(IP_B, T0 + 1));
	ASSERT_FALSE(record.IsBanned(IP_A, T0 + 1));
}

// The sweep exists so a table of long-lapsed entries does not grow without
// bound when nobody looks those addresses up again. It reports how many it
// dropped, for the same reason the lookup does.
TEST(BanRecord, TheSweepDropsOnlyLapsedEntriesAndReportsHowMany)
{
	CBanRecord record;
	ASSERT_TRUE(record.Ban(IP_A, T0));
	ASSERT_TRUE(record.Ban(IP_B, T0 + CBanRecord::BAN_DURATION_MS));

	// Only the first has lapsed at this point.
	const uint64 now = T0 + CBanRecord::BAN_DURATION_MS + 1;
	ASSERT_EQUALS(1u, (unsigned)record.DropLapsed(now));
	ASSERT_EQUALS(1u, (unsigned)record.Size());
	ASSERT_TRUE(record.IsBanned(IP_B, now));

	// A second sweep at the same instant has nothing left to do.
	ASSERT_EQUALS(0u, (unsigned)record.DropLapsed(now));
}
