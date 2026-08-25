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

// Characterisation tests for aMule's address behaviour.
//
// Widening the internal address type is a wide, mechanical diff with a narrow
// behavioural surface, and its acceptance criterion is that nothing changed.
// The failure mode is therefore silence: a flipped byte order, a lost ordering
// or a zero that stopped meaning "absent" changes no interface and breaks no
// build, and a smoke run does not notice.
//
// These tests exist to make that noisy. They record what the tree does today --
// not what it ought to do -- for the three places a mistake would hide:
//
//   1. IP filter range matching, including its byte order.
//   2. Address keying and comparison as the client list performs it.
//   3. The bytes an address occupies on the wire.
//
// They are expected to hold unchanged for the whole of the migration. If one of
// them has to be edited to make a refactor pass, the refactor changed behaviour
// and the edit is the bug report.

#include <muleunit/test.h>

#include <IPFilterRanges.h>
#include <MemFile.h>
#include <NetworkAddress.h>
#include <NetworkFunctions.h>

#include <cstring>
#include <map>

using namespace muleunit;

DECLARE_SIMPLE(AddressCharacterisation)

// ---------------------------------------------------------------------------
// 2.1 IP filter matching
// ---------------------------------------------------------------------------

// Builds the pair of parallel tables CIPFilter keeps: range starts in host
// (numeric) order, and the encoded lengths beside them.
struct RangeTable
{
	std::vector<uint32_t> ips;
	std::vector<uint16_t> lengths;

	void Add(const char *start, uint16_t length)
	{
		uint32_t hostOrder = 0;
		// The table is built from the same conversion the filter's own reader
		// produces: an ed2k-order parse, byte-swapped into host order.
		CNetworkAddress::FromString(start).ToIPv4HostOrder(hostOrder);
		ips.push_back(hostOrder);
		lengths.push_back(length);
	}

	bool Contains(const char *address) const
	{
		uint32_t hostOrder = 0;
		if (!CNetworkAddress::FromString(address).ToIPv4HostOrder(hostOrder)) {
			return false;
		}
		size_t index = 0;
		return IPFilterRangesContain(ips, lengths, hostOrder, index);
	}
};

TEST(AddressCharacterisation, IPFilterMatchesInclusiveRanges)
{
	RangeTable table;
	table.Add("10.0.0.0", 0xFF);   // 10.0.0.0 - 10.0.0.255
	table.Add("192.0.2.0", 0x03);  // 192.0.2.0 - 192.0.2.3
	table.Add("203.0.113.7", 0x0); // a single address

	// Both bounds are inclusive; one past either end is not matched.
	ASSERT_TRUE(table.Contains("10.0.0.0"));
	ASSERT_TRUE(table.Contains("10.0.0.128"));
	ASSERT_TRUE(table.Contains("10.0.0.255"));
	ASSERT_FALSE(table.Contains("10.0.1.0"));
	ASSERT_FALSE(table.Contains("9.255.255.255"));

	ASSERT_TRUE(table.Contains("192.0.2.0"));
	ASSERT_TRUE(table.Contains("192.0.2.3"));
	ASSERT_FALSE(table.Contains("192.0.2.4"));
	ASSERT_FALSE(table.Contains("192.0.1.255"));

	// A zero length is a range of exactly one address.
	ASSERT_TRUE(table.Contains("203.0.113.7"));
	ASSERT_FALSE(table.Contains("203.0.113.6"));
	ASSERT_FALSE(table.Contains("203.0.113.8"));

	// Nothing between the ranges matches, which is the property the binary
	// search is easiest to break.
	ASSERT_FALSE(table.Contains("11.0.0.0"));
	ASSERT_FALSE(table.Contains("200.0.0.0"));
	ASSERT_FALSE(table.Contains("255.255.255.255"));
	ASSERT_FALSE(table.Contains("0.0.0.0"));
}

TEST(AddressCharacterisation, IPFilterMatchingIsSensitiveToByteOrder)
{
	// The table is in host order, and the address CIPFilter::IsFiltered() is
	// handed is in ed2k order -- which is why it byte-swaps before searching.
	// Getting that backwards does not fail loudly, it just filters a different
	// address, so the two directions are pinned separately here.
	RangeTable table;
	table.Add("1.2.3.4", 0x0);

	ASSERT_TRUE(table.Contains("1.2.3.4"));
	// The same 32 bits read in the other convention are a different address,
	// and are not matched.
	ASSERT_FALSE(table.Contains("4.3.2.1"));

	uint32_t hostOrder = 0;
	uint32_t ed2kOrder = 0;
	ASSERT_TRUE(CNetworkAddress::FromString("1.2.3.4").ToIPv4HostOrder(hostOrder));
	ASSERT_TRUE(CNetworkAddress::FromString("1.2.3.4").ToIPv4NetworkOrder(ed2kOrder));
	ASSERT_EQUALS(0x01020304u, hostOrder);
	ASSERT_EQUALS(0x04030201u, ed2kOrder);
	// This is the identity the swap at every existing conversion site relies on.
	ASSERT_EQUALS(hostOrder, CNetworkAddress::SwapOctets(ed2kOrder));

	// And the ed2k order is the one Uint32toStringIP() prints, which is how the
	// rest of the tree signals which convention a uint32 is in.
	ASSERT_EQUALS(wxString("1.2.3.4"), Uint32toStringIP(ed2kOrder));
	ASSERT_EQUALS(wxString("1.2.3.4"), KadIPToString(hostOrder));
}

TEST(AddressCharacterisation, IPFilterCompressedLengthEncoding)
{
	// A length of 0x8000 or more is a compressed form: the low 15 bits shifted
	// up 12 places, plus 0xfff. Pinned because it is pure arithmetic on the
	// same 32-bit value the widening touches.
	RangeTable table;
	table.Add("10.0.0.0", 0x8001);

	ASSERT_TRUE(table.Contains("10.0.0.0"));
	ASSERT_TRUE(table.Contains("10.0.31.255")); // + 0x1fff
	ASSERT_FALSE(table.Contains("10.0.32.0"));  // + 0x2000

	// An empty table matches nothing, and does not walk off the front.
	const std::vector<uint32_t> noIPs;
	const std::vector<uint16_t> noLengths;
	size_t index = 0xAA;
	ASSERT_FALSE(IPFilterRangesContain(noIPs, noLengths, 0x0A000000u, index));
	ASSERT_EQUALS((size_t)0xAA, index); // untouched on no match
}

// ---------------------------------------------------------------------------
// 2.2 Client-list address comparison
// ---------------------------------------------------------------------------

// The client list groups clients by address in a std::multimap keyed on the
// 32-bit ed2k-order value. What matters for the migration is not the ordering
// of that map -- nothing iterates it in address order -- but that grouping and
// lookup put exactly the same addresses together afterwards, and that the
// address that means "unknown" is still not a group.
TEST(AddressCharacterisation, ClientListAddressKeyingIsPreserved)
{
	static const char *const addresses[] = { "0.0.0.0",
		"1.0.0.0",
		"0.0.0.1",
		"10.0.0.1",
		"10.0.0.2",
		"192.0.2.1",
		"203.0.113.255",
		"255.255.255.255",
		"127.0.0.1" };
	static const size_t count = sizeof(addresses) / sizeof(addresses[0]);

	std::multimap<uint32_t, int> byUint32;
	std::multimap<CNetworkAddress, int> byAddress;

	for (size_t i = 0; i < count; ++i) {
		const CNetworkAddress address = CNetworkAddress::FromString(addresses[i]);
		ASSERT_TRUE(address.IsPresent());
		uint32_t key = 0;
		ASSERT_TRUE(address.ToIPv4NetworkOrder(key));
		byUint32.insert(std::make_pair(key, (int)i));
		byAddress.insert(std::make_pair(address, (int)i));
		// Two entries under the same address, to exercise grouping.
		byUint32.insert(std::make_pair(key, (int)i + 100));
		byAddress.insert(std::make_pair(address, (int)i + 100));
	}

	ASSERT_EQUALS(byUint32.size(), byAddress.size());

	// Every address groups the same entries either way, which is the whole of
	// what FindClientByIP / GetClientsByIP / IsIPAlreadyKnown depend on.
	for (size_t i = 0; i < count; ++i) {
		const CNetworkAddress address = CNetworkAddress::FromString(addresses[i]);
		uint32_t key = 0;
		ASSERT_TRUE(address.ToIPv4NetworkOrder(key));
		ASSERT_EQUALS(byUint32.count(key), byAddress.count(address));
		ASSERT_EQUALS((size_t)2, byAddress.count(address));
	}

	// Distinct addresses never share a group, including the pairs that differ
	// only by byte order.
	ASSERT_TRUE(CNetworkAddress::FromString("1.0.0.0") != CNetworkAddress::FromString("0.0.0.1"));
	ASSERT_EQUALS((size_t)0, byAddress.count(CNetworkAddress::FromString("10.0.0.3")));
	ASSERT_EQUALS((size_t)0, byAddress.count(CNetworkAddress::Absent()));
}

TEST(AddressCharacterisation, ClientListZeroMeansUnknownAtTheBoundary)
{
	// CClientList records a client under its address only if the address is
	// known, and the 32-bit field it is handed spells "unknown" as zero. That
	// test used to be `if (newIP)`; the boundary conversion is what preserves
	// it now, so it is pinned here rather than inferred.
	ASSERT_TRUE(CNetworkAddress::FromIPv4NetworkOrderOrAbsent(0).IsAbsent());

	// An absent address has no key, so no client can be recorded or found
	// under it -- which is exactly the old behaviour of never inserting 0.
	uint32_t key = 0xAB;
	ASSERT_FALSE(CNetworkAddress::FromIPv4NetworkOrderOrAbsent(0).ToIPv4NetworkOrder(key));
	ASSERT_EQUALS(0xABu, key);

	// Every other value is a real address and keys normally, 0.0.0.0 included
	// when it arrives through the non-overloaded conversion.
	ASSERT_TRUE(CNetworkAddress::FromIPv4NetworkOrderOrAbsent(0x0100007Fu).IsPresent());
	ASSERT_TRUE(CNetworkAddress::FromIPv4NetworkOrder(0).IsPresent());
	ASSERT_TRUE(CNetworkAddress::FromIPv4NetworkOrder(0).ToIPv4NetworkOrder(key));
	ASSERT_EQUALS(0u, key);
}

// ---------------------------------------------------------------------------
// 2.3 Address serialisation on the wire
// ---------------------------------------------------------------------------

TEST(AddressCharacterisation, WireBytesOfAnAddressAreUnchanged)
{
	// ed2k writes an IP as a 32-bit field, and CFileDataIO writes 32-bit fields
	// little-endian. Combined with the ed2k-order convention, the four octets
	// therefore appear on the wire in reading order: 192.0.2.1 is C0 00 02 01.
	//
	// That is the byte sequence a capture taken before this change contains, so
	// it is asserted literally rather than derived. A fixed buffer is used so
	// this exercises only the encoding, not CMemFile's growth path.
	uint8_t buffer[16];
	memset(buffer, 0xCC, sizeof(buffer));

	uint32_t ed2kOrder = 0;
	ASSERT_TRUE(CNetworkAddress::FromString("192.0.2.1").ToIPv4NetworkOrder(ed2kOrder));

	{
		CMemFile file(buffer, sizeof(buffer));
		file.WriteUInt32(ed2kOrder);
		file.WriteUInt16(4662);
	}

	ASSERT_EQUALS(0xC0, (unsigned)buffer[0]);
	ASSERT_EQUALS(0x00, (unsigned)buffer[1]);
	ASSERT_EQUALS(0x02, (unsigned)buffer[2]);
	ASSERT_EQUALS(0x01, (unsigned)buffer[3]);
	// The port follows, little-endian: 4662 == 0x1236.
	ASSERT_EQUALS(0x36, (unsigned)buffer[4]);
	ASSERT_EQUALS(0x12, (unsigned)buffer[5]);
	// Nothing beyond the fields written was touched.
	ASSERT_EQUALS(0xCC, (unsigned)buffer[6]);

	// And reading it back yields the same address, through the conversion that
	// names the byte order.
	{
		CMemFile file(buffer, sizeof(buffer));
		const uint32_t readBack = file.ReadUInt32();
		ASSERT_EQUALS(ed2kOrder, readBack);
		ASSERT_TRUE(CNetworkAddress::FromIPv4NetworkOrder(readBack) ==
			    CNetworkAddress::FromString("192.0.2.1"));
		ASSERT_EQUALS((uint16_t)4662, file.ReadUInt16());
	}
}

TEST(AddressCharacterisation, WireBytesOfTheKadConventionAreUnchanged)
{
	// Kad holds the same address in the other convention, and swaps at the wire
	// boundary. The bytes that reach the wire are identical -- that identity is
	// what makes the swap sites correct, and what a widening most easily
	// breaks.
	uint8_t buffer[8];
	memset(buffer, 0xCC, sizeof(buffer));

	uint32_t kadOrder = 0;
	ASSERT_TRUE(CNetworkAddress::FromString("192.0.2.1").ToIPv4HostOrder(kadOrder));
	ASSERT_EQUALS(0xC0000201u, kadOrder);

	{
		CMemFile file(buffer, sizeof(buffer));
		// What the Kad send paths do: swap into ed2k order, then write.
		file.WriteUInt32(CNetworkAddress::SwapOctets(kadOrder));
	}

	ASSERT_EQUALS(0xC0, (unsigned)buffer[0]);
	ASSERT_EQUALS(0x00, (unsigned)buffer[1]);
	ASSERT_EQUALS(0x02, (unsigned)buffer[2]);
	ASSERT_EQUALS(0x01, (unsigned)buffer[3]);

	// The all-zero address serialises to four zero bytes and is a perfectly
	// ordinary address on the wire. It is the absence of an address that has no
	// encoding, which is why the two must not be conflated.
	memset(buffer, 0xCC, sizeof(buffer));
	{
		CMemFile file(buffer, sizeof(buffer));
		file.WriteUInt32(CNetworkAddress::FromString("0.0.0.0").ToIPv4NetworkOrderOrZero());
	}
	ASSERT_EQUALS(0x00, (unsigned)buffer[0]);
	ASSERT_EQUALS(0x00, (unsigned)buffer[3]);
	ASSERT_EQUALS(0xCC, (unsigned)buffer[4]);
}

// File_checked_for_headers
