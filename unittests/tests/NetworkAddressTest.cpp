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

// Contract of the internal address type: byte order stated in the signature,
// absence distinguishable from the all-zero address, failed narrowing rather
// than truncation, and a total order fit to key a container.
//
// This is the type every uint32 IP in the tree is being migrated onto, so its
// contract is pinned here rather than left to the applications. None of it needs
// a running aMule: the type is a value type over boost::asio::ip::address.

#include <muleunit/test.h>

#include <AddressFamilyPolicy.h>
#include <NetworkAddress.h>

#include <map>
#include <set>

using namespace muleunit;

DECLARE_SIMPLE(NetworkAddress)

// 192.0.2.1 (RFC 5737 documentation range) in each of the two conventions.
static const uint32_t TEST_IP_HOST_ORDER = 0xC0000201u;
static const uint32_t TEST_IP_ED2K_ORDER = 0x010200C0u;

TEST(NetworkAddress, ByteOrderIsInTheSignature)
{
	const CNetworkAddress fromHost = CNetworkAddress::FromIPv4HostOrder(TEST_IP_HOST_ORDER);
	const CNetworkAddress fromNetwork = CNetworkAddress::FromIPv4NetworkOrder(TEST_IP_ED2K_ORDER);

	// Both name the same address, reached through the convention each caller has.
	ASSERT_EQUALS(wxString("192.0.2.1"), wxString(fromHost.ToString()));
	ASSERT_EQUALS(wxString("192.0.2.1"), wxString(fromNetwork.ToString()));
	ASSERT_TRUE(fromHost == fromNetwork);

	// And they round-trip back into the convention that is asked for, not into
	// whichever one they were built from.
	uint32_t out = 0;
	ASSERT_TRUE(fromHost.ToIPv4HostOrder(out));
	ASSERT_EQUALS(TEST_IP_HOST_ORDER, out);
	ASSERT_TRUE(fromHost.ToIPv4NetworkOrder(out));
	ASSERT_EQUALS(TEST_IP_ED2K_ORDER, out);
	ASSERT_TRUE(fromNetwork.ToIPv4HostOrder(out));
	ASSERT_EQUALS(TEST_IP_HOST_ORDER, out);

	// The two conventions are byte reversals of each other, which is the
	// identity wxUINT32_SWAP_ALWAYS relies on at every existing swap site.
	ASSERT_EQUALS(TEST_IP_ED2K_ORDER, CNetworkAddress::SwapOctets(TEST_IP_HOST_ORDER));
	ASSERT_EQUALS(TEST_IP_HOST_ORDER, CNetworkAddress::SwapOctets(TEST_IP_ED2K_ORDER));

	// Feeding a value in the wrong convention cannot be a silent no-op: it
	// yields a different, visibly wrong address. Nothing stops a caller doing
	// that, but nothing hides it either.
	ASSERT_EQUALS(wxString("1.2.0.192"),
		wxString(CNetworkAddress::FromIPv4HostOrder(TEST_IP_ED2K_ORDER).ToString()));
}

TEST(NetworkAddress, MappedAndNativeAreDistinct)
{
	const CNetworkAddress native = CNetworkAddress::FromIPv4HostOrder(TEST_IP_HOST_ORDER);
	const CNetworkAddress mapped = CNetworkAddress::FromString("::ffff:192.0.2.1");

	ASSERT_TRUE(native.IsIPv4());
	ASSERT_FALSE(native.IsIPv6());
	ASSERT_FALSE(native.IsIPv4Mapped());

	ASSERT_TRUE(mapped.IsIPv6());
	ASSERT_FALSE(mapped.IsIPv4());
	ASSERT_TRUE(mapped.IsIPv4Mapped());

	// The distinction is preserved: the mapped form is an IPv6 address and is
	// not equal to the IPv4 address it embeds.
	ASSERT_TRUE(native != mapped);

	// A caller that wants them treated alike says so.
	ASSERT_TRUE(mapped.Unmapped() == native);
	ASSERT_TRUE(native.Unmapped() == native);

	// The mapped form still narrows losslessly, in either convention.
	uint32_t out = 0;
	ASSERT_TRUE(mapped.ToIPv4HostOrder(out));
	ASSERT_EQUALS(TEST_IP_HOST_ORDER, out);
	ASSERT_TRUE(mapped.ToIPv4NetworkOrder(out));
	ASSERT_EQUALS(TEST_IP_ED2K_ORDER, out);

	// A non-mapped v6 address is not mistaken for a mapped one, whichever end
	// of the ::ffff: prefix differs.
	ASSERT_FALSE(CNetworkAddress::FromString("2001:db8::1").IsIPv4Mapped());
	ASSERT_FALSE(CNetworkAddress::FromString("::fffe:192.0.2.1").IsIPv4Mapped());
	ASSERT_FALSE(CNetworkAddress::FromString("1::ffff:192.0.2.1").IsIPv4Mapped());
}

TEST(NetworkAddress, NarrowingAnIPv6AddressFails)
{
	const CNetworkAddress v6 = CNetworkAddress::FromString("2001:db8::1");
	ASSERT_TRUE(v6.IsPresent());
	ASSERT_TRUE(v6.IsIPv6());

	// The failure is reported, and the caller's variable is left exactly as it
	// was -- no truncation, no hash, no fabricated value even for a caller that
	// ignores the return.
	uint32_t out = 0xDEADBEEFu;
	ASSERT_FALSE(v6.ToIPv4HostOrder(out));
	ASSERT_EQUALS(0xDEADBEEFu, out);
	ASSERT_FALSE(v6.ToIPv4NetworkOrder(out));
	ASSERT_EQUALS(0xDEADBEEFu, out);

	// The unspecified IPv6 address is not narrowable either, even though its
	// octets would truncate to a value that happens to look valid.
	const CNetworkAddress v6Any = CNetworkAddress::FromString("::");
	ASSERT_TRUE(v6Any.IsPresent());
	ASSERT_TRUE(v6Any.IsUnspecified());
	out = 0xDEADBEEFu;
	ASSERT_FALSE(v6Any.ToIPv4NetworkOrder(out));
	ASSERT_EQUALS(0xDEADBEEFu, out);

	// The lossy convenience form reports the same failure as a zero, which is
	// why it is only for edges that cannot act on the difference.
	ASSERT_EQUALS(0u, v6.ToIPv4NetworkOrderOrZero());
}

TEST(NetworkAddress, AbsenceIsNotTheAllZeroAddress)
{
	const CNetworkAddress absent;
	const CNetworkAddress zero = CNetworkAddress::FromIPv4NetworkOrder(0);

	ASSERT_TRUE(absent.IsAbsent());
	ASSERT_FALSE(absent.IsPresent());
	ASSERT_FALSE(absent.IsUnspecified()); // it is not an address at all
	ASSERT_TRUE(absent == CNetworkAddress::Absent());

	ASSERT_TRUE(zero.IsPresent());
	ASSERT_TRUE(zero.IsUnspecified());
	ASSERT_TRUE(zero.IsIPv4());
	ASSERT_EQUALS(wxString("0.0.0.0"), wxString(zero.ToString()));

	// The whole point: these two are different values.
	ASSERT_TRUE(absent != zero);
	ASSERT_EQUALS(wxString("<absent>"), wxString(absent.ToString()));

	// 0.0.0.0 narrows to zero; an absent address refuses to narrow at all, and
	// again leaves the caller's variable untouched.
	uint32_t out = 7;
	ASSERT_TRUE(zero.ToIPv4NetworkOrder(out));
	ASSERT_EQUALS(0u, out);
	out = 7;
	ASSERT_FALSE(absent.ToIPv4NetworkOrder(out));
	ASSERT_EQUALS(7u, out);

	// The boundary conversions resolve the ed2k zero overload towards absence,
	// and only there.
	ASSERT_TRUE(CNetworkAddress::FromIPv4NetworkOrderOrAbsent(0).IsAbsent());
	ASSERT_TRUE(CNetworkAddress::FromIPv4HostOrderOrAbsent(0).IsAbsent());
	ASSERT_TRUE(CNetworkAddress::FromIPv4NetworkOrder(0).IsPresent());
	ASSERT_TRUE(CNetworkAddress::FromIPv4HostOrder(0).IsPresent());
	ASSERT_TRUE(CNetworkAddress::FromIPv4NetworkOrderOrAbsent(TEST_IP_ED2K_ORDER) ==
		    CNetworkAddress::FromIPv4NetworkOrder(TEST_IP_ED2K_ORDER));

	// A string that is not an address is absent, not 0.0.0.0 -- unlike
	// StringIPtoUint32(), which cannot tell the caller the difference.
	ASSERT_TRUE(CNetworkAddress::FromString("").IsAbsent());
	ASSERT_TRUE(CNetworkAddress::FromString("not an address").IsAbsent());
	ASSERT_TRUE(CNetworkAddress::FromString("192.0.2.256").IsAbsent());
	ASSERT_TRUE(CNetworkAddress::FromString("0.0.0.0").IsPresent());
}

TEST(NetworkAddress, OrderingIsTotalAndUsableAsAKey)
{
	const CNetworkAddress absent;
	const CNetworkAddress v4Zero = CNetworkAddress::FromString("0.0.0.0");
	const CNetworkAddress v4Low = CNetworkAddress::FromString("10.0.0.1");
	const CNetworkAddress v4High = CNetworkAddress::FromString("192.0.2.1");
	const CNetworkAddress mapped = CNetworkAddress::FromString("::ffff:192.0.2.1");
	const CNetworkAddress v6 = CNetworkAddress::FromString("2001:db8::1");

	// Absent first, then IPv4 by value, then IPv6.
	ASSERT_TRUE(absent < v4Zero);
	ASSERT_TRUE(v4Zero < v4Low);
	ASSERT_TRUE(v4Low < v4High);
	ASSERT_TRUE(v4High < mapped);
	ASSERT_TRUE(mapped < v6);

	// Antisymmetry and irreflexivity, which is what makes it a strict weak
	// order and therefore safe for std::map.
	ASSERT_FALSE(v4High < v4High);
	ASSERT_FALSE(v4High < v4Low);
	ASSERT_TRUE(v4Low <= v4High);
	ASSERT_TRUE(v4High >= v4Low);
	ASSERT_TRUE(v4High > v4Low);
	ASSERT_FALSE(absent < CNetworkAddress::Absent());

	// Transitivity across the family boundary.
	ASSERT_TRUE(absent < v6);
	ASSERT_TRUE(v4Zero < v6);

	// No two distinct addresses collide, and equal ones do not duplicate.
	std::set<CNetworkAddress> keys;
	keys.insert(absent);
	keys.insert(v4Zero);
	keys.insert(v4Low);
	keys.insert(v4High);
	keys.insert(mapped);
	keys.insert(v6);
	ASSERT_EQUALS(6u, (unsigned)keys.size());
	keys.insert(CNetworkAddress::FromIPv4HostOrder(TEST_IP_HOST_ORDER)); // == v4High
	keys.insert(CNetworkAddress::Absent());
	ASSERT_EQUALS(6u, (unsigned)keys.size());

	// The order is the one documented, in order.
	std::set<CNetworkAddress>::const_iterator it = keys.begin();
	ASSERT_TRUE((it++)->IsAbsent());
	ASSERT_EQUALS(wxString("0.0.0.0"), wxString((it++)->ToString()));
	ASSERT_EQUALS(wxString("10.0.0.1"), wxString((it++)->ToString()));
	ASSERT_EQUALS(wxString("192.0.2.1"), wxString((it++)->ToString()));
	ASSERT_TRUE((it++)->IsIPv4Mapped());
	ASSERT_EQUALS(wxString("2001:db8::1"), wxString((it++)->ToString()));
	ASSERT_TRUE(it == keys.end());

	// Lookup by an equal address built the other way round still hits.
	std::map<CNetworkAddress, int> byAddress;
	byAddress[v4High] = 1;
	byAddress[mapped] = 2;
	ASSERT_EQUALS(2u, (unsigned)byAddress.size());
	ASSERT_EQUALS(1, byAddress[CNetworkAddress::FromIPv4NetworkOrder(TEST_IP_ED2K_ORDER)]);
	ASSERT_EQUALS(2, byAddress[CNetworkAddress::FromString("::ffff:c000:201")]);
	ASSERT_EQUALS(2u, (unsigned)byAddress.size());
}

// Task 3.4: the family a socket is opened in comes from the target address or
// the configuration, never from a literal v4() at the call site.
//
// The configured answer was IPv4-only when this file was written, which was what
// kept every removed v4() pin behaviourally identical. Dual stack is now the
// default -- that is what amule-dual-stack-reachability ships -- so both
// configurations are pinned here: the IPv4-only branch is still exercised
// because a user who restricts the client to IPv4, and a host with no IPv6
// stack, must behave exactly as this tree did before.
TEST(NetworkAddress, FamilySelectionForV4AndV6Targets)
{
	using namespace AddressFamilyPolicy;

	const CNetworkAddress v4 = CNetworkAddress::FromIPv4NetworkOrder(TEST_IP_ED2K_ORDER);
	const CNetworkAddress mapped = CNetworkAddress::FromString("::ffff:192.0.2.1");
	const CNetworkAddress v6 = CNetworkAddress::FromString("2001:db8::1");

	// --- The default: dual stack.
	ASSERT_TRUE(Configured() == Families::DualStack);
	ASSERT_TRUE(PermitsIPv4());
	ASSERT_TRUE(PermitsIPv6());

	ASSERT_TRUE(Permits(v4));
	ASSERT_TRUE(TcpProtocolForTarget(v4).value() == boost::asio::ip::tcp::v4());
	// A v4-mapped target narrows losslessly, so it is reached in the v4
	// family whatever the configuration says.
	ASSERT_TRUE(Permits(mapped));
	ASSERT_TRUE(TcpProtocolForTarget(mapped).value() == boost::asio::ip::tcp::v4());
	// And a native v6 target now gets a v6 socket rather than no socket.
	ASSERT_TRUE(Permits(v6));
	ASSERT_TRUE(TcpProtocolForTarget(v6).value() == boost::asio::ip::tcp::v6());

	// Absence is not a family, in any configuration.
	ASSERT_FALSE(Permits(CNetworkAddress::Absent()));
	ASSERT_FALSE(TcpProtocolForTarget(CNetworkAddress::Absent()).has_value());

	// Under dual stack a name lookup states no family, so the caller queries
	// unrestricted and picks from the answers. The wildcard for a caller that
	// did not say which family it wants stays 0.0.0.0 -- the callers are the EC
	// listener and the web server, and moving their socket to :: as a side
	// effect of the ed2k work would change what an EC client has to dial.
	ASSERT_FALSE(TcpResolverProtocol().has_value());
	ASSERT_EQUALS(wxString("0.0.0.0"), wxString(AnyAddress().to_string()));
	ASSERT_EQUALS(wxString("::"), wxString(AnyIPv6Address().to_string()));

	// --- Restricted to IPv4: exactly the old behaviour, pin for pin.
	SetConfigured(Families::IPv4Only);
	ASSERT_TRUE(PermitsIPv4());
	ASSERT_FALSE(PermitsIPv6());
	ASSERT_TRUE(Permits(v4));
	ASSERT_TRUE(TcpProtocolForTarget(v4).value() == boost::asio::ip::tcp::v4());
	ASSERT_TRUE(Permits(mapped));
	ASSERT_TRUE(TcpProtocolForTarget(mapped).value() == boost::asio::ip::tcp::v4());
	// No protocol at all for a native v6 target: it is not quietly downgraded
	// to a v4 socket, which is how a truncated address becomes a connection to
	// the wrong host.
	ASSERT_FALSE(Permits(v6));
	ASSERT_FALSE(TcpProtocolForTarget(v6).has_value());
	ASSERT_TRUE(TcpResolverProtocol().value() == boost::asio::ip::tcp::v4());
	ASSERT_EQUALS(wxString("0.0.0.0"), wxString(AnyAddress().to_string()));

	// --- Restricted to IPv6.
	SetConfigured(Families::IPv6Only);
	ASSERT_FALSE(PermitsIPv4());
	ASSERT_TRUE(PermitsIPv6());
	ASSERT_FALSE(Permits(v4));
	ASSERT_TRUE(TcpProtocolForTarget(v6).value() == boost::asio::ip::tcp::v6());
	ASSERT_TRUE(TcpResolverProtocol().value() == boost::asio::ip::tcp::v6());
	// With no IPv4 permitted there is nothing else the wildcard can be.
	ASSERT_EQUALS(wxString("::"), wxString(AnyAddress().to_string()));

	// Left as the process found it: the policy is global, and a later test
	// reading a value this one set would be a test depending on run order.
	SetConfigured(Families::DualStack);
}

TEST(NetworkAddress, TruncatedToPrefixClearsHostBits)
{
	// The prefix operation a per-block limit or rule needs. Asserted against
	// literal prefixes rather than against a mask computed the same way the
	// implementation computes it -- a symmetric off-by-one in a shift would
	// cancel out and pass.
	ASSERT_EQUALS(wxString("192.0.2.0"),
		wxString(CNetworkAddress::FromString("192.0.2.130").TruncatedToPrefix(24).ToString()));
	ASSERT_EQUALS(wxString("192.0.0.0"),
		wxString(CNetworkAddress::FromString("192.0.2.130").TruncatedToPrefix(16).ToString()));
	ASSERT_EQUALS(wxString("0.0.0.0"),
		wxString(CNetworkAddress::FromString("192.0.2.130").TruncatedToPrefix(0).ToString()));
	// A prefix at or beyond the family width is the address itself, not an
	// undefined shift.
	ASSERT_EQUALS(wxString("192.0.2.130"),
		wxString(CNetworkAddress::FromString("192.0.2.130").TruncatedToPrefix(32).ToString()));
	ASSERT_EQUALS(wxString("192.0.2.130"),
		wxString(CNetworkAddress::FromString("192.0.2.130").TruncatedToPrefix(128).ToString()));

	// IPv6, including a prefix that ends mid-byte -- /60 keeps the high nibble
	// of the eighth byte and clears the low one.
	ASSERT_EQUALS(wxString("2001:db8:1::"),
		wxString(CNetworkAddress::FromString("2001:db8:1:2:3:4:5:6")
				 .TruncatedToPrefix(48)
				 .ToString()));
	ASSERT_EQUALS(wxString("2001:db8:1:f0::"),
		wxString(CNetworkAddress::FromString("2001:db8:1:f2:3:4:5:6")
				 .TruncatedToPrefix(60)
				 .ToString()));
	ASSERT_EQUALS(wxString("2001:db8:1:2::"),
		wxString(CNetworkAddress::FromString("2001:db8:1:2:3:4:5:6")
				 .TruncatedToPrefix(64)
				 .ToString()));
	ASSERT_EQUALS(wxString("::"),
		wxString(
			CNetworkAddress::FromString("2001:db8:1:2:3:4:5:6").TruncatedToPrefix(0).ToString()));
	ASSERT_TRUE(CNetworkAddress::FromString("2001:db8:1:2:3:4:5:6").TruncatedToPrefix(128) ==
		    CNetworkAddress::FromString("2001:db8:1:2:3:4:5:6"));

	// A prefix of an absent address is still absent: no prefix is invented for
	// a peer that has no address.
	ASSERT_TRUE(CNetworkAddress::Absent().TruncatedToPrefix(64).IsAbsent());

	// The truncation stays inside its family. A /24 of an IPv4 address is an
	// IPv4 address, and no prefix width turns one family into the other.
	ASSERT_TRUE(CNetworkAddress::FromString("192.0.2.130").TruncatedToPrefix(24).IsIPv4());
	ASSERT_TRUE(CNetworkAddress::FromString("2001:db8::1").TruncatedToPrefix(64).IsIPv6());
}

// File_checked_for_headers
