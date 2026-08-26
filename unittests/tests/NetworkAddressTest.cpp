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
// a running aMule: the type is a value type over sixteen octets and a family tag.

#include <muleunit/test.h>

#include <AddressFamilyPolicyAsio.h>
#include <NetworkAddressAsio.h>
#include <NetworkAddress.h>

#include <algorithm>
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

// CNetworkAddress no longer stores a boost::asio::ip::address, so the three
// predicates that used to be asio's -- loopback, link-local, unique-local --
// are now prefix tests in NetworkAddress.h. This pins each range it must
// reject, because getting one prefix wrong here does not fail a build: it
// advertises an address no peer can reach, and the only symptom is a wasted
// connect attempt on the far side.
TEST(NetworkAddress, GloballyRoutableIPv6RejectsEveryUnreachableRange)
{
	// Routable: a documentation prefix (2001:db8::/32) is a global unicast
	// address as far as the address itself can say.
	ASSERT_TRUE(CNetworkAddress::FromString("2001:db8::1").IsGloballyRoutableIPv6());
	ASSERT_TRUE(CNetworkAddress::FromString("2606:4700::1111").IsGloballyRoutableIPv6());

	// Not an IPv6 address at all.
	ASSERT_FALSE(CNetworkAddress::Absent().IsGloballyRoutableIPv6());
	ASSERT_FALSE(CNetworkAddress::FromString("192.0.2.1").IsGloballyRoutableIPv6());
	// A mapped address is reachable over IPv4, so it is not an IPv6 address to
	// advertise as one.
	ASSERT_FALSE(CNetworkAddress::FromString("::ffff:192.0.2.1").IsGloballyRoutableIPv6());

	// The unspecified address and loopback.
	ASSERT_FALSE(CNetworkAddress::AnyIPv6().IsGloballyRoutableIPv6());
	ASSERT_FALSE(CNetworkAddress::FromString("::").IsGloballyRoutableIPv6());
	ASSERT_FALSE(CNetworkAddress::FromString("::1").IsGloballyRoutableIPv6());

	// fe80::/10, link-local -- both ends of the range, since the prefix is ten
	// bits and a byte-wide test would let the upper half through.
	ASSERT_FALSE(CNetworkAddress::FromString("fe80::1").IsGloballyRoutableIPv6());
	ASSERT_FALSE(CNetworkAddress::FromString("febf:ffff::1").IsGloballyRoutableIPv6());

	// fec0::/10, the deprecated site-local range.
	ASSERT_FALSE(CNetworkAddress::FromString("fec0::1").IsGloballyRoutableIPv6());
	ASSERT_FALSE(CNetworkAddress::FromString("feff:ffff::1").IsGloballyRoutableIPv6());

	// fc00::/7, unique-local. Both halves: fc00::/8 and fd00::/8.
	ASSERT_FALSE(CNetworkAddress::FromString("fc00::1").IsGloballyRoutableIPv6());
	ASSERT_FALSE(CNetworkAddress::FromString("fd12:3456::1").IsGloballyRoutableIPv6());
	ASSERT_FALSE(CNetworkAddress::FromString("fdff:ffff::1").IsGloballyRoutableIPv6());

	// ff00::/8, multicast.
	ASSERT_FALSE(CNetworkAddress::FromString("ff02::1").IsGloballyRoutableIPv6());

	// And the addresses immediately outside those prefixes stay routable, so
	// the tests above are pinning a prefix and not a whole leading byte.
	ASSERT_TRUE(CNetworkAddress::FromString("fbff:ffff::1").IsGloballyRoutableIPv6());
	ASSERT_TRUE(CNetworkAddress::FromString("fe00::1").IsGloballyRoutableIPv6());
	ASSERT_TRUE(CNetworkAddress::FromString("fe7f:ffff::1").IsGloballyRoutableIPv6());
}

// The octets are the storage now, so what GetOctets() hands out is what every
// bit-arithmetic caller (IPFilterMatch.h above all) works on. Two things are
// worth pinning: the order is wire order for both families, and an IPv4
// address leaves the tail zero rather than filling in the mapped prefix --
// callers relying on the latter would silently match the wrong rule.
TEST(NetworkAddress, OctetsAreWireOrderAndLeaveTheIPv4TailZero)
{
	// 192.0.2.1 reached through either 32-bit convention gives the same octets,
	// most significant first -- neither convention is the storage order.
	const CNetworkAddress v4 = CNetworkAddress::FromIPv4NetworkOrder(TEST_IP_ED2K_ORDER);
	const CNetworkAddress::Octets v4Octets = v4.GetOctets();
	ASSERT_EQUALS(192, static_cast<int>(v4Octets[0]));
	ASSERT_EQUALS(0, static_cast<int>(v4Octets[1]));
	ASSERT_EQUALS(2, static_cast<int>(v4Octets[2]));
	ASSERT_EQUALS(1, static_cast<int>(v4Octets[3]));
	for (int i = 4; i < 16; ++i) {
		ASSERT_EQUALS(0, static_cast<int>(v4Octets[i]));
	}
	ASSERT_EQUALS(0ul, v4.GetScopeId());

	// The mapped form of the same address is a different set of octets, which
	// is the storage-level statement of MappedAndNativeAreDistinct above.
	const CNetworkAddress::Octets mappedOctets =
		CNetworkAddress::FromString("::ffff:192.0.2.1").GetOctets();
	ASSERT_EQUALS(0xff, static_cast<int>(mappedOctets[10]));
	ASSERT_EQUALS(0xff, static_cast<int>(mappedOctets[11]));
	ASSERT_EQUALS(192, static_cast<int>(mappedOctets[12]));
	ASSERT_EQUALS(1, static_cast<int>(mappedOctets[15]));
	ASSERT_TRUE(v4Octets != mappedOctets);

	// IPv6FromOctets() applies no absence rule, so the all-zero octets are the
	// unspecified address and not absence -- unlike FromIPv6Bytes(), which is
	// the wire-tag edge where all-zero does mean "this peer has no IPv6".
	ASSERT_TRUE(CNetworkAddress::AnyIPv6().IsPresent());
	ASSERT_TRUE(CNetworkAddress::AnyIPv6().IsIPv6());
	ASSERT_TRUE(CNetworkAddress::AnyIPv6().IsUnspecified());
	ASSERT_EQUALS(wxString("::"), wxString(CNetworkAddress::AnyIPv6().ToString()));
	const std::uint8_t allZero[16] = { 0 };
	ASSERT_TRUE(CNetworkAddress::FromIPv6Bytes(allZero).IsAbsent());
	ASSERT_TRUE(CNetworkAddress::AnyIPv6() != CNetworkAddress::Absent());
}

// ToIPv6Bytes() is the wire-side writer: the CT_MOD_IP_V6 handshake tag, Kad's
// "ip6" tag and the NAT endpoint hint each hand it a bare sixteen-byte buffer
// and then read all sixteen back. Nothing pinned that it fills all sixteen, so
// the postcondition lived only in the doc comment -- and a short write there is
// not a cosmetic bug: the bytes it left alone become part of an address a peer
// is told to punch at.
TEST(NetworkAddress, ToIPv6BytesFillsAllSixteenOrWritesNothing)
{
	// Sentinel fill rather than zero fill: a byte still holding 0xCD afterwards
	// is a byte the writer skipped, which a zero-filled buffer would hide behind
	// a plausible-looking 0.
	std::uint8_t bytes[16];
	std::fill(std::begin(bytes), std::end(bytes), 0xCD);

	const CNetworkAddress v6 = CNetworkAddress::FromString("2001:db8::1");
	ASSERT_TRUE(v6.ToIPv6Bytes(bytes));
	const CNetworkAddress::Octets &expected = v6.GetOctets();
	for (std::size_t i = 0; i < expected.size(); ++i) {
		ASSERT_EQUALS(static_cast<int>(expected[i]), static_cast<int>(bytes[i]));
	}
	// Stated separately for the trailing octet, because the tail is what a copy
	// that stops early loses first. It is 1 rather than 0 here, so "skipped" and
	// "correctly written" cannot coincide.
	ASSERT_EQUALS(1, static_cast<int>(bytes[15]));

	// A mapped IPv4 address is an IPv6 address for this writer's purposes, and it
	// goes out as the mapped form -- all sixteen octets again, not four.
	std::fill(std::begin(bytes), std::end(bytes), 0xCD);
	ASSERT_TRUE(CNetworkAddress::FromString("::ffff:192.0.2.1").ToIPv6Bytes(bytes));
	ASSERT_EQUALS(0xff, static_cast<int>(bytes[10]));
	ASSERT_EQUALS(0xff, static_cast<int>(bytes[11]));
	ASSERT_EQUALS(192, static_cast<int>(bytes[12]));
	ASSERT_EQUALS(1, static_cast<int>(bytes[15]));

	// The failure paths write nothing at all, so a caller that ignores the result
	// cannot mistake a stale buffer for an address it never received.
	std::fill(std::begin(bytes), std::end(bytes), 0xCD);
	ASSERT_FALSE(CNetworkAddress::FromIPv4HostOrder(TEST_IP_HOST_ORDER).ToIPv6Bytes(bytes));
	ASSERT_FALSE(CNetworkAddress::Absent().ToIPv6Bytes(bytes));
	ASSERT_FALSE(v6.ToIPv6Bytes(nullptr));
	for (std::size_t i = 0; i < 16; ++i) {
		ASSERT_EQUALS(0xCD, static_cast<int>(bytes[i]));
	}
}

// The socket backend is the one caller that still needs a real asio address, so
// NetworkAddressAsio.h is the single bridge. It has to be exactly lossless in
// both directions: a swapped IPv4 conversion here would connect to the wrong
// host, and a dropped scope id would fold two distinct link-local destinations
// into one.
TEST(NetworkAddress, AsioBridgeRoundTripsWithoutLosingAnything)
{
	const CNetworkAddress cases[] = {
		CNetworkAddress::FromIPv4NetworkOrder(TEST_IP_ED2K_ORDER),
		CNetworkAddress::FromString("0.0.0.0"),
		CNetworkAddress::FromString("255.255.255.254"),
		CNetworkAddress::FromString("2001:db8::1"),
		CNetworkAddress::FromString("::ffff:192.0.2.1"),
		CNetworkAddress::AnyIPv6(),
		CNetworkAddress::FromString("::1"),
	};
	for (const CNetworkAddress &address : cases) {
		const CNetworkAddress roundTripped = FromAsioAddress(ToAsioAddress(address));
		ASSERT_TRUE(roundTripped == address);
		// Not just equal -- the same text, so a family or octet swap that
		// happened to compare equal would still be caught.
		ASSERT_EQUALS(wxString(address.ToString()), wxString(roundTripped.ToString()));
	}

	// The 32-bit conventions survive the crossing: asio's to_uint() is host
	// order, which is the convention FromIPv4HostOrder() names.
	ASSERT_EQUALS(wxString("192.0.2.1"),
		wxString(FromAsioAddress(boost::asio::ip::make_address("192.0.2.1")).ToString()));
	std::uint32_t hostOrder = 0;
	ASSERT_TRUE(FromAsioAddress(boost::asio::ip::make_address("192.0.2.1")).ToIPv4HostOrder(hostOrder));
	ASSERT_EQUALS(TEST_IP_HOST_ORDER, hostOrder);

	// A scope id is part of the address's identity, so it crosses too. Without
	// it fe80::1%7 and fe80::1%9 would be one key in every container that uses
	// this type.
	const CNetworkAddress scoped = FromAsioAddress(boost::asio::ip::make_address("fe80::1%7"));
	ASSERT_EQUALS(7ul, scoped.GetScopeId());
	ASSERT_TRUE(scoped == FromAsioAddress(ToAsioAddress(scoped)));
	ASSERT_TRUE(scoped != CNetworkAddress::FromString("fe80::1"));
	ASSERT_TRUE(CNetworkAddress::FromString("fe80::1").GetScopeId() == 0ul);

	// An asio address is always a present address: nothing it can hold means
	// absence, 0.0.0.0 included. That overload belongs to the wire edges.
	ASSERT_TRUE(FromAsioAddress(boost::asio::ip::make_address("0.0.0.0")).IsPresent());
	ASSERT_TRUE(FromAsioAddress(boost::asio::ip::make_address("0.0.0.0")).IsUnspecified());
}

// File_checked_for_headers
