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

// The IP filter's IPv6 half, and the mapped-address bypass it has to survive.
//
// This is the security-relevant test in amule-dual-stack-reachability. Before
// dual-stack listening, an IPv4 rule could only ever be tested against an IPv4
// address, because nothing else could arrive. With an IPv6 socket bound, the
// same host can arrive as ::ffff:a.b.c.d -- and a filter that matches on the
// address as received would let every blocked IPv4 peer straight in by
// connecting over IPv6 instead. That is a filter bypass, not a formatting
// detail, so the normalisation is pinned here together with the requirement
// that the resulting block still names the IPv4 rule that caused it.

#include <muleunit/test.h>

#include <IPFilterMatch.h>
#include <NetworkAddress.h>

using namespace muleunit;

DECLARE_SIMPLE(IPFilterIPv6)

// 192.0.2.0/24 (RFC 5737 documentation range) as the filter's own table stores
// it: start address in host order, length as included-end minus start.
static std::vector<uint32_t> BlockedV4Starts()
{
	return std::vector<uint32_t>{ 0xC0000200u };
}

static std::vector<uint16_t> BlockedV4Lengths()
{
	return std::vector<uint16_t>{ 0x00FFu };
}

static CIPv6FilterTable BlockedV6Table()
{
	CIPv6FilterTable table;
	// 2001:db8::/32 is the RFC 3849 documentation prefix.
	SIPv6Prefix prefix;
	ASSERT_TRUE(ParseIPv6Prefix("2001:db8::/32", prefix));
	table.Add(prefix, "documentation prefix");
	return table;
}

TEST(IPFilterIPv6, ParsesAPrefixAndItsLength)
{
	SIPv6Prefix prefix;
	ASSERT_TRUE(ParseIPv6Prefix("2001:db8::/32", prefix));
	ASSERT_EQUALS(32u, (unsigned)prefix.prefixBits);

	// A bare address is a single host, i.e. a /128.
	ASSERT_TRUE(ParseIPv6Prefix("2001:db8::1", prefix));
	ASSERT_EQUALS(128u, (unsigned)prefix.prefixBits);

	// Whitespace is what a hand-edited list has in it.
	ASSERT_TRUE(ParseIPv6Prefix("  2001:db8::/48\t", prefix));
	ASSERT_EQUALS(48u, (unsigned)prefix.prefixBits);

	// Rejected: not an address, an IPv4 address (that is the other table's
	// business), a prefix length that is not a number, and one out of range.
	ASSERT_FALSE(ParseIPv6Prefix("", prefix));
	ASSERT_FALSE(ParseIPv6Prefix("not-an-address/32", prefix));
	ASSERT_FALSE(ParseIPv6Prefix("192.0.2.1/24", prefix));
	ASSERT_FALSE(ParseIPv6Prefix("2001:db8::/x", prefix));
	ASSERT_FALSE(ParseIPv6Prefix("2001:db8::/129", prefix));
	ASSERT_FALSE(ParseIPv6Prefix("2001:db8::/", prefix));
}

TEST(IPFilterIPv6, PrefixMatchingIsBitwiseNotBytewise)
{
	SIPv6Prefix prefix;
	// /33 splits a byte, which is where a bytewise implementation silently
	// widens or narrows the rule.
	ASSERT_TRUE(ParseIPv6Prefix("2001:db8:8000::/33", prefix));

	ASSERT_TRUE(IPv6PrefixContains(prefix, CNetworkAddress::FromString("2001:db8:8000::1")));
	ASSERT_TRUE(IPv6PrefixContains(prefix, CNetworkAddress::FromString("2001:db8:ffff::1")));
	ASSERT_FALSE(IPv6PrefixContains(prefix, CNetworkAddress::FromString("2001:db8:7fff::1")));
	ASSERT_FALSE(IPv6PrefixContains(prefix, CNetworkAddress::FromString("2001:db8::1")));

	// A /0 rule covers everything, and a /128 exactly one host.
	SIPv6Prefix all;
	ASSERT_TRUE(ParseIPv6Prefix("::/0", all));
	ASSERT_TRUE(IPv6PrefixContains(all, CNetworkAddress::FromString("2001:db8::1")));

	SIPv6Prefix host;
	ASSERT_TRUE(ParseIPv6Prefix("2001:db8::1/128", host));
	ASSERT_TRUE(IPv6PrefixContains(host, CNetworkAddress::FromString("2001:db8::1")));
	ASSERT_FALSE(IPv6PrefixContains(host, CNetworkAddress::FromString("2001:db8::2")));
}

TEST(IPFilterIPv6, PeerInsideAnIPv6PrefixIsBlocked)
{
	// GIVEN a filter list containing an IPv6 prefix
	const CIPv6FilterTable v6 = BlockedV6Table();

	// WHEN a peer inside that prefix connects
	const SFilterVerdict verdict = MatchFilterRules(CNetworkAddress::FromString("2001:db8::dead:beef"),
		BlockedV4Starts(),
		BlockedV4Lengths(),
		v6);

	// THEN the connection is blocked, by the IPv6 rule that covers it
	ASSERT_TRUE(verdict.blocked);
	ASSERT_TRUE(verdict.family == EFilterRuleFamily::IPv6);
	ASSERT_EQUALS(0u, (unsigned)verdict.ruleIndex);
	ASSERT_TRUE(verdict.decided);
}

TEST(IPFilterIPv6, IPv6PeerOutsideEveryPrefixIsNotBlocked)
{
	const SFilterVerdict verdict = MatchFilterRules(CNetworkAddress::FromString("2001:db9::1"),
		BlockedV4Starts(),
		BlockedV4Lengths(),
		BlockedV6Table());

	// An IPv6 address is now a decidable one: before this change the filter had
	// no table to look it up in and blocked it for want of a verdict.
	ASSERT_TRUE(verdict.decided);
	ASSERT_FALSE(verdict.blocked);
	ASSERT_TRUE(verdict.family == EFilterRuleFamily::None);
}

TEST(IPFilterIPv6, MappedFormOfABlockedIPv4PeerIsStillBlockedByTheIPv4Rule)
{
	// GIVEN an IPv4 range that the filter blocks
	// WHEN a connection arrives from the IPv4-mapped IPv6 form of an address in
	// that range
	const SFilterVerdict verdict = MatchFilterRules(CNetworkAddress::FromString("::ffff:192.0.2.5"),
		BlockedV4Starts(),
		BlockedV4Lengths(),
		BlockedV6Table());

	// THEN the connection is blocked
	ASSERT_TRUE(verdict.blocked);
	// AND the block is attributed to the matching IPv4 rule -- not to an IPv6
	// rule, and not to "undecidable".
	ASSERT_TRUE(verdict.family == EFilterRuleFamily::IPv4);
	ASSERT_EQUALS(0u, (unsigned)verdict.ruleIndex);
	// The address the rule was matched against is reported in its normalised
	// form, so the log line names the IPv4 address the rule is written about.
	ASSERT_EQUALS(wxString("192.0.2.5"), wxString(verdict.matchedAddress.ToString()));
	ASSERT_TRUE(verdict.arrivedMapped);
}

TEST(IPFilterIPv6, MappedFormOfAnAllowedIPv4PeerIsStillAllowed)
{
	// The normalisation must not turn into a blanket block on mapped addresses:
	// a mapped peer outside every range is an allowed peer.
	const SFilterVerdict verdict = MatchFilterRules(CNetworkAddress::FromString("::ffff:198.51.100.9"),
		BlockedV4Starts(),
		BlockedV4Lengths(),
		BlockedV6Table());

	ASSERT_FALSE(verdict.blocked);
	ASSERT_TRUE(verdict.decided);
	ASSERT_TRUE(verdict.arrivedMapped);
	ASSERT_EQUALS(wxString("198.51.100.9"), wxString(verdict.matchedAddress.ToString()));
}

TEST(IPFilterIPv6, MappedAddressIsNeverTestedAgainstTheIPv6Table)
{
	// A ::ffff:0:0/96 rule in the IPv6 table must not become a way to block, or
	// to whitelist, the whole IPv4 internet through the wrong table. Mapped
	// addresses are normalised before matching, so they never reach it.
	CIPv6FilterTable v6;
	SIPv6Prefix mappedSpace;
	ASSERT_TRUE(ParseIPv6Prefix("::ffff:0:0/96", mappedSpace));
	v6.Add(mappedSpace, "all mapped IPv4");

	const SFilterVerdict verdict = MatchFilterRules(CNetworkAddress::FromString("::ffff:198.51.100.9"),
		BlockedV4Starts(),
		BlockedV4Lengths(),
		v6);

	ASSERT_FALSE(verdict.blocked);
	ASSERT_TRUE(verdict.family == EFilterRuleFamily::None);
}

TEST(IPFilterIPv6, NativeIPv4PeerBehavesExactlyAsBefore)
{
	const SFilterVerdict blocked = MatchFilterRules(CNetworkAddress::FromString("192.0.2.5"),
		BlockedV4Starts(),
		BlockedV4Lengths(),
		BlockedV6Table());
	ASSERT_TRUE(blocked.blocked);
	ASSERT_TRUE(blocked.family == EFilterRuleFamily::IPv4);
	ASSERT_FALSE(blocked.arrivedMapped);

	const SFilterVerdict allowed = MatchFilterRules(CNetworkAddress::FromString("198.51.100.9"),
		BlockedV4Starts(),
		BlockedV4Lengths(),
		BlockedV6Table());
	ASSERT_FALSE(allowed.blocked);
}

TEST(IPFilterIPv6, AbsentAddressHasNothingToBlock)
{
	const SFilterVerdict verdict = MatchFilterRules(
		CNetworkAddress::Absent(), BlockedV4Starts(), BlockedV4Lengths(), BlockedV6Table());
	ASSERT_FALSE(verdict.blocked);
	ASSERT_FALSE(verdict.decided);
	ASSERT_TRUE(verdict.family == EFilterRuleFamily::None);
}

TEST(IPFilterIPv6, RuleDescriptionsSurviveForTheLogLine)
{
	const CIPv6FilterTable v6 = BlockedV6Table();
	ASSERT_EQUALS(1u, (unsigned)v6.Size());
	ASSERT_EQUALS(wxString("documentation prefix"), wxString(v6.Description(0)));
	// Out-of-range index answers empty rather than reading past the end: the
	// descriptions vector is only populated when filter debugging is on, so the
	// index a match reports routinely has no description behind it.
	ASSERT_EQUALS(wxString(""), wxString(v6.Description(7)));
}

TEST(IPFilterIPv6, FilterLineWithAnIPv6PrefixIsRecognisedAsOne)
{
	// The .dat format is `range , access level , description`, and an IPv6 line
	// is recognised by its address rather than by a separate file: a user who
	// adds an IPv6 prefix to ipfilter.dat gets a working rule, not a silently
	// discarded line.
	SIPv6Prefix prefix;
	uint16_t accessLevel = 0;
	std::string description;
	ASSERT_TRUE(ParseIPv6FilterLine(
		"2001:db8::/32 , 100 , Documentation net", prefix, accessLevel, description));
	ASSERT_EQUALS(32u, (unsigned)prefix.prefixBits);
	ASSERT_EQUALS(100u, (unsigned)accessLevel);
	ASSERT_EQUALS(wxString("Documentation net"), wxString(description));

	// No access level given: the format's own default of 0, i.e. blocked at
	// every level the user can select.
	ASSERT_TRUE(ParseIPv6FilterLine("2001:db8::/32", prefix, accessLevel, description));
	ASSERT_EQUALS(0u, (unsigned)accessLevel);

	// An IPv4 line is not this parser's business and must fall through to the
	// existing lexer untouched.
	ASSERT_FALSE(
		ParseIPv6FilterLine("192.0.2.0-192.0.2.255 , 100 , v4", prefix, accessLevel, description));
	ASSERT_FALSE(ParseIPv6FilterLine("# a comment", prefix, accessLevel, description));
	ASSERT_FALSE(ParseIPv6FilterLine("", prefix, accessLevel, description));
}
