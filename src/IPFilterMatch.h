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

#ifndef IPFILTERMATCH_H
#define IPFILTERMATCH_H

#include "IPFilterRanges.h" // Needed for IPFilterRangesContain
#include "NetworkAddress.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/**
 * The whole matching decision of the IP filter, for both address families.
 *
 * Two things live here that used to be impossible and are now security
 * relevant.
 *
 * **The mapped-address bypass.** Until an IPv6 socket was bound, an IPv4 rule
 * could only ever be tested against an IPv4 address, because nothing else could
 * arrive. With dual-stack listening the same host can arrive as
 * @c ::ffff:a.b.c.d, and a filter matching on the address as received would wave
 * through every blocked IPv4 peer that reconnects over IPv6. So a mapped
 * address is normalised to its IPv4 form *before* any table is consulted, and
 * the resulting block is attributed to the IPv4 rule that caused it -- an
 * attribution that names the wrong rule is a log a user cannot act on.
 *
 * **IPv6 rules.** A prefix table, matched bitwise. Kept separate from the
 * 32-bit range table rather than merged into it: the existing table's encoding
 * (a start plus a 15-bit compressed length) has no room for 128-bit addresses,
 * and the binary search over it is on aMule's hot connection path.
 *
 * Header-only and free of wxWidgets for the same reason as IPFilterRanges.h:
 * CIPFilter is a wxEvtHandler that reads thePrefs and writes theStats, so the
 * decision it makes is otherwise unobservable without a running application.
 */

//! One IPv6 rule: a prefix and the number of leading bits that must match.
struct SIPv6Prefix
{
	std::array<std::uint8_t, 16> bytes{};
	std::uint8_t prefixBits = 0;
};

/**
 * Parses a textual IPv6 prefix, with or without a @c /length suffix.
 *
 * A bare address is a single host, i.e. a @c /128. An IPv4 address is rejected:
 * it belongs to the 32-bit range table, and accepting it here would give the
 * same address two places to be filtered from and two verdicts to disagree.
 *
 * @return True when @a out was filled. @a out is untouched on failure.
 */
inline bool ParseIPv6Prefix(const std::string &text, SIPv6Prefix &out)
{
	// Trim the whitespace a hand-edited list has in it.
	const std::size_t first = text.find_first_not_of(" \t\r\n");
	if (first == std::string::npos) {
		return false;
	}
	const std::size_t last = text.find_last_not_of(" \t\r\n");
	const std::string trimmed = text.substr(first, last - first + 1);

	std::string addressPart = trimmed;
	unsigned prefixBits = 128;
	const std::size_t slash = trimmed.find('/');
	if (slash != std::string::npos) {
		addressPart = trimmed.substr(0, slash);
		const std::string lengthPart = trimmed.substr(slash + 1);
		if (lengthPart.empty()) {
			return false;
		}
		prefixBits = 0;
		for (const char c : lengthPart) {
			if (c < '0' || c > '9') {
				return false;
			}
			prefixBits = (prefixBits * 10) + static_cast<unsigned>(c - '0');
			if (prefixBits > 128) {
				return false;
			}
		}
	}

	const CNetworkAddress address = CNetworkAddress::FromString(addressPart);
	// ToIPv6Bytes() states the family requirement in its return value, so the
	// separate IsIPv6() test this used to need is now the same test.
	if (!address.ToIPv6Bytes(out.bytes.data())) {
		return false;
	}
	out.prefixBits = static_cast<std::uint8_t>(prefixBits);
	return true;
}

/**
 * Whether @a address falls inside @a prefix.
 *
 * Bitwise, not bytewise: a rule such as @c /33 splits a byte, and comparing
 * whole bytes silently widens or narrows it. @a address must be IPv6; anything
 * else answers false rather than guessing.
 */
inline bool IPv6PrefixContains(const SIPv6Prefix &prefix, const CNetworkAddress &address) noexcept
{
	std::uint8_t bytes[16];
	if (!address.ToIPv6Bytes(bytes)) {
		return false;
	}
	const unsigned wholeBytes = prefix.prefixBits / 8u;
	for (unsigned i = 0; i < wholeBytes; ++i) {
		if (bytes[i] != prefix.bytes[i]) {
			return false;
		}
	}
	const unsigned remainingBits = prefix.prefixBits % 8u;
	if (remainingBits != 0) {
		const std::uint8_t mask = static_cast<std::uint8_t>(0xFFu << (8u - remainingBits));
		if ((bytes[wholeBytes] & mask) != (prefix.bytes[wholeBytes] & mask)) {
			return false;
		}
	}
	return true;
}

/**
 * The IPv6 half of the filter's rule storage.
 *
 * A flat vector scanned linearly. The IPv4 table is binary-searched because it
 * routinely holds hundreds of thousands of ranges; published IPv6 block lists
 * are orders of magnitude smaller, and a linear scan over a contiguous vector
 * needs no invariant to be maintained at load time -- one less thing that can
 * be subtly wrong in a security-relevant table.
 */
class CIPv6FilterTable
{
public:
	void Add(const SIPv6Prefix &prefix, const std::string &description)
	{
		m_prefixes.push_back(prefix);
		m_descriptions.push_back(description);
	}

	void Clear()
	{
		m_prefixes.clear();
		m_descriptions.clear();
	}

	std::size_t Size() const noexcept { return m_prefixes.size(); }
	bool Empty() const noexcept { return m_prefixes.empty(); }

	/** The description of a rule, or empty when the index has none. */
	const std::string &Description(std::size_t index) const
	{
		static const std::string none;
		return index < m_descriptions.size() ? m_descriptions[index] : none;
	}

	/**
	 * @param matchIndex Assigned the index of the matching rule on success;
	 *                   untouched on failure, like IPFilterRangesContain().
	 */
	bool Contains(const CNetworkAddress &address, std::size_t &matchIndex) const noexcept
	{
		for (std::size_t i = 0; i < m_prefixes.size(); ++i) {
			if (IPv6PrefixContains(m_prefixes[i], address)) {
				matchIndex = i;
				return true;
			}
		}
		return false;
	}

private:
	std::vector<SIPv6Prefix> m_prefixes;
	std::vector<std::string> m_descriptions;
};

/**
 * Parses one line of an ipfilter .dat file as an IPv6 rule.
 *
 * The format is `range , access level , description`, the same shape the
 * existing lexer reads for IPv4. Recognition is by the address itself rather
 * than by putting IPv6 rules in a separate file: a user who adds a prefix to
 * their ipfilter.dat gets a working rule instead of a silently discarded line.
 *
 * @return False for anything this parser does not own -- a comment, a blank
 *         line, or an IPv4 range, all of which must fall through to the
 *         existing lexer untouched.
 */
inline bool ParseIPv6FilterLine(
	const std::string &line, SIPv6Prefix &prefix, std::uint16_t &accessLevel, std::string &description)
{
	const std::size_t first = line.find_first_not_of(" \t\r\n");
	if (first == std::string::npos || line[first] == '#' || line[first] == ';') {
		return false;
	}
	// Only a line whose first field holds a colon can be an IPv6 rule, and
	// checking for one keeps every IPv4 line out of the parse below.
	const std::size_t firstComma = line.find(',');
	const std::string addressField =
		firstComma == std::string::npos ? line.substr(first) : line.substr(first, firstComma - first);
	if (addressField.find(':') == std::string::npos) {
		return false;
	}
	if (!ParseIPv6Prefix(addressField, prefix)) {
		return false;
	}

	// Access level and description are both optional. A missing access level is
	// the format's own default of 0: blocked at every level the user can pick.
	accessLevel = 0;
	description.clear();
	if (firstComma == std::string::npos) {
		return true;
	}
	const std::size_t secondComma = line.find(',', firstComma + 1);
	const std::string levelField = line.substr(firstComma + 1,
		secondComma == std::string::npos ? std::string::npos : secondComma - firstComma - 1);
	unsigned level = 0;
	bool sawDigit = false;
	for (const char c : levelField) {
		if (c >= '0' && c <= '9') {
			level = (level * 10) + static_cast<unsigned>(c - '0');
			sawDigit = true;
		} else if (c != ' ' && c != '\t') {
			sawDigit = false;
			break;
		}
	}
	if (sawDigit && level < 256) {
		accessLevel = static_cast<std::uint16_t>(level);
	}
	if (secondComma != std::string::npos) {
		description = line.substr(secondComma + 1);
		const std::size_t descFirst = description.find_first_not_of(" \t");
		const std::size_t descLast = description.find_last_not_of(" \t\r\n");
		description = descFirst == std::string::npos
				      ? std::string()
				      : description.substr(descFirst, descLast - descFirst + 1);
	}
	return true;
}

//! Which table produced a verdict, so a block can be attributed to the rule
//! that caused it rather than to the family the connection arrived on.
enum class EFilterRuleFamily
{
	None,
	IPv4,
	IPv6
};

struct SFilterVerdict
{
	//! Whether a rule matched.
	bool blocked = false;
	/**
	 * Whether the filter reached a verdict at all. False only for an address
	 * there is nothing to decide about (an absent one). An IPv6 address is
	 * decidable now that there is a table for it -- before this change the
	 * filter blocked every one of them for want of a verdict.
	 */
	bool decided = false;
	EFilterRuleFamily family = EFilterRuleFamily::None;
	//! Index into the matching table's rules. Meaningful only when blocked.
	std::size_t ruleIndex = 0;
	//! The address the rules were matched against: the normalised form, so a
	//! mapped peer is reported as the IPv4 address the rule is written about.
	CNetworkAddress matchedAddress;
	//! True when the connection arrived as an IPv4-mapped IPv6 address.
	bool arrivedMapped = false;
};

/**
 * Matches @a address against both rule tables.
 *
 * @param rangeIPs      IPv4 range starts, host order, ascending -- the existing
 *                      table, unchanged.
 * @param rangeLengths  Encoded IPv4 range lengths, parallel to @a rangeIPs.
 * @param ipv6Rules     The IPv6 prefix table.
 */
inline SFilterVerdict MatchFilterRules(const CNetworkAddress &address,
	const std::vector<std::uint32_t> &rangeIPs,
	const std::vector<std::uint16_t> &rangeLengths,
	const CIPv6FilterTable &ipv6Rules)
{
	SFilterVerdict verdict;
	if (address.IsAbsent()) {
		// No connection, so nothing to filter and nothing to decide.
		return verdict;
	}

	verdict.decided = true;
	verdict.arrivedMapped = address.IsIPv4Mapped();
	// The normalisation that closes the bypass. Everything below matches on
	// this, never on the address as received.
	verdict.matchedAddress = address.Unmapped();

	std::uint32_t hostOrder = 0;
	if (verdict.matchedAddress.ToIPv4HostOrder(hostOrder)) {
		std::size_t index = 0;
		if (IPFilterRangesContain(rangeIPs, rangeLengths, hostOrder, index)) {
			verdict.blocked = true;
			verdict.family = EFilterRuleFamily::IPv4;
			verdict.ruleIndex = index;
		}
		return verdict;
	}

	std::size_t index = 0;
	if (ipv6Rules.Contains(verdict.matchedAddress, index)) {
		verdict.blocked = true;
		verdict.family = EFilterRuleFamily::IPv6;
		verdict.ruleIndex = index;
	}
	return verdict;
}

#endif // IPFILTERMATCH_H
// File_checked_for_headers
