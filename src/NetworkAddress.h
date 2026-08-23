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

#ifndef NETWORKADDRESS_H
#define NETWORKADDRESS_H

#include <boost/asio/ip/address.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

/**
 * The internal, family-agnostic address type.
 *
 * aMule stores IP addresses as bare @c uint32 across Kademlia, the client list
 * and the IP filter. That representation cannot hold an IPv6 address, and it
 * carries two further defects that a plain widening would silently inherit:
 *
 *  - **Byte order is not in the type.** A @c uint32 IP in this tree is in one
 *    of two conventions depending on the call site, and the two are bridged by
 *    scattered @c wxUINT32_SWAP_ALWAYS calls. Which convention a value is in
 *    is documented in comments at best.
 *  - **Zero doubles as "no address".** So a client whose address is genuinely
 *    unknown is indistinguishable from one at @c 0.0.0.0.
 *
 * This type fixes both by construction. There is no implicit conversion to or
 * from @c uint32: every narrowing and widening goes through a named function
 * whose name states the byte order, and absence is a state of the object
 * rather than a magic value.
 *
 * The stored address is a @c boost::asio::ip::address, which the Asio socket
 * backend already uses natively (see LibSocketAsio.cpp). It handles the v4/v6
 * variant and IPv4-mapped forms, so no separate address abstraction is needed.
 *
 * ## The two 32-bit conventions
 *
 * For the address @c 192.0.2.1:
 *
 * | Convention | Value | Used by |
 * | --- | --- | --- |
 * | host order (numeric) | @c 0xC0000201 | Kademlia (`KadIPToString`) |
 * | network order | @c 0x010200C0 | ed2k core (`Uint32toStringIP`) |
 *
 * "Network order" is the name used in this type's API for what the rest of
 * aMule's comments call *anti-host order*: the four octets packed with the
 * first octet in the numerically least significant byte. On a little-endian
 * host that is the value obtained by loading four network-order bytes straight
 * into a @c uint32, which is how it arises in practice — an ed2k packet field
 * read by CFileDataIO. The two conventions are exact byte reversals of each
 * other on every platform, which is why @c wxUINT32_SWAP_ALWAYS converts
 * between them unconditionally.
 *
 * ## Comparison rule
 *
 * One rule, applied everywhere:
 *
 *  1. An absent address sorts before every present one, and equals only
 *     another absent address.
 *  2. IPv4 sorts before IPv6.
 *  3. Within a family, addresses sort by their octets, most significant
 *     first.
 *
 * IPv4-mapped forms are **not** normalised: @c ::ffff:192.0.2.1 is an IPv6
 * address, so it is neither equal to nor adjacent to the IPv4 address
 * @c 192.0.2.1. This keeps the ordering total with no two distinct addresses
 * comparing equal, which is what makes the type safe as a container key.
 * Callers that want the two treated alike must say so by calling Unmapped()
 * first.
 */
class CNetworkAddress
{
public:
	/** Constructs an absent address -- @b not @c 0.0.0.0. */
	CNetworkAddress() = default;

	explicit CNetworkAddress(const boost::asio::ip::address &address) : m_address(address) {}

	/** An explicitly absent address, for call sites where the name reads better. */
	static CNetworkAddress Absent() { return CNetworkAddress(); }

	/**
	 * Builds an IPv4 address from a 32-bit value in host (numeric) order,
	 * i.e. @c 192.0.2.1 is @c 0xC0000201. This is the Kademlia convention.
	 */
	static CNetworkAddress FromIPv4HostOrder(std::uint32_t ip)
	{
		return CNetworkAddress(boost::asio::ip::address(
			boost::asio::ip::address_v4(static_cast<boost::asio::ip::address_v4::uint_type>(ip))));
	}

	/**
	 * Builds an IPv4 address from a 32-bit value in network order, i.e.
	 * @c 192.0.2.1 is @c 0x010200C0. This is the ed2k convention, called
	 * "anti-host order" elsewhere in the tree.
	 */
	static CNetworkAddress FromIPv4NetworkOrder(std::uint32_t ip)
	{
		return FromIPv4HostOrder(SwapOctets(ip));
	}

	/**
	 * The conversion boundary for a 32-bit ed2k-order address field in which
	 * zero is overloaded to mean "no address".
	 *
	 * This is the lossy direction and the only place the overload is allowed to
	 * live. A caller holding such a field cannot tell @c 0.0.0.0 from "unknown",
	 * so this resolves the ambiguity once, at the edge, in favour of absence --
	 * which is what the @c if (ip) tests it replaces already did. Use it only
	 * where the old code actually tested the value against zero; where zero was
	 * simply a value, FromIPv4NetworkOrder() keeps behaviour identical.
	 */
	static CNetworkAddress FromIPv4NetworkOrderOrAbsent(std::uint32_t ip)
	{
		return ip == 0 ? Absent() : FromIPv4NetworkOrder(ip);
	}

	/** As FromIPv4NetworkOrderOrAbsent(), for the Kad host-order convention. */
	static CNetworkAddress FromIPv4HostOrderOrAbsent(std::uint32_t ip)
	{
		return ip == 0 ? Absent() : FromIPv4HostOrder(ip);
	}

	/**
	 * Builds an IPv6 address from sixteen big-endian bytes -- the form the
	 * @c CT_MOD_IP_V6 hello tag and the Kad @c "ip6" tag carry.
	 *
	 * @return The address, or an @b absent address when @a bytes is NULL or
	 *         the sixteen bytes are all zero. The all-zero value is @c :: ,
	 *         which is what a peer that has no IPv6 address sends when it
	 *         emits the tag anyway; treating it as an address would have aMule
	 *         dialling the unspecified address.
	 */
	static CNetworkAddress FromIPv6Bytes(const std::uint8_t *bytes)
	{
		if (bytes == nullptr) {
			return Absent();
		}
		boost::asio::ip::address_v6::bytes_type raw;
		bool allZero = true;
		for (std::size_t i = 0; i < raw.size(); ++i) {
			raw[i] = bytes[i];
			if (bytes[i] != 0) {
				allZero = false;
			}
		}
		if (allZero) {
			return Absent();
		}
		return CNetworkAddress(boost::asio::ip::address(boost::asio::ip::address_v6(raw)));
	}

	/**
	 * Parses a textual address, IPv4 or IPv6.
	 *
	 * @return The address, or an @b absent address if @a text is not a valid
	 *         literal. Note that this never yields @c 0.0.0.0 on failure, unlike
	 *         StringIPtoUint32().
	 */
	static CNetworkAddress FromString(const std::string &text)
	{
		if (text.empty()) {
			return Absent();
		}
		boost::system::error_code ec;
		const boost::asio::ip::address address = boost::asio::ip::make_address(text, ec);
		if (ec) {
			return Absent();
		}
		return CNetworkAddress(address);
	}

	bool IsPresent() const noexcept { return m_address.has_value(); }
	bool IsAbsent() const noexcept { return !m_address.has_value(); }

	/** True for a present address whose every octet is zero (@c 0.0.0.0 or @c ::). */
	bool IsUnspecified() const noexcept { return IsPresent() && m_address->is_unspecified(); }

	bool IsIPv4() const noexcept { return IsPresent() && m_address->is_v4(); }
	bool IsIPv6() const noexcept { return IsPresent() && m_address->is_v6(); }

	/** True only for an IPv6 address in the @c ::ffff:a.b.c.d form. */
	bool IsIPv4Mapped() const noexcept
	{
		if (!IsIPv6()) {
			return false;
		}
		// Tested against the octets rather than via address_v6::is_v4_mapped(),
		// which Boost deprecated after 1.66 and has since removed. The prefix is
		// RFC 4291 section 2.5.5.2: eighty zero bits, then 0xffff.
		const boost::asio::ip::address_v6::bytes_type bytes = m_address->to_v6().to_bytes();
		for (int i = 0; i < 10; ++i) {
			if (bytes[i] != 0) {
				return false;
			}
		}
		return bytes[10] == 0xff && bytes[11] == 0xff;
	}

	/**
	 * The wrapped Asio address.
	 *
	 * @pre IsPresent(). Absent addresses have no Asio equivalent -- asio's own
	 *      default-constructed address is @c 0.0.0.0, which is exactly the
	 *      conflation this type exists to prevent.
	 */
	const boost::asio::ip::address &Get() const { return *m_address; }

	/**
	 * The same address with any IPv4-mapped IPv6 form collapsed to plain IPv4.
	 * Everything else, including absence, is returned unchanged. Call this
	 * deliberately at sites that must treat the mapped and native forms as one
	 * address; the comparison operators never do it for you.
	 */
	CNetworkAddress Unmapped() const
	{
		if (IsIPv4Mapped()) {
			return CNetworkAddress(boost::asio::ip::address(EmbeddedIPv4()));
		}
		return *this;
	}

	/**
	 * Narrows to a 32-bit IPv4 value in host (numeric) order.
	 *
	 * @param out Assigned only on success; left untouched on failure, so a
	 *            caller that ignores the result cannot end up with a fabricated
	 *            address.
	 * @return False if the address is absent, or is an IPv6 address that is not
	 *         IPv4-mapped. Such an address has no 32-bit form and this
	 *         deliberately fails rather than truncating or hashing it.
	 */
	bool ToIPv4HostOrder(std::uint32_t &out) const noexcept
	{
		if (IsIPv4()) {
			out = m_address->to_v4().to_uint();
			return true;
		}
		if (IsIPv4Mapped()) {
			out = EmbeddedIPv4().to_uint();
			return true;
		}
		return false;
	}

	/**
	 * Narrows to a 32-bit IPv4 value in network order (ed2k / "anti-host"
	 * order). Same failure contract as ToIPv4HostOrder().
	 */
	bool ToIPv4NetworkOrder(std::uint32_t &out) const noexcept
	{
		std::uint32_t hostOrder = 0;
		if (!ToIPv4HostOrder(hostOrder)) {
			return false;
		}
		out = SwapOctets(hostOrder);
		return true;
	}

	/**
	 * Narrows back to an ed2k-order field that uses zero for "no address",
	 * for handing to an edge this refactor has not reached yet.
	 *
	 * @return Zero for an absent address, and also for an address with no
	 *         32-bit form. Prefer ToIPv4NetworkOrder() wherever the caller can
	 *         act on the difference: this one cannot report it.
	 */
	std::uint32_t ToIPv4NetworkOrderOrZero() const noexcept
	{
		std::uint32_t value = 0;
		ToIPv4NetworkOrder(value);
		return value;
	}

	/**
	 * Writes an IPv6 address out as sixteen big-endian bytes -- the form the
	 * @c CT_MOD_IP_V6 hello tag and the Kad @c "ip6" tag carry.
	 *
	 * @param out Sixteen bytes, written only on success, so a caller that
	 *            ignores the result cannot emit a half-filled address.
	 * @return False for an absent or IPv4 address. An IPv4-mapped one is
	 *         written as the mapped IPv6 address it is: that is what the peer
	 *         asked for when it asked for an IPv6 address.
	 */
	bool ToIPv6Bytes(std::uint8_t *out) const noexcept
	{
		if (out == nullptr || !IsIPv6()) {
			return false;
		}
		const boost::asio::ip::address_v6::bytes_type bytes = m_address->to_v6().to_bytes();
		for (std::size_t i = 0; i < bytes.size(); ++i) {
			out[i] = bytes[i];
		}
		return true;
	}

	/**
	 * Whether this is an IPv6 address worth telling a peer about: present,
	 * IPv6, not mapped, and globally routable as far as the address itself can
	 * say -- so not the unspecified address, not loopback, not link-local and
	 * not a unique-local address.
	 *
	 * Advertising any of those is worse than advertising nothing: the peer
	 * cannot reach them and spends a connect attempt finding out.
	 */
	bool IsGloballyRoutableIPv6() const noexcept
	{
		if (!IsIPv6() || IsIPv4Mapped() || IsUnspecified()) {
			return false;
		}
		const boost::asio::ip::address_v6 v6 = m_address->to_v6();
		if (v6.is_loopback() || v6.is_link_local() || v6.is_site_local() ||
			v6.is_multicast()) {
			return false;
		}
		// fc00::/7, unique-local. asio's is_site_local() only covers the
		// deprecated fec0::/10, so this is tested here rather than assumed.
		const boost::asio::ip::address_v6::bytes_type bytes = v6.to_bytes();
		return (bytes[0] & 0xFE) != 0xFC;
	}

	/**
	 * The network address of the prefix this address falls in: the same
	 * address with every bit below @a prefixBits cleared.
	 *
	 * Used where a limit or a rule applies to a block rather than to a host --
	 * an IPv6 subscriber is delegated a prefix, not an address, so a per-address
	 * budget under IPv6 counts to one forever (see PeerIdentity.h).
	 *
	 * @param prefixBits Counted from the most significant bit of the address in
	 *                   its own family: 0..32 for IPv4, 0..128 for IPv6. A value
	 *                   at or above the family's width returns the address
	 *                   unchanged.
	 * @return The prefix's network address. An absent address is returned
	 *         unchanged -- there is no prefix to compute and none is invented.
	 */
	CNetworkAddress TruncatedToPrefix(unsigned prefixBits) const
	{
		if (IsAbsent()) {
			return *this;
		}
		if (m_address->is_v4()) {
			if (prefixBits >= 32) {
				return *this;
			}
			const std::uint32_t mask =
				prefixBits == 0 ? 0u : (0xFFFFFFFFu << (32 - prefixBits));
			return FromIPv4HostOrder(m_address->to_v4().to_uint() & mask);
		}
		if (prefixBits >= 128) {
			return *this;
		}
		boost::asio::ip::address_v6::bytes_type bytes = m_address->to_v6().to_bytes();
		for (std::size_t i = 0; i < bytes.size(); ++i) {
			const unsigned bitsBefore = static_cast<unsigned>(i) * 8u;
			if (prefixBits >= bitsBefore + 8u) {
				continue; // Wholly inside the prefix.
			}
			if (prefixBits <= bitsBefore) {
				bytes[i] = 0; // Wholly outside it.
			} else {
				bytes[i] = static_cast<std::uint8_t>(
					bytes[i] & (0xFFu << (bitsBefore + 8u - prefixBits)));
			}
		}
		// The scope id is deliberately not carried over: a prefix is not
		// interface-scoped, and keeping it would make the same prefix seen on
		// two interfaces into two prefixes.
		return CNetworkAddress(boost::asio::ip::address(boost::asio::ip::address_v6(bytes)));
	}

	/** Textual form, or @c "<absent>" when there is no address. */
	std::string ToString() const
	{
		if (IsAbsent()) {
			return "<absent>";
		}
		return m_address->to_string();
	}

	// Comparison. See the class comment for the single rule these implement.
	bool operator==(const CNetworkAddress &other) const noexcept
	{
		return m_address == other.m_address;
	}
	bool operator!=(const CNetworkAddress &other) const noexcept { return !(*this == other); }

	bool operator<(const CNetworkAddress &other) const noexcept
	{
		if (IsAbsent() || other.IsAbsent()) {
			// Absent sorts first; two absents are equal, so neither is less.
			return IsAbsent() && other.IsPresent();
		}
		if (m_address->is_v4() != other.m_address->is_v4()) {
			return m_address->is_v4(); // IPv4 before IPv6
		}
		if (m_address->is_v4()) {
			return m_address->to_v4().to_uint() < other.m_address->to_v4().to_uint();
		}
		// Octet-wise, most significant first. Explicit rather than deferring to
		// asio so the order is pinned by this file and stable across versions.
		const boost::asio::ip::address_v6::bytes_type lhs = m_address->to_v6().to_bytes();
		const boost::asio::ip::address_v6::bytes_type rhs = other.m_address->to_v6().to_bytes();
		if (lhs != rhs) {
			return lhs < rhs;
		}
		// Same octets: order by scope id so two distinct addresses never tie.
		return m_address->to_v6().scope_id() < other.m_address->to_v6().scope_id();
	}
	bool operator>(const CNetworkAddress &other) const noexcept { return other < *this; }
	bool operator<=(const CNetworkAddress &other) const noexcept { return !(other < *this); }
	bool operator>=(const CNetworkAddress &other) const noexcept { return !(*this < other); }

	/**
	 * Reverses the four octets of a 32-bit IPv4 value, converting between the
	 * host-order and network-order conventions in either direction.
	 *
	 * Equivalent to @c wxUINT32_SWAP_ALWAYS, spelled out here so this header
	 * stays free of wxWidgets and can be unit tested on its own.
	 */
	static std::uint32_t SwapOctets(std::uint32_t value) noexcept
	{
		return ((value & 0x000000FFu) << 24) | ((value & 0x0000FF00u) << 8) |
		       ((value & 0x00FF0000u) >> 8) | ((value & 0xFF000000u) >> 24);
	}

private:
	/**
	 * The IPv4 address embedded in an IPv4-mapped IPv6 address.
	 * @pre IsIPv4Mapped().
	 */
	boost::asio::ip::address_v4 EmbeddedIPv4() const noexcept
	{
		const boost::asio::ip::address_v6::bytes_type bytes = m_address->to_v6().to_bytes();
		boost::asio::ip::address_v4::bytes_type v4Bytes = { { bytes[12], bytes[13], bytes[14],
			bytes[15] } };
		return boost::asio::ip::address_v4(v4Bytes);
	}

	//! Absent when unset. Never conflated with the all-zero address.
	std::optional<boost::asio::ip::address> m_address;
};

#endif // NETWORKADDRESS_H
// File_checked_for_headers
