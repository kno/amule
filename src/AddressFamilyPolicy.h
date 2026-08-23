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

#ifndef ADDRESSFAMILYPOLICY_H
#define ADDRESSFAMILYPOLICY_H

#include "NetworkAddress.h"

#include <boost/asio/ip/tcp.hpp>

#include <optional>

/**
 * The single place that decides which address families aMule uses.
 *
 * The Asio backend used to answer that question with a literal
 * @c ip::tcp::v4() at every socket-opening site, which meant the family was not
 * a decision at all -- it was five independent constants. This namespace makes
 * it one decision, derived either from configuration or from the target
 * address, so that enabling IPv6 later is a change to Configured() and not a
 * hunt through LibSocketAsio.cpp.
 *
 * The configured answer is deliberately still IPv4-only. Widening it is
 * amule-dual-stack-reachability's job: the ed2k core, the EC listener and
 * Kademlia all still key clients on 32-bit addresses, so a socket layer that
 * accepted IPv6 today would hand the rest of the tree addresses it cannot
 * store. Every function here therefore returns exactly what the hardcoded
 * @c v4() calls used to return, and the value of the change is that the
 * hardcoding is gone.
 */
namespace AddressFamilyPolicy
{

enum class Families
{
	IPv4Only,
	IPv6Only,
	DualStack
};

/** The configured family set. */
inline Families Configured() noexcept
{
	return Families::IPv4Only;
}

inline bool PermitsIPv4() noexcept
{
	return Configured() != Families::IPv6Only;
}

inline bool PermitsIPv6() noexcept
{
	return Configured() != Families::IPv4Only;
}

/**
 * Whether a socket may be opened towards @a target at all.
 *
 * An IPv4-mapped IPv6 target counts as IPv4: it narrows losslessly, so an
 * IPv4-only configuration can reach it.
 */
inline bool Permits(const CNetworkAddress &target) noexcept
{
	if (target.IsAbsent()) {
		return false;
	}
	if (target.IsIPv4() || target.IsIPv4Mapped()) {
		return PermitsIPv4();
	}
	return PermitsIPv6();
}

/**
 * The TCP protocol a socket towards @a target must be opened in.
 *
 * @return The protocol, or no value when @a target is absent or its family is
 *         not permitted by the configuration. There is no fallback: opening a
 *         v4 socket for a v6 target is how a truncated address turns into a
 *         connection to the wrong host.
 */
inline std::optional<boost::asio::ip::tcp> TcpProtocolForTarget(const CNetworkAddress &target) noexcept
{
	if (!Permits(target)) {
		return std::nullopt;
	}
	if (target.IsIPv4() || target.IsIPv4Mapped()) {
		return boost::asio::ip::tcp::v4();
	}
	return boost::asio::ip::tcp::v6();
}

/**
 * The protocol to restrict a name lookup to.
 *
 * getaddrinfo() with an unrestricted family answers with AAAA records on any
 * host, whether or not it has IPv6 connectivity, so the query has to state the
 * family it wants. Under a dual-stack configuration there is nothing to state
 * and the caller should query unrestricted, hence the empty result.
 */
inline std::optional<boost::asio::ip::tcp> TcpResolverProtocol() noexcept
{
	switch (Configured()) {
	case Families::IPv4Only:
		return boost::asio::ip::tcp::v4();
	case Families::IPv6Only:
		return boost::asio::ip::tcp::v6();
	case Families::DualStack:
		break;
	}
	return std::nullopt;
}

/**
 * The wildcard "any address of this machine" for the configured family.
 * Under dual stack this is the IPv6 wildcard, which accepts v4-mapped peers.
 */
inline boost::asio::ip::address AnyAddress() noexcept
{
	if (Configured() == Families::IPv4Only) {
		return boost::asio::ip::address(boost::asio::ip::address_v4::any());
	}
	return boost::asio::ip::address(boost::asio::ip::address_v6::any());
}

} // namespace AddressFamilyPolicy

#endif // ADDRESSFAMILYPOLICY_H
// File_checked_for_headers
