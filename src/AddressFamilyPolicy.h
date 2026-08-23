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

#include <atomic>
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
 * The configured answer is dual stack as of amule-dual-stack-reachability, and
 * it is now a runtime value rather than a compile-time constant: a host with no
 * IPv6 stack must keep working exactly as it did, and that is decided when the
 * listeners are bound, not when the tree is compiled.
 *
 * What dual stack does @b not mean here: Kademlia stays IPv4. Its wire format
 * carries 32-bit addresses and its routing table keys on them, so widening the
 * socket layer gives Kad nothing to widen into. That boundary is deliberate and
 * is documented in openspec/specs/network-addressing/spec.md.
 */
namespace AddressFamilyPolicy
{

enum class Families
{
	IPv4Only,
	IPv6Only,
	DualStack
};

/**
 * The configured family set.
 *
 * Atomic because it is read from the Asio thread pool (socket opening, name
 * resolution) and written once from the main thread during startup. Relaxed
 * ordering is enough: nothing else is published with it, and a socket opened in
 * the same instant as a reconfiguration is allowed to see either value.
 */
inline std::atomic<Families> &ConfiguredStorage() noexcept
{
	static std::atomic<Families> families{ Families::DualStack };
	return families;
}

inline Families Configured() noexcept
{
	return ConfiguredStorage().load(std::memory_order_relaxed);
}

/**
 * Sets the configured family set. Called once from startup with what the user
 * asked for; also used by tests to reach the branches a given host cannot.
 *
 * Sockets already open are unaffected -- this decides what the @b next socket
 * does, exactly like the bind-interface setting next to it.
 */
inline void SetConfigured(Families families) noexcept
{
	ConfiguredStorage().store(families, std::memory_order_relaxed);
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

/** The IPv4 wildcard, @c 0.0.0.0. */
inline boost::asio::ip::address AnyIPv4Address() noexcept
{
	return boost::asio::ip::address(boost::asio::ip::address_v4::any());
}

/**
 * The IPv6 wildcard, @c ::. With @c IPV6_V6ONLY off it also accepts IPv4 peers,
 * which arrive in IPv4-mapped form.
 */
inline boost::asio::ip::address AnyIPv6Address() noexcept
{
	return boost::asio::ip::address(boost::asio::ip::address_v6::any());
}

/**
 * The wildcard "any address of this machine" for a caller that has not said
 * which family it wants.
 *
 * This stays the IPv4 wildcard whenever IPv4 is permitted, dual stack included,
 * and that is deliberate. The callers are the ones that bind a single socket
 * and are not part of the ed2k dual-stack work: the external-connection
 * listener and the web server. Handing them @c :: because the ed2k listener now
 * wants both families would silently move the daemon's control channel onto
 * another family -- a change to what an EC client must dial, made as a side
 * effect. A caller that genuinely wants both families says so by asking for
 * AnyIPv6Address() and clearing @c IPV6_V6ONLY, which is what the ed2k
 * listeners do; see DualStackListeners.h.
 */
inline boost::asio::ip::address AnyAddress() noexcept
{
	if (PermitsIPv4()) {
		return AnyIPv4Address();
	}
	return AnyIPv6Address();
}

} // namespace AddressFamilyPolicy

#endif // ADDRESSFAMILYPOLICY_H
// File_checked_for_headers
