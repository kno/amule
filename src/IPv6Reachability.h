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

#ifndef IPV6REACHABILITY_H
#define IPV6REACHABILITY_H

#include "DualStackListeners.h" // Needed for DualStack::EFamily
#include "PeerCapabilities.h"   // Needed for MOD_MISCOPT_IPV6

#include <cstdint>

namespace DualStack
{

/**
 * How reachable this client is on one address family.
 *
 * The middle state is the whole point. A bound socket is not reachability: a
 * host can bind @c :: and still sit behind a firewall that drops every inbound
 * IPv6 packet. A client that advertises IPv6 on the strength of a successful
 * bind sends peers to an address that never answers -- the peer opens a
 * handshake, nothing completes, and neither side logs a reason. That is the same
 * failure mode as advertising a capability that is not implemented, and it is
 * why the spec requires verified inbound connectivity before the claim.
 *
 * The values are wire format: they cross EC packed two bits per family. Kept
 * numerically stable for that reason.
 */
enum class EReachability : std::uint8_t
{
	//! No socket for this family, so nothing can arrive on it.
	Unavailable = 0,
	//! A socket is listening. Peers may be able to reach it; nothing has yet.
	Bound = 1,
	//! An inbound connection has actually arrived on this family.
	Verified = 2
};

/**
 * The status word shown for a family.
 *
 * One function, two displays: the local GUI reads it through theApp, the remote
 * GUI reads the states out of EC and renders them with this same call. Two
 * tables would drift the first time a state is added -- which is exactly how
 * the capability display in PeerCapabilities.h ended up centralised too.
 *
 * Deliberately untranslated, like the capability names next door: these are
 * short protocol status words that also appear verbatim in the log lines and in
 * amuleweb's output, and a translated log is a log a bug report cannot be
 * grepped for.
 */
inline const char *ReachabilityLabel(EReachability state) noexcept
{
	switch (state) {
	case EReachability::Bound:
		return "Listening";
	case EReachability::Verified:
		return "Verified";
	case EReachability::Unavailable:
		break;
	}
	return "Unavailable";
}

/**
 * This client's own reachability, per family, and everything that may be
 * claimed on the strength of it.
 *
 * Owned by the application object and updated from two places: the listener
 * setup, which says what is bound, and the accept path, which says what has
 * actually arrived.
 */
class CLocalReachability
{
public:
	CLocalReachability() = default;

	void Reset() noexcept
	{
		m_state[0] = EReachability::Unavailable;
		m_state[1] = EReachability::Unavailable;
	}

	/**
	 * Records whether a family has a listening socket.
	 *
	 * Losing the socket clears any verification with it: a reconfiguration
	 * that no longer binds IPv6 must not leave the claim standing, or the
	 * address stays advertised with nothing listening on it.
	 */
	void SetBound(EFamily family, bool bound) noexcept
	{
		if (!bound) {
			m_state[Index(family)] = EReachability::Unavailable;
		} else if (m_state[Index(family)] == EReachability::Unavailable) {
			m_state[Index(family)] = EReachability::Bound;
		}
	}

	/**
	 * Records an inbound connection that arrived on @a family -- the only thing
	 * that counts as verification.
	 *
	 * Ignored when that family has no socket. An inbound connection cannot
	 * arrive on a family with nothing listening, so reaching this is a bug
	 * somewhere else, and it must not become the way a client talks itself into
	 * advertising IPv6.
	 */
	void RecordInboundConnection(EFamily family) noexcept
	{
		if (m_state[Index(family)] != EReachability::Unavailable) {
			m_state[Index(family)] = EReachability::Verified;
		}
	}

	//! Sets a state directly. For the EC mirror and for tests.
	void SetState(EFamily family, EReachability state) noexcept { m_state[Index(family)] = state; }

	EReachability State(EFamily family) const noexcept { return m_state[Index(family)]; }

	bool IsBound(EFamily family) const noexcept { return State(family) != EReachability::Unavailable; }

	bool IsVerified(EFamily family) const noexcept { return State(family) == EReachability::Verified; }

	/**
	 * True while either family has a listening socket. The client MUST NOT
	 * report itself unreachable in that case, even if only one family came up.
	 */
	bool IsAnyFamilyListening() const noexcept
	{
		return IsBound(EFamily::IPv4) || IsBound(EFamily::IPv6);
	}

	/**
	 * Whether the IPv6 address and the @c CT_MOD_IP_V6 / @c "ip6" tags may go
	 * out at all. Verified reachability only -- a bound socket is not enough.
	 */
	bool MayAdvertiseIPv6() const noexcept { return IsVerified(EFamily::IPv6); }

	/**
	 * The @c CT_MOD_MISCOPTIONS word this client puts in its own handshake.
	 *
	 * Exactly bit 2 when IPv6 is verified, and nothing else ever: the other
	 * four vendor bits belong to the changes that ship those transports, and
	 * turning one on here would advertise a transport aMule does not have.
	 */
	std::uint32_t AdvertisedModMiscOptions() const noexcept
	{
		return MayAdvertiseIPv6() ? static_cast<std::uint32_t>(MOD_MISCOPT_IPV6) : 0u;
	}

	//! Both families packed two bits each, for EC. Bits 4-7 are reserved.
	std::uint8_t ToECWord() const noexcept
	{
		return static_cast<std::uint8_t>(
			static_cast<std::uint8_t>(m_state[0]) | (static_cast<std::uint8_t>(m_state[1]) << 2));
	}

	/**
	 * The inverse. Reserved bits and unknown state values are ignored rather
	 * than trusted: a newer daemon using them must not make an older client
	 * read a state it does not know as "verified".
	 */
	static CLocalReachability FromECWord(std::uint8_t word) noexcept
	{
		CLocalReachability reachability;
		reachability.m_state[0] = Decode(word & 0x03u);
		reachability.m_state[1] = Decode((word >> 2) & 0x03u);
		return reachability;
	}

private:
	static EReachability Decode(unsigned bits) noexcept
	{
		switch (bits) {
		case 2:
			return EReachability::Verified;
		case 1:
			return EReachability::Bound;
		default:
			break;
		}
		return EReachability::Unavailable;
	}

	static constexpr std::size_t Index(EFamily family) noexcept
	{
		return family == EFamily::IPv4 ? 0u : 1u;
	}

	EReachability m_state[2] = { EReachability::Unavailable, EReachability::Unavailable };
};

} // namespace DualStack

#endif // IPV6REACHABILITY_H
// File_checked_for_headers
