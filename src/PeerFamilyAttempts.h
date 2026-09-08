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

#ifndef PEERFAMILYATTEMPTS_H
#define PEERFAMILYATTEMPTS_H

#include "AddressFamilyPolicy.h"
#include "DualStackListeners.h" // Needed for DualStack::EFamily
#include "NetworkAddress.h"

#include <cstddef>

namespace DualStack
{

/**
 * The family an address belongs to for dialling purposes.
 *
 * An IPv4-mapped IPv6 address answers IPv4: it narrows losslessly and the
 * socket that reaches it is an IPv4 socket, so calling it IPv6 would make a
 * one-family peer look like a two-family one.
 *
 * @pre The address is present. An absent address has no family; callers hold a
 *      candidate list that never contains one.
 */
inline EFamily FamilyOf(const CNetworkAddress &address) noexcept
{
	return (address.IsIPv4() || address.IsIPv4Mapped()) ? EFamily::IPv4 : EFamily::IPv6;
}

/**
 * Per-peer outbound attempt accounting across address families.
 *
 * Two rules from the spec live here:
 *
 *  - a peer advertising both families gets both tried, IPv6 first, before any
 *    verdict is reached;
 *  - the peer MUST NOT be marked dead until every advertised family has
 *    failed.
 *
 * The second is the one that would otherwise regress silently: aMule's existing
 * failure handling assumes one address per peer, so the first connect error is
 * the whole story. Left as it was, every IPv4-reachable peer that also
 * advertised an unreachable IPv6 address would be written off on the IPv6
 * error alone.
 *
 * IPv6 goes first because it is the family with no NAT in the path -- when it
 * works, it works better than the IPv4 attempt, and when it does not, the IPv4
 * address is still there. Order is fixed rather than adaptive on purpose: a
 * per-peer preference learned from past failures is a second piece of state to
 * get wrong, and the fallback already costs only one failed connect.
 */
class CPeerConnectAttempts
{
public:
	CPeerConnectAttempts() = default;

	/**
	 * Sets the peer's advertised addresses and rewinds the sequence.
	 *
	 * Addresses that are absent, or whose family the configuration does not
	 * permit, are dropped here: there is no point dialling an address this
	 * build cannot open a socket for. A mapped form of the IPv4 address is
	 * dropped as a duplicate for the same reason -- it is the same host over
	 * the same family.
	 */
	void Reset(const CNetworkAddress &ipv4, const CNetworkAddress &ipv6)
	{
		m_count = 0;
		m_index = 0;
		m_failed[0] = false;
		m_failed[1] = false;

		// IPv6 first, then IPv4. Both are checked against the policy so a
		// configuration with a family switched off never dials it.
		if (Usable(ipv6) && FamilyOf(ipv6) == EFamily::IPv6) {
			m_candidates[m_count++] = ipv6;
		}
		if (Usable(ipv4)) {
			m_candidates[m_count++] = ipv4;
		} else if (m_count == 0 && Usable(ipv6)) {
			// The "IPv6" address was a mapped IPv4 one and there was no
			// separate IPv4 address: it is still reachable, as IPv4.
			m_candidates[m_count++] = ipv6.Unmapped();
		}
	}

	std::size_t CandidateCount() const noexcept { return m_count; }

	/** The address to dial now, or an absent address when none is left. */
	const CNetworkAddress &Current() const noexcept
	{
		return m_index < m_count ? m_candidates[m_index] : s_absent;
	}

	/**
	 * Records that the current attempt failed and moves to the next family.
	 *
	 * @return True when another candidate is now current, i.e. the caller
	 *         should try again rather than give up on the peer.
	 */
	bool RecordFailureAndAdvance() noexcept
	{
		if (m_index < m_count) {
			m_failed[FamilyIndex(FamilyOf(m_candidates[m_index]))] = true;
			++m_index;
		}
		return m_index < m_count;
	}

	/**
	 * Records that a connection came up. The sequence rewinds, because a
	 * transient failure on one family is not a permanent verdict on it: the
	 * next time this peer is dialled it gets both families again.
	 */
	void RecordSuccess() noexcept
	{
		m_index = 0;
		m_failed[0] = false;
		m_failed[1] = false;
	}

	/**
	 * Whether the peer may now be counted as dead.
	 *
	 * True once no candidate is left -- including the degenerate case of a peer
	 * with no usable address at all, which must not be kept alive by this
	 * accounting.
	 */
	bool MayMarkDead() const noexcept { return m_index >= m_count; }

	bool HasFamilyFailed(EFamily family) const noexcept { return m_failed[FamilyIndex(family)]; }

	std::size_t FailedFamilyCount() const noexcept
	{
		return (m_failed[0] ? 1u : 0u) + (m_failed[1] ? 1u : 0u);
	}

private:
	static bool Usable(const CNetworkAddress &address) noexcept
	{
		return address.IsPresent() && AddressFamilyPolicy::Permits(address);
	}

	static constexpr std::size_t FamilyIndex(EFamily family) noexcept
	{
		return family == EFamily::IPv4 ? 0u : 1u;
	}

	static const CNetworkAddress s_absent;

	//! At most one address per family, so a fixed pair beats a vector here:
	//! this object is per peer and there are tens of thousands of peers.
	CNetworkAddress m_candidates[2];
	std::size_t m_count = 0;
	std::size_t m_index = 0;
	bool m_failed[2] = { false, false };
};

inline const CNetworkAddress CPeerConnectAttempts::s_absent = CNetworkAddress();

} // namespace DualStack

#endif // PEERFAMILYATTEMPTS_H
// File_checked_for_headers
