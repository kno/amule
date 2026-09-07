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

#ifndef BANRECORD_H
#define BANRECORD_H

#include "NetworkAddress.h" // Needed for CNetworkAddress
#include "PeerAddressing.h" // Needed for PeerAddressing::IsIndexable / IndexKey
#include "Types.h"          // Needed for uint64

#include <protocol/ed2k/Constants.h> // Needed for CLIENTBANTIME

#include <map>

/**
 * The addresses banned from the upload queue, and when each ban started.
 *
 * Every operation answers whether it *changed* the record, because the caller
 * keeps a statistic alongside it and must move that counter exactly when the
 * set of banned addresses moves. Doing this inline was what let the two drift
 * apart: assigning the tick for an address already present overwrites without
 * inserting, and `erase()` on one that is absent removes nothing, yet both
 * reported success to a caller that then counted them.
 *
 * That is not a theoretical pairing. `CUpDownClient::SetSpammer(true)` calls
 * `Ban()` with no `IsBanned()` check, so a client banned for aggressiveness
 * and later flagged as a spammer reaches the add path twice for one banned
 * address.
 *
 * The tick is a parameter rather than a call to `GetTickCount64()`, so a ban
 * lapsing is a value passed in rather than four hours of waiting, which is
 * what makes the expiry rules testable at all.
 *
 * Keyed on the address rather than on a 32-bit integer, so an IPv6 peer can be
 * banned at all: a 32-bit key had no value that could name one, and a peer the
 * ban list cannot express is a peer that cannot be banned. The key comes from
 * PeerAddressing::IndexKey(), which is what makes a peer arriving as
 * 192.0.2.1 and later as ::ffff:192.0.2.1 one banned peer rather than two.
 */
class CBanRecord
{
public:
	/**
	 * How long a ban lasts, in milliseconds.
	 *
	 * An alias for the protocol constant rather than a second copy of the
	 * figure: expiry is decided in here, and a duration written twice is a
	 * rule two places are free to disagree about. The name exists so a test
	 * can express "one millisecond before the ban lapses" without repeating
	 * the number either.
	 *
	 * One boundary is settled here that the two callers used to answer
	 * differently. The sweep dropped an entry on `start + duration < now`
	 * while the lookup treated `start + duration > now` as still banned, so
	 * an entry at exactly `start + duration` survived a sweep and was then
	 * dropped by the next lookup. Both now lapse at that instant: a ban lasts
	 * for the duration and not one tick longer, which is the reading its name
	 * gives. That is a behaviour change, small and in one direction.
	 */
	static constexpr uint64 BAN_DURATION_MS = CLIENTBANTIME;

	/**
	 * Ban @p address, or refresh an existing ban.
	 *
	 * @return true only when the address was not already banned, so the
	 *         caller increments once per banned address rather than once per
	 *         call. A refresh still extends the ban; it is the count that
	 *         must not follow it.
	 *
	 * An address we do not have is refused outright: `CUpDownClient` holds
	 * an absent address until it has a socket, and a single entry under that
	 * key would make every such client read back as banned. Absence is the
	 * whole of the rule -- 0.0.0.0 and :: are odd addresses but they are
	 * addresses, and a peer claiming one is a peer whose claim we know.
	 */
	bool Ban(const CNetworkAddress &address, uint64 nowMs)
	{
		if (!PeerAddressing::IsIndexable(address)) {
			return false;
		}
		const CNetworkAddress key = PeerAddressing::IndexKey(address);
		const bool isNew = m_banned.find(key) == m_banned.end();
		m_banned[key] = nowMs;
		return isNew;
	}

	/**
	 * Lift the ban on @p address.
	 *
	 * @return true only when there was one to lift.
	 *
	 * Needs no absence guard: Ban() never inserts under an absent key, so
	 * erasing one removes nothing and answers false of its own accord.
	 */
	bool Unban(const CNetworkAddress &address)
	{
		return m_banned.erase(PeerAddressing::IndexKey(address)) != 0;
	}

	/**
	 * Whether @p address is banned as of @p nowMs.
	 *
	 * A lapsed ban is dropped here rather than reported and left behind, so
	 * the record cannot answer false for an address it still holds. @p
	 * dropped, when given, says whether this call removed such an entry --
	 * the caller has no other way to know it should decrement, since the
	 * removal happens inside a query.
	 */
	bool IsBanned(const CNetworkAddress &address, uint64 nowMs, bool *dropped = nullptr) const
	{
		if (dropped != nullptr) {
			*dropped = false;
		}
		if (!PeerAddressing::IsIndexable(address)) {
			return false;
		}
		BanMap::iterator it = m_banned.find(PeerAddressing::IndexKey(address));
		if (it == m_banned.end()) {
			return false;
		}
		if (it->second + BAN_DURATION_MS > nowMs) {
			return true;
		}
		m_banned.erase(it);
		if (dropped != nullptr) {
			*dropped = true;
		}
		return false;
	}

	/**
	 * Drop every ban that has lapsed as of @p nowMs.
	 *
	 * @return how many were dropped, so the caller can move its counter by
	 *         that much in one step.
	 *
	 * Needed because IsBanned() only reclaims an address somebody asks
	 * about: without a sweep, a table of peers that never came back would
	 * grow for as long as the process runs.
	 */
	std::size_t DropLapsed(uint64 nowMs)
	{
		std::size_t removed = 0;
		BanMap::iterator it = m_banned.begin();
		while (it != m_banned.end()) {
			// Post-increment before erasing: the iterator being erased is
			// invalidated, and the next one has to be in hand already.
			BanMap::iterator current = it++;
			if (current->second + BAN_DURATION_MS <= nowMs) {
				m_banned.erase(current);
				++removed;
			}
		}
		return removed;
	}

	//! How many addresses are banned. The figure the caller's statistic is
	//! meant to equal, which is what makes a test able to check the pairing.
	std::size_t Size() const { return m_banned.size(); }

	void Clear() { m_banned.clear(); }

private:
	typedef std::map<CNetworkAddress, uint64> BanMap;

	// Mutable so IsBanned() can stay const while reclaiming a lapsed entry:
	// dropping one changes no answer this record gives, and the alternative
	// is a non-const query that every caller has to hold a mutable reference
	// for.
	mutable BanMap m_banned;
};

#endif // BANRECORD_H
