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

#ifndef IPFILTERRANGES_H
#define IPFILTERRANGES_H

#include <cstddef>
#include <cstdint>
#include <vector>

/**
 * The range-lookup half of CIPFilter::IsFiltered().
 *
 * Lifted out of CIPFilter verbatim so the matching contract can be pinned by a
 * unit test. CIPFilter itself is a wxEvtHandler that reads thePrefs and writes
 * theStats, so the search it performs was previously unobservable without a
 * running application -- and this search is precisely where a byte-order or
 * ordering mistake made while widening the address type would hide.
 *
 * Behaviour is unchanged, overflow and all. In particular @a hostOrderIP must
 * be in host (numeric) order -- the caller in IsFiltered() byte-swaps the
 * ed2k-order address it is given before calling in.
 *
 * @param rangeIPs      Range start addresses, host order, sorted ascending.
 * @param rangeLengths  Encoded range lengths, parallel to @a rangeIPs. A value
 *                      of 0x8000 or above is a compressed form: the low 15 bits
 *                      shifted up by 12 plus 0xfff.
 * @param hostOrderIP   The address to test, host (numeric) order.
 * @param matchIndex    Assigned the index of the matching range on success;
 *                      untouched on failure.
 * @return True if the address falls inside one of the ranges.
 */
inline bool IPFilterRangesContain(const std::vector<std::uint32_t> &rangeIPs,
	const std::vector<std::uint16_t> &rangeLengths, std::uint32_t hostOrderIP,
	std::size_t &matchIndex)
{
	int imin = 0;
	int imax = static_cast<int>(rangeIPs.size()) - 1;
	while (imin <= imax) {
		const int i = (imin + imax) / 2;
		const std::uint32_t curIP = rangeIPs[i];
		if (curIP <= hostOrderIP) {
			std::uint32_t curLength = rangeLengths[i];
			if (curLength >= 0x8000) {
				curLength = ((curLength & 0x7fff) << 12) + 0xfff;
			}
			if (curIP + curLength >= hostOrderIP) {
				matchIndex = static_cast<std::size_t>(i);
				return true;
			}
		}
		if (curIP > hostOrderIP) {
			imax = i - 1;
		} else {
			imin = i + 1;
		}
	}
	return false;
}

#endif // IPFILTERRANGES_H
// File_checked_for_headers
