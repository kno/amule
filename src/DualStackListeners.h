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

#ifndef DUALSTACKLISTENERS_H
#define DUALSTACKLISTENERS_H

#include "AddressFamilyPolicy.h"

#include <vector>

/**
 * Which listening sockets aMule tries to open, and what it says when one of
 * them cannot be opened.
 *
 * This is the decision half of dual-stack listening, kept apart from the socket
 * calls on purpose. Every case the spec names -- both families available, IPv6
 * unavailable, the platform refusing a dual-stack socket -- is a branch here,
 * and none of them is reachable in a test if the branch lives inside
 * CListenSocket's constructor: it would need a host that actually has that
 * network stack, or lacks it.
 *
 * The socket layer's job is reduced to executing an attempt and reporting
 * whether it worked. Which attempts to make, in which order, and how loudly to
 * complain, is all here.
 */
namespace DualStack
{

enum class EFamily
{
	IPv4,
	IPv6
};

/** The family word used in every bind and bind-failure log line. */
inline const char *FamilyName(EFamily family) noexcept
{
	return family == EFamily::IPv4 ? "IPv4" : "IPv6";
}

/**
 * One socket to open.
 *
 * @c servesBothFamilies marks the arrangement where a single IPv6 socket with
 * @c IPV6_V6ONLY off also accepts IPv4 peers, which arrive in IPv4-mapped form.
 * That is one socket, one port reservation and one acceptor for both families,
 * so it is what gets tried first -- but not every platform allows it (OpenBSD
 * refuses outright, and a Linux host can have @c net.ipv6.bindv6only set), so
 * it cannot be the only arrangement supported.
 */
struct SBindAttempt
{
	EFamily family = EFamily::IPv4;
	bool servesBothFamilies = false;
	//! Whether the socket must be opened with IPV6_V6ONLY on. Meaningless for
	//! an IPv4 socket and always false there.
	bool v6Only = false;
};

/** The ordered bind attempts for a configured family set. */
class CListenPlan
{
public:
	explicit CListenPlan(AddressFamilyPolicy::Families families) noexcept
	: m_families(families)
	{
	}

	/**
	 * What to try first. One socket under a single-family configuration, and
	 * under dual stack the one-socket-serves-both arrangement.
	 */
	std::vector<SBindAttempt> FirstAttempts() const
	{
		std::vector<SBindAttempt> attempts;
		switch (m_families) {
		case AddressFamilyPolicy::Families::IPv4Only:
			attempts.push_back(Attempt(EFamily::IPv4, false, false));
			break;
		case AddressFamilyPolicy::Families::IPv6Only:
			attempts.push_back(Attempt(EFamily::IPv6, false, true));
			break;
		case AddressFamilyPolicy::Families::DualStack:
			attempts.push_back(Attempt(EFamily::IPv6, true, false));
			break;
		}
		return attempts;
	}

	/**
	 * What to try when FirstAttempts() failed in a way that a different
	 * arrangement could survive -- i.e. the platform rejected the dual-stack
	 * socket. Empty for a single-family configuration: one family cannot be
	 * arranged a second way, and retrying the same socket is not a fallback.
	 */
	std::vector<SBindAttempt> FallbackAttempts() const
	{
		std::vector<SBindAttempt> attempts;
		if (m_families == AddressFamilyPolicy::Families::DualStack) {
			attempts.push_back(Attempt(EFamily::IPv4, false, false));
			// Restricted deliberately: with two sockets on the same port, an
			// unrestricted IPv6 socket would also claim mapped IPv4 traffic
			// and the two bindings would contend for it.
			attempts.push_back(Attempt(EFamily::IPv6, false, true));
		}
		return attempts;
	}

private:
	static SBindAttempt Attempt(EFamily family, bool both, bool v6Only) noexcept
	{
		SBindAttempt attempt;
		attempt.family = family;
		attempt.servesBothFamilies = both;
		attempt.v6Only = v6Only;
		return attempt;
	}

	AddressFamilyPolicy::Families m_families;
};

/**
 * Which families ended up listening, plus the once-per-family-per-start latch
 * for the failure log line.
 *
 * The latch is here rather than at the log call because the retry loop belongs
 * to the caller: the socket layer re-arms an accept, and a rebind after a
 * suspend/resume runs the same sequence again. A log line emitted per attempt
 * turns one unavailable family into a scrolling wall, which is exactly what the
 * spec forbids.
 */
class CListenerState
{
public:
	void Reset() noexcept
	{
		m_listening[Index(EFamily::IPv4)] = false;
		m_listening[Index(EFamily::IPv6)] = false;
		m_reported[Index(EFamily::IPv4)] = false;
		m_reported[Index(EFamily::IPv6)] = false;
	}

	/**
	 * Records a successful bind.
	 *
	 * @param servesBothFamilies True for the single unrestricted IPv6 socket,
	 *        which makes the client reachable on IPv4 as well even though no
	 *        IPv4 socket exists.
	 */
	void RecordBound(EFamily family, bool servesBothFamilies) noexcept
	{
		m_listening[Index(family)] = true;
		if (servesBothFamilies) {
			m_listening[Index(EFamily::IPv4)] = true;
			m_listening[Index(EFamily::IPv6)] = true;
		}
	}

	void RecordFailure(EFamily family) noexcept { m_listening[Index(family)] = false; }

	/**
	 * Whether this failure is the first for @a family since the last Reset(),
	 * and therefore the one that gets logged. Latches on the way out, so the
	 * caller can put it straight in an @c if.
	 */
	bool ShouldReportFailure(EFamily family) noexcept
	{
		if (m_reported[Index(family)]) {
			return false;
		}
		m_reported[Index(family)] = true;
		return true;
	}

	bool IsListening(EFamily family) const noexcept { return m_listening[Index(family)]; }

	bool IsAnyListening() const noexcept
	{
		return IsListening(EFamily::IPv4) || IsListening(EFamily::IPv6);
	}

	/**
	 * True only when no family is listening at all. This is the condition the
	 * "you will be LOWID" warning belongs to: the client MUST NOT report
	 * itself unreachable while either socket is listening.
	 */
	bool IsUnreachable() const noexcept { return !IsAnyListening(); }

private:
	static constexpr std::size_t Index(EFamily family) noexcept
	{
		return family == EFamily::IPv4 ? 0u : 1u;
	}

	bool m_listening[2] = { false, false };
	bool m_reported[2] = { false, false };
};

} // namespace DualStack

#endif // DUALSTACKLISTENERS_H
// File_checked_for_headers
