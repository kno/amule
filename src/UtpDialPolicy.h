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

#ifndef UTPDIALPOLICY_H
#define UTPDIALPOLICY_H

#include <cstdint>

#include "NetworkAddress.h" // Needed for CNetworkAddress
#include "UtpContext.h"     // Needed for CUtpContext::IsUsableEndpoint

/**
 * Whether this peer is dialled over uTP, and -- when it is not -- whether
 * anything failed.
 *
 * A function rather than a few conditions inside CUpDownClient::Connect(),
 * because the case that matters is the one with no symptom. Almost every ed2k
 * peer does not advertise MOD_MISCOPT_NAT_TRAVERSAL, and for every one of them
 * the connection must be the connection aMule made before uTP existed: no uTP
 * attempt, and no transport failure recorded. Recording one anyway would not
 * break the dial -- the fallback still reaches TCP -- it would change what
 * happens to the peer afterwards, because both CUpDownClient::Connect() and
 * ::Disconnected() branch on the transport state. A peer that never had
 * anything to do with uTP would stop being blamed for its own failures, and the
 * only trace would be sources that behave slightly differently for no reason
 * anyone can find.
 *
 * The mirror rule is the one the spec delta states: every reason *this end*
 * cannot use uTP for a peer that did advertise it is a transport failure, never
 * the peer's fault. See UtpTransportFailure.h.
 */

//! Why the dial went the way it did. Recorded so a log line can name the
//! reason rather than saying "uTP unavailable" for four different situations.
enum EUtpDialRefusal
{
	//! uTP is on the table and being dialled.
	UTP_DIAL_ATTEMPT,
	//! The peer never claimed uTP. Nothing was attempted, so nothing failed:
	//! this is the ordinary ed2k peer and the pre-uTP TCP path.
	UTP_DIAL_PEER_DOES_NOT_ADVERTISE_UTP,
	//! No uTP context: libutp is not in this build, or the context could not
	//! be created. A property of our side of the path.
	UTP_DIAL_NO_CONTEXT,
	//! This socket is configured to reach peers through a proxy. uTP is
	//! carried over the ed2k UDP socket and negotiates nothing with a SOCKS or
	//! HTTP proxy, so dialling it here would send a SYN the proxy was never
	//! told about.
	UTP_DIAL_PROXY_IN_USE,
	//! The peer's address is not one this transport carries yet -- IPv4 only
	//! for now -- or there is no address at all.
	UTP_DIAL_ADDRESS_FAMILY_NOT_CARRIED
};

/**
 * What the connection path does with a peer.
 *
 * The two flags are never both set: `attemptUtp` means an attempt is in flight
 * and will report its own outcome, and recording a failure at the same time
 * would have Connect() fall back to TCP underneath a live uTP dial.
 */
struct SUtpDialDecision
{
	//! Dial uTP. The caller must not also dial TCP.
	bool attemptUtp = false;
	//! Report a transport failure before falling back to TCP, so the peer is
	//! not blamed for something that is ours.
	bool recordTransportFailure = false;
	EUtpDialRefusal refusal = UTP_DIAL_PEER_DOES_NOT_ADVERTISE_UTP;
};

/**
 * Decide how to dial one peer.
 *
 * @param peerAdvertisesUtp  the peer's MOD_MISCOPT_NAT_TRAVERSAL bit, i.e.
 *        CPeerModCapabilities::SupportsNatTraversal().
 * @param contextAvailable   CUtpContext::IsAvailable(): false in every build
 *        configured with -DENABLE_UTP=NO, which is the default.
 * @param proxyInUse  CProxySocket::GetUseProxy() on the socket about to dial.
 * @param peer  the address about to be dialled.
 */
inline SUtpDialDecision DecideUtpDial(
	bool peerAdvertisesUtp, bool contextAvailable, bool proxyInUse, const CNetworkAddress &peer)
{
	SUtpDialDecision decision;

	if (!peerAdvertisesUtp) {
		// The ordinary ed2k peer. Both flags stay false, which is what keeps
		// this connection byte-for-byte the one that predates uTP.
		decision.refusal = UTP_DIAL_PEER_DOES_NOT_ADVERTISE_UTP;
		return decision;
	}

	if (!contextAvailable) {
		decision.recordTransportFailure = true;
		decision.refusal = UTP_DIAL_NO_CONTEXT;
		return decision;
	}

	// A proxy is a TCP relay the peer's uTP SYN would never reach: uTP rides
	// the ed2k UDP socket and negotiates nothing with SOCKS or HTTP CONNECT.
	// Ours, not the peer's -- the user configured the proxy.
	if (proxyInUse) {
		decision.recordTransportFailure = true;
		decision.refusal = UTP_DIAL_PROXY_IN_USE;
		return decision;
	}

	// The family rule is read from the context rather than restated here, so
	// enabling IPv6 uTP later is still a change to one predicate.
	if (!CUtpContext::IsUsableEndpoint(peer)) {
		decision.recordTransportFailure = true;
		decision.refusal = UTP_DIAL_ADDRESS_FAMILY_NOT_CARRIED;
		return decision;
	}

	decision.attemptUtp = true;
	decision.refusal = UTP_DIAL_ATTEMPT;
	return decision;
}

#endif // UTPDIALPOLICY_H
