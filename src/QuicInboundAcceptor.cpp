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

#include "QuicInboundAcceptor.h" // Interface declarations

#include "ClientList.h"          // Needed for CClientList
#include "ClientTCPSocket.h"     // Needed for CClientTCPSocket
#include "IPFilter.h"            // Needed for CIPFilter
#include "ListenSocket.h"        // Needed for CListenSocket
#include "Logger.h"              // Needed for AddDebugLogLineN
#include "QuicSocketTransport.h" // Needed for CQuicSocketTransport
#include "Statistics.h"          // Needed for theStats
#include "amule.h"               // Needed for theApp

#include <memory>

CQuicSocketTransport *CQuicInboundAcceptor::AcceptQuicConnection(
	IQuicStreamWriter *writer, const CNetworkAddress &from, std::uint16_t port)
{
	if (writer == NULL) {
		return NULL;
	}

	if (theApp == NULL || !theApp->IsRunning() || theApp->listensocket == NULL ||
		theApp->listensocket->OnShutdown()) {
		return NULL;
	}

	// The same admission tests CListenSocket::AcceptFrom() and
	// CClientTCPSocket::InitNetworkData() apply, asked before anything is
	// constructed. That ordering is what keeps this function's ownership rule
	// provable by reading it: nothing can refuse the connection once a
	// CClientTCPSocket is holding the transport.
	//
	// Applied even though the peer has already proved its ed2k identity: a peer
	// being who it says it is has never been a reason to exempt it from a ban,
	// and the socket limit is about this end's resources rather than about the
	// peer at all.
	if (!from.IsPresent() || from.IsUnspecified()) {
		return NULL;
	}

	if (theApp->listensocket->TooManySockets()) {
		theStats::AddMaxConnectionLimitReached();
		return NULL;
	}

	// Family-agnostic entry point, which normalises an IPv4-mapped address
	// before matching, exactly as the TCP accept path does.
	if (theApp->ipfilter != NULL && theApp->ipfilter->IsFiltered(from)) {
		AddDebugLogLineN(logClient,
			CFormat("Denied inbound QUIC connection from %s (Filtered IP)") %
				wxString(from.ToString()));
		return NULL;
	}

	if (theApp->clientlist != NULL && theApp->clientlist->IsBannedClient(from.Unmapped())) {
		AddDebugLogLineN(logClient,
			CFormat("Denied inbound QUIC connection from %s (Banned IP)") %
				wxString(from.ToString()));
		return NULL;
	}

	// Past this point the connection is taken. The transport is handed to the
	// socket, the socket registers itself in CListenSocket's list from its own
	// constructor, and from then on the connection is torn down by the same
	// paths that tear down a TCP one.
	std::unique_ptr<CQuicSocketTransport> transport(new CQuicSocketTransport(from, port));
	// Connected on arrival. A QUIC connection reaches this function only after
	// its handshake completed and its peer proof validated, so there is no state
	// left to wait for -- and a transport that waited for one would refuse every
	// write for the life of the connection.
	transport->AttachWriter(writer);

	CQuicSocketTransport *taken = transport.get();
	CClientTCPSocket *newclient = new CClientTCPSocket();
	newclient->AttachQuicTransport(std::move(transport));
	newclient->InitNetworkData();

	// An inbound connection that got this far is the only thing that verifies
	// reachability on its family -- a bound socket proves nothing, because the
	// firewall in front of it may drop every packet. IPv4 unconditionally: this
	// transport carries nothing else yet
	// (CQuicContext::IsUsableEndpointAddress()).
	theApp->GetReachability().RecordInboundConnection(DualStack::EFamily::IPv4);

	AddDebugLogLineN(logClient,
		CFormat("Accepted an authenticated inbound QUIC connection from %s:%u") %
			wxString(from.ToString()) % (unsigned)port);

	return taken;
}
