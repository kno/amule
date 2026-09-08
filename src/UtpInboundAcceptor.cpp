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

#include "UtpInboundAcceptor.h" // Interface declarations

#include "ClientList.h"         // Needed for CClientList
#include "ClientTCPSocket.h"    // Needed for CClientTCPSocket
#include "IPFilter.h"           // Needed for CIPFilter
#include "ListenSocket.h"       // Needed for CListenSocket
#include "Logger.h"             // Needed for AddDebugLogLineN
#include "Statistics.h"         // Needed for theStats
#include "UtpSocketTransport.h" // Needed for CUtpSocketTransport
#include "amule.h"              // Needed for theApp

#include <memory>

CUtpSocketTransport *CUtpInboundAcceptor::AcceptUtpConnection(
	CUtpContext &context, void *socket, const CNetworkAddress &from, std::uint16_t port)
{
	// Every refusal below happens before anything takes ownership of the
	// socket, so each one closes it here, exactly once. See the contract in
	// the header: after the transport exists, this function cannot fail.
	if (theApp == NULL || !theApp->IsRunning() || theApp->listensocket == NULL ||
		theApp->listensocket->OnShutdown()) {
		context.CloseSocket(socket);
		return nullptr;
	}

	// The same admission tests CListenSocket::AcceptFrom() and
	// CClientTCPSocket::InitNetworkData() apply, asked here rather than after
	// the socket exists. That ordering is what keeps the ownership rule
	// provable by reading this function: nothing can refuse the connection
	// once a CClientTCPSocket is holding it.
	if (!from.IsPresent() || from.IsUnspecified()) {
		context.CloseSocket(socket);
		return nullptr;
	}

	if (theApp->listensocket->TooManySockets()) {
		theStats::AddMaxConnectionLimitReached();
		context.CloseSocket(socket);
		return nullptr;
	}

	// Family-agnostic entry point, which normalises an IPv4-mapped address
	// before matching, exactly as the TCP accept path does.
	if (theApp->ipfilter != NULL && theApp->ipfilter->IsFiltered(from)) {
		AddDebugLogLineN(logClient,
			CFormat("Denied inbound uTP connection from %s (Filtered IP)") %
				wxString(from.ToString()));
		context.CloseSocket(socket);
		return nullptr;
	}

	if (theApp->clientlist != NULL && theApp->clientlist->IsBannedClient(from.Unmapped())) {
		AddDebugLogLineN(logClient,
			CFormat("Denied inbound uTP connection from %s (Banned IP)") %
				wxString(from.ToString()));
		context.CloseSocket(socket);
		return nullptr;
	}

	// Past this point the connection is taken. The transport is handed to the
	// socket, the socket registers itself in CListenSocket's list from its own
	// constructor, and from then on the connection is torn down by the same
	// paths that tear down a TCP one -- which is also what closes the
	// utp_socket, through ~CUtpSocketTransport.
	std::unique_ptr<CUtpSocketTransport> transport(new CUtpSocketTransport(context, from, port));
	// True: libutp completed the handshake before it called us, so this
	// connection is up on arrival. There is no UTP_STATE_CONNECT for an
	// accepted socket, and a transport that waited for one would refuse every
	// write for the life of the connection.
	transport->AttachSocket(socket, true);

	CUtpSocketTransport *taken = transport.get();
	CClientTCPSocket *newclient = new CClientTCPSocket();
	newclient->AttachUtpTransport(std::move(transport));
	newclient->InitNetworkData();

	// An inbound connection that got this far is the only thing that verifies
	// reachability on its family -- a bound socket proves nothing, because the
	// firewall in front of it may drop every packet. IPv4 unconditionally:
	// this transport carries nothing else yet
	// (CUtpContext::IsUsableEndpoint()).
	theApp->GetReachability().RecordInboundConnection(DualStack::EFamily::IPv4);

	AddDebugLogLineN(logClient,
		CFormat("Accepted inbound uTP connection from %s:%u") % wxString(from.ToString()) %
			(unsigned)port);

	return taken;
}
