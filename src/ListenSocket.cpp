//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2026 aMule Team ( https://amule-org.github.io )
// Copyright (c) 2002-2011 Merkur ( devs@emule-project.net / http://www.emule-project.net )
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

#include "ListenSocket.h" // Interface declarations

#include <common/EventIDs.h>

#include "ClientTCPSocket.h" // Needed for CClientRequestSocket
#include "Logger.h"          // Needed for AddLogLineM
#include "Statistics.h"      // Needed for theStats
#include "Preferences.h"     // Needed for CPreferences
#include "amule.h"           // Needed for theApp
#include "ServerConnect.h"   // Needed for CServerConnect

//-----------------------------------------------------------------------------
// CListenSocket
//-----------------------------------------------------------------------------
//
// This is the socket that listens to incoming connections in aMule's TCP port
// As soon as a connection is detected, it creates a new socket of type
// CClientTCPSocket to handle (accept) the connection.
//

CListenSocketSecondary::CListenSocketSecondary(
	amuleIPV4Address &addr, CListenSocket *owner, const CProxyData *ProxyData)
: CSocketServerProxy(addr, MULE_SOCKET_NOWAIT | MULE_SOCKET_REUSEADDR, ProxyData)
, m_owner(owner)
{
}

void CListenSocketSecondary::OnAccept()
{
	// Straight through to the owner: connection limits, the socket list and the
	// statistics are all one listener's, whichever family the peer arrived on.
	m_owner->AcceptFrom(*this);
}

CListenSocket::CListenSocket(amuleIPV4Address &addr, const CProxyData *ProxyData)
: // wxSOCKET_NOWAIT    - means non-blocking i/o
  // wxSOCKET_REUSEADDR - means we can reuse the socket immediately (wx-2.5.3)
	CSocketServerProxy(addr, MULE_SOCKET_NOWAIT | MULE_SOCKET_REUSEADDR, ProxyData)
{
	// 0.42e - vars not used by us
	m_pending = false;
	shutdown = false;
	m_OpenSocketsInterval = 0;
	totalconnectionchecks = 0;
	averageconnections = 0.0;
	memset(m_ConnectionStates, 0, 3 * sizeof(m_ConnectionStates[0]));
	const CNetworkAddress bound = addr.GetAddress();
	m_primaryFamily = bound.IsIPv6() ? DualStack::EFamily::IPv6 : DualStack::EFamily::IPv4;
	// An IPv6 socket with IPV6_V6ONLY off accepts IPv4 peers too, in mapped
	// form, so it is the whole listener on its own.
	m_primaryServesBoth = bound.IsIPv6() && !addr.IsV6Only();
	// Set the listen socket event handler -- The handler is written in amule.cpp
	if (IsOk()) {
		Notify(true);

		// One line per family, naming the family and the address, because
		// "which families came up" is the observable outcome of dual-stack
		// listening and the old "ListenSocket: Ok." could not say it. Two
		// whole sentences rather than one with an appended fragment: a
		// translator needs the sentence, not a comma and a clause.
		if (m_primaryServesBoth) {
			AddLogLineNS(CFormat(_("ListenSocket: listening on %s (IPv6, also accepting "
					       "IPv4 peers in mapped form).")) %
				     addr.IPAddress());
		} else {
			AddLogLineNS(CFormat(_("ListenSocket: listening on %s (%s).")) % addr.IPAddress() %
				     DualStack::FamilyName(m_primaryFamily));
		}
	} else {
		// Debug only. Which arrangements were attempted is implementation
		// detail -- the first attempt failing is how the fallback is reached,
		// not an error the user can act on -- and the user-visible report is
		// owned by CamuleApp::LogBindFailure(), which emits one line per
		// family per start however many sockets hit the same missing stack.
		AddDebugLogLineN(logGeneral,
			CFormat("CListenSocket could not bind %s (%s)") % addr.IPAddress() %
				DualStack::FamilyName(m_primaryFamily));
	}
}

bool CListenSocket::AddSecondaryListener(amuleIPV4Address &addr, const CProxyData *ProxyData)
{
	std::unique_ptr<CListenSocketSecondary> secondary(new CListenSocketSecondary(addr, this, ProxyData));
	const CNetworkAddress bound = addr.GetAddress();
	const DualStack::EFamily family =
		bound.IsIPv6() ? DualStack::EFamily::IPv6 : DualStack::EFamily::IPv4;
	if (!secondary->IsOk()) {
		// Not fatal, and deliberately not retried: the family that did bind
		// keeps working. The caller owns the one log line this failure gets.
		return false;
	}
	secondary->Notify(true);
	m_secondary = std::move(secondary);
	AddLogLineNS(CFormat(_("ListenSocket: listening on %s (%s).")) % addr.IPAddress() %
		     DualStack::FamilyName(family));
	return true;
}

CListenSocket::~CListenSocket()
{
	shutdown = true;
	Discard();
	Close();
	if (m_secondary) {
		m_secondary->Close();
		m_secondary.reset();
	}

#ifdef __DEBUG__
	// No new sockets should have been opened by now
	for (SocketSet::iterator it = socket_list.begin(); it != socket_list.end(); ++it) {
		wxASSERT((*it)->IsDestroying());
	}
#endif

	KillAllSockets();
}

void CListenSocket::CloseSecondaryListener()
{
	if (m_secondary) {
		m_secondary->Close();
	}
}

void CListenSocket::OnAccept()
{
	AcceptFrom(*this);
}

void CListenSocket::AcceptFrom(CLibSocketServer &server)
{
	m_pending = theApp->IsRunning(); // just do nothing if we are shutting down
	// If the client is still at maxconnections,
	// this will allow it to go above it ...
	// But if you don't, you will get a lowID on all servers.
	while (m_pending && (theApp->serverconnect->IsConnecting() || !TooManySockets())) {
		if (!server.SocketAvailable()) {
			m_pending = false;
		} else {
			// Create a new socket to deal with the connection
			CClientTCPSocket *newclient = new CClientTCPSocket();
			// Accept the connection and give it to the newly created socket
			if (!server.AcceptWith(*newclient, false)) {
				newclient->Safe_Delete();
				m_pending = false;
			} else {
				// The family is read from the accepted connection itself,
				// not from the acceptor it came through: one unrestricted
				// IPv6 socket serves both families, so the acceptor cannot
				// answer this.
				const CNetworkAddress peer = newclient->GetPeerAddress();
				if (!newclient->InitNetworkData()) {
					// IP or port were not returned correctly
					// from the accepted address, or filtered.
					newclient->Safe_Delete();
				} else if (peer.IsPresent()) {
					// An inbound connection that got this far is the only
					// thing that verifies reachability on its family. A
					// bound socket proves nothing: the firewall in front
					// of it may drop every packet. Mapped peers count as
					// IPv4, which is what they are.
					const bool nativeIPv6 = peer.IsIPv6() && !peer.IsIPv4Mapped();
					// Read before recording: the log line below is for the
					// connection that turned IPv6 from "listening" into
					// "verified", once, not for every IPv6 peer thereafter.
					const bool wasVerified = theApp->GetReachability().IsVerified(
						DualStack::EFamily::IPv6);
					theApp->GetReachability().RecordInboundConnection(
						nativeIPv6 ? DualStack::EFamily::IPv6
							   : DualStack::EFamily::IPv4);
					if (nativeIPv6) {
						// Where the peer reached us. Only a globally
						// routable address is kept, and only from a
						// native IPv6 peer: a mapped-IPv4 connection
						// lands on a mapped local address, which says
						// nothing about IPv6 reachability.
						const CNetworkAddress localAddress =
							newclient->GetLocalAddress();
						theApp->SetVerifiedIPv6Address(localAddress);
						if (!wasVerified) {
							AddLogLineNS(CFormat(_("Inbound IPv6 connection from "
									       "%s on %s.")) %
								     wxString(peer.ToString()) %
								     wxString(localAddress.ToString()));
						}
					}
				}
			}
		}
	}
	if (m_pending) {
		theStats::AddMaxConnectionLimitReached();
	}
}

void CListenSocket::AddConnection()
{
	m_OpenSocketsInterval++;
}

void CListenSocket::Process()
{
	// 042e + Kry changes for Destroy
	m_OpenSocketsInterval = 0;
	SocketSet::iterator it = socket_list.begin();
	while (it != socket_list.end()) {
		CClientTCPSocket *cur_socket = *it++;
		if (!cur_socket->IsDestroying()) {
			cur_socket->CheckTimeOut();
		}
	}

	// SocketAvailable() as well as m_pending: the socket layer arms one
	// async accept at a time and only re-arms it from AcceptWith(), so a
	// connection it accepted but we then declined to take -- OnAccept()
	// bails out when the app is not running yet -- leaves the acceptor
	// idle with m_pending clear. Nothing would ever call AcceptWith()
	// again and the listen socket would stay deaf for the rest of the
	// session, with the kernel still completing handshakes into a backlog
	// no one reads. Taking it here re-arms the acceptor.
	if (m_pending || SocketAvailable()) {
		AcceptFrom(*this);
	}
	// The second family's acceptor is polled for exactly the same reason: it
	// arms one async accept at a time and only re-arms it from AcceptWith().
	if (m_secondary && m_secondary->SocketAvailable()) {
		AcceptFrom(*m_secondary);
	}
}

void CListenSocket::RecalculateStats()
{
	// 0.42e
	memset(m_ConnectionStates, 0, 3 * sizeof(m_ConnectionStates[0]));
	for (SocketSet::iterator it = socket_list.begin(); it != socket_list.end();) {
		CClientTCPSocket *cur_socket = *it++;
		switch (cur_socket->GetConState()) {
		case ES_DISCONNECTED:
			m_ConnectionStates[0]++;
			break;
		case ES_NOTCONNECTED:
			m_ConnectionStates[1]++;
			break;
		case ES_CONNECTED:
			m_ConnectionStates[2]++;
			break;
		}
	}
}

void CListenSocket::AddSocket(CClientTCPSocket *toadd)
{
	wxASSERT(toadd);
	socket_list.insert(toadd);
	theStats::AddActiveConnection();
}

void CListenSocket::RemoveSocket(CClientTCPSocket *todel)
{
	wxASSERT(todel);
	socket_list.erase(todel);
	theStats::RemoveActiveConnection();
}

void CListenSocket::KillAllSockets()
{
	// 0.42e reviewed - they use delete, but our safer is Destroy...
	// But I bet it would be better to call Safe_Delete on the socket.
	// Update: no... Safe_Delete MARKS for deletion. We need to delete it.
	for (SocketSet::iterator it = socket_list.begin(); it != socket_list.end();) {
		CClientTCPSocket *cur_socket = *it++;
		if (cur_socket->GetClient()) {
			cur_socket->Safe_Delete_Client();
		} else {
			cur_socket->Safe_Delete();
			cur_socket->Destroy();
		}
	}
}

bool CListenSocket::TooManySockets(bool bIgnoreInterval)
{
	if (GetOpenSockets() > thePrefs::GetMaxConnections() ||
		(!bIgnoreInterval && m_OpenSocketsInterval >
					     (thePrefs::GetMaxConperFive() * GetMaxConperFiveModifier()))) {
		return true;
	} else {
		return false;
	}
}

bool CListenSocket::IsValidSocket(CClientTCPSocket *totest)
{
	// 0.42e
	return socket_list.find(totest) != socket_list.end();
}

void CListenSocket::UpdateConnectionsStatus()
{
	// 0.42e xcept for the khaos stats
	if (theApp->IsConnected()) {
		totalconnectionchecks++;
		float percent;
		percent = (float)(totalconnectionchecks - 1) / (float)totalconnectionchecks;
		if (percent > .99f) {
			percent = .99f;
		}
		averageconnections =
			(averageconnections * percent) + (float)GetOpenSockets() * (1.0f - percent);
	}
}

float CListenSocket::GetMaxConperFiveModifier()
{
	float SpikeSize = GetOpenSockets() - averageconnections;
	if (SpikeSize < 1) {
		return 1;
	}

	float SpikeTolerance = 2.5f * thePrefs::GetMaxConperFive();
	if (SpikeSize > SpikeTolerance) {
		return 0;
	}

	return 1.0f - (SpikeSize / SpikeTolerance);
}
// File_checked_for_headers
