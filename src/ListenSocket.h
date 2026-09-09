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

//
// Handling incoming connections (up or downloadrequests)
//

#ifndef LISTENSOCKET_H
#define LISTENSOCKET_H

#include "DualStackListeners.h" // Needed for DualStack::EFamily
#include "Proxy.h"              // Needed for CProxyData, CSocketServerProxy

#include <memory>
#include <set>

class CClientTCPSocket;
class CListenSocket;

/**
 * The second acceptor of a dual-stack ed2k listener.
 *
 * Exists only where one socket cannot serve both families -- either because the
 * platform refuses a dual-stack socket, or because the two families were bound
 * separately on purpose. It owns no state of its own: accepted connections go
 * into the same socket list, count towards the same connection limits and are
 * reported in the same statistics, because as far as everything above the
 * socket layer is concerned there is one ed2k listener.
 *
 * That is also why this is a separate class rather than a second CListenSocket:
 * a second CListenSocket would mean a second socket list, a second connection
 * counter and a second set of statistics, and every one of the two dozen
 * `theApp->listensocket->...` call sites would have to learn which of the two it
 * meant.
 */
class CListenSocketSecondary : public CSocketServerProxy
{
public:
	CListenSocketSecondary(amuleIPV4Address &addr, CListenSocket *owner, const CProxyData *ProxyData);
	void OnAccept();

private:
	CListenSocket *m_owner;
};

// CListenSocket command target
class CListenSocket : public CSocketServerProxy
{
public:
	CListenSocket(amuleIPV4Address &addr, const CProxyData *ProxyData = NULL);
	~CListenSocket();
	void OnAccept();

	/**
	 * Adds a second listening socket for the other address family.
	 *
	 * @return True when the second socket is listening. False leaves this
	 *         object exactly as it was: the family that did bind keeps working,
	 *         which is the whole point of falling back rather than failing.
	 */
	bool AddSecondaryListener(amuleIPV4Address &addr, const CProxyData *ProxyData = NULL);

	/** Accepts everything pending on @a server. Shared by both acceptors. */
	void AcceptFrom(CLibSocketServer &server);

	//! The family this object's own (primary) socket was bound in.
	DualStack::EFamily GetPrimaryFamily() const { return m_primaryFamily; }
	//! Whether the primary socket serves both families by itself.
	bool PrimaryServesBothFamilies() const { return m_primaryServesBoth; }
	bool HasSecondaryListener() const { return m_secondary != NULL; }

	/**
	 * Stops the second family's acceptor. Called on shutdown alongside
	 * Close(), which only closes this object's own socket -- an acceptor left
	 * armed would keep completing handshakes into a listener that is being
	 * torn down.
	 */
	void CloseSecondaryListener();

	void Process();
	void RemoveSocket(CClientTCPSocket *todel);
	void AddSocket(CClientTCPSocket *toadd);
	uint32 GetOpenSockets() { return socket_list.size(); }
	void KillAllSockets();
	bool TooManySockets(bool bIgnoreInterval = false);
	bool IsValidSocket(CClientTCPSocket *totest);
	void AddConnection();
	void RecalculateStats();
	void UpdateConnectionsStatus();

	float GetMaxConperFiveModifier();
	uint32 GetTotalConnectionChecks() { return totalconnectionchecks; }
	float GetAverageConnections() { return averageconnections; }

	bool OnShutdown() { return shutdown; }

private:
	typedef std::set<CClientTCPSocket *> SocketSet;
	SocketSet socket_list;

	bool shutdown;
	bool m_pending;
	//! The other family's acceptor, when one socket could not serve both.
	std::unique_ptr<CListenSocketSecondary> m_secondary;
	DualStack::EFamily m_primaryFamily;
	bool m_primaryServesBoth;

	uint16 m_OpenSocketsInterval;
	uint16 m_ConnectionStates[3];
	uint32 totalconnectionchecks;
	float averageconnections;
};

#endif // LISTENSOCKET_H
// File_checked_for_headers
