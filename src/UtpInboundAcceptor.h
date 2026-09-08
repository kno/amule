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

#ifndef UTPINBOUNDACCEPTOR_H
#define UTPINBOUNDACCEPTOR_H

#include "UtpContext.h" // Needed for IUtpConnectionAcceptor

/**
 * Where an inbound uTP connection becomes an ed2k client connection.
 *
 * This object existing is what lets this end serve uTP at all, and therefore
 * what lets it honestly advertise MOD_MISCOPT_NAT_TRAVERSAL: libutp registers
 * UTP_ON_ACCEPT only when the context has an acceptor
 * (CUtpLibraryAdapter::CreateContext), and without that callback it drops every
 * inbound uTP connection outright.
 *
 * The connection ends up in exactly the same place a TCP one does -- a
 * CClientTCPSocket in CListenSocket's socket list, counted in the same
 * statistics and subject to the same limits -- because as far as everything
 * above the socket is concerned there is one ed2k listener. See
 * CListenSocket::AcceptFrom(), whose admission tests this mirrors.
 */
class CUtpInboundAcceptor : public IUtpConnectionAcceptor
{
public:
	/**
	 * Take an inbound uTP connection.
	 *
	 * **This function owns `socket` from the moment it is called.** A NULL
	 * return means the connection was refused and the socket has already been
	 * closed, or handed to an object that will close it; the caller must not
	 * close it again. libutp's utp_close() is not safe to call twice on the
	 * same socket, and splitting the ownership between the two would make that
	 * a matter of which refusal path was taken.
	 *
	 * @return the transport that now owns the connection, or NULL when it was
	 *         refused.
	 */
	CUtpSocketTransport *AcceptUtpConnection(
		CUtpContext &context, void *socket, const CNetworkAddress &from, std::uint16_t port) override;
};

#endif // UTPINBOUNDACCEPTOR_H
