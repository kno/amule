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

#ifndef QUICINBOUNDACCEPTOR_H
#define QUICINBOUNDACCEPTOR_H

#include "QuicContext.h" // Needed for IQuicConnectionAcceptor

/**
 * Where a validated QUIC connection becomes an ed2k client connection.
 *
 * The QUIC twin of CUtpInboundAcceptor, and it exists for the same two reasons:
 * this object existing is what lets the transport serve a peer at all, and it
 * needs theApp, CClientTCPSocket and the IP filter -- none of which
 * QuicLibraryAdapter.cpp may include, because that translation unit is the one
 * that sees ngtcp2's and GnuTLS's headers.
 *
 * The connection ends up in exactly the same place a TCP one does -- a
 * CClientTCPSocket in CListenSocket's socket list, counted in the same
 * statistics and subject to the same limits -- because as far as everything
 * above the socket is concerned there is one ed2k listener. See
 * CListenSocket::AcceptFrom(), whose admission tests this mirrors.
 *
 * One difference from the uTP acceptor is worth stating, because it changes what
 * the admission tests are for rather than merely when they run: a peer reaching
 * this function has already proved which ed2k identity it is. The IP filter, the
 * ban list and the socket limit are therefore not identity checks here -- the
 * proof was -- they are policy, and they are applied anyway because a peer being
 * who it says it is has never been a reason to exempt it from a ban.
 */
class CQuicInboundAcceptor : public IQuicConnectionAcceptor
{
public:
	/**
	 * Take a QUIC connection whose peer proof has validated.
	 *
	 * **This function does not own the connection.** Unlike the uTP acceptor,
	 * which is handed a `utp_socket *` it must close on every refusal, the
	 * connection here stays owned by the endpoint: a NULL return means refused,
	 * and the caller closes it. The asymmetry is libutp's -- utp_close() is not
	 * safe to call twice, so ownership had to move -- and ngtcp2 imposes no
	 * such rule, so the simpler ownership is the one to have.
	 *
	 * @return the transport now bound to the connection, or NULL when refused.
	 */
	CQuicSocketTransport *AcceptQuicConnection(
		IQuicStreamWriter *writer, const CNetworkAddress &from, std::uint16_t port) override;
};

#endif // QUICINBOUNDACCEPTOR_H
