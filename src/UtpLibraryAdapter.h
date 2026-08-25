//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2026 aMule Team ( https://amule-org.github.io )
//
// The callback wiring follows eMule AI's CUtpSocket:
// Copyright (C) 2013 David Xanatos ( XanatosDavid (a) gmail.com / http://NeoLoader.to )
// Copyright (C) 2026 eMule AI
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

#ifndef UTPLIBRARYADAPTER_H
#define UTPLIBRARYADAPTER_H

#include "UtpContext.h" // Needed for IUtpLibrary

/**
 * The only place that calls libutp.
 *
 * Everything above this file -- CUtpContext, CUtpStream, the write-buffer
 * policy, the datagram routing -- is ordinary C++ that compiles and is unit
 * tested with no libutp present. That is deliberate: uTP is opt-in
 * (-DENABLE_UTP, off by default), so a build without it has to be a build with
 * no uTP rather than a build that does not compile. libutp itself is vendored
 * at src/extern/libutp -- see cmake/libutp.cmake.
 *
 * Without AMULE_UTP_TRANSPORT every method here is inert and CUtpContext is
 * simply never configured with one, which is the -DENABLE_UTP=NO build.
 *
 * libutp's headers appear in UtpLibraryAdapter.cpp and nowhere else, and this
 * declaration is deliberately free of them. That is not tidiness: libutp's
 * utp_types.h defines `int64` as int64_t and `byte` as unsigned char at global
 * scope, while aMule's Types.h defines `int64` as uint64_t and one aMule header
 * pulls in `using namespace std` (so `byte` collides with std::byte too). The
 * two sets of typedefs cannot coexist in one translation unit in either order,
 * so exactly one translation unit sees libutp's -- and it sees none of aMule's.
 *
 * Addresses cross this boundary through CNetworkAddress's host-order accessors
 * and htonl/ntohl rather than by reinterpreting a uint32, so the conversion
 * carries no endianness assumption.
 */
class CUtpLibraryAdapter : public IUtpLibrary
{
public:
	//! @param owner the context whose sink outbound datagrams go through.
	//! libutp's sendto callback has no argument for it, so it travels as the
	//! utp_context's user data.
	explicit CUtpLibraryAdapter(CUtpContext *owner)
	: m_owner(owner)
	{
	}

	void *CreateContext() override;
	void DestroyContext(void *context) override;
	bool ProcessDatagram(void *context,
		const std::uint8_t *payload,
		std::size_t length,
		const CNetworkAddress &from,
		std::uint16_t port) override;
	bool AcceptsInboundConnections(void *context) const override;
	void IssueDeferredAcks(void *context) override;
	void CheckTimeouts(void *context) override;
	long WriteToSocket(void *socket, const std::uint8_t *data, std::size_t length) override;
	void *CreateOutboundSocket(
		void *context, void *userData, const CNetworkAddress &to, std::uint16_t port) override;
	void CloseSocket(void *socket) override;
	void NotifyReadDrained(void *socket) override;

private:
	CUtpContext *m_owner = nullptr;

	/**
	 * Whether CreateContext() registered UTP_ON_ACCEPT on the context it
	 * built. Set at the point of registration and nowhere else, so it cannot
	 * claim an accept path that is not there. The registration itself follows
	 * whether the owning context has an acceptor
	 * (CUtpContext::HasInboundAcceptor()): libutp answers an inbound SYN as
	 * soon as the callback exists, so registering it with nowhere to put the
	 * connection would complete a handshake and then drop it.
	 *
	 * Read through AcceptsInboundConnections(), which is what decides whether
	 * this client advertises MOD_MISCOPT_NAT_TRAVERSAL. A libutp-free bool
	 * rather than a query on the utp_context: libutp exposes no getter for a
	 * registered callback, and this header must stay free of its types.
	 */
	bool m_acceptsInboundConnections = false;
};

#endif // UTPLIBRARYADAPTER_H
