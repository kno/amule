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

// libutp's headers first and alone. See the note in UtpLibraryAdapter.h: this
// translation unit must not pull in aMule's Types.h (conflicting `int64`) nor
// any header that does `using namespace std` (ambiguous `byte`). UtpContext.h
// and NetworkAddress.h are safe -- they include only <cstdint>, <optional>,
// <string> and Boost.Asio's address type.

#ifdef AMULE_UTP_TRANSPORT
#include <libutp/utp.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#endif // AMULE_UTP_TRANSPORT

#include "UtpLibraryAdapter.h"

#ifdef AMULE_UTP_TRANSPORT

namespace
{

bool ToSockAddr(const CNetworkAddress &address, std::uint16_t port, sockaddr_in &out)
{
	std::uint32_t hostOrder = 0;
	if (!address.ToIPv4HostOrder(hostOrder)) {
		return false;
	}

	out = sockaddr_in();
	out.sin_family = AF_INET;
	out.sin_port = htons(port);
	out.sin_addr.s_addr = htonl(hostOrder);
	return true;
}

//! libutp wants to put a datagram on the wire. It goes out through the ed2k UDP
//! socket, wrapped in the 0xB2/0x00 frame by the sink, so that uTP and ed2k UDP
//! share one port and one NAT mapping.
std::uint64_t OnSendTo(utp_callback_arguments *arguments)
{
	if (arguments == nullptr || arguments->address == nullptr) {
		return 0;
	}

	CUtpContext *owner = static_cast<CUtpContext *>(utp_context_get_userdata(arguments->context));
	if (owner == nullptr) {
		return 0;
	}

	if (arguments->address->sa_family != AF_INET) {
		// IPv4 only for now; see CUtpContext::IsUsableEndpoint.
		return 0;
	}

	const sockaddr_in *peer = reinterpret_cast<const sockaddr_in *>(arguments->address);
	owner->SendDatagram(arguments->buf,
		arguments->len,
		CNetworkAddress::FromIPv4HostOrder(ntohl(peer->sin_addr.s_addr)),
		ntohs(peer->sin_port));
	return 0;
}

} // namespace

void *CUtpLibraryAdapter::CreateContext()
{
	utp_context *context = utp_init(2);
	if (context == nullptr) {
		return nullptr;
	}

	utp_context_set_userdata(context, m_owner);
	utp_set_callback(context, UTP_SENDTO, &OnSendTo);

	// UTP_ON_ACCEPT is deliberately not registered yet: there is no
	// established dial to hand an accepted connection to, because substituting
	// CUtpStream under CClientTCPSocket is still open (task 3.1). libutp drops
	// an inbound connection outright when this callback is absent, so until it
	// is registered this end cannot serve a uTP connection -- and must not
	// advertise MOD_MISCOPT_NAT_TRAVERSAL, or peers spend attempts on a client
	// that discards them with nothing logged on either side.
	//
	// Whoever registers it sets this flag in the same breath. The registration
	// and the claim are one fact and must not be able to disagree.
	m_acceptsInboundConnections = false;

	return context;
}

bool CUtpLibraryAdapter::AcceptsInboundConnections(void *context) const
{
	return context != nullptr && m_acceptsInboundConnections;
}

void CUtpLibraryAdapter::DestroyContext(void *context)
{
	if (context != nullptr) {
		utp_destroy(static_cast<utp_context *>(context));
	}
}

bool CUtpLibraryAdapter::ProcessDatagram(void *context,
	const std::uint8_t *payload,
	std::size_t length,
	const CNetworkAddress &from,
	std::uint16_t port)
{
	if (context == nullptr) {
		return false;
	}

	sockaddr_in peer;
	if (!ToSockAddr(from, port, peer)) {
		return false;
	}

	return utp_process_udp(static_cast<utp_context *>(context),
		       payload,
		       length,
		       reinterpret_cast<const sockaddr *>(&peer),
		       sizeof(peer)) != 0;
}

void CUtpLibraryAdapter::IssueDeferredAcks(void *context)
{
	if (context != nullptr) {
		utp_issue_deferred_acks(static_cast<utp_context *>(context));
	}
}

void CUtpLibraryAdapter::CheckTimeouts(void *context)
{
	if (context != nullptr) {
		utp_check_timeouts(static_cast<utp_context *>(context));
	}
}

long CUtpLibraryAdapter::WriteToSocket(void *socket, const std::uint8_t *data, std::size_t length)
{
	if (socket == nullptr) {
		return -1;
	}

	// utp_write takes a non-const pointer but does not modify the buffer; the
	// cast is the library's signature, not a licence.
	return (long)utp_write(static_cast<utp_socket *>(socket), const_cast<std::uint8_t *>(data), length);
}

#else // !AMULE_UTP_TRANSPORT

// No libutp in this build. Inert rather than absent, so the call sites above
// stay one shape and the compiler still checks them.

void *CUtpLibraryAdapter::CreateContext()
{
	return nullptr;
}

void CUtpLibraryAdapter::DestroyContext(void *)
{
}

bool CUtpLibraryAdapter::AcceptsInboundConnections(void *) const
{
	// No libutp, so nothing can be accepted and nothing is advertised.
	return false;
}

bool CUtpLibraryAdapter::ProcessDatagram(
	void *, const std::uint8_t *, std::size_t, const CNetworkAddress &, std::uint16_t)
{
	return false;
}

void CUtpLibraryAdapter::IssueDeferredAcks(void *)
{
}

void CUtpLibraryAdapter::CheckTimeouts(void *)
{
}

long CUtpLibraryAdapter::WriteToSocket(void *, const std::uint8_t *, std::size_t)
{
	return -1;
}

#endif // AMULE_UTP_TRANSPORT
