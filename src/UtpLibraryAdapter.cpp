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
// Both are free of aMule's Types.h and of `using namespace std`, so they are
// includable here: UtpSocketTransport.h is the shim's own header-only code, and
// UtpDatagramRouting.h reaches only protocol/Protocols.h, which is #defines.
#include "UtpDatagramRouting.h" // Needed for UTP_FRAME_HEADER_LENGTH
#include "UtpSocketTransport.h" // Needed for CUtpSocketTransport

#ifdef AMULE_UTP_TRANSPORT

#include <chrono>
#include <cstdlib>

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

//! The context that owns a callback's context, or NULL.
CUtpContext *OwnerOf(utp_callback_arguments *arguments)
{
	if (arguments == nullptr || arguments->context == nullptr) {
		return nullptr;
	}
	return static_cast<CUtpContext *>(utp_context_get_userdata(arguments->context));
}

//! The transport that owns a callback's socket, or NULL. NULL is the ordinary
//! case for a connection whose owner has gone away: CloseSocket() clears the
//! user data before utp_close(), precisely so the callbacks libutp still fires
//! while it flushes have nothing to dereference.
CUtpSocketTransport *TransportOf(utp_callback_arguments *arguments)
{
	if (arguments == nullptr || arguments->socket == nullptr) {
		return nullptr;
	}
	return static_cast<CUtpSocketTransport *>(utp_get_userdata(arguments->socket));
}

//! libutp wants to put a datagram on the wire. It goes out through the ed2k UDP
//! socket, wrapped in the 0xB2/0x00 frame by the sink, so that uTP and ed2k UDP
//! share one port and one NAT mapping.
std::uint64_t OnSendTo(utp_callback_arguments *arguments)
{
	if (arguments == nullptr || arguments->address == nullptr) {
		return 0;
	}

	CUtpContext *owner = OwnerOf(arguments);
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

/**
 * An inbound uTP connection. This callback existing is what makes this end able
 * to serve one at all: without it libutp answers nothing and drops the SYN.
 *
 * libutp has already completed the handshake by the time this runs, so refusing
 * here costs the peer a round trip. That is why the callback is registered only
 * when the context has an acceptor -- see CUtpLibraryAdapter::CreateContext().
 */
std::uint64_t OnAccept(utp_callback_arguments *arguments)
{
	CUtpContext *owner = OwnerOf(arguments);
	if (owner == nullptr || arguments->socket == nullptr) {
		return 0;
	}

	// An absent address for anything that is not IPv4: the context declines it
	// on the same predicate that governs the rest of the transport
	// (CUtpContext::IsUsableEndpoint) rather than on a second family test here.
	CNetworkAddress from;
	std::uint16_t port = 0;
	if (arguments->address != nullptr && arguments->address->sa_family == AF_INET) {
		const sockaddr_in *peer = reinterpret_cast<const sockaddr_in *>(arguments->address);
		from = CNetworkAddress::FromIPv4HostOrder(ntohl(peer->sin_addr.s_addr));
		port = ntohs(peer->sin_port);
	}

	// Closing a refused connection is not this function's business, and
	// deliberately so: whoever refuses owns the close, so utp_close() has one
	// caller per socket no matter which refusal path was taken. See
	// CUtpContext::OnInboundConnection() and IUtpConnectionAcceptor.
	CUtpSocketTransport *transport = owner->OnInboundConnection(arguments->socket, from, port);
	if (transport == nullptr) {
		return 0;
	}

	// From here every callback for this connection finds its transport. The
	// acceptor has already attached the socket to it.
	utp_set_userdata(arguments->socket, transport);
	return 0;
}

//! The handshake of an outbound dial completed. libutp reports it through
//! UTP_STATE_CONNECT as well, so this only exists because libutp calls both and
//! a missing UTP_ON_CONNECT would log as an unhandled callback.
std::uint64_t OnConnect(utp_callback_arguments *arguments)
{
	CUtpSocketTransport *transport = TransportOf(arguments);
	if (transport != nullptr) {
		transport->OnUtpStateChange(UTP_SOCKET_CONNECTED);
	}
	return 0;
}

std::uint64_t OnStateChange(utp_callback_arguments *arguments)
{
	CUtpSocketTransport *transport = TransportOf(arguments);
	if (transport == nullptr) {
		return 0;
	}

	switch (arguments->state) {
	case UTP_STATE_CONNECT:
		transport->OnUtpStateChange(UTP_SOCKET_CONNECTED);
		break;
	case UTP_STATE_WRITABLE:
		transport->OnUtpStateChange(UTP_SOCKET_WRITABLE);
		break;
	case UTP_STATE_EOF:
		transport->OnUtpStateChange(UTP_SOCKET_EOF);
		break;
	case UTP_STATE_DESTROYING:
		// Nothing may refer to the socket after this returns, which is what
		// the transport uses this state to record.
		transport->OnUtpStateChange(UTP_SOCKET_DESTROYING);
		break;
	default:
		break;
	}
	return 0;
}

/**
 * libutp gave up on a connection.
 *
 * The mapping from libutp's three codes onto ours is the load-bearing part: a
 * refusal is a fact about the peer, a timeout or a reset is a fact about the
 * path. Read the second as the first and every peer behind one UDP-blocking
 * middlebox is marked dead. See UtpTransportFailure.h.
 */
std::uint64_t OnError(utp_callback_arguments *arguments)
{
	CUtpSocketTransport *transport = TransportOf(arguments);
	if (transport == nullptr) {
		return 0;
	}

	switch (arguments->error_code) {
	case UTP_ECONNREFUSED:
		transport->OnUtpError(UTP_SOCKET_REFUSED);
		break;
	case UTP_ECONNRESET:
		transport->OnUtpError(UTP_SOCKET_RESET);
		break;
	case UTP_ETIMEDOUT:
	default:
		transport->OnUtpError(UTP_SOCKET_TIMEDOUT);
		break;
	}
	return 0;
}

std::uint64_t OnRead(utp_callback_arguments *arguments)
{
	CUtpSocketTransport *transport = TransportOf(arguments);
	if (transport != nullptr && arguments->buf != nullptr) {
		transport->OnUtpDataReceived(arguments->buf, arguments->len);
	}
	return 0;
}

//! How much this end has buffered and not yet handed to the application.
//! libutp subtracts it from the receive window it advertises.
std::uint64_t OnGetReadBufferSize(utp_callback_arguments *arguments)
{
	CUtpSocketTransport *transport = TransportOf(arguments);
	return transport != nullptr ? (std::uint64_t)transport->GetPendingReadBytes() : 0;
}

/**
 * The clock, the randomness and the MTU.
 *
 * libutp has no defaults for these: utp_call_get_milliseconds() and its
 * siblings return 0 when the callback is unset (utp_callbacks.cpp), so a
 * context without them has a clock frozen at zero, connection IDs that are all
 * zero and an MTU ceiling of zero. Nothing asserts and nothing logs; the
 * transport simply never works. libutp ships utp_default_* implementations, but
 * in a private header that is not installed, so they are unavailable to a build
 * linking a system libutp -- these are written out here instead of depending on
 * a symbol that may not be there.
 */
std::uint64_t OnGetMilliseconds(utp_callback_arguments *)
{
	using namespace std::chrono;
	return (std::uint64_t)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

std::uint64_t OnGetMicroseconds(utp_callback_arguments *)
{
	using namespace std::chrono;
	return (std::uint64_t)duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count();
}

//! Connection IDs and initial sequence numbers. Not a security boundary --
//! libutp uses it for the same purpose TCP uses its ISN -- so rand() matches
//! what upstream's own default does.
std::uint64_t OnGetRandom(utp_callback_arguments *)
{
	return (std::uint64_t)(std::uint32_t)rand();
}

/**
 * The usable payload of one datagram, and the per-datagram overhead.
 *
 * Both are ten bytes tighter than a plain UDP socket's. Two of them are the
 * OP_UDPRESERVEDPROT2 / OP_NATT_FRAME_UTP frame header that lets uTP and ed2k
 * UDP share this port (UtpDatagramRouting.h). The other eight are the eD2k UDP
 * obfuscation header, reserved whether or not a given datagram turns out to be
 * obfuscated -- that is decided per peer and per moment, well after libutp has
 * been told how large a datagram it may build. Reporting the untightened
 * figures would have libutp build datagrams over the path MTU and read the
 * resulting loss as congestion.
 */
std::uint64_t OnGetUdpMtu(utp_callback_arguments *)
{
	// 1500 Ethernet, less IPv4 (20), UDP (8), and upstream's allowance for
	// GRE/PPPoE/MPPE tunnelling plus the fudge for observed small-MTU paths
	// (24 + 8 + 2 + 36) -- then the shared-port framing and the obfuscation
	// header.
	return 1500u - 20u - 8u - 24u - 8u - 2u - 36u - UTP_FRAME_HEADER_LENGTH -
	       UDP_OBFUSCATION_HEADER_LENGTH;
}

std::uint64_t OnGetUdpOverhead(utp_callback_arguments *)
{
	// IPv4 header, UDP header, the two shared-port framing bytes and the
	// obfuscation header.
	return 20u + 8u + UTP_FRAME_HEADER_LENGTH + UDP_OBFUSCATION_HEADER_LENGTH;
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

	// libutp has no defaults for these; unregistered, each returns zero. A
	// context with a clock frozen at zero, all-zero connection IDs and an MTU
	// ceiling of zero does not fail loudly -- it just never carries data.
	utp_set_callback(context, UTP_GET_MILLISECONDS, &OnGetMilliseconds);
	utp_set_callback(context, UTP_GET_MICROSECONDS, &OnGetMicroseconds);
	utp_set_callback(context, UTP_GET_RANDOM, &OnGetRandom);
	utp_set_callback(context, UTP_GET_UDP_MTU, &OnGetUdpMtu);
	utp_set_callback(context, UTP_GET_UDP_OVERHEAD, &OnGetUdpOverhead);

	// The per-connection callbacks. Each resolves the connection's transport
	// from the socket's user data, so a connection whose owner is gone is a
	// no-op rather than a dangling dereference.
	utp_set_callback(context, UTP_ON_CONNECT, &OnConnect);
	utp_set_callback(context, UTP_ON_STATE_CHANGE, &OnStateChange);
	utp_set_callback(context, UTP_ON_ERROR, &OnError);
	utp_set_callback(context, UTP_ON_READ, &OnRead);
	utp_set_callback(context, UTP_GET_READ_BUFFER_SIZE, &OnGetReadBufferSize);

	// UTP_ON_ACCEPT last, and conditionally. libutp answers an inbound SYN as
	// soon as this callback exists, so registering it without an acceptor
	// would complete a handshake and then drop the connection -- worse for the
	// peer than never answering, because it looks like a working client that
	// discards data. The registration and the claim
	// (AcceptsInboundConnections(), which gates the advertised
	// MOD_MISCOPT_NAT_TRAVERSAL bit) are set together here and nowhere else,
	// so the two cannot disagree.
	m_acceptsInboundConnections = m_owner != nullptr && m_owner->HasInboundAcceptor();
	if (m_acceptsInboundConnections) {
		utp_set_callback(context, UTP_ON_ACCEPT, &OnAccept);
	}

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

void *CUtpLibraryAdapter::CreateOutboundSocket(
	void *context, void *userData, const CNetworkAddress &to, std::uint16_t port)
{
	if (context == nullptr) {
		return nullptr;
	}

	sockaddr_in peer;
	if (!ToSockAddr(to, port, peer)) {
		return nullptr;
	}

	utp_socket *socket = utp_create_socket(static_cast<utp_context *>(context));
	if (socket == nullptr) {
		return nullptr;
	}

	// Before utp_connect(), not after: the SYN goes out inside that call and
	// libutp may report on the connection before it returns.
	utp_set_userdata(socket, userData);

	if (utp_connect(socket, reinterpret_cast<const sockaddr *>(&peer), sizeof(peer)) != 0) {
		utp_set_userdata(socket, nullptr);
		utp_close(socket);
		return nullptr;
	}

	return socket;
}

void CUtpLibraryAdapter::CloseSocket(void *socket)
{
	if (socket == nullptr) {
		return;
	}

	// The order matters. libutp keeps the socket alive after utp_close() until
	// it has flushed what it can, and fires UTP_STATE_DESTROYING at the end. A
	// callback arriving in that window with the old user data would dereference
	// a transport its owner has already destroyed.
	utp_set_userdata(static_cast<utp_socket *>(socket), nullptr);
	utp_close(static_cast<utp_socket *>(socket));
}

void CUtpLibraryAdapter::NotifyReadDrained(void *socket)
{
	if (socket != nullptr) {
		utp_read_drained(static_cast<utp_socket *>(socket));
	}
}

#else // !AMULE_UTP_TRANSPORT

// No libutp in this build. Inert rather than absent, so the call sites above
// stay one shape and the compiler still checks them.

void *CUtpLibraryAdapter::CreateContext()
{
	return nullptr;
}

void CUtpLibraryAdapter::DestroyContext(void *) {}

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

void CUtpLibraryAdapter::IssueDeferredAcks(void *) {}

void CUtpLibraryAdapter::CheckTimeouts(void *) {}

long CUtpLibraryAdapter::WriteToSocket(void *, const std::uint8_t *, std::size_t)
{
	return -1;
}

void *CUtpLibraryAdapter::CreateOutboundSocket(void *, void *, const CNetworkAddress &, std::uint16_t)
{
	return nullptr;
}

void CUtpLibraryAdapter::CloseSocket(void *) {}

void CUtpLibraryAdapter::NotifyReadDrained(void *) {}

#endif // AMULE_UTP_TRANSPORT
