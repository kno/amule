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

#ifndef STREAMTRANSPORT_H
#define STREAMTRANSPORT_H

#include <cstdint>

#include "NetworkAddress.h" // Needed for CNetworkAddress

/**
 * The socket-shaped surface CLibSocket routes when it is not carrying TCP.
 *
 * aMule has no socket-layer abstraction -- which is why the uTP change needed a
 * shim in the first place -- and CLibSocket is the seam it invented: everything
 * above it (CProxySocket, CEncryptedStreamSocket, CEMSocket, CClientTCPSocket)
 * consumes exactly these calls and never touches the asio socket directly.
 *
 * This interface exists because there is now a second substitute. uTP arrived
 * first and CLibSocket routed to CUtpSocketTransport by name; QUIC is the same
 * substitution with a different library underneath, and naming a second concrete
 * type at each of the fifteen routing sites would double them -- fifteen pairs
 * of branches whose two halves must never drift, in the one file where a drift
 * shows up as a connection that reads bytes but never writes them. One
 * interface, one branch each, and the transports differ only in what they are
 * constructed from.
 *
 * The contract is the asio path's, exactly, because the layers above cannot be
 * changed and were never told there was a choice:
 *
 *   - **The would-block contract is exact.** CEMSocket checks BlocksRead() and
 *     BlocksWrite() *before* LastError() (EMSocket.cpp:240, :658), so "nothing
 *     right now" must be a zero return with the blocks flag set and LastError()
 *     still zero. An error there instead turns an ordinary closed send window
 *     into a dropped connection.
 *   - **IsOk() means usable, not merely constructed.** A connect in flight
 *     answers false on the asio path, and CUpDownClient::ConnectToCurrentCandidate()
 *     dials only when it is false.
 *   - **LastError() carries no meaning beyond zero or non-zero.** Every call
 *     site in this tree tests it for truth; inventing an errno for a transport
 *     failure would suggest a precision that does not exist.
 *
 * Free of wxWidgets, of theApp, and of both transport libraries, so a transport
 * implementing it stays unit testable -- which is the whole reason the uTP shim
 * has tests at all.
 */
class IStreamTransport
{
public:
	virtual ~IStreamTransport() = default;

	//! True only once the handshake completed. Mirrors
	//! CAsioSocketImpl::IsConnected().
	virtual bool IsConnected() const = 0;

	//! True once the connection is usable. Mirrors CAsioSocketImpl::IsOk().
	virtual bool IsOk() const = 0;

	//! @return bytes copied. Zero with BlocksRead() true is "nothing right
	//!         now", and LastError() must stay zero for it.
	virtual std::uint32_t Read(void *buffer, std::uint32_t nbytes) = 0;

	//! @return bytes accepted. Zero with BlocksWrite() true means retry, which
	//!         is the TCP convention the layers above already implement.
	virtual std::uint32_t Write(const void *buffer, std::uint32_t nbytes) = 0;

	//! Ordinary close. Must not set a transport failure: a closed connection
	//! and a failed one are different answers, and only the second must keep
	//! the peer blameless.
	virtual void Close() = 0;

	virtual bool BlocksRead() const = 0;
	virtual bool BlocksWrite() const = 0;

	//! Zero while healthy or merely blocked, non-zero once failed. See the
	//! class comment: the value itself says nothing more.
	virtual int LastError() const = 0;

	virtual const CNetworkAddress &GetPeerAddress() const = 0;
	virtual std::uint16_t GetPeerPort() const = 0;
};

/**
 * How a substituted transport wakes the socket above it.
 *
 * The same four events the asio reactor posts, so CClientTCPSocket cannot tell
 * this connection from a TCP one: OnConnect() still sends the hello, OnReceive()
 * still reads packets, OnSend() still drains the send queue, OnLost() still
 * tears the connection down.
 *
 * Delivery must be deferred rather than direct, and that is a property of the
 * implementation rather than of this interface, but it is stated here because
 * both transports need it for the same reason: their callbacks fire from inside
 * the library, on the ed2k UDP receive path or the core timer, and the client
 * code they would re-enter closes sockets -- which would destroy the very
 * object the library is standing on. See CStreamTransportNotifier in
 * LibSocketAsio.cpp.
 */
class IStreamTransportEvents
{
public:
	virtual ~IStreamTransportEvents() = default;

	//! The handshake completed. The socket above sends its hello from here.
	virtual void OnStreamTransportConnected() = 0;
	//! Bytes arrived and Read() will return them.
	virtual void OnStreamTransportReadable() = 0;
	//! The send window opened; a previously blocked Write() will now take
	//! bytes.
	virtual void OnStreamTransportWritable() = 0;
	//! The connection is gone, for any reason.
	virtual void OnStreamTransportLost() = 0;
};

#endif // STREAMTRANSPORT_H
