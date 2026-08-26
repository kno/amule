//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2026 aMule Team ( https://amule-org.github.io )
// Copyright (c) 2011-2026 Stu Redman ( https://amule-org.github.io )
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

#ifndef __LIBSOCKET_H__
#define __LIBSOCKET_H__

#include "NetworkAddress.h" // Needed for CNetworkAddress
#include "Types.h"
#include <memory> // shared_ptr for CAsioUDPSocketImpl ownership
class amuleIPV4Address;
class CUtpSocketTransport;
class CQuicSocketTransport;
class CStreamTransportNotifier;
class IStreamTransport;

// Socket flags (unused in ASIO implementation, just provide the names)
enum
{
	MULE_SOCKET_NONE,
	MULE_SOCKET_NOWAIT_READ,
	MULE_SOCKET_NOWAIT_WRITE,
	MULE_SOCKET_NOWAIT,
	MULE_SOCKET_WAITALL_READ,
	MULE_SOCKET_WAITALL_WRITE,
	MULE_SOCKET_WAITALL,
	MULE_SOCKET_BLOCK,
	MULE_SOCKET_REUSEADDR,
	MULE_SOCKET_BROADCAST,
	MULE_SOCKET_NOBIND
};
typedef int muleSocketFlags;

// Socket events (used for proxy notification)
enum
{
	MULE_SOCKET_CONNECTION,
	MULE_SOCKET_INPUT,
	MULE_SOCKET_OUTPUT,
	MULE_SOCKET_LOST
};

//
// Abstraction class for library TCP socket
// Can be a wxSocket or an ASIO socket
//

//
// Client TCP socket
//
class CLibSocket
{
	friend class CAsioSocketImpl;
	friend class CAsioSocketServerImpl;

public:
	CLibSocket(int flags = 0);
	virtual ~CLibSocket();

	// wx Stuff
	void Notify(bool);
	bool Connect(const amuleIPV4Address &adr, bool wait);
	// Bound the synchronous connect to `ms` milliseconds (0 = no bound,
	// the default). Only affects the blocking connect path used by the
	// synchronous EC clients (amulecmd); the async path is unaffected.
	void SetConnectTimeout(int ms);
	bool IsConnected() const;
	bool IsOk() const;
	void SetLocal(const amuleIPV4Address &local);
	uint32 Read(void *buffer, uint32 nbytes);
	uint32 Write(const void *buffer, uint32 nbytes);
	void Close();
	void Destroy();

	// Swap in a fresh asio socket impl on this same wrapper so the socket
	// can be re-connected after a loss WITHOUT recreating the CLibSocket
	// (and therefore without invalidating any pointer the app still holds
	// to us — the remote GUI pins its CRemoteConnect in every container).
	// The outgoing impl is detached race-safely first (see LinkSocketImpl).
	void ResetForReconnect();

	// Get last error, 0 == no error
	int LastError() const;

	// not supported
	void SetFlags(int) {}
	void Discard() {}
	bool WaitOnConnect(long, long) { return true; }
	bool WaitForWrite(long, long) { return true; }
	bool WaitForRead(long, long) { return true; }

	// new Stuff

	// Check if socket is currently blocking for read or write
	bool BlocksRead() const;
	bool BlocksWrite() const;

	// Show we're ready for another event
	void EventProcessed();

	// Get IP of client
	const wxChar *GetIP() const;

	// True if Destroy() has been called for socket
	bool IsDestroying() const;

	// Get/set proxy state
	bool GetProxyState() const;
	void SetProxyState(bool state, const amuleIPV4Address *adr = 0);

	// Get peer address (better API than wx)
	wxString GetPeer();
	uint32 GetPeerInt();
	// The peer's address with its family intact. GetPeerInt() answers zero for
	// an IPv6 peer -- the same zero it answers for 0.0.0.0 -- so a caller that
	// has to tell those apart, such as the ed2k accept path, reads this.
	const CNetworkAddress &GetPeerAddress() const;
	// The local end of the connection. For an accepted socket this is the
	// address the peer reached us on, which is where a wildcard-bound listener
	// learns which of the machine's own addresses is reachable from outside.
	CNetworkAddress GetLocalAddress() const;

	// Turn on TCP keepalive with per-socket timings so a half-open
	// connection (peer gone, FIN/RST lost or never sent) gets torn
	// down at the TCP layer instead of sitting idle forever. Used by
	// the EC sockets on both ends — see CECMuleSocket / CECServerSocket.
	// Idle seconds before the kernel starts probing, the interval
	// between probes, and how many probes before declaring the peer
	// dead.  Effective only on POSIX (TCP_KEEPIDLE / TCP_KEEPINTVL /
	// TCP_KEEPCNT) and Windows (SIO_KEEPALIVE_VALS; only idle +
	// interval are settable, count uses the system default). No-op if
	// the underlying socket is not open.
	void EnableTcpKeepalive(int idleSec, int probeIntervalSec, int probeCount);

	//
	// Transport substitution: uTP and QUIC
	//
	// aMule has no socket-layer abstraction -- that is the whole reason the
	// uTP change needed a shim (see openspec/changes/amule-utp-transport). This
	// wrapper is the seam: everything above it (CProxySocket,
	// CEncryptedStreamSocket, CEMSocket, CClientTCPSocket) consumes
	// Read/Write/IsConnected/IsOk/BlocksRead/BlocksWrite and the peer
	// accessors, and never touches the asio socket directly. So a wrapper that
	// wears a substituted transport routes exactly those calls through it and
	// the entire stack above is unchanged, obfuscation included.
	//
	// The absence of a transport is the only thing an ordinary TCP connection
	// can observe: every intercepting method is `if (m_streamTransport) {...}`
	// followed by the call it always made. In a build with neither -DENABLE_UTP
	// nor -DENABLE_QUIC nothing ever attaches one, so that branch is never
	// taken.
	//
	// There is one pointer for both transports rather than one each, and that is
	// not a saving but a correctness measure: the alternative is fifteen pairs
	// of routing branches whose two halves must never drift, in the one file
	// where a drift shows up as a connection that reads bytes and never writes
	// them. The two are mutually exclusive by construction -- a connection is
	// dialled or accepted over exactly one transport -- so one pointer is also
	// the honest shape. See IStreamTransport in src/StreamTransport.h.

	/**
	 * Substitute uTP for TCP on this wrapper. Takes ownership.
	 *
	 * Must be called before any connect: the asio socket is then never opened,
	 * and the peer accessors answer from the transport instead of from a
	 * connection that does not exist.
	 */
	void AttachUtpTransport(std::unique_ptr<CUtpSocketTransport> transport);

	/**
	 * Substitute an authenticated QUIC connection for TCP. Takes ownership.
	 *
	 * Only ever reached from CQuicInboundAcceptor, i.e. after the peer proof
	 * validated -- so the first byte this wrapper reads is the first byte of the
	 * ed2k hello, and CEncryptedStreamSocket above it sees exactly what it sees
	 * on a TCP connection.
	 */
	void AttachQuicTransport(std::unique_ptr<CQuicSocketTransport> transport);

	//! Whether a transport is substituted for TCP at all, of either kind.
	bool HasStreamTransport() const { return m_streamTransport != nullptr; }

	/**
	 * Whether the substituted transport is specifically uTP.
	 *
	 * Distinct from HasStreamTransport() because the one caller
	 * (CUpDownClient::ConnectOverUtp) is asking "is a uTP dial already in
	 * flight on this socket", and answering yes for a QUIC connection would
	 * suppress a uTP dial that should have happened.
	 */
	bool HasUtpTransport() const { return m_utpTransport != nullptr; }
	CUtpSocketTransport *GetUtpTransport() const { return m_utpTransport; }

	// Handlers
	virtual void OnConnect(int) {}
	virtual void OnSend(int) {}
	virtual void OnReceive(int) {}
	// Int argument is unused — exists to give the CLibSocket-layer
	// hook a different signature from CECSocket::OnLost(), so a class
	// that multi-inherits from both (CECMuleSocket) can override the
	// CLibSocket-side hook unambiguously and forward to the EC-layer
	// OnLost().  Without that disambiguation, the Asio reactor's
	// EOF-on-read dispatch lands on the empty CLibSocket::OnLost{}
	// instead of CRemoteConnect / CECServerSocket overrides.
	virtual void OnLost(int) {}
	virtual void OnProxyEvent(int) {}

private:
	// Replace the internal socket. Takes ownership of the passed shared_ptr.
	void LinkSocketImpl(std::shared_ptr<class CAsioSocketImpl>);

	// shared_ptr so the asio impl can outlive this wrapper for as long as
	// any in-flight async callback still holds a shared_from_this() ref.
	// Required to fix the wake-from-sleep use-after-free crash (issue #384).
	std::shared_ptr<class CAsioSocketImpl> m_aSocket;

	// NULL for every TCP connection, which is every connection unless this
	// build has libutp or ngtcp2 and the peer used it. Held by unique_ptr on an
	// incomplete type, so ~CLibSocket() and the two Attach*Transport() methods
	// are out-of-line in LibSocketAsio.cpp, where the transports are complete.
	std::unique_ptr<IStreamTransport> m_streamTransport;
	// The same object as m_streamTransport when the transport is uTP, and NULL
	// otherwise. Non-owning, and it exists only so HasUtpTransport() and
	// GetUtpTransport() can answer "which kind" without a dynamic_cast at a
	// call site. Set and cleared together with m_streamTransport, in the one
	// place each is assigned.
	CUtpSocketTransport *m_utpTransport = nullptr;
	// Turns the transport's events back into the CoreNotify_LibSocket* events
	// the asio reactor posts, so the socket above sees no difference. Defined
	// in LibSocketAsio.cpp, next to those notifications.
	std::unique_ptr<CStreamTransportNotifier> m_utpNotifier;

	void LastCount();   // No. We don't have this. We return it directly with Read() and Write()
	bool Error() const; // Only use LastError
};

//
// TCP socket server
//
class CLibSocketServer
{
public:
	CLibSocketServer(const amuleIPV4Address &adr, int flags);
	// Bind the acceptor to a specific network interface (empty = any),
	// independent of the global bind-to-interface pin set via
	// SetSocketBindInterface(). Used by the EC listener so external-control
	// traffic can live on a different interface than ed2k/Kad.
	CLibSocketServer(const amuleIPV4Address &adr, int flags, const wxString &bindInterface);
	virtual ~CLibSocketServer();
	// Accepts an incoming connection request, and creates a new CLibSocket object which represents the
	// server-side of the connection.
	CLibSocket *Accept(bool wait = true);
	// Accept an incoming connection using the specified socket object.
	bool AcceptWith(CLibSocket &socket, bool wait);

	virtual void OnAccept() {}

	bool IsOk() const;

	void Close();

	// Not needed here
	void Discard() {}
	bool Notify(bool) { return true; }

	// new Stuff

	// Do we have a socket available if AcceptWith() is called ?
	bool SocketAvailable();

private:
	// shared_ptr for the same reason as CLibSocket::m_aSocket — pending
	// async_accept completions must keep the impl alive past wrapper death.
	std::shared_ptr<class CAsioSocketServerImpl> m_aServer;
};

//
// UDP socket
//
class CLibUDPSocket
{
	friend class CAsioUDPSocketImpl;

public:
	CLibUDPSocket(amuleIPV4Address &address, int flags);
	virtual ~CLibUDPSocket();

	// wx Stuff
	bool IsOk() const;
	virtual uint32 RecvFrom(amuleIPV4Address &addr, void *buf, uint32 nBytes);
	virtual uint32 SendTo(const amuleIPV4Address &addr, const void *buf, uint32 nBytes);
	int LastError() const;
	void Close();
	void Destroy();
	void SetClientData(class CMuleUDPSocket *);

	// Not needed here
	bool Notify(bool) { return true; }

	// Check if socket is currently blocking for write
	// Well - we apparently have block in wx. At least we handle it in MuleUDPSocket.
	// But this makes no sense. We send a packet to an IP in background.
	// Either this works after some time, or not. But there is no block.
	bool BlocksWrite() const { return false; }

private:
	// shared_ptr so the asio impl can outlive this wrapper for as long as
	// any in-flight async callback still holds a shared_from_this() ref.
	// Required to fix the wake-from-sleep use-after-free crash (issue #384).
	std::shared_ptr<class CAsioUDPSocketImpl> m_aSocket;
	void LastCount();   // block this
	bool Error() const; // Only use LastError
};

//
// ASIO event loop
//
class CAsioService
{
public:
	CAsioService();
	~CAsioService();
	void Stop();

private:
	static const int m_numberOfThreads;
	class CAsioServiceThread *m_threads;
};

// Set the network interface every socket binds its egress to (empty = system
// default). Pushed in by the core from thePrefs::GetNetworkInterface() so this
// socket library stays independent of CPreferences. Takes effect for sockets
// opened after the call.
void SetSocketBindInterface(const wxString &iface);

// Outcome of validating the configured bind interface, so the core can report
// it once at startup instead of discovering it silently per socket.
enum BindInterfaceStatus
{
	BindIface_Empty,      // no interface configured (default)
	BindIface_OK,         // resolves and binds
	BindIface_NotFound,   // name/index does not match any interface
	BindIface_Denied,     // bind needs a privilege we don't have (Linux CAP_NET_RAW)
	BindIface_Unsupported // platform can't bind, or another error
};

// Validate the configured bind interface on a throwaway socket. Lets the core
// warn the user (not found / permission denied) before any real socket opens,
// rather than leaving traffic silently unbound.
BindInterfaceStatus TestSocketBindInterface(const wxString &iface);

// Bind an already-open raw socket to the given interface, reusing the exact
// same per-platform logic as aMule's own sockets. For non-asio sockets such as
// libcurl's HTTP socket (via CURLOPT_SOCKOPTFUNCTION). The fd is passed as
// uintptr_t so a Windows SOCKET survives without truncation. Returns true if
// bound (or nothing to do), false if the bind failed.
bool BindRawSocketToInterface(uintptr_t fd, const wxString &iface);

#endif /* __LIBSOCKET_H__ */
