//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2026 aMule Team ( https://amule-org.github.io )
//
// Parts of this file are ported from eMule AI's CUtpSocket:
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

#ifndef UTPCONTEXT_H
#define UTPCONTEXT_H

#include <cstddef>
#include <cstdint>

#include "NetworkAddress.h" // Needed for CNetworkAddress

/**
 * The uTP context: aMule's side of libutp.
 *
 * eMuleAI gets this shape almost free, because its MFC socket stack has a
 * layer concept and CUtpSocket is just another CAsyncSocketExLayer. aMule has
 * no layer abstraction, so the context is an explicit object owned by the
 * client UDP socket and driven by three inputs, exactly as the design says:
 *
 *   - inbound datagrams recognised as uTP on the shared ed2k UDP port,
 *   - a periodic tick, independent of traffic,
 *   - application writes (buffered -- see CUtpWriteBufferPolicy).
 *
 * There is one context per client instance, not per connection: libutp keeps
 * its own socket table inside a context, and a context per connection would
 * split congestion state across one UDP port and leave inbound accepts with
 * nowhere to land.
 *
 * libutp itself sits behind IUtpLibrary. Two reasons, and neither is taste:
 * the shim has to compile in a build configured with -DENABLE_UTP=NO (where
 * there is no libutp at all), and the tick guarantee is not observable through
 * a real libutp without a peer on the network.
 */

/**
 * The subset of libutp this shim uses.
 *
 * Implemented for real by CUtpLibraryAdapter (UtpLibraryAdapter.h), which is a
 * no-op unless AMULE_UTP_TRANSPORT is defined. `void *` is a `utp_context *`;
 * the type does not appear here so that this header stays includable without
 * libutp's headers.
 */
class IUtpLibrary
{
public:
	virtual ~IUtpLibrary() = default;

	//! utp_init() plus callback registration. Returns NULL on failure.
	virtual void *CreateContext() = 0;
	//! utp_destroy().
	virtual void DestroyContext(void *context) = 0;

	/**
	 * utp_process_udp().
	 *
	 * @return true when libutp claimed the datagram. False means it did not
	 *         look like uTP to libutp, and the caller must let the datagram
	 *         continue to the ed2k UDP parser.
	 */
	virtual bool ProcessDatagram(void *context,
		const std::uint8_t *payload,
		std::size_t length,
		const CNetworkAddress &from,
		std::uint16_t port) = 0;

	/**
	 * Whether an inbound uTP connection arriving on `context` would be
	 * handed to this end rather than dropped, i.e. whether UTP_ON_ACCEPT is
	 * registered on it.
	 *
	 * libutp discards an inbound connection outright when that callback is
	 * absent, so this is the difference between a transport that can serve a
	 * peer and one that merely exists. It is asked of the library because
	 * only the library knows what was registered.
	 */
	virtual bool AcceptsInboundConnections(void *context) const = 0;

	//! utp_issue_deferred_acks().
	virtual void IssueDeferredAcks(void *context) = 0;
	//! utp_check_timeouts().
	virtual void CheckTimeouts(void *context) = 0;

	/**
	 * utp_write(). `socket` is a `utp_socket *`, not a context: writes are
	 * per connection.
	 *
	 * @return bytes accepted, 0 when libutp's send window is closed, and a
	 *         negative value on error. Zero is the ordinary case under load
	 *         and must not be treated as a failure -- see CUtpStream's
	 *         backoff.
	 */
	virtual long WriteToSocket(void *socket, const std::uint8_t *data, std::size_t length) = 0;
};

/**
 * Where outbound uTP datagrams go: the ed2k UDP socket.
 *
 * The sink receives the uTP payload and is responsible for the 0xB2/0x00
 * framing (WriteUtpFrameHeader, UtpDatagramRouting.h), because the framing is
 * a property of the shared port rather than of the context.
 */
class IUtpDatagramSink
{
public:
	virtual ~IUtpDatagramSink() = default;

	virtual void SendUtpDatagram(const std::uint8_t *payload,
		std::size_t length,
		const CNetworkAddress &to,
		std::uint16_t port) = 0;
};

class CUtpContext
{
public:
	CUtpContext() = default;

	~CUtpContext() { Reset(); }

	CUtpContext(const CUtpContext &) = delete;
	CUtpContext &operator=(const CUtpContext &) = delete;

	/**
	 * Bind the context to a library and an outbound socket.
	 *
	 * @param library  NULL in a build without libutp, which is the default
	 *                 build. Then the context is permanently unavailable and
	 *                 every path through it is inert -- the receive path and
	 *                 the core timer both run in that build too.
	 */
	void Configure(IUtpLibrary *library, IUtpDatagramSink *sink)
	{
		Reset();
		m_library = library;
		m_sink = sink;
	}

	//! Whether there is a library to talk to at all.
	bool IsAvailable() const { return m_library != nullptr; }

	/**
	 * Whether this end can serve a uTP connection: a context exists, and an
	 * inbound uTP attempt on it would be handled rather than dropped.
	 *
	 * This is what gates the advertised MOD_MISCOPT_NAT_TRAVERSAL bit
	 * (AdvertisedModMiscOptions(), PeerCapabilities.h). IsAvailable() is not
	 * that answer: it says libutp is linked, which is the equivalent of a
	 * bound socket. A build with libutp, a context and no accept callback
	 * discards every inbound uTP connection, and a peer that read the bit
	 * would spend its connection attempts on a client that silently drops
	 * them -- nothing logs on either side, and the only symptom is a source
	 * that never transfers.
	 *
	 * Not const, and it creates the context, for the same reason Tick() does:
	 * the answer must not depend on whether a tick happened to run first, or
	 * the advertised capability would flap for one core-timer period after
	 * every socket reopen.
	 */
	bool CanServeConnections()
	{
		void *context = EnsureContext();
		if (context == nullptr) {
			return false;
		}

		return m_library->AcceptsInboundConnections(context);
	}

	/**
	 * Offer an inbound datagram to libutp.
	 *
	 * @param payload  the uTP payload, i.e. past the 0xB2/0x00 framing.
	 * @param from     the peer. IPv4 only for now, see below.
	 * @return true when libutp claimed it. False means the caller must let
	 *         the datagram continue to the ed2k UDP parser unmodified.
	 */
	bool ProcessDatagram(const std::uint8_t *payload,
		std::size_t length,
		const CNetworkAddress &from,
		std::uint16_t port)
	{
		if (!IsUsableEndpoint(from)) {
			return false;
		}

		void *context = EnsureContext();
		if (context == nullptr) {
			return false;
		}

		return m_library->ProcessDatagram(context, payload, length, from, port);
	}

	/**
	 * The periodic tick. Must be called at least every 500 ms, which is
	 * libutp's documented requirement for utp_check_timeouts(); aMule's core
	 * timer runs every 100 ms (300 ms in the daemon), so one call per core
	 * tick satisfies it with room to spare.
	 *
	 * Deliberately unconditional. Retransmission and congestion control live
	 * in utp_check_timeouts(), so a context serviced only when a packet
	 * arrives cannot recover a lost packet on an idle connection -- the
	 * packet that would drive the recovery is the one that was lost. The
	 * context is also created here if it does not exist yet, so the
	 * guarantee does not depend on a first inbound packet.
	 */
	void Tick()
	{
		void *context = EnsureContext();
		if (context == nullptr) {
			return;
		}

		m_library->IssueDeferredAcks(context);
		m_library->CheckTimeouts(context);
	}

	/**
	 * Send a uTP datagram, i.e. what libutp's sendto callback ends up
	 * calling. Goes out through the ed2k UDP socket so that uTP and ed2k UDP
	 * share one port -- and one NAT mapping.
	 *
	 * @return false when there is no socket to send through, or when the
	 *         peer is not an address family this transport carries yet.
	 */
	bool SendDatagram(const std::uint8_t *payload,
		std::size_t length,
		const CNetworkAddress &to,
		std::uint16_t port)
	{
		if (m_sink == nullptr || !IsAvailable() || !IsUsableEndpoint(to)) {
			return false;
		}

		m_sink->SendUtpDatagram(payload, length, to, port);
		return true;
	}

	/**
	 * Whether this transport carries traffic to that peer.
	 *
	 * IPv4 only, deliberately, even though address widening has landed:
	 * adding a transport and an address family in one change makes a stall
	 * impossible to attribute. The interface is family-generic -- it takes a
	 * CNetworkAddress rather than a uint32 -- so enabling IPv6 uTP is a
	 * change to this one predicate.
	 */
	static bool IsUsableEndpoint(const CNetworkAddress &address) { return address.IsIPv4(); }

private:
	//! Create the single context on first use, and hand back the same one
	//! afterwards.
	void *EnsureContext()
	{
		if (m_library == nullptr) {
			return nullptr;
		}
		if (m_context == nullptr) {
			m_context = m_library->CreateContext();
		}
		return m_context;
	}

	void Reset()
	{
		if (m_library != nullptr && m_context != nullptr) {
			m_library->DestroyContext(m_context);
		}
		m_context = nullptr;
	}

	IUtpLibrary *m_library = nullptr;
	IUtpDatagramSink *m_sink = nullptr;
	void *m_context = nullptr;
};

#endif // UTPCONTEXT_H
