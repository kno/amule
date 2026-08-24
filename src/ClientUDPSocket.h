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

#ifndef CLIENTUDPSOCKET_H
#define CLIENTUDPSOCKET_H

#include "MuleUDPSocket.h"
#include "PeerIdentity.h"           // Needed for PeerIdentity::EUdpRoute
#include "ReservedProtocolFrames.h" // Needed for CUnknownFrameLogThrottle
#include "UtpContext.h"             // Needed for CUtpContext / IUtpDatagramSink
#include "UtpInboundAcceptor.h"     // Needed for CUtpInboundAcceptor
#include "UtpLibraryAdapter.h"      // Needed for CUtpLibraryAdapter

/**
 * The ed2k UDP socket, which is also the uTP socket.
 *
 * uTP gets no port of its own: its datagrams arrive and leave here, wrapped in
 * OP_UDPRESERVEDPROT2 / OP_NATT_FRAME_UTP. Sharing the port is what lets uTP
 * reuse the NAT mapping ed2k UDP already has, which is the whole reason uTP is
 * useful for NAT traversal later. IUtpDatagramSink is how the context reaches
 * this socket on the way out; ProcessUtpDatagram is the way in.
 */
class CClientUDPSocket : public CMuleUDPSocket, public IUtpDatagramSink
{
public:
	CClientUDPSocket(const amuleIPV4Address &address, const CProxyData *ProxyData = NULL);

	/**
	 * Drive the uTP context. Called from CamuleApp::OnCoreTimer, i.e. every
	 * CORE_TIMER_PERIOD ms and independently of any traffic: libutp does its
	 * retransmission and congestion control in utp_check_timeouts(), so a
	 * context serviced only from the receive path cannot recover a lost
	 * packet on an idle connection.
	 */
	//! @param nowMs a millisecond tick, for the per-connection write buffers
	//!        and their idle accounting and their zero-write backoff. The context passes
	//!        it to every live connection.
	void ServiceUtp(uint64_t nowMs) { m_utpContext.Tick(nowMs); }

	/**
	 * Whether this client can serve a uTP connection to a peer right now.
	 *
	 * This is what gates the MOD_MISCOPT_NAT_TRAVERSAL bit in the handshake
	 * (CUpDownClient::SendHelloTypePacket). It is not "was uTP compiled in":
	 * a build configured with -DENABLE_UTP=YES has a context and still drops
	 * every inbound uTP connection until the accept path is wired, and a peer
	 * that read the bit would spend its connection attempts on a client that
	 * discards them. False in every default build, where the context has no
	 * library at all.
	 */
	bool CanServeUtpConnections() { return m_utpContext.CanServeConnections(); }

	/**
	 * The one uTP context, for the outbound dial.
	 *
	 * CUpDownClient::ConnectOverUtp() needs it to create a connection. Handed
	 * out rather than wrapped in a Dial() method here, because the dial belongs
	 * to the client that owns the socket, not to the UDP socket that carries
	 * the datagrams -- and there is exactly one context per client instance for
	 * every connection to share.
	 */
	CUtpContext *GetUtpContext() { return &m_utpContext; }

	//! Outbound uTP datagrams, from the context's send callback. Framed and
	//! queued on this socket so uTP and ed2k UDP share one port.
	void SendUtpDatagram(
		const uint8_t *payload, size_t length, const CNetworkAddress &to, uint16_t port) override;

protected:
	void OnReceive(int errorCode);

private:
	void OnPacketReceived(
		const CNetworkAddress &peer, uint16 port, uint8_t *buffer, size_t length);
	void ProcessPacket(
		uint8_t *packet, int16 size, int8 opcode, const CNetworkAddress &host, uint16 port);

	/**
	 * The ed2k UDP parser: the protocol-byte switch this socket has always
	 * had, unchanged. Reached only after the uTP context has declined the
	 * datagram, and reached with the datagram exactly as it arrived.
	 *
	 * @param datagram  the decrypted datagram, protocol byte first.
	 * @param datagramLength  its length, at least 1.
	 * @param receivedLength  the length of the datagram as it came off the
	 *                        wire, before decryption. This is what the Kad
	 *                        overhead statistics count, so it is passed
	 *                        rather than recomputed.
	 * @param peer  the sender, at full width. Used for the ed2k side and for
	 *              naming the peer in the drop log below; `ip` is the same
	 *              address narrowed to 32 bits, and is zero for a native IPv6
	 *              peer.
	 * @param route  what this sender's address can be routed to. Kad is IPv4
	 *               in this build, so a datagram whose route is not
	 *               Ed2kAndKad has no Kad contact to be attributed to and is
	 *               dropped with the boundary named.
	 */
	void ProcessEd2kDatagram(uint8_t *datagram,
		size_t datagramLength,
		size_t receivedLength,
		const CNetworkAddress &peer,
		PeerIdentity::EUdpRoute route,
		uint32 ip,
		uint16 port,
		uint32_t receiverVerifyKey,
		uint32_t senderVerifyKey);

	/**
	 * OP_UDPRESERVEDPROT2: no opcode, a frame type byte instead.
	 *
	 * @param frame  points at the frame type byte.
	 * @param frameLength  bytes available from there. Zero is a datagram
	 *                     that carried nothing but the protocol byte.
	 */
	void ProcessReservedProt2Frame(
		const uint8_t *frame, size_t frameLength, const CNetworkAddress &peer, uint16 port);

	//! One unknown-frame line per minute, with a suppressed count. A peer
	//! speaking a frame type this build does not know retries, so the useful
	//! information is that it happened plus how often.
	CUnknownFrameLogThrottle m_unknownFrameLog{ 60 * 1000 };

	//! One uTP context per client instance, not per connection: libutp keeps
	//! its own socket table inside a context. Unavailable unless this build
	//! was configured with -DENABLE_UTP=YES, in which case the shared port
	//! behaves exactly as it did before uTP existed.
	CUtpContext m_utpContext;
	CUtpLibraryAdapter m_utpLibrary{ &m_utpContext };

	//! Where an inbound uTP connection becomes a CClientTCPSocket. Its
	//! presence is what makes CUtpLibraryAdapter register UTP_ON_ACCEPT, and
	//! therefore what makes CanServeUtpConnections() -- and the advertised
	//! MOD_MISCOPT_NAT_TRAVERSAL bit -- able to be true.
	CUtpInboundAcceptor m_utpAcceptor;
};

#endif // CLIENTUDPSOCKET_H
// File_checked_for_headers
