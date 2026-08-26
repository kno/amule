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
#include "NatRendezvousManager.h"   // Needed for CNatRendezvousManager
#include "NatRendezvousRelay.h"     // Needed for CRendezvousRelayLimiter
#include "PeerIdentity.h"           // Needed for PeerIdentity::EUdpRoute
#include "QuicContext.h"            // Needed for CQuicContext / IQuicDatagramSink
#include "QuicLibraryAdapter.h"     // Needed for CQuicLibraryAdapter
#include "ReservedProtocolFrames.h" // Needed for CUnknownFrameLogThrottle
#include "UtpContext.h"             // Needed for CUtpContext / IUtpDatagramSink
#include "QuicInboundAcceptor.h"    // Needed for CQuicInboundAcceptor
#include "UtpInboundAcceptor.h"     // Needed for CUtpInboundAcceptor
#include "UtpLibraryAdapter.h"      // Needed for CUtpLibraryAdapter

/**
 * The ed2k UDP socket, which is also the uTP socket and the QUIC socket.
 *
 * Neither transport gets a port of its own: their datagrams arrive and leave
 * here, wrapped in OP_UDPRESERVEDPROT2 with a frame type -- OP_NATT_FRAME_UTP
 * (0x00) or OP_NATT_FRAME_QUIC (0x01). Sharing the port is what lets them reuse
 * the NAT mapping ed2k UDP already has, which is the whole reason either is
 * useful for NAT traversal. The two sink interfaces are how the contexts reach
 * this socket on the way out; RouteInboundDatagram() is the way in, and the
 * classification order it fixes -- uTP, then QUIC, then the ed2k parser -- lives
 * in UtpDatagramRouting.h rather than here.
 */
class CClientUDPSocket : public CMuleUDPSocket,
			 public IUtpDatagramSink,
			 public IQuicDatagramSink,
			 public IQuicConnectionObserver
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
	 * Drive the QUIC context, from the same core timer and for the same
	 * reason: QUIC's loss detection and idle timer live in this pass, so an
	 * endpoint serviced only from the receive path cannot recover a lost
	 * packet on an idle connection.
	 *
	 * Inert in every build configured with -DENABLE_QUIC=NO, which is the
	 * default and the only configuration macOS gets.
	 */
	void ServiceQuic(uint64_t nowMs) { m_quicContext.Tick(nowMs); }

	/**
	 * Whether this client can serve a QUIC connection to a peer right now.
	 *
	 * The QUIC twin of CanServeUtpConnections(), gating the
	 * MOD_MISCOPT_NAT_TRAVERSAL_QUIC bit and the localCanServeQuic input to
	 * SelectNattFrameType(). Again not "was QUIC compiled in": a build with
	 * ngtcp2 whose TLS credentials failed to come up answers no handshake, and
	 * a peer that read the bit would wait out the whole 1500 ms window before
	 * falling back -- a second and a half per connection, with nothing logged
	 * on either side.
	 */
	bool CanServeQuicConnections() { return m_quicContext.CanServeConnections(); }

	/**
	 * The QUIC context, for the connect path.
	 *
	 * CUpDownClient needs it to register what an inbound QUIC connection from a
	 * peer must prove, because the two values that expectation is built from
	 * arrive in that peer's ed2k hello and this socket never sees one. Handed
	 * out rather than wrapped, on the same reasoning as GetUtpContext() and
	 * GetNatRendezvousManager(): there is one per client instance and the
	 * decision belongs to the client, not to the socket that carries bytes.
	 */
	CQuicContext *GetQuicContext() { return &m_quicContext; }

	/**
	 * Drive the hole-punch schedules. Also called from
	 * CamuleApp::OnCoreTimer, and for the same reason ServiceUtp() is: the
	 * schedules are polled rather than timer-driven, so a rendezvous that is
	 * waiting out an attempt's spacing has to be asked.
	 *
	 * Emits nothing at all unless a rendezvous is in flight, which for an
	 * ordinary peer never happens -- see CNatRendezvousManager.
	 */
	void ServiceNatRendezvous(uint64_t nowMs);

	/**
	 * The rendezvous exchanges in flight, for the connect path.
	 *
	 * CUpDownClient needs it to fill SRendezvousInputs::backoffActive and to
	 * report a connection coming up, both of which are per peer and neither of
	 * which this socket can decide. Handed out rather than wrapped, on the same
	 * reasoning as GetUtpContext(): there is one per client instance and the
	 * decision belongs to the client, not to the socket that carries bytes.
	 */
	CNatRendezvousManager *GetNatRendezvousManager() { return &m_natRendezvous; }

	/**
	 * Ask a relay to reach @a peerHash on this client's behalf.
	 *
	 * @param ownEndpoint this client's believed external endpoint. Sent as a
	 *        hint, and the relay is expected to ignore its value and forward
	 *        what it observed instead -- which is what RelayRendezvousRequest()
	 *        does when the roles are reversed. It is sent because the relay
	 *        validates the hint against the source, so a request without one
	 *        is discarded.
	 * @return whether a request went out.
	 */
	bool SendRendezvousRequest(const uint8_t *peerHash,
		const CNetworkAddress &relay,
		uint16_t relayPort,
		const CNetworkAddress &ownEndpoint,
		uint16_t ownPort);

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

	//! Outbound QUIC datagrams, from the endpoint's send path. Framed with
	//! 0xB2/0x01 and queued on this socket so QUIC, uTP and ed2k UDP share one
	//! port and one NAT mapping.
	void SendQuicDatagram(
		const uint8_t *payload, size_t length, const CNetworkAddress &to, uint16_t port) override;

	/**
	 * One QUIC connection came up or ended.
	 *
	 * The log line lives here rather than in the bridge because
	 * QuicLibraryAdapter.cpp is the one translation unit that sees ngtcp2's and
	 * GnuTLS's headers and therefore cannot include Logger.h -- the same
	 * constraint that puts CUtpInboundAcceptor's logging outside
	 * UtpLibraryAdapter.cpp. What this function must not do is decide which
	 * kind of failure it was: that is IsQuicAuthenticationOutcome(), which
	 * QuicContextTest asserts, because a classification written inside a log
	 * statement cannot be.
	 */
	void OnQuicConnectionOutcome(EQuicConnectionOutcome outcome,
		EQuicProofResult proofResult,
		const CNetworkAddress &peer,
		uint16_t port) override;

protected:
	void OnReceive(int errorCode) override;

private:
	void OnPacketReceived(
		const CNetworkAddress &peer, uint16 port, uint8_t *buffer, size_t length) override;
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

	/**
	 * The rendezvous and hole-punch control messages, inside an
	 * OP_NATT_FRAME_UTP frame.
	 *
	 * Reached only after the uTP context declined the datagram, which is what
	 * makes the two parsers on this frame type unambiguous: a libutp v1 header
	 * cannot begin with 0xA0, 0xA1 or 0xAA, and none of those three can be a
	 * libutp header -- see the classification argument in
	 * NatRendezvousProtocol.h.
	 *
	 * This function is dispatch and no policy. Every decision it appears to
	 * make is made in a header that a test binary can link: the relay
	 * validation and its rate limit in RelayRendezvousRequest(), the guards on
	 * the other direction in AcceptRelayedRendezvous(), the bounds in
	 * CNatRendezvousManager. That split is deliberate -- this class needs
	 * theApp and cannot be linked into a test at all, so anything decided here
	 * could not be asserted anywhere.
	 *
	 * @param frame points at the control opcode, i.e. past the 0xB2 and 0x00
	 *        framing bytes.
	 */
	void ProcessNattControlFrame(
		const uint8_t *frame, size_t frameLength, const CNetworkAddress &peer, uint16 port);

	//! Frame and queue one control message on this socket: OP_UDPRESERVEDPROT2
	//! then OP_NATT_FRAME_UTP, exactly as SendUtpDatagram() does, so the punch
	//! opens the mapping uTP will use rather than one of its own.
	void SendNattControlMessage(
		const uint8_t *payload, size_t length, const CNetworkAddress &to, uint16_t port);

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

	//! One QUIC context per client instance, on the same reasoning as the uTP
	//! one: ngtcp2 keeps its connections inside an endpoint, and an endpoint
	//! per connection would split its state across one UDP port. Unavailable
	//! unless this build was configured with -DENABLE_QUIC=YES, in which case
	//! the shared port behaves exactly as it did before QUIC existed.
	CQuicContext m_quicContext;
	CQuicLibraryAdapter m_quicLibrary{ &m_quicContext };

	//! Where a validated inbound QUIC connection becomes a CClientTCPSocket.
	//! Its presence is what lets a connection whose peer proof passed reach the
	//! ed2k layer at all: without it the adapter closes every authenticated
	//! connection, because a validated stream nothing reads would accumulate
	//! bytes for a consumer that never arrives.
	CQuicInboundAcceptor m_quicAcceptor;

	//! The rendezvous exchanges in flight. Empty in every ordinary session:
	//! an entry exists only for a firewalled peer that advertised traversal
	//! and that this client could not reach any other way.
	CNatRendezvousManager m_natRendezvous;

	/**
	 * One relay budget for both directions.
	 *
	 * Deliberately one object rather than two: a peer that has spent its
	 * budget asking this client to relay must not get a second allowance by
	 * sending forwards instead. Two limiters would be two budgets for one
	 * peer, which is the amplification this change exists to not be.
	 */
	CRendezvousRelayLimiter m_relayLimiter;
};

#endif // CLIENTUDPSOCKET_H
// File_checked_for_headers
