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

#include "ClientUDPSocket.h" // Interface declarations

#include <protocol/Protocols.h>
#include <protocol/ed2k/Client2Client/TCP.h> // Sometimes we reply with TCP packets.
#include <protocol/ed2k/Client2Client/UDP.h>
#include <protocol/kad2/Client2Client/UDP.h>
#include <common/EventIDs.h>
#include <common/Format.h> // Needed for CFormat

#include "Preferences.h"     // Needed for CPreferences
#include "PartFile.h"        // Needed for CPartFile
#include "updownclient.h"    // Needed for CUpDownClient
#include "UploadQueue.h"     // Needed for CUploadQueue
#include "Packet.h"          // Needed for CPacket
#include "SharedFileList.h"  // Needed for CSharedFileList
#include "DownloadQueue.h"   // Needed for CDownloadQueue
#include "Statistics.h"      // Needed for theStats
#include "amule.h"           // Needed for theApp
#include "ClientList.h"      // Needed for clientlist (buddy support)
#include "ClientTCPSocket.h" // Needed for CClientTCPSocket
#include "MemFile.h"         // Needed for CMemFile
#include "Logger.h"
#include "PeerIdentity.h" // Needed for PeerIdentity::ClassifyUdpPeer
#include "kademlia/kademlia/Kademlia.h"
#include "kademlia/utils/KadUDPKey.h"
#include <zlib.h>
#include "EncryptedDatagramSocket.h"
#include "NatRendezvousProtocol.h" // Needed for the control message codec
#include "NatRendezvousRelay.h"    // Needed for RelayRendezvousRequest
#include "NatTraversalPolicy.h"    // Needed for CNattCandidateSet
#include "NetworkAddress.h"        // Needed for CNetworkAddress
#include "UtpDatagramRouting.h"    // Needed for RouteInboundDatagram

//
// CClientUDPSocket -- Extended eMule UDP socket
//

CClientUDPSocket::CClientUDPSocket(const amuleIPV4Address &address, const CProxyData *ProxyData)
: CMuleUDPSocket("Client UDP-Socket", ID_CLIENTUDPSOCKET_EVENT, address, ProxyData)
{
	if (!thePrefs::IsUDPDisabled()) {
		Open();
	}

#ifdef AMULE_UTP_TRANSPORT
	// Only in a build that has libutp. Without this call the context has no
	// library, IsAvailable() is false, and the shared port behaves exactly
	// as it did before uTP existed -- which is what every default build
	// does, because ENABLE_UTP is off by default.
	// The acceptor is what turns the inbound half on: CUtpLibraryAdapter
	// registers UTP_ON_ACCEPT only when the context has one, because libutp
	// answers an inbound SYN as soon as that callback exists.
	m_utpContext.Configure(&m_utpLibrary, this, &m_utpAcceptor);
#endif
}

void CClientUDPSocket::SendUtpDatagram(
	const uint8_t *payload, size_t length, const CNetworkAddress &to, uint16_t port)
{
	uint32_t ip = 0;
	if (!to.ToIPv4NetworkOrder(ip) || length == 0) {
		return;
	}

	// CPacket writes [protocol][opcode] as the UDP header, which is exactly
	// the two framing bytes WriteUtpFrameHeader() defines and the receive
	// path recognises: OP_UDPRESERVEDPROT2 then OP_NATT_FRAME_UTP.
	CPacket *packet = new CPacket(OP_NATT_FRAME_UTP, length, OP_UDPRESERVEDPROT2);
	packet->CopyToDataBuffer(0, payload, length);
	theStats::AddUpOverheadOther(packet->GetPacketSize());

	// Never obfuscated and never a Kad packet: uTP carries its own framing
	// and the peer recognises it by the two header bytes.
	SendPacket(packet, ip, port, false, NULL, false, 0);
}

void CClientUDPSocket::OnReceive(int errorCode)
{
	CMuleUDPSocket::OnReceive(errorCode);

	// TODO: A better solution is needed.
	if (thePrefs::IsUDPDisabled()) {
		Close();
	}
}

void CClientUDPSocket::OnPacketReceived(
	const CNetworkAddress &peer, uint16 port, uint8_t *buffer, size_t length)
{
	wxCHECK_RET(length >= 2, "Invalid packet.");

	const PeerIdentity::EUdpRoute route = PeerIdentity::ClassifyUdpPeer(peer);
	if (route == PeerIdentity::EUdpRoute::Reject) {
		// The receive path already rejects an absent or unspecified peer, so
		// reaching this is a caller bug rather than hostile traffic.
		AddDebugLogLineN(logClientUDP,
			CFormat("Dropped UDP packet from unusable peer address %s") %
				wxString(peer.ToString()));
		return;
	}

	// The 32-bit form, for the parts of this path that are 32-bit by protocol:
	// Kad, and the ed2k UDP obfuscation key. Zero for a native IPv6 peer, and
	// every use of it below is guarded by the route rather than by that zero.
	uint32_t ip = 0;
	peer.ToIPv4NetworkOrder(ip);

	uint8_t *decryptedBuffer = buffer;
	uint32_t receiverVerifyKey = 0;
	uint32_t senderVerifyKey = 0;
	int packetLen = static_cast<int>(length);
	if (route == PeerIdentity::EUdpRoute::Ed2kAndKad) {
		packetLen = CEncryptedDatagramSocket::DecryptReceivedClient(
			buffer, length, &decryptedBuffer, ip, &receiverVerifyKey, &senderVerifyKey);
	}
	// Otherwise the datagram is left exactly as it arrived. The ed2k UDP
	// obfuscation key is MD5 over our user hash, a 32-bit address and a magic
	// byte, and the protocol defines no IPv6 input to it, so an obfuscated
	// datagram from a native IPv6 peer is undecryptable by any implementation.
	// Passing a fabricated zero to the derivation would produce a wrong key and
	// the packet would then read as junk with no reason recorded. An
	// unobfuscated datagram -- which is what its first byte being a known
	// protocol byte means, and what DecryptReceivedClient() itself checks
	// first -- is unaffected and handled in full below.

	if (packetLen < 1) {
		return;
	}

	// uTP first, then the ed2k UDP parser. The order is the design decision,
	// not a preference: offer the ed2k side everything first and uTP never
	// sees a packet, and a datagram the uTP context declines has to continue
	// to the ed2k parser whole and unmodified, because the ed2k side owns the
	// other OP_UDPRESERVEDPROT2 frame types. RouteInboundDatagram() is where
	// that order lives (UtpDatagramRouting.h), so this function cannot
	// express it any other way, and UtpDatagramRoutingTest asserts it in both
	// directions.
	RouteInboundDatagram(
		decryptedBuffer,
		(size_t)packetLen,
		m_utpContext.IsAvailable(),
		[this, &peer, port](const uint8_t *utpPayload, size_t utpPayloadLength) {
			// The peer at full width, not the 32-bit narrowing: uTP shares
			// this socket, the socket is dual-stack, and a uTP datagram
			// from a native IPv6 peer must not be attributed to 0.0.0.0.
			return m_utpContext.ProcessDatagram(utpPayload, utpPayloadLength, peer, port);
		},
		[this, decryptedBuffer, length, &peer, route, ip, port, receiverVerifyKey, senderVerifyKey](
			const uint8_t *datagram, size_t datagramLength) {
			// Same buffer, same length: the ed2k parser is entitled to
			// the datagram it has always been given. The pointer is
			// re-taken from the capture rather than cast away from the
			// callback's const, so nothing here can quietly advance it.
			wxASSERT(datagram == decryptedBuffer);
			ProcessEd2kDatagram(decryptedBuffer,
				datagramLength,
				length,
				peer,
				route,
				ip,
				port,
				receiverVerifyKey,
				senderVerifyKey);
		});
}

void CClientUDPSocket::ProcessEd2kDatagram(uint8_t *decryptedBuffer,
	size_t datagramLength,
	size_t receivedLength,
	const CNetworkAddress &peer,
	PeerIdentity::EUdpRoute route,
	uint32 ip,
	uint16 port,
	uint32_t receiverVerifyKey,
	uint32_t senderVerifyKey)
{
	const int packetLen = (int)datagramLength;
	uint8_t protocol = decryptedBuffer[0];
	uint8_t opcode = datagramLength >= 2 ? decryptedBuffer[1] : 0;

	{
		try {
			switch (protocol) {
			case OP_EMULEPROT:
				ProcessPacket(decryptedBuffer + 2, packetLen - 2, opcode, peer, port);
				break;

			case OP_KADEMLIAHEADER:
				theStats::AddDownOverheadKad(receivedLength);
				if (route != PeerIdentity::EUdpRoute::Ed2kAndKad) {
					// Kad's interface is 32-bit behind a documented
					// conversion boundary (amule-address-widening
					// design), so a Kad datagram from a native IPv6
					// peer has no contact to be attributed to. Dropped
					// with the boundary named, not narrowed to a zero
					// that would enter the routing table as 0.0.0.0.
					AddDebugLogLineN(logClientKadUDP,
						CFormat("Dropped Kad packet from IPv6 peer %s: Kad is "
							"IPv4 in this build") %
							wxString(peer.ToString()));
				} else if (packetLen >= 2) {
					Kademlia::CKademlia::ProcessPacket(decryptedBuffer,
						packetLen,
						wxUINT32_SWAP_ALWAYS(ip),
						port,
						(Kademlia::CPrefs::GetUDPVerifyKey(ip) == receiverVerifyKey),
						Kademlia::CKadUDPKey(
							senderVerifyKey, theApp->GetPublicIP(false)));
				} else {
					throw wxString("Kad packet too short");
				}
				break;

			case OP_KADEMLIAPACKEDPROT:
				theStats::AddDownOverheadKad(receivedLength);
				if (route != PeerIdentity::EUdpRoute::Ed2kAndKad) {
					AddDebugLogLineN(logClientKadUDP,
						CFormat("Dropped compressed Kad packet from IPv6 peer %s: "
							"Kad is IPv4 in this build") %
							wxString(peer.ToString()));
				} else if (packetLen >= 2) {
					uint32_t newSize = packetLen * 10 + 300; // Should be enough...
					std::vector<uint8_t> unpack(newSize);
					uLongf unpackedsize = newSize - 2;
					uint16_t result = uncompress(&(unpack[2]),
						&unpackedsize,
						decryptedBuffer + 2,
						packetLen - 2);
					if (result == Z_OK) {
						AddDebugLogLineN(logClientKadUDP,
							"Correctly uncompressed Kademlia packet");
						unpack[0] = OP_KADEMLIAHEADER;
						unpack[1] = opcode;
						Kademlia::CKademlia::ProcessPacket(&(unpack[0]),
							unpackedsize + 2,
							wxUINT32_SWAP_ALWAYS(ip),
							port,
							(Kademlia::CPrefs::GetUDPVerifyKey(ip) ==
								receiverVerifyKey),
							Kademlia::CKadUDPKey(
								senderVerifyKey, theApp->GetPublicIP(false)));
					} else {
						AddDebugLogLineN(logClientKadUDP,
							"Failed to uncompress Kademlia packet");
					}
				} else {
					throw wxString("Kad packet (compressed) too short");
				}
				break;

			case OP_UDPRESERVEDPROT2:
				// eMuleAI NAT traversal. Not an eD2k opcode: the byte
				// after the protocol byte is a frame type. Dispatched
				// here rather than through ProcessPacket() above, whose
				// second argument is an opcode.
				//
				// This branch reaches no packet accounting at all, which
				// is what keeps a dropped frame from feeding a ban:
				// CPacketTracking is only entered from the Kad listener
				// (kademlia/net/KademliaUDPListener.cpp:263), and an
				// eMuleAI peer's NAT-T traffic would otherwise arrive
				// here as an unknown protocol and read as malformed.
				ProcessReservedProt2Frame(decryptedBuffer + 1, packetLen - 1, peer, port);
				break;

			default:
				AddDebugLogLineN(logClientUDP,
					CFormat("Unknown opcode on received packet: 0x%x") % protocol);
			}
		} catch (const wxString &DEBUG_ONLY(e)) {
			AddDebugLogLineN(logClientUDP, "Error while parsing UDP packet: " + e);
		} catch (const CInvalidPacket &DEBUG_ONLY(e)) {
			AddDebugLogLineN(logClientUDP, "Invalid UDP packet encountered: " + e.what());
		} catch (const CEOFException &DEBUG_ONLY(e)) {
			AddDebugLogLineN(logClientUDP,
				"Malformed packet encountered while parsing UDP packet: " + e.what());
		}
	}
}

void CClientUDPSocket::ProcessReservedProt2Frame(
	const uint8_t *frame, size_t frameLength, const CNetworkAddress &peer, uint16 port)
{
	// Nothing in this path needs a 32-bit address: every branch drops the
	// frame with a reason, so the peer only has to be printable. An eMuleAI
	// peer's NAT traversal frames arrive over both families.
	const wxString peerText = wxString(peer.ToString());
	const SReservedProt2Frame classified = ClassifyReservedProt2Frame(frame, frameLength);

	switch (classified.disposition) {
	case RP2_TRUNCATED:
		// Nothing but the protocol byte arrived, so there is no type byte
		// to read. Dropped without reading the window -- the guard is the
		// point, this is the shortest datagram that can reach here.
		AddDebugLogLineN(logClientUDP,
			CFormat("Dropping truncated NAT-T datagram from %s:%u") % peerText % port);
		return;

	case RP2_UNKNOWN_TYPE:
		// A frame type this protocol does not define. Dropped, and
		// deliberately not counted anywhere: see the OP_UDPRESERVEDPROT2
		// comment in OnPacketReceived().
		if (m_unknownFrameLog.ShouldLog(::GetTickCount64())) {
			AddDebugLogLineN(logClientUDP,
				CFormat("Dropping NAT-T frame of unknown type 0x%02X from %s:%u (%u further "
					"occurrences suppressed)") %
					classified.type % peerText % port %
					m_unknownFrameLog.TakeSuppressedCount());
		}
		return;

	case RP2_KNOWN_TYPE:
		break;
	}

	// The five registered types. Each is handled or dropped in its own case:
	// the change that ships a transport replaces its own case and nothing
	// else, and until then a peer's NAT-T attempt is a recognised frame aMule
	// cannot serve rather than malformed traffic.
	switch (classified.type) {
	case OP_NATT_FRAME_UTP:
		// The rendezvous and hole-punch control messages. Reached only after
		// the uTP context declined the datagram in OnPacketReceived(), so
		// libutp has already had its chance at these bytes; a payload that is
		// neither a libutp header nor one of the three control opcodes is
		// dropped inside ProcessNattControlFrame().
		//
		// classified.payload is past the frame type byte, so the control
		// opcode is its first byte.
		ProcessNattControlFrame(classified.payload, classified.payloadLength, peer, port);
		break;

	case OP_NATT_FRAME_QUIC:
		AddDebugLogLineN(logClientUDP,
			CFormat("Ignoring QUIC NAT-T frame from %s:%u: no QUIC transport in this build") %
				peerText % port);
		break;

	case OP_NATT_FRAME_CAPS:
	case OP_NATT_FRAME_CAPS_ACK:
		// Answering the capability negotiation would claim a transport
		// aMule does not have. Silence is the correct answer here.
		AddDebugLogLineN(logClientUDP,
			CFormat("Ignoring NAT-T capability frame 0x%02X from %s:%u: nothing to negotiate") %
				classified.type % peerText % port);
		break;

	case OP_NATT_FRAME_KEY:
		AddDebugLogLineN(logClientUDP,
			CFormat("Ignoring NAT-T key frame from %s:%u: no NAT traversal in this build") %
				peerText % port);
		break;

	default:
		// Unreachable: ClassifyReservedProt2Frame only reports
		// RP2_KNOWN_TYPE for the five cases above. Kept so that adding a
		// type there without a case here fails loudly rather than
		// silently taking the drop path.
		wxFAIL;
		break;
	}
}

void CClientUDPSocket::SendNattControlMessage(
	const uint8_t *payload, size_t length, const CNetworkAddress &to, uint16_t port)
{
	uint32_t ip = 0;
	if (payload == NULL || length == 0 || port == 0 || !to.ToIPv4NetworkOrder(ip)) {
		// The same IPv4 narrowing SendUtpDatagram() has, and the same reason:
		// this socket's send path takes a 32-bit address. A native IPv6 peer
		// is not punched at rather than being punched at 0.0.0.0 -- see the
		// address-widening boundary in PeerIdentity.h.
		return;
	}

	CPacket *packet = new CPacket(OP_NATT_FRAME_UTP, length, OP_UDPRESERVEDPROT2);
	packet->CopyToDataBuffer(0, payload, length);
	theStats::AddUpOverheadOther(packet->GetPacketSize());

	// Never obfuscated and never a Kad packet, exactly as a uTP datagram is
	// not: the peer recognises this by the two header bytes.
	SendPacket(packet, ip, port, false, NULL, false, 0);
}

bool CClientUDPSocket::SendRendezvousRequest(const uint8_t *peerHash,
	const CNetworkAddress &relay,
	uint16_t relayPort,
	const CNetworkAddress &ownEndpoint,
	uint16_t ownPort)
{
	uint8_t request[NATT_RENDEZVOUS_MAX_LENGTH];
	const size_t length =
		EncodeRendezvousRequest(peerHash, ownEndpoint, ownPort, request, sizeof(request));
	if (length == 0) {
		// No usable endpoint of our own to name. Not sent rather than sent
		// blank: the relay validates the hint against the source and would
		// discard it anyway, and a request with the hint bit set and nothing
		// behind it is what makes the far parser read past the datagram.
		return false;
	}

	SendNattControlMessage(request, length, relay, relayPort);
	return true;
}

void CClientUDPSocket::ServiceNatRendezvous(uint64_t nowMs)
{
	// Our own identity travels in the punch, so the receiver pairs the packet
	// by identity rather than by the address it arrived from -- the address is
	// exactly what the NAT under test rewrites.
	const CMD4Hash &ownHash = thePrefs::GetUserHash();
	if (ownHash.IsEmpty()) {
		return;
	}

	uint8_t punch[NATT_HOLEPUNCH_LENGTH];
	if (EncodeHolePunch(ownHash.GetHash(), punch, sizeof(punch)) != NATT_HOLEPUNCH_LENGTH) {
		return;
	}

	m_natRendezvous.Tick(
		nowMs, [this, &punch](const uint8_t * /* peerHash */, const SNattPunchRequest &request) {
			// The peer hash is the manager's key, not part of the packet: a
			// punch names its SENDER, because that is the end whose identity
			// the receiver cannot otherwise recover.
			SendNattControlMessage(
				punch, NATT_HOLEPUNCH_LENGTH, request.destination, request.port);
		});
}

void CClientUDPSocket::ProcessNattControlFrame(
	const uint8_t *frame, size_t frameLength, const CNetworkAddress &peer, uint16 port)
{
	const wxString peerText = wxString(peer.ToString());
	const uint64_t nowMs = ::GetTickCount64();

	switch (ClassifyNattControlMessage(frame, frameLength)) {
	case NATT_CONTROL_RENDEZVOUS: {
		// Which direction this is comes off the wire, never from local state.
		// A relay request and a relayed rendezvous carry the same opcode and
		// mean opposite things, and inferring the direction would leave the
		// acting path reachable by a crafted request -- which is precisely the
		// reflection the relay validation exists to prevent.
		SNattRendezvousRequest peeked;
		const bool parsed = ParseRendezvousRequest(frame, frameLength, peeked);

		if (parsed && peeked.isRelayed) {
			// A relay forwarded a rendezvous to us. Acted on only from a
			// peer already in the client list, and only within the same
			// per-peer budget a requester spends from.
			const bool relayIsKnown = theApp->clientlist->FindClientByIP(peer, port) != NULL;
			const CNetworkAddress ownEndpoint =
				CNetworkAddress::FromIPv4NetworkOrderOrAbsent(theApp->GetPublicIP(false));

			const SRelayedRendezvousDecision decision = AcceptRelayedRendezvous(
				frame, frameLength, peer, relayIsKnown, ownEndpoint, nowMs, m_relayLimiter);
			if (!decision.punch) {
				AddDebugLogLineN(logClientUDP,
					CFormat("Dropping relayed rendezvous from %s:%u: reason %d") %
						peerText % port % (int)decision.acceptance);
				return;
			}

			// The addresses we already hold for that peer come first, so the
			// relayed endpoint is one candidate among them and can never
			// displace one. CNattCandidateSet has no method that removes
			// anything, which is what makes that structural rather than
			// remembered.
			CNattCandidateSet known;
			const CMD4Hash targetHash(decision.peerHash);
			const CClientList::SourceList matches =
				theApp->clientlist->GetClientsByHash(targetHash);
			for (CClientList::SourceList::const_iterator it = matches.begin();
				it != matches.end();
				++it) {
				const CUpDownClient *client = it->GetClient();
				if (client != NULL) {
					known.AddKnown(client->GetConnectAddress(), client->GetUserPort());
				}
			}

			if (m_natRendezvous.OnRelayedRendezvous(decision, known, nowMs)) {
				AddDebugLogLineN(logClientUDP,
					CFormat("Punching toward %s:%u for a rendezvous relayed by "
						"%s:%u") %
						wxString(decision.punchEndpoint.ToString()) %
						decision.punchPort % peerText % port);
			}
			return;
		}

		// Otherwise it is a request to relay -- including a malformed one,
		// which reaches RelayRendezvousRequest() so that it is charged against
		// its sender's budget rather than being free.
		//
		// The requester's identity comes from our own client list, never from
		// the datagram: it is the value the forwarded message carries, so a
		// datagram that could set it would make this relay vouch for anyone.
		const CUpDownClient *requester = theApp->clientlist->FindClientByIP(peer, port);
		const uint8_t *requesterHash = requester != NULL && requester->HasValidHash()
						       ? requester->GetUserHash().GetHash()
						       : NULL;

		const SRelayDecision decision = RelayRendezvousRequest(
			frame,
			frameLength,
			peer,
			port,
			requesterHash,
			nowMs,
			m_relayLimiter,
			// The only source of a destination address in this path: our own
			// client list, looked up by hash. There is no branch in which an
			// address out of the datagram is sent to.
			[](const uint8_t *hash, CNetworkAddress &address, uint16_t &targetPort) {
				const CMD4Hash wanted(hash);
				const CClientList::SourceList candidates =
					theApp->clientlist->GetClientsByHash(wanted);
				for (CClientList::SourceList::const_iterator it = candidates.begin();
					it != candidates.end();
					++it) {
					const CUpDownClient *client = it->GetClient();
					if (client == NULL) {
						continue;
					}
					const CNetworkAddress candidate = client->GetConnectAddress();
					if (candidate.IsPresent() && !candidate.IsUnspecified() &&
						client->GetUserPort() != 0) {
						address = candidate;
						targetPort = client->GetUserPort();
						return true;
					}
				}
				return false;
			},
			[this](const CNetworkAddress &destination,
				uint16_t destinationPort,
				const uint8_t *payload,
				size_t payloadLength) {
				SendNattControlMessage(payload, payloadLength, destination, destinationPort);
			});

		if (!decision.emitted) {
			// No reply to the requester either. A refusal reply would be a
			// second amplification channel with a smaller factor.
			AddDebugLogLineN(logClientUDP,
				CFormat("Discarding rendezvous request from %s:%u: reason %d") % peerText %
					port % (int)decision.disposition);
		}
		return;
	}

	case NATT_CONTROL_HOLEPUNCH: {
		SNattHolePunch punchMessage;
		if (!ParseHolePunch(frame, frameLength, punchMessage)) {
			AddDebugLogLineN(logClientUDP,
				CFormat("Dropping malformed hole punch from %s:%u") % peerText % port);
			return;
		}

		// Matched against the pairs already in flight, and it may not create
		// one: a peer this client never punched toward gets no schedule and no
		// budget out of sending a punch. The mapping it arrived from is
		// recorded, because a mapping that delivered a packet is evidence and
		// an endpoint hint is a guess.
		if (m_natRendezvous.OnHolePunchReceived(punchMessage.senderHash, peer, port, nowMs)) {
			AddDebugLogLineN(logClientUDP,
				CFormat("Hole punch from %s:%u matched a rendezvous in flight") % peerText %
					port);
		}
		return;
	}

	case NATT_CONTROL_ENDPOINT_HINT:
		// A bare hint, outside any rendezvous. Dropped, and this is a decision
		// rather than an omission: the message carries an address and a port
		// and no identity at all, so the only peer it could be attributed to is
		// whoever sent the datagram. Acting on it would mean letting an
		// arbitrary host name an endpoint for this client to send toward, which
		// is the reflection vector with the relay validation removed. Hints are
		// acted on only where they arrive attributed -- inside an
		// OP_RENDEZVOUS a known relay forwarded.
		AddDebugLogLineN(logClientUDP,
			CFormat("Ignoring unsolicited endpoint hint from %s:%u") % peerText % port);
		return;

	case NATT_CONTROL_NOT_A_CONTROL_MESSAGE:
		// Neither a libutp header (the context already declined it) nor one of
		// the three control opcodes. Dropped without guessing at a length.
		if (m_unknownFrameLog.ShouldLog(nowMs)) {
			AddDebugLogLineN(logClientUDP,
				CFormat("Dropping uTP NAT-T frame from %s:%u that is neither uTP nor a "
					"control message (%u further occurrences suppressed)") %
					peerText % port % m_unknownFrameLog.TakeSuppressedCount());
		}
		return;
	}
}

void CClientUDPSocket::ProcessPacket(
	uint8_t *packet, int16 size, int8 opcode, const CNetworkAddress &host, uint16 port)
{
	// Printable form for the logs, and the 32-bit form for the two handlers
	// whose *payload* is an ed2k wire field -- the relayed callback address and
	// the ed2k id a new client object is built from. Replies go to the address
	// itself, so an IPv6 peer gets answered. The 32-bit form is zero for a
	// native IPv6 peer and both uses of it are guarded, because a zero there
	// would name the wrong host inside a packet.
	const wxString hostText = wxString(host.ToString());
	uint32 hostIPv4 = 0;
	const bool hasIPv4 = host.ToIPv4NetworkOrder(hostIPv4);

	switch (opcode) {
	case OP_REASKCALLBACKUDP: {
		AddDebugLogLineN(logClientUDP, "Client UDP socket; OP_REASKCALLBACKUDP");
		theStats::AddDownOverheadOther(size);
		CUpDownClient *buddy = theApp->clientlist->GetBuddy();
		if (buddy) {
			if (size < 17 || buddy->GetSocket() == NULL) {
				break;
			}
			if (!hasIPv4) {
				// The relayed OP_REASKCALLBACKTCP carries the
				// requester's address as a 32-bit ed2k field, so there
				// is nowhere in this packet to put an IPv6 address. The
				// wire format is not widened here; the request is
				// dropped with the reason named.
				AddDebugLogLineN(logClientUDP,
					CFormat("Dropping OP_REASKCALLBACKUDP from %s: the relayed "
						"callback field is a 32-bit ed2k address") %
						hostText);
				break;
			}
			if (!md4cmp(packet, buddy->GetBuddyID())) {
				/*
					The packet has an initial 16 bytes key for the buddy.
					This is currently unused, so to make the transformation
					we discard the first 10 bytes below and then overwrite
					the other 6 with ip/port.
				*/
				CMemFile mem_packet(packet + 10, size - 10);
				// Change the ip and port while leaving the rest untouched
				mem_packet.Seek(0, wxFromStart);
				mem_packet.WriteUInt32(hostIPv4);
				mem_packet.WriteUInt16(port);
				CPacket *response =
					new CPacket(mem_packet, OP_EMULEPROT, OP_REASKCALLBACKTCP);
				AddDebugLogLineN(logClientUDP, "Client UDP socket: send OP_REASKCALLBACKTCP");
				theStats::AddUpOverheadFileRequest(response->GetPacketSize());
				buddy->GetSocket()->SendPacket(response);
			}
		}
		break;
	}
	case OP_REASKFILEPING: {
		AddDebugLogLineN(logClientUDP, "Client UDP socket: OP_REASKFILEPING");
		theStats::AddDownOverheadFileRequest(size);

		CMemFile data_in(packet, size);
		CMD4Hash reqfilehash = data_in.ReadHash();
		CKnownFile *reqfile = theApp->sharedfiles->GetFileByID(reqfilehash);
		bool bSenderMultipleIpUnknown = false;
		CUpDownClient *sender = theApp->uploadqueue->GetWaitingClientByIP_UDP(
			host, port, true, &bSenderMultipleIpUnknown);

		if (!reqfile) {
			CPacket *response = new CPacket(OP_FILENOTFOUND, 0, OP_EMULEPROT);
			theStats::AddUpOverheadFileRequest(response->GetPacketSize());
			if (sender) {
				SendPacket(response,
					host,
					port,
					sender->ShouldReceiveCryptUDPPackets(),
					sender->GetUserHash().GetHash(),
					false,
					0);
			} else {
				SendPacket(response, host, port, false, NULL, false, 0);
			}

			break;
		}

		if (sender) {
			sender->CheckForAggressive();
			if (sender->IsBanned()) {
				// CheckForAggressive can call Ban() on score >= 10.
				// Mirror the TCP file-request path at
				// ClientTCPSocket.cpp:539 and short-circuit so a
				// freshly-banned client cannot keep the seeder
				// processing UDP file-info packets.
				break;
			}

			// Make sure we are still thinking about the same file
			if (reqfilehash == sender->GetUploadFileID()) {
				sender->AddAskedCount();
				sender->SetUDPPort(port);
				sender->SetLastUpRequest();

				if (sender->GetUDPVersion() > 3) {
					sender->ProcessExtendedInfo(&data_in, reqfile);
				} else if (sender->GetUDPVersion() > 2) {
					uint16 nCompleteCountLast = sender->GetUpCompleteSourcesCount();
					uint16 nCompleteCountNew = data_in.ReadUInt16();
					sender->SetUpCompleteSourcesCount(nCompleteCountNew);
					if (nCompleteCountLast != nCompleteCountNew) {
						reqfile->UpdatePartsInfo();
					}
				}

				CMemFile data_out(128);
				if (sender->GetUDPVersion() > 3) {
					if (reqfile->IsPartFile()) {
						static_cast<CPartFile *>(reqfile)->WritePartStatus(&data_out);
					} else {
						data_out.WriteUInt16(0);
					}
				}

				data_out.WriteUInt16(sender->GetUploadQueueWaitingPosition());
				CPacket *response = new CPacket(data_out, OP_EMULEPROT, OP_REASKACK);
				theStats::AddUpOverheadFileRequest(response->GetPacketSize());
				AddDebugLogLineN(logClientUDP,
					"Client UDP socket: OP_REASKACK to " + sender->GetFullIP());
				SendPacket(response,
					host,
					port,
					sender->ShouldReceiveCryptUDPPackets(),
					sender->GetUserHash().GetHash(),
					false,
					0);
			} else {
				AddDebugLogLineN(logClientUDP,
					"Client UDP socket; ReaskFilePing; reqfile does not match");
			}
		} else {
			if (!bSenderMultipleIpUnknown) {
				if ((theStats::GetWaitingUserCount() + 50) > thePrefs::GetQueueSize()) {
					CPacket *response = new CPacket(OP_QUEUEFULL, 0, OP_EMULEPROT);
					theStats::AddUpOverheadFileRequest(response->GetPacketSize());
					SendPacket(response,
						host,
						port,
						false,
						NULL,
						false,
						0); // we cannot answer this one encrypted since we dont know
						    // this client
				}
			} else {
				AddDebugLogLineN(logClientUDP,
					CFormat("UDP Packet received - multiple clients with the same IP but "
						"different UDP port found. Possible UDP Portmapping problem, "
						"enforcing TCP connection. IP: %s, Port: %u") %
						hostText % port);
			}
		}
		break;
	}
	case OP_QUEUEFULL: {
		AddDebugLogLineN(logClientUDP, "Client UDP socket: OP_QUEUEFULL");
		theStats::AddDownOverheadOther(size);
		CUpDownClient *sender = theApp->downloadqueue->GetDownloadClientByIP_UDP(host, port);
		if (sender) {
			sender->SetRemoteQueueFull(true);
			sender->UDPReaskACK(0);
		}
		break;
	}
	case OP_REASKACK: {
		theStats::AddDownOverheadFileRequest(size);
		CUpDownClient *sender = theApp->downloadqueue->GetDownloadClientByIP_UDP(host, port);
		if (sender) {
			CMemFile data_in(packet, size);
			if (sender->GetUDPVersion() > 3) {
				sender->ProcessFileStatus(true, &data_in, sender->GetRequestFile());
			}
			uint16 nRank = data_in.ReadUInt16();
			sender->SetRemoteQueueFull(false);
			sender->UDPReaskACK(nRank);
		}
		break;
	}
	case OP_FILENOTFOUND: {
		AddDebugLogLineN(logClientUDP, "Client UDP socket: OP_FILENOTFOUND");
		theStats::AddDownOverheadFileRequest(size);
		CUpDownClient *sender = theApp->downloadqueue->GetDownloadClientByIP_UDP(host, port);
		if (sender) {
			sender->UDPReaskFNF(); // may delete 'sender'!
			sender = NULL;
		}
		break;
	}
	case OP_DIRECTCALLBACKREQ: {
		AddDebugLogLineN(logClientUDP, "Client UDP socket: OP_DIRECTCALLBACKREQ");
		theStats::AddDownOverheadOther(size);
		if (!theApp->clientlist->AllowCallbackRequest(host)) {
			AddDebugLogLineN(logClientUDP,
				"Ignored DirectCallback Request because this IP (" + hostText +
					") has sent too many requests within a short time");
			break;
		}
		// do we accept callbackrequests at all?
		if (Kademlia::CKademlia::IsRunning() && Kademlia::CKademlia::IsFirewalled()) {
			theApp->clientlist->AddTrackCallbackRequests(host);
			CMemFile data(packet, size);
			uint16_t remoteTCPPort = data.ReadUInt16();
			CMD4Hash userHash(data.ReadHash());
			uint8_t connectOptions = data.ReadUInt8();
			CUpDownClient *requester = NULL;
			CClientList::SourceList clients = theApp->clientlist->GetClientsByHash(userHash);
			for (CClientList::SourceList::iterator it = clients.begin(); it != clients.end();
				++it) {
				if ((host.IsAbsent() || it->GetClient()->GetAddress() == host) &&
					(remoteTCPPort == 0 || it->GetUserPort() == remoteTCPPort)) {
					requester = it->GetClient();
					break;
				}
			}
			if (requester == NULL) {
				// The ed2k id argument is the peer's 32-bit address, so a
				// native IPv6 requester is created with none and given its
				// real address immediately below. SetAddress() is what
				// makes it findable afterwards, in either family.
				requester =
					new CUpDownClient(remoteTCPPort, hostIPv4, 0, 0, NULL, true, true);
				requester->SetUserHash(CMD4Hash(userHash));
				theApp->clientlist->AddClient(requester);
			}
			requester->SetConnectOptions(connectOptions, true, false);
			requester->SetDirectUDPCallbackSupport(false);
			requester->SetAddress(host);
			requester->SetUserPort(remoteTCPPort);
			AddDebugLogLineN(
				logClientUDP, "Accepting incoming DirectCallback Request from " + hostText);
			requester->TryToConnect();
		} else {
			AddDebugLogLineN(logClientUDP,
				"Ignored DirectCallback Request because we do not accept Direct Callbacks at "
				"all (" +
					hostText + ")");
		}
		break;
	}
	default:
		theStats::AddDownOverheadOther(size);
	}
}
// File_checked_for_headers
