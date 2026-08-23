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

#include <wx/wx.h>
#include <algorithm>

#include "MuleUDPSocket.h" // Interface declarations

#include <protocol/ed2k/Constants.h>

#include "amule.h"                  // Needed for theApp
#include "GetTickCount.h"           // Needed for GetTickCount64()
#include "Packet.h"                 // Needed for CPacket
#include <common/StringFunctions.h> // Needed for unicode2char
#include "Proxy.h"                  // Needed for CDatagramSocketProxy
#include "Logger.h"                 // Needed for AddDebugLogLine{C,N}
#include "UploadBandwidthThrottler.h"
#include "EncryptedDatagramSocket.h"
#include "OtherFunctions.h"
#include "kademlia/kademlia/Prefs.h"
#include "ClientList.h"
#include "Preferences.h"

CMuleUDPSocket::CMuleUDPSocket(
	const wxString &name, int id, const amuleIPV4Address &address, const CProxyData *ProxyData)
: m_busy(false)
, m_name(name)
, m_id(id)
, m_addr(address)
, m_proxy(ProxyData)
, m_socket(NULL)
{
}

CMuleUDPSocket::~CMuleUDPSocket()
{
	theApp->uploadBandwidthThrottler->RemoveFromAllQueues(this);

	wxMutexLocker lock(m_mutex);
	DestroySocket();
}

void CMuleUDPSocket::CreateSocket()
{
	wxCHECK_RET(!m_socket, "Socket already opened.");

	m_socket = new CEncryptedDatagramSocket(m_addr, MULE_SOCKET_NOWAIT, m_proxy);
	m_socket->SetClientData(this);
	m_socket->Notify(true);

	if (!m_socket->IsOk()) {
		AddDebugLogLineC(logMuleUDP, "Failed to create valid " + m_name);
		DestroySocket();
	} else {
		// One template rather than concatenation: translators need to be able to
		// reorder the name and the port. m_name is a construction-time identifier
		// ("Server UDP-Socket"), left untranslated on purpose.
		AddLogLineN(CFormat(_("Created %s at port %u")) % m_name % m_addr.Service());
	}
}

void CMuleUDPSocket::DestroySocket()
{
	if (m_socket) {
		AddDebugLogLineN(logMuleUDP, "Shutting down " + m_name);
		m_socket->Close();
		m_socket->Destroy();
		m_socket = NULL;
	}
}

void CMuleUDPSocket::Open()
{
	wxMutexLocker lock(m_mutex);

	CreateSocket();
}

void CMuleUDPSocket::Close()
{
	wxMutexLocker lock(m_mutex);

	DestroySocket();
}

void CMuleUDPSocket::OnSend(int errorCode)
{
	if (errorCode) {
		return;
	}

	{
		wxMutexLocker lock(m_mutex);
		m_busy = false;
		if (m_queue.empty()) {
			return;
		}
	}

	theApp->uploadBandwidthThrottler->QueueForSendingControlPacket(this);
}

void CMuleUDPSocket::OnReceive(int errorCode)
{
	AddDebugLogLineN(logMuleUDP,
		CFormat("Got UDP callback for read: Error %i Socket state %i") % errorCode % Ok());

	char buffer[UDP_BUFFER_SIZE];
	amuleIPV4Address addr;
	unsigned length = 0;
	bool error = false;
	int lastError = 0;

	{
		wxMutexLocker lock(m_mutex);

		if (errorCode || (m_socket == NULL) || !m_socket->IsOk()) {
			DestroySocket();
			CreateSocket();

			return;
		}

		length = m_socket->RecvFrom(addr, buffer, UDP_BUFFER_SIZE);
		lastError = m_socket->LastError();
		error = lastError != 0;
	}

	// StringIPtoUint32() answers zero both for the address 0.0.0.0 and for a
	// string it could not parse, so the peer address is taken through the
	// address type as well: the reject below can then say which of the two
	// happened instead of testing one value that means either.
	// Mapped forms are normalised here, once, so everything below -- the ban
	// check, the filter and the ed2k handlers -- sees the IPv4 address the peer
	// really is rather than its ::ffff: spelling.
	const CNetworkAddress peer =
		CNetworkAddress::FromString(addr.IPAddress().ToStdString()).Unmapped();
	uint32 ip = 0;
	peer.ToIPv4NetworkOrder(ip);
	const uint16 port = addr.Service();
	if (error) {
		OnReceiveError(lastError, ip, port);
	} else if (length < 2) {
		// 2 bytes (protocol and opcode) is the smallets possible packet.
		AddDebugLogLineN(logMuleUDP, m_name + ": Invalid Packet received");
	} else if (peer.IsAbsent() || peer.IsUnspecified()) {
		// wxFAIL;
		// Both are rejected, exactly as `!ip` rejected both before, but they
		// are no longer the same condition: absent is an address this build
		// cannot parse or represent, unspecified is a peer claiming 0.0.0.0.
		AddDebugLogLineN(logMuleUDP,
			(peer.IsAbsent() ? "Unparsable ip receiving a UDP packet! Ignoring: '"
					 : "Unspecified ip receiving a UDP packet! Ignoring: '") +
				addr.IPAddress() + "'");
	} else if (!port) {
		// wxFAIL;
		AddDebugLogLineN(logMuleUDP, "Unknown port receiving a UDP packet! Ignoring");
	} else if (theApp->clientlist->IsBannedClient(peer)) {
		// The ban list is keyed on the address now, so an IPv6 peer is checked
		// against it as itself rather than being unbannable.
		AddDebugLogLineN(logMuleUDP, m_name + ": Dropped packet from banned IP " + addr.IPAddress());
	} else {
		// A datagram from a native IPv6 peer used to be dropped right here: the
		// handlers below identified a peer by its 32-bit address and this one
		// has none, and a fabricated zero was refused on purpose. They now take
		// the address, so the peer is handled -- each handler deciding for
		// itself what it can do for a family its subsystem may not speak. See
		// PeerIdentity::ClassifyUdpPeer().
		AddDebugLogLineN(logMuleUDP,
			(m_name + ": Packet received (")
				<< addr.IPAddress() << ":" << port << "): " << length << "b");
		OnPacketReceived(peer, port, (uint8_t *)buffer, length);
	}
}

void CMuleUDPSocket::OnReceiveError(int DEBUG_ONLY(errorCode), uint32 WXUNUSED(ip), uint16 WXUNUSED(port))
{
	AddDebugLogLineN(logMuleUDP, (m_name + ": Error while reading: ") << errorCode);
}

void CMuleUDPSocket::OnDisconnected(int WXUNUSED(errorCode))
{
	/* Due to bugs in wxWidgets, UDP sockets will sometimes
	 * be closed. This is caused by the fact that wx treats
	 * zero-length datagrams as EOF, which is only the case
	 * when dealing with streaming sockets.
	 *
	 * This has been reported as patch #1885472:
	 * http://sourceforge.net/tracker/index.php?func=detail&aid=1885472&group_id=9863&atid=309863
	 */
	AddDebugLogLineC(logMuleUDP, m_name + "Socket died, recreating.");
	DestroySocket();
	CreateSocket();
}

void CMuleUDPSocket::SendPacket(CPacket *packet,
	uint32 IP,
	uint16 port,
	bool bEncrypt,
	const uint8 *pachTargetClientHashORKadID,
	bool bKad,
	uint32 nReceiverVerifyKey)
{
	// Zero has always meant "no target" in the 32-bit fields this overload
	// serves, and the conversion resolves that overload at the boundary. The
	// address form then rejects it, as `!IP` did here.
	SendPacket(packet,
		CNetworkAddress::FromIPv4NetworkOrderOrAbsent(IP),
		port,
		bEncrypt,
		pachTargetClientHashORKadID,
		bKad,
		nReceiverVerifyKey);
}

void CMuleUDPSocket::SendPacket(CPacket *packet,
	const CNetworkAddress &target,
	uint16 port,
	bool bEncrypt,
	const uint8 *pachTargetClientHashORKadID,
	bool bKad,
	uint32 nReceiverVerifyKey)
{
	wxCHECK_RET(packet, "Invalid packet.");
	/*wxCHECK_RET(port, "Invalid port.");
	wxCHECK_RET(IP, "Invalid IP.");
	*/

	// Absent and unspecified are both refused, exactly as `!IP` refused both.
	if (!port || target.IsAbsent() || target.IsUnspecified()) {
		return;
	}

	const wxString targetText = wxString(target.ToString()) + ":" + (CFormat("%u") % port).GetString();

	if (!Ok()) {
		AddDebugLogLineN(logMuleUDP,
			(m_name + ": Packet discarded, socket not Ok (")
				<< targetText << "): " << packet->GetPacketSize() << "b");
		delete packet;

		return;
	}

	AddDebugLogLineN(logMuleUDP,
		(m_name + ": Packet queued (") << targetText << "): " << packet->GetPacketSize() << "b");

	UDPPack newpending;
	newpending.target = target;
	// Zero when the target has no 32-bit form, i.e. a native IPv6 peer. Every
	// use of it below tests it first.
	newpending.IP = target.ToIPv4NetworkOrderOrZero();
	newpending.port = port;
	newpending.packet = packet;
	newpending.time = GetTickCount64();
	// The ed2k UDP obfuscation key is derived from a 32-bit address on both
	// sides (CEncryptedDatagramSocket), so a native IPv6 target cannot derive
	// the same key and would read an obfuscated datagram as junk. Sending it in
	// the clear is the only thing the protocol allows for that peer; a peer
	// requiring obfuscation is one that could not have reached us over IPv6 in
	// the first place.
	newpending.bEncrypt = bEncrypt &&
			      (pachTargetClientHashORKadID != NULL || (bKad && nReceiverVerifyKey != 0)) &&
			      thePrefs::IsClientCryptLayerSupported() && newpending.IP != 0;
	newpending.bKad = bKad;
	newpending.nReceiverVerifyKey = nReceiverVerifyKey;
	if (newpending.bEncrypt && pachTargetClientHashORKadID != NULL) {
		md4cpy(newpending.pachTargetClientHashORKadID, pachTargetClientHashORKadID);
	} else {
		md4clr(newpending.pachTargetClientHashORKadID);
	}

	{
		wxMutexLocker lock(m_mutex);
		m_queue.push_back(newpending);
	}

	theApp->uploadBandwidthThrottler->QueueForSendingControlPacket(this);
}

bool CMuleUDPSocket::Ok()
{
	wxMutexLocker lock(m_mutex);

	return m_socket && m_socket->IsOk();
}

SocketSentBytes CMuleUDPSocket::SendControlData(uint32 maxNumberOfBytesToSend, uint32 WXUNUSED(minFragSize))
{
	wxMutexLocker lock(m_mutex);
	uint32 sentBytes = 0;
	while (!m_queue.empty() && !m_busy && (sentBytes < maxNumberOfBytesToSend)) {
		UDPPack item = m_queue.front();
		CPacket *packet = item.packet;
		if (GetTickCount64() - item.time < UDPMAXQUEUETIME) {
			uint32_t len = packet->GetPacketSize() + 2;
			uint8_t *sendbuffer = new uint8_t[len];
			memcpy(sendbuffer, packet->GetUDPHeader(), 2);
			memcpy(sendbuffer + 2, packet->GetDataBuffer(), packet->GetPacketSize());

			if (item.bEncrypt && (theApp->GetPublicIP() > 0 || item.bKad)) {
				len = CEncryptedDatagramSocket::EncryptSendClient(&sendbuffer,
					len,
					item.pachTargetClientHashORKadID,
					item.bKad,
					item.nReceiverVerifyKey,
					(item.bKad ? Kademlia::CPrefs::GetUDPVerifyKey(item.IP) : 0));
			}

			if (SendTo(sendbuffer, len, item.target, item.port)) {
				sentBytes += len;
				m_queue.pop_front();
				delete packet;
				delete[] sendbuffer;
			} else {
				// TODO: Needs better error handling, see SentTo
				delete[] sendbuffer;
				break;
			}
		} else {
			m_queue.pop_front();
			delete packet;
		}
	}
	if (!m_busy && !m_queue.empty()) {
		theApp->uploadBandwidthThrottler->QueueForSendingControlPacket(this);
	}
	SocketSentBytes returnVal = { true, 0, sentBytes };

	return returnVal;
}

bool CMuleUDPSocket::SendTo(
	uint8_t *buffer, uint32_t length, const CNetworkAddress &target, uint16_t port)
{
	// Just pretend that we sent the packet in order to avoid infinite loops.
	if (!(m_socket && m_socket->IsOk())) {
		return true;
	}

	amuleIPV4Address addr;
	// SetAddress() keeps the family, where Hostname(uint32) could only ever
	// produce an IPv4 endpoint -- which is why a reply to an IPv6 peer had
	// nowhere to go before.
	addr.SetAddress(target);
	addr.Service(port);
	const wxString targetText = wxString(target.ToString()) + ":" + (CFormat("%u") % port).GetString();

	// We better clear this flag here, status might have been changed
	// between the U.B.T. addition and the real sending happening later
	m_busy = false;
	bool sent = false;
	m_socket->SendTo(addr, buffer, length);
	if (m_socket->BlocksWrite()) {
		// Socket is busy and can't send this data right now,
		// so we just return not sent and set the wouldblock
		// flag so it gets resent when socket is ready.
		m_busy = true;
	} else if (uint32 error = m_socket->LastError()) {
		// An error which we can't handle happened, so we drop
		// the packet rather than risk entering an infinite loop.
		AddLogLineN(
			CFormat(_("WARNING! %s: Packet to %s discarded due to error (%s) while sending.")) %
			m_name % targetText % error);
		sent = true;
	} else {
		AddDebugLogLineN(logMuleUDP,
			(m_name + ": Packet sent (") << targetText << "): " << length << "b");
		sent = true;
	}

	return sent;
}

// File_checked_for_headers
