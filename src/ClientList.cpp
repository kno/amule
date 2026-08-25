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

#include "ClientList.h" // Interface declarations.

#include "BrowseManager.h"

#include <protocol/Protocols.h>
#include <protocol/ed2k/Constants.h>
#include <protocol/kad/Client2Client/UDP.h>
#include <protocol/kad/Constants.h>
#include <protocol/kad2/Client2Client/TCP.h>

#include "amule.h"            // Needed for theApp
#include "ChatSessionStore.h" // Needed for CChatSessionStore
#include "ClientTCPSocket.h"  // Needed for CClientTCPSocket
#include "DownloadQueue.h"    // Needed for CDownloadQueue
#include "UploadQueue.h"      // Needed for CUploadQueue
#include "IPFilter.h"         // Needed for CIPFIlter
#include "updownclient.h"     // Needed for CUpDownClient
#include "Preferences.h"      // Needed for thePrefs
#include "Statistics.h"       // Needed for theStats
#include "Logger.h"
#include "GuiEvents.h" // Needed for Notify_*
#include "Packet.h"

#include <common/Format.h>

#include "kademlia/kademlia/Search.h"
#include "kademlia/kademlia/SearchManager.h"
#include "kademlia/kademlia/UDPFirewallTester.h"
#include "kademlia/net/KademliaUDPListener.h"
#include "kademlia/routing/Contact.h"

/**
 * CDeletedClient Class
 *
 * This class / list is a bit overkill, but currently needed to avoid any
 * exploit possibility. It will keep track of certain clients attributes
 * for 2 hours, while the CUpDownClient object might be deleted already.
 * Currently saves: IP, Port, UserHash.
 */
class CDeletedClient
{
public:
	CDeletedClient(CUpDownClient *pClient)
	{
		m_dwInserted = ::GetTickCount64();
		PortAndHash porthash = { pClient->GetUserPort(), pClient->GetCreditsHash() };
		m_ItemsList.push_back(porthash);
	}

	struct PortAndHash
	{
		uint16 nPort;
		void *pHash;
	};

	typedef std::list<PortAndHash> PaHList;
	PaHList m_ItemsList;
	uint64 m_dwInserted;
};

CClientList::CClientList()
: m_deadSources(true)
{
	m_dwLastBannCleanUp = 0;
	m_dwLastTrackedCleanUp = 0;
	m_dwLastClientCleanUp = 0;
	m_nBuddyStatus = Disconnected;
}

CClientList::~CClientList()
{
	DeleteContents(m_trackedClientsList);

	wxASSERT(m_clientList.empty());
}

void CClientList::AddClient(CUpDownClient *toadd)
{
	// Ensure that only new clients can be added to the list
	if (toadd->GetClientState() == CS_NEW) {
		// Update the client-state
		toadd->m_clientState = CS_LISTED;

		// Notify_ClientCtrlAddClient( toadd );

		// We always add the ID/ptr pair, regardless of the actual ID value
		m_clientList.insert(IDMapPair(toadd->GetUserIDHybrid(),
			CCLIENTREF(toadd, "CClientList::AddClient m_clientList.insert")));

		// We only add the address if we have one. `if (toadd->GetIP())` used to
		// mean that, and no longer can: a native IPv6 peer's 32-bit form is
		// zero, so it would have been read as "no address" and left unindexed --
		// which is exactly the drop this change exists to remove.
		if (PeerIdentity::IsIndexable(toadd->GetAddress())) {
			m_ipList.insert(AddressMapPair(PeerIdentity::IndexKey(toadd->GetAddress()),
				CCLIENTREF(toadd, "CClientList::AddClient m_ipList.insert")));
		}

		// We only add the hash if it is valid
		if (toadd->HasValidHash()) {
			m_hashList.insert(HashMapPair(toadd->GetUserHash(),
				CCLIENTREF(toadd, "CClientList::AddClient m_hashList.insert")));
		}

		toadd->UpdateStats();
	}
}

void CClientList::RemoveClient(CUpDownClient *client)
{
	RemoveFromKadList(client);
	RemoveDirectCallback(client);
	// Drop any browse of this client: the manager holds a reference, and the
	// client is going away, so there is nothing left to report a result to.
	// Guarded like the clientlist call in CUpDownClient::Safe_Delete: clients
	// are still being reaped while the app tears itself down.
	if (theApp->browsemanager) {
		theApp->browsemanager->Forget(client);
	}

	if (RemoveIDFromList(client)) {
		// Also remove the ip and hash entries
		RemoveIPFromList(client);
		RemoveHashFromList(client);
	}
}

void CClientList::UpdateClientID(CUpDownClient *client, uint32 newID)
{
	// Sanity check
	if ((client->GetClientState() != CS_LISTED) || (client->GetUserIDHybrid() == newID))
		return;

	// First remove the ID entry
	RemoveIDFromList(client);

	// Add the new entry
	m_clientList.insert(IDMapPair(newID, CCLIENTREF(client, "CClientList::UpdateClientID")));
}

void CClientList::UpdateClientIP(CUpDownClient *client, const CNetworkAddress &newIP)
{
	// Sanity check. The client now stores the address itself, so this is a
	// direct comparison: an absent new address compares equal to a client that
	// has no address, which is the "nothing to do" case the old
	// `GetIP() == newIP` covered.
	if ((client->GetClientState() != CS_LISTED) || (client->GetAddress() == newIP)) {
		return;
	}

	// Remove the old IP entry
	RemoveIPFromList(client);

	// Explicit absence check, not `if (newIP)`. Every present address has a key
	// now, whatever family it is in; absence still has none.
	if (PeerIdentity::IsIndexable(newIP)) {
		m_ipList.insert(AddressMapPair(
			PeerIdentity::IndexKey(newIP), CCLIENTREF(client, "CClientList::UpdateClientIP")));
	}
}

void CClientList::UpdateClientHash(CUpDownClient *client, const CMD4Hash &newHash)
{
	// Sanity check
	if ((client->GetClientState() != CS_LISTED) || (client->GetUserHash() == newHash))
		return;

	// Remove the old entry
	RemoveHashFromList(client);

	// And add the new one if valid
	if (!newHash.IsEmpty()) {
		m_hashList.insert(HashMapPair(newHash, CCLIENTREF(client, "CClientList::UpdateClientHash")));
	}
}

bool CClientList::RemoveIDFromList(CUpDownClient *client)
{
	bool result = false;

	// First remove the ID entry
	std::pair<IDMap::iterator, IDMap::iterator> range =
		m_clientList.equal_range(client->GetUserIDHybrid());

	for (; range.first != range.second; ++range.first) {
		if (client == range.first->second.GetClient()) {
			/* erase() will invalidate the iterator, but we're not using it anymore
			    anyway (notice the break;) */
			m_clientList.erase(range.first);
			result = true;

			break;
		}
	}

	return result;
}

void CClientList::RemoveIPFromList(CUpDownClient *client)
{
	// Check if we need to look for the IP entry. Explicit absence check rather
	// than `if (!client->GetIP())`: UpdateClientIP() never records an absent
	// address, so there can be no entry to remove for one.
	if (!PeerIdentity::IsIndexable(client->GetAddress())) {
		return;
	}

	// Remove the IP entry
	std::pair<AddressMap::iterator, AddressMap::iterator> range =
		m_ipList.equal_range(PeerIdentity::IndexKey(client->GetAddress()));

	for (; range.first != range.second; ++range.first) {
		if (client == range.first->second.GetClient()) {
			/* erase() will invalidate the iterator, but we're not using it anymore
			    anyway (notice the break;) */
			m_ipList.erase(range.first);
			break;
		}
	}
}

void CClientList::RemoveHashFromList(CUpDownClient *client)
{
	// Nothing to remove
	if (!client->HasValidHash()) {
		return;
	}

	// Find all items with the specified hash
	std::pair<HashMap::iterator, HashMap::iterator> range = m_hashList.equal_range(client->GetUserHash());

	for (; range.first != range.second; ++range.first) {
		if (client == range.first->second.GetClient()) {
			/* erase() will invalidate the iterator, but we're not using it anymore
			    anyway (notice the break;) */
			m_hashList.erase(range.first);
			break;
		}
	}
}

CUpDownClient *CClientList::FindMatchingClient(CUpDownClient *client)
{
	typedef std::pair<IDMap::const_iterator, IDMap::const_iterator> IDMapIteratorPair;
	typedef std::pair<AddressMap::const_iterator, AddressMap::const_iterator> AddressMapIteratorPair;
	wxCHECK(client, NULL);

	const CNetworkAddress userAddress = PeerIdentity::IndexKey(client->GetAddress());
	const uint32 userID = client->GetUserIDHybrid();
	const uint16 userPort = client->GetUserPort();
	const uint16 userKadPort = client->GetKadPort();

	// LowID clients need a different set of checks
	if (client->HasLowID()) {
		// User is firewalled ... Must do two checks.
		if (userAddress.IsPresent() && (userPort || userKadPort)) {
			AddressMapIteratorPair range = m_ipList.equal_range(userAddress);

			for (; range.first != range.second; ++range.first) {
				CUpDownClient *other = range.first->second.GetClient();
				wxASSERT(userAddress == PeerIdentity::IndexKey(other->GetAddress()));

				if (userPort && (userPort == other->GetUserPort())) {
					return other;
				} else if (userKadPort && (userKadPort == other->GetKadPort())) {
					return other;
				}
			}
		}

		const uint32 serverIP = client->GetServerIP();
		const uint32 serverPort = client->GetServerPort();
		if (userID && serverIP && serverPort) {
			IDMapIteratorPair range = m_clientList.equal_range(userID);

			for (; range.first != range.second; ++range.first) {
				CUpDownClient *other = range.first->second.GetClient();
				wxASSERT(userID == other->GetUserIDHybrid());

				// For lowid, we also have to check the server
				if (serverIP == other->GetServerIP()) {
					if (serverPort == other->GetServerPort()) {
						return other;
					}
				}
			}
		}
	} else if (userPort || userKadPort) {
		// Check by address first, then by ID. The two indexes are keyed on
		// different types now -- an address and an ed2k ID are not the same kind
		// of value and never were -- so the pair is walked as two passes rather
		// than as one table over a shared key type.
		if (userAddress.IsPresent()) {
			AddressMapIteratorPair range = m_ipList.equal_range(userAddress);

			if (userPort) {
				for (AddressMap::const_iterator it = range.first; it != range.second; ++it) {
					if (userPort == it->second.GetUserPort()) {
						return it->second.GetClient();
					}
				}
			}

			if (userKadPort) {
				for (AddressMap::const_iterator it = range.first; it != range.second; ++it) {
					if (userKadPort == it->second.GetClient()->GetKadPort()) {
						return it->second.GetClient();
					}
				}
			}
		}

		if (userID != 0) {
			IDMapIteratorPair range = m_clientList.equal_range(userID);

			if (userPort) {
				for (IDMap::const_iterator it = range.first; it != range.second; ++it) {
					if (userPort == it->second.GetUserPort()) {
						return it->second.GetClient();
					}
				}
			}

			if (userKadPort) {
				for (IDMap::const_iterator it = range.first; it != range.second; ++it) {
					if (userKadPort == it->second.GetClient()->GetKadPort()) {
						return it->second.GetClient();
					}
				}
			}
		}
	}

	// If anything else fails, then we look at hashes
	if (client->HasValidHash()) {
		// Find all items with the specified hash
		std::pair<HashMap::iterator, HashMap::iterator> range =
			m_hashList.equal_range(client->GetUserHash());

		// Just return the first item if any
		if (range.first != range.second) {
			return range.first->second.GetClient();
		}
	}

	// Nothing found, must be a new client
	return NULL;
}

uint32 CClientList::GetClientCount() const
{
	return m_clientList.size();
}

void CClientList::DeleteAll()
{
	m_ipList.clear();
	m_hashList.clear();

	while (!m_clientList.empty()) {
		IDMap::iterator it = m_clientList.begin();

		// Will call the removal of the item on this same class
		it->second.GetClient()->Disconnected("Removed while deleting all from ClientList.");
		it->second.GetClient()->Safe_Delete();
	}
}

bool CClientList::AttachToAlreadyKnown(CUpDownClient **client, CClientTCPSocket *sender)
{
	CUpDownClient *tocheck = (*client);

	CUpDownClient *found_client = FindMatchingClient(tocheck);

	if (tocheck == found_client) {
		// We found the same client instance (client may have sent more than one OP_HELLO). do not
		// delete that client!
		return true;
	}

	if (found_client != NULL) {
		if (sender) {
			if (found_client->GetSocket()) {
				if (found_client->IsConnected() &&
					(found_client->GetAddress() != tocheck->GetAddress() ||
						found_client->GetUserPort() != tocheck->GetUserPort())) {
					// if found_client is connected and has the IS_IDENTIFIED, it's safe
					// to say that the other one is a bad guy
					if (found_client->IsIdentified()) {
						AddDebugLogLineN(logClient,
							"Client: " + tocheck->GetUserName() + "(" +
								tocheck->GetFullIP() +
								"), Banreason: Userhash invalid");
						tocheck->Ban();
						return false;
					}

					AddDebugLogLineN(logClient,
						"WARNING! Found matching client, to a currently connected "
						"client: " +
							tocheck->GetUserName() + "(" + tocheck->GetFullIP() +
							") and " + found_client->GetUserName() + "(" +
							found_client->GetFullIP() + ")");
					return false;
				}
				found_client->GetSocket()->Safe_Delete();
			}
			found_client->SetSocket(sender);
			tocheck->SetSocket(NULL);
		}
		*client = 0;
		tocheck->Safe_Delete();
		*client = found_client;
		return true;
	}

	return false;
}

CUpDownClient *CClientList::FindClientByIP(const CNetworkAddress &address, uint16 port)
{
	if (!PeerIdentity::IsIndexable(address)) {
		return NULL;
	}

	// Find all items with the specified address
	std::pair<AddressMap::iterator, AddressMap::iterator> range =
		m_ipList.equal_range(PeerIdentity::IndexKey(address));

	for (; range.first != range.second; ++range.first) {
		CUpDownClient *cur_client = range.first->second.GetClient();
		// Check if it's actually the client we want
		if (cur_client->GetUserPort() == port) {
			return cur_client;
		}
	}

	return NULL;
}

CUpDownClient *CClientList::FindClientByIP(const CNetworkAddress &address)
{
	if (!PeerIdentity::IsIndexable(address)) {
		return NULL;
	}

	// Find all items with the specified address
	std::pair<AddressMap::iterator, AddressMap::iterator> range =
		m_ipList.equal_range(PeerIdentity::IndexKey(address));

	return (range.first != range.second) ? range.first->second.GetClient() : NULL;
}

CUpDownClient *CClientList::FindClientByIP(uint32 clientip, uint16 port)
{
	return FindClientByIP(CNetworkAddress::FromIPv4NetworkOrderOrAbsent(clientip), port);
}

CUpDownClient *CClientList::FindClientByIP(uint32 clientip)
{
	return FindClientByIP(CNetworkAddress::FromIPv4NetworkOrderOrAbsent(clientip));
}

CUpDownClient *CClientList::FindClientByECID(uint32 ecid) const
{
	for (IDMap::const_iterator it = m_clientList.begin(); it != m_clientList.end(); ++it) {
		if (it->second.ECID() == ecid) {
			return it->second.GetClient();
		}
	}

	return NULL;
}

bool CClientList::IsIPAlreadyKnown(const CNetworkAddress &address)
{
	if (!PeerIdentity::IsIndexable(address)) {
		// Absence was never recorded, so it is not known.
		return false;
	}
	// Find all items with the specified address
	std::pair<AddressMap::iterator, AddressMap::iterator> range =
		m_ipList.equal_range(PeerIdentity::IndexKey(address));
	return range.first != range.second;
}

bool CClientList::ComparePriorUserhash(const CNetworkAddress &address, uint16 nPort, void *pNewHash)
{
	if (!PeerIdentity::IsIndexable(address)) {
		// No address, no tracked history to contradict the new hash. Formerly
		// this looked the literal 0 up, which could only ever miss.
		return true;
	}
	std::map<CNetworkAddress, CDeletedClient *>::iterator it =
		m_trackedClientsList.find(PeerIdentity::IndexKey(address));

	if (it != m_trackedClientsList.end()) {
		CDeletedClient *pResult = it->second;

		CDeletedClient::PaHList::iterator it2 = pResult->m_ItemsList.begin();
		for (; it2 != pResult->m_ItemsList.end(); ++it2) {
			if (it2->nPort == nPort) {
				if (it2->pHash != pNewHash) {
					return false;
				} else {
					break;
				}
			}
		}
	}
	return true;
}

void CClientList::AddTrackClient(CUpDownClient *toadd)
{
	if (!PeerIdentity::IsIndexable(toadd->GetAddress())) {
		// Nothing to track a hash change against: the entry would be keyed on
		// "unknown", where every addressless client would collide.
		return;
	}
	const CNetworkAddress key = PeerIdentity::IndexKey(toadd->GetAddress());
	std::map<CNetworkAddress, CDeletedClient *>::iterator it = m_trackedClientsList.find(key);

	if (it != m_trackedClientsList.end()) {
		CDeletedClient *pResult = it->second;

		pResult->m_dwInserted = ::GetTickCount64();

		CDeletedClient::PaHList::iterator it2 = pResult->m_ItemsList.begin();
		for (; it2 != pResult->m_ItemsList.end(); ++it2) {
			if (it2->nPort == toadd->GetUserPort()) {
				// already tracked, update
				it2->pHash = toadd->GetCreditsHash();
				return;
			}
		}

		// New client for that IP, add an entry
		CDeletedClient::PortAndHash porthash = { toadd->GetUserPort(), toadd->GetCreditsHash() };
		pResult->m_ItemsList.push_back(porthash);
	} else {
		m_trackedClientsList[key] = new CDeletedClient(toadd);
	}
}

void CClientList::Process()
{
	const uint64 cur_tick = ::GetTickCount64();

	if (m_dwLastBannCleanUp + BAN_CLEANUP_TIME < cur_tick) {
		m_dwLastBannCleanUp = cur_tick;

		ClientMap::iterator it = m_bannedList.begin();
		while (it != m_bannedList.end()) {
			if (it->second + CLIENTBANTIME < cur_tick) {
				ClientMap::iterator tmp = it++;

				m_bannedList.erase(tmp);
				theStats::RemoveBannedClient();
			} else {
				++it;
			}
		}
	}

	if (m_dwLastTrackedCleanUp + TRACKED_CLEANUP_TIME < cur_tick) {
		m_dwLastTrackedCleanUp = cur_tick;

		std::map<CNetworkAddress, CDeletedClient *>::iterator it = m_trackedClientsList.begin();
		while (it != m_trackedClientsList.end()) {
			std::map<CNetworkAddress, CDeletedClient *>::iterator cur_src = it++;

			if (cur_src->second->m_dwInserted + KEEPTRACK_TIME < cur_tick) {
				delete cur_src->second;
				m_trackedClientsList.erase(cur_src);
			}
		}
	}

	// We need to try to connect to the clients in m_KadList
	// If connected, remove them from the list and send a message back to Kad so we can send a ACK.
	// If we don't connect, we need to remove the client..
	// The sockets timeout should delete this object.

	// buddy is just a flag that is used to make sure we are still connected or connecting to a buddy.
	buddyState buddy = Disconnected;

	CClientRefSet::iterator current_it = m_KadSources.begin();
	while (current_it != m_KadSources.end()) {
		CUpDownClient *cur_client = current_it->GetClient();
		++current_it; // Won't be used anymore till while loop
		if (!Kademlia::CKademlia::IsRunning()) {
			// Clear out this list if we stop running Kad.
			// Setting the Kad state to KS_NONE causes it to be removed in the switch below.
			cur_client->SetKadState(KS_NONE);
		}
		switch (cur_client->GetKadState()) {
		case KS_QUEUED_FWCHECK:
		case KS_QUEUED_FWCHECK_UDP:
			// Another client asked us to try to connect to them to check their firewalled status.
			cur_client->TryToConnect(true);
			break;

		case KS_CONNECTING_FWCHECK:
			// Ignore this state as we are just waiting for results.
			break;

		case KS_FWCHECK_UDP:
		case KS_CONNECTING_FWCHECK_UDP:
			// We want a UDP firewallcheck from this client and are just waiting to get connected
			// to send the request
			break;

		case KS_CONNECTED_FWCHECK:
			// We successfully connected to the client.
			// We now send a ack to let them know.
			if (cur_client->GetKadVersion() >= 7) {
				// The result is now sent per TCP instead of UDP, because this will fail if
				// our intern port is unreachable. But we want the TCP testresult regardless
				// if UDP is firewalled, the new UDP state and test takes care of the rest
				wxASSERT(cur_client->IsConnected());
				AddDebugLogLineN(logLocalClient,
					"Local Client: OP_KAD_FWTCPCHECK_ACK to " +
						Uint32toStringIP(cur_client->GetIP()));
				CPacket *packet = new CPacket(OP_KAD_FWTCPCHECK_ACK, 0, OP_EMULEPROT);
				cur_client->SafeSendPacket(packet);
			} else {
				AddDebugLogLineN(logClientKadUDP,
					"KadFirewalledAckRes to " +
						Uint32_16toStringIP_Port(
							cur_client->GetIP(), cur_client->GetKadPort()));
				Kademlia::CKademlia::GetUDPListener()->SendNullPacket(
					KADEMLIA_FIREWALLED_ACK_RES,
					wxUINT32_SWAP_ALWAYS(cur_client->GetIP()),
					cur_client->GetKadPort(),
					0,
					NULL);
			}
			// We are done with this client. Set Kad status to KS_NONE and it will be removed in
			// the next cycle.
			cur_client->SetKadState(KS_NONE);
			break;

		case KS_INCOMING_BUDDY:
			// A firewalled client wants us to be his buddy.
			// If we already have a buddy, we set Kad state to KS_NONE and it's removed in the
			// next cycle. If not, this client will change to KS_CONNECTED_BUDDY when it connects.
			if (m_nBuddyStatus == Connected) {
				cur_client->SetKadState(KS_NONE);
			}
			break;

		case KS_QUEUED_BUDDY:
			// We are firewalled and want to request this client to be a buddy.
			// But first we check to make sure we are not already trying another client.
			// If we are not already trying. We try to connect to this client.
			// If we are already connected to a buddy, we set this client to KS_NONE and it's
			// removed next cycle. If we are trying to connect to a buddy, we just ignore as the
			// one we are trying may fail and we can then try this one.
			if (m_nBuddyStatus == Disconnected) {
				buddy = Connecting;
				m_nBuddyStatus = Connecting;
				cur_client->SetKadState(KS_CONNECTING_BUDDY);
				cur_client->TryToConnect(true);
				Notify_ServerUpdateED2KInfo();
			} else {
				if (m_nBuddyStatus == Connected) {
					cur_client->SetKadState(KS_NONE);
				}
			}
			break;

		case KS_CONNECTING_BUDDY:
			// We are trying to connect to this client.
			// Although it should NOT happen, we make sure we are not already connected to a
			// buddy. If we are we set to KS_NONE and it's removed next cycle. But if we are not
			// already connected, make sure we set the flag to connecting so we know things are
			// working correctly.
			if (m_nBuddyStatus == Connected) {
				cur_client->SetKadState(KS_NONE);
			} else {
				wxASSERT(m_nBuddyStatus == Connecting);
				buddy = Connecting;
			}
			break;

		case KS_CONNECTED_BUDDY:
			// A potential connected buddy client wanting to me in the Kad network
			// We set our flag to connected to make sure things are still working correctly.
			buddy = Connected;

			// If m_nBuddyStatus is not connected already, we set this client as our buddy!
			if (m_nBuddyStatus != Connected) {
				m_pBuddy.Link(cur_client CLIENT_DEBUGSTRING(
					"CClientList::Process KS_CONNECTED_BUDDY m_pBuddy.Link"));
				m_nBuddyStatus = Connected;
				Notify_ServerUpdateED2KInfo();
			}
			if (m_pBuddy.GetClient() == cur_client && theApp->IsFirewalled() &&
				cur_client->SendBuddyPingPong()) {
				cur_client->SendBuddyPing();
			}
			break;

		default:
			RemoveFromKadList(cur_client);
		}
	}

	// We either never had a buddy, or lost our buddy..
	if (buddy == Disconnected) {
		if (m_nBuddyStatus != Disconnected || m_pBuddy.IsLinked()) {
			if (Kademlia::CKademlia::IsRunning() && theApp->IsFirewalled() &&
				Kademlia::CUDPFirewallTester::IsFirewalledUDP(true)) {
				// We are a lowID client and we just lost our buddy.
				// Go ahead and instantly try to find a new buddy.
				Kademlia::CKademlia::GetPrefs()->SetFindBuddy();
			}
			m_pBuddy.Unlink();
			m_nBuddyStatus = Disconnected;
			Notify_ServerUpdateED2KInfo();
		}
	}

	if (Kademlia::CKademlia::IsConnected()) {
		// we only need a buddy if direct callback is not available
		if (Kademlia::CKademlia::IsFirewalled() &&
			Kademlia::CUDPFirewallTester::IsFirewalledUDP(true)) {
			// TODO: Kad buddies won't work with RequireCrypt, so it is disabled for now, but
			// should (and will) be fixed in later version Update: buddy connections themselves
			// support obfuscation properly since eMule 0.49a and aMule SVN 2008-05-09 (this makes
			// it work fine if our buddy uses require crypt), however callback requests don't
			// support it yet so we wouldn't be able to answer callback requests with
			// RequireCrypt, protocolchange intended for eMule 0.49b
			if (m_nBuddyStatus == Disconnected &&
				Kademlia::CKademlia::GetPrefs()->GetFindBuddy() &&
				!thePrefs::IsClientCryptLayerRequired()) {
				AddDebugLogLineN(logKadMain, "Starting BuddySearch");
				// We are a firewalled client with no buddy. We have also waited a set time
				// to try to avoid a false firewalled status.. So lets look for a buddy..
				if (!Kademlia::CSearchManager::PrepareLookup(Kademlia::CSearch::FINDBUDDY,
					    true,
					    Kademlia::CUInt128(true) ^
						    (Kademlia::CKademlia::GetPrefs()->GetKadID()))) {
					// This search ID was already going. Most likely reason is that
					// we found and lost our buddy very quickly and the last search hadn't
					// had time to be removed yet. Go ahead and set this to happen again
					// next time around.
					Kademlia::CKademlia::GetPrefs()->SetFindBuddy();
				}
			}
		} else {
			if (m_pBuddy.IsLinked()) {
				// Lets make sure that if we have a buddy, they are firewalled!
				// If they are also not firewalled, then someone must have fixed their
				// firewall or stopped saturating their line.. We just set the state of this
				// buddy to KS_NONE and things will be cleared up with the next cycle.
				if (!m_pBuddy.HasLowID()) {
					m_pBuddy.GetClient()->SetKadState(KS_NONE);
				}
			}
		}
	} else {
		if (m_pBuddy.IsLinked()) {
			// We are not connected anymore. Just set this buddy to KS_NONE and things will be
			// cleared out on next cycle.
			m_pBuddy.GetClient()->SetKadState(KS_NONE);
		}
	}

	CleanUpClientList();
	ProcessDirectCallbackList();
	theApp->browsemanager->Process(cur_tick);
}

void CClientList::AddBannedClient(const CNetworkAddress &address)
{
	if (!PeerIdentity::IsIndexable(address)) {
		// Nothing to ban. Previously an absent address arrived here as the
		// literal 0 and was banned as "0.0.0.0", banning a value no real peer
		// has while telling theStats one more client was banned.
		AddDebugLogLineN(logClient,
			CFormat("AddBannedClient: no bannable address (%s), ignored") % address.ToString());
		return;
	}
	// An IPv6 peer is bannable now: the key is the address, so there is no
	// longer a family the ban list cannot express.
	m_bannedList[PeerIdentity::IndexKey(address)] = ::GetTickCount64();
	theStats::AddBannedClient();
}

bool CClientList::IsBannedClient(const CNetworkAddress &address)
{
	if (!PeerIdentity::IsIndexable(address)) {
		return false;
	}

	ClientMap::iterator it = m_bannedList.find(PeerIdentity::IndexKey(address));

	if (it != m_bannedList.end()) {
		if (it->second + CLIENTBANTIME > ::GetTickCount64()) {
			return true;
		} else {
			RemoveBannedClient(address);
		}
	}
	return false;
}

void CClientList::RemoveBannedClient(const CNetworkAddress &address)
{
	if (!PeerIdentity::IsIndexable(address)) {
		return;
	}
	m_bannedList.erase(PeerIdentity::IndexKey(address));
	theStats::RemoveBannedClient();
}

void CClientList::FilterQueues()
{
	// Filter client list
	for (AddressMap::iterator it = m_ipList.begin(); it != m_ipList.end();) {
		AddressMap::iterator tmp = it++; // Don't change this to a ++it!
		CUpDownClient *client = tmp->second.GetClient();
		if (theApp->ipfilter->IsFiltered(client->GetConnectAddress())) {
			client->Disconnected("Filtered by IPFilter");
			client->Safe_Delete();
		}
	}
}

CClientList::SourceList CClientList::GetClientsByHash(const CMD4Hash &hash)
{
	SourceList results;

	// Find all items with the specified hash
	std::pair<HashMap::iterator, HashMap::iterator> range = m_hashList.equal_range(hash);

	for (; range.first != range.second; ++range.first) {
		results.push_back(range.first->second);
	}

	return results;
}

CClientList::SourceList CClientList::GetClientsByIP(const CNetworkAddress &address)
{
	SourceList results;

	if (!PeerIdentity::IsIndexable(address)) {
		// Absence is not a key: no client can be recorded under it, so the
		// empty list is the whole answer.
		return results;
	}

	// Find all items with the specified address
	std::pair<AddressMap::iterator, AddressMap::iterator> range =
		m_ipList.equal_range(PeerIdentity::IndexKey(address));

	for (; range.first != range.second; range.first++) {
		results.push_back(range.first->second);
	}

	return results;
}

CClientList::SourceList CClientList::GetClientsInRateLimitScope(const CNetworkAddress &address)
{
	SourceList results;

	const CNetworkAddress scope = PeerIdentity::RateLimitScope(address);
	if (scope.IsAbsent()) {
		return results;
	}

	// The index is ordered by address, octets most significant first, so every
	// member of a prefix occupies one contiguous run of it. Starting at the
	// prefix's network address and stopping when the scope changes therefore
	// visits exactly that run -- O(log n + k), the same cost class as the
	// exact-address lookup this replaces, rather than a scan of every client.
	AddressMap::iterator it = m_ipList.lower_bound(scope);
	for (; it != m_ipList.end(); ++it) {
		if (PeerIdentity::RateLimitScope(it->first) != scope) {
			break;
		}
		results.push_back(it->second);
	}

	return results;
}

const CClientList::IDMap &CClientList::GetClientList()
{
	return m_clientList;
}

void CClientList::AddDeadSource(const CUpDownClient *client)
{
	m_deadSources.AddDeadSource(client);
}

bool CClientList::IsDeadSource(const CUpDownClient *client)
{
	return m_deadSources.IsDeadSource(client);
}

bool CClientList::SendChatMessage(uint64 client_id, const wxString &message)
{
	CUpDownClient *client = FindClientByIP(IP_FROM_GUI_ID(client_id), PORT_FROM_GUI_ID(client_id));
	AddDebugLogLineN(logClient, "Trying to Send Message.");
	if (client) {
		AddDebugLogLineN(logClient, "Sending.");
	} else {
		AddDebugLogLineC(logClient,
			CFormat("No client (GUI_ID %lli [%s:%llu]) found in CClientList::SendChatMessage(). "
				"Creating") %
				client_id % Uint32toStringIP(IP_FROM_GUI_ID(client_id)) %
				PORT_FROM_GUI_ID(client_id));
		client = new CUpDownClient(
			PORT_FROM_GUI_ID(client_id), IP_FROM_GUI_ID(client_id), 0, 0, NULL, true, true);
		AddClient(client);
	}
	// Record before sending, and record regardless of the result: a false
	// return from CUpDownClient::SendChatMessage means "queued while
	// connecting", not "failed" (the desktop optimistically prints
	// *** Connecting to Client *** and keeps the line in the transcript), so
	// gating the store on it would drop exactly the messages a slow peer
	// receives a moment later.
	if (theApp->chatsessions) {
		theApp->chatsessions->AddOutgoing(client_id, message);
	}
	return client->SendChatMessage(message);
}

void CClientList::SetChatState(uint64 client_id, uint8 state)
{
	CUpDownClient *client = FindClientByIP(IP_FROM_GUI_ID(client_id), PORT_FROM_GUI_ID(client_id));
	if (client) {
		client->SetChatState(state);
	}
}

/* Kad stuff */

bool CClientList::RequestTCP(Kademlia::CContact *contact, uint8_t connectOptions)
{
	uint32_t nContactIP = wxUINT32_SWAP_ALWAYS(contact->GetIPAddress());
	// don't connect ourself
	if (theApp->GetPublicIP() == nContactIP && thePrefs::GetPort() == contact->GetTCPPort()) {
		return false;
	}

	CUpDownClient *pNewClient = FindClientByIP(nContactIP, contact->GetTCPPort());

	if (!pNewClient) {
		// #warning Do we actually have to check friendstate here?
		pNewClient = new CUpDownClient(
			contact->GetTCPPort(), contact->GetIPAddress(), 0, 0, NULL, false, true);
	} else if (pNewClient->GetKadState() != KS_NONE) {
		return false; // already busy with this client in some way (probably buddy stuff), don't mess
			      // with it
	}

	// Add client to the lists to be processed.
	pNewClient->SetKadPort(contact->GetUDPPort());
	pNewClient->SetKadState(KS_QUEUED_FWCHECK);
	if (contact->GetClientID() != 0) {
		uint8_t ID[16];
		contact->GetClientID().ToByteArray(ID);
		pNewClient->SetUserHash(CMD4Hash(ID));
		pNewClient->SetConnectOptions(connectOptions, true, false);
	}
	AddToKadList(pNewClient); // This was a direct adding, but I like to check duplicates
	// This method checks if this is a dup already.
	AddClient(pNewClient);
	return true;
}

void CClientList::RequestBuddy(Kademlia::CContact *contact, uint8_t connectOptions)
{
	uint32_t nContactIP = wxUINT32_SWAP_ALWAYS(contact->GetIPAddress());
	// Don't connect to ourself
	if (theApp->GetPublicIP() == nContactIP && thePrefs::GetPort() == contact->GetTCPPort()) {
		return;
	}

	CUpDownClient *pNewClient = FindClientByIP(nContactIP, contact->GetTCPPort());
	if (!pNewClient) {
		pNewClient = new CUpDownClient(
			contact->GetTCPPort(), contact->GetIPAddress(), 0, 0, NULL, false, true);
	} else if (pNewClient->GetKadState() != KS_NONE) {
		return; // already busy with this client in some way (probably fw stuff), don't mess with it
	} else if (IsKadFirewallCheckIP(nContactIP)) { // doing a kad firewall check with this IP, abort
		AddDebugLogLineN(logKadMain,
			"Kad TCP firewallcheck / Buddy request collision for IP " +
				Uint32toStringIP(nContactIP));
		return;
	}

	// Add client to the lists to be processed.
	pNewClient->SetKadPort(contact->GetUDPPort());
	pNewClient->SetKadState(KS_QUEUED_BUDDY);
	uint8_t ID[16];
	contact->GetClientID().ToByteArray(ID);
	pNewClient->SetUserHash(CMD4Hash(ID));
	pNewClient->SetConnectOptions(connectOptions, true, false);
	AddToKadList(pNewClient);
	// This method checks if this is a dup already.
	AddClient(pNewClient);
}

bool CClientList::IncomingBuddy(Kademlia::CContact *contact, Kademlia::CUInt128 *buddyID)
{
	uint32_t nContactIP = wxUINT32_SWAP_ALWAYS(contact->GetIPAddress());
	// If aMule already knows this client, abort this.. It could cause conflicts.
	// Although the odds of this happening is very small, it could still happen.
	if (FindClientByIP(nContactIP, contact->GetTCPPort())) {
		return false;
	} else if (IsKadFirewallCheckIP(nContactIP)) { // doing a kad firewall check with this IP, abort
		AddDebugLogLineN(logKadMain,
			"Kad TCP firewallcheck / Buddy request collision for IP " +
				Uint32toStringIP(nContactIP));
		return false;
	}

	if (theApp->GetPublicIP() == nContactIP && thePrefs::GetPort() == contact->GetTCPPort()) {
		return false; // don't connect ourself
	}

	// Add client to the lists to be processed.
	CUpDownClient *pNewClient =
		new CUpDownClient(contact->GetTCPPort(), contact->GetIPAddress(), 0, 0, NULL, false, true);
	pNewClient->SetKadPort(contact->GetUDPPort());
	pNewClient->SetKadState(KS_INCOMING_BUDDY);
	uint8_t ID[16];
	contact->GetClientID().ToByteArray(ID);
	pNewClient->SetUserHash(CMD4Hash(ID));
	buddyID->ToByteArray(ID);
	pNewClient->SetBuddyID(ID);
	AddToKadList(pNewClient);
	AddClient(pNewClient);
	return true;
}

void CClientList::RemoveFromKadList(CUpDownClient *torem)
{
	wxCHECK_RET(torem, "NULL pointer in RemoveFromKadList");

	if (m_KadSources.erase(CCLIENTREF(torem, ""))) {
		if (torem == m_pBuddy.GetClient()) {
			m_pBuddy.Unlink();
			m_nBuddyStatus = Disconnected;
			Notify_ServerUpdateED2KInfo();
		}
	}
}

void CClientList::AddToKadList(CUpDownClient *toadd)
{
	wxCHECK_RET(toadd, "NULL pointer in AddToKadList");

	m_KadSources.insert(
		CCLIENTREF(toadd, "CClientList::AddToKadList")); // This will take care of duplicates.
}

bool CClientList::DoRequestFirewallCheckUDP(const Kademlia::CContact &contact)
{
	// first make sure we don't know this IP already from somewhere
	// contact.GetIPAddress() is in Kad host order; the conversion says so
	// instead of a bare wxUINT32_SWAP_ALWAYS.
	if (IsIPAlreadyKnown(CNetworkAddress::FromIPv4HostOrderOrAbsent(contact.GetIPAddress()))) {
		return false;
	}
	// fine, just create the client object, set the state and wait
	// TODO: We don't know the client's userhash, this means we cannot build an obfuscated connection,
	// which again mean that the whole check won't work on "Require Obfuscation" setting, which is not a
	// huge problem, but certainly not nice. Only somewhat acceptable way to solve this is to use the
	// KadID instead.
	CUpDownClient *pNewClient =
		new CUpDownClient(contact.GetTCPPort(), contact.GetIPAddress(), 0, 0, NULL, false, true);
	pNewClient->SetKadState(KS_QUEUED_FWCHECK_UDP);
	AddDebugLogLineN(
		logClient, "Selected client for UDP Firewallcheck: " + KadIPToString(contact.GetIPAddress()));
	AddToKadList(pNewClient);
	AddClient(pNewClient);
	wxASSERT(!pNewClient->SupportsDirectUDPCallback());
	return true;
}

void CClientList::CleanUpClientList()
{
	// We remove clients which are not needed any more by time
	// this check is also done on CUpDownClient::Disconnected, however it will not catch all
	// cases (if a client changes the state without being connected
	//
	// Adding this check directly to every point where any state changes would be more effective,
	// is however not compatible with the current code, because there are points where a client has
	// no state for some code lines and the code is also not prepared that a client object gets
	// invalid while working with it (aka setting a new state)
	// so this way is just the easy and safe one to go (as long as amule is basically single threaded)
	const uint64 cur_tick = ::GetTickCount64();
	if (m_dwLastClientCleanUp + CLIENTLIST_CLEANUP_TIME < cur_tick) {
		m_dwLastClientCleanUp = cur_tick;
		DEBUG_ONLY(uint32 cDeleted = 0;)
		IDMap::iterator current_it = m_clientList.begin();
		while (current_it != m_clientList.end()) {
			CUpDownClient *pCurClient = current_it->second.GetClient();
			++current_it; // Won't be used till while loop again
			// Don't delete sources coming from source seeds for 10 mins,
			// to give them a chance to connect and become a useful source.
			if (pCurClient->GetSourceFrom() == SF_SOURCE_SEEDS &&
				cur_tick - theStats::GetStartTime() < MIN2MS(10))
				continue;
			if ((pCurClient->GetUploadState() == US_NONE ||
				    (pCurClient->GetUploadState() == US_BANNED && !pCurClient->IsBanned())) &&
				pCurClient->GetDownloadState() == DS_NONE &&
				pCurClient->GetChatState() == MS_NONE &&
				pCurClient->GetKadState() == KS_NONE && pCurClient->GetSocket() == NULL) {
				DEBUG_ONLY(cDeleted++;)
				pCurClient->Disconnected("Removed during ClientList cleanup.");
				pCurClient->Safe_Delete();
#ifdef __DEBUG__
			} else {
				if (!(pCurClient->GetUploadState() == US_NONE ||
					    (pCurClient->GetUploadState() == US_BANNED &&
						    !pCurClient->IsBanned()))) {
					AddDebugLogLineN(logProxy,
						CFormat("Debug: Not deleted client %p with up state: %i ") %
							static_cast<void *>(pCurClient) %
							pCurClient->GetUploadState());
				}
				if (!(pCurClient->GetDownloadState() == DS_NONE)) {
					AddDebugLogLineN(logProxy,
						CFormat("Debug: Not deleted client %p with down state: %i ") %
							static_cast<void *>(pCurClient) %
							pCurClient->GetDownloadState());
				}
				if (!(pCurClient->GetChatState() == MS_NONE)) {
					AddDebugLogLineN(logProxy,
						CFormat("Debug: Not deleted client %p with chat state: %i ") %
							static_cast<void *>(pCurClient) %
							pCurClient->GetChatState());
				}
				if (!(pCurClient->GetKadState() == KS_NONE)) {
					AddDebugLogLineN(logProxy,
						CFormat("Debug: Not deleted client %p with kad state: %i ip: "
							"%s") %
							static_cast<void *>(pCurClient) %
							(int)pCurClient->GetKadState() %
							pCurClient->GetFullIP());
				}
				if (!(pCurClient->GetSocket() == NULL)) {
					AddDebugLogLineN(logProxy,
						CFormat("Debug: Not deleted client %p: has socket") %
							static_cast<void *>(pCurClient));
				}
				AddDebugLogLineN(logProxy,
					CFormat("Debug: Not deleted client %p with kad version: %i") %
						static_cast<void *>(pCurClient) %
						pCurClient->GetKadVersion());
#endif
			}
		}
		AddDebugLogLineN(logClient,
			CFormat("Cleaned ClientList, removed %i not used known clients") % cDeleted);
	}
}

void CClientList::AddKadFirewallRequest(uint32 ip)
{
	uint64 ticks = ::GetTickCount64();
	IpAndTicks add = { ip, ticks };
	m_firewallCheckRequests.push_front(add);
	while (!m_firewallCheckRequests.empty()) {
		if (ticks - m_firewallCheckRequests.back().inserted > SEC2MS(180)) {
			m_firewallCheckRequests.pop_back();
		} else {
			break;
		}
	}
}

bool CClientList::IsKadFirewallCheckIP(uint32 ip) const
{
	uint64 ticks = ::GetTickCount64();
	for (IpAndTicksList::const_iterator it = m_firewallCheckRequests.begin();
		it != m_firewallCheckRequests.end();
		++it) {
		if (it->ip == ip && ticks - it->inserted < SEC2MS(180)) {
			return true;
		}
	}
	return false;
}

void CClientList::AddDirectCallbackClient(CUpDownClient *toAdd)
{
	wxASSERT(toAdd->GetDirectCallbackTimeout() != 0);
	if (toAdd->HasBeenDeleted()) {
		return;
	}
	for (DirectCallbackList::const_iterator it = m_currentDirectCallbacks.begin();
		it != m_currentDirectCallbacks.end();
		++it) {
		if (it->GetClient() == toAdd) {
			wxFAIL; // might happen very rarely on multiple connection tries, could be fixed in
				// the client class, till then it's not much of a problem though
			return;
		}
	}
	m_currentDirectCallbacks.push_back(CCLIENTREF(toAdd, "CClientList::AddDirectCallbackClient"));
}

void CClientList::ProcessDirectCallbackList()
{
	// we do check if any direct callbacks have timed out by now
	const uint64_t cur_tick = ::GetTickCount64();
	for (DirectCallbackList::iterator it = m_currentDirectCallbacks.begin();
		it != m_currentDirectCallbacks.end();) {
		DirectCallbackList::iterator it2 = it++;
		CUpDownClient *curClient = it2->GetClient();
		if (curClient->GetDirectCallbackTimeout() < cur_tick) {
			wxASSERT(curClient->GetDirectCallbackTimeout() != 0);
			// TODO LOGREMOVE
			// DebugLog(_T("DirectCallback timed out (%s)"), pCurClient->DbgGetClientInfo());
			m_currentDirectCallbacks.erase(it2);
			if (curClient->Disconnected("Direct Callback Timeout")) {
				curClient->Safe_Delete();
			}
		}
	}
}

void CClientList::AddTrackCallbackRequests(const CNetworkAddress &address)
{
	const CNetworkAddress scope = PeerIdentity::RateLimitScope(address);
	if (scope.IsAbsent()) {
		// No address, no budget to charge. Recording absence would put every
		// addressless requester in one bucket and let one of them throttle the
		// rest.
		return;
	}
	uint64_t now = ::GetTickCount64();
	ScopeAndTicks add = { scope, now };
	m_directCallbackRequests.push_front(add);
	while (!m_directCallbackRequests.empty()) {
		if (now - m_directCallbackRequests.back().inserted > MIN2MS(3)) {
			m_directCallbackRequests.pop_back();
		} else {
			break;
		}
	}
}

bool CClientList::AllowCallbackRequest(const CNetworkAddress &address) const
{
	const CNetworkAddress scope = PeerIdentity::RateLimitScope(address);
	if (scope.IsAbsent()) {
		// An unidentifiable requester gets no callback: it cannot be charged
		// for one either, so allowing it would be an unlimited budget.
		return false;
	}
	uint64_t now = ::GetTickCount64();
	for (ScopeAndTicksList::const_iterator it = m_directCallbackRequests.begin();
		it != m_directCallbackRequests.end();
		++it) {
		if (it->scope == scope && now - it->inserted < MIN2MS(3)) {
			return false;
		}
	}
	return true;
}

uint32 CClientList::GetBuddyIP()
{
	return GetBuddy()->GetIP();
}

uint16 CClientList::GetBuddyPort()
{
	return GetBuddy()->GetUDPPort();
}

// File_checked_for_headers
