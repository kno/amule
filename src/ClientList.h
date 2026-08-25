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

#ifndef CLIENTLIST_H
#define CLIENTLIST_H

#include "DeadSourceList.h" // Needed for CDeadSourceList
#include "ClientRef.h"
#include "NetworkAddress.h" // Needed for CNetworkAddress
#include "PeerIdentity.h"   // Needed for PeerIdentity::IndexKey

#include <deque>
#include <list>
#include <map>
#include <set>

class CUpDownClient;
class CClientTCPSocket;
class CDeletedClient;
class CMD4Hash;
namespace Kademlia
{
class CContact;
class CUInt128;
} // namespace Kademlia

enum buddyState
{
	Disconnected,
	Connecting,
	Connected
};

#define BAN_CLEANUP_TIME 1200000 // 20 min

/**
 * This class takes care of managing existing clients.
 *
 * This class tracks a number of attributes related to existing and deleted
 * clients. Among other things, it keeps track of existing, banned, dead and
 * dying clients, as well as offers support for matching new client-instances
 * against already exist clients to avoid duplicates.
 */
class CClientList
{
public:
	/**
	 * Constructor.
	 */
	CClientList();

	/**
	 * Destructor.
	 */
	~CClientList();

	/**
	 * Adds a client to the global list of clients.
	 *
	 * @param toadd The new client.
	 */
	void AddClient(CUpDownClient *toadd);

	/**
	 * Removes a client from the  client lists.
	 *
	 * @param client The client to be removed.
	 *
	 * To be called from CUpDownClient::Safe_Delete only.
	 */
	void RemoveClient(CUpDownClient *client);

	/**
	 * Updates the recorded IP of the specified client.
	 *
	 * @param client The client to have its entry updated.
	 * @param newIP The new IP address of the client.
	 *
	 * This function is to be called before the client actually changes its
	 * IP-address, and will update the old entry with the new value. An absent
	 * address adds no entry.
	 *
	 * The absence test used to be @c if (newIP), i.e. a client at @c 0.0.0.0 was
	 * indistinguishable from one whose address is unknown. It is now an explicit
	 * IsAbsent() check, and callers holding a 32-bit ed2k field resolve the
	 * overload at the boundary with
	 * CNetworkAddress::FromIPv4NetworkOrderOrAbsent().
	 */
	void UpdateClientIP(CUpDownClient *client, const CNetworkAddress &newIP);

	/**
	 * Updates the recorded ID of the specified client.
	 *
	 * @param client The client to have its entry updated.
	 * @param newID The new ID of the client.
	 *
	 * This function is to be called before the client actually changes its
	 * ID, and will update the old entry with the new value. Unlike the other
	 * two functions, this function will always ensure that there is an entry
	 * for the client, regardless of the value of newID.
	 */
	void UpdateClientID(CUpDownClient *client, uint32 newID);

	/**
	 * Updates the recorded hash of the specified client.
	 *
	 * @param client The client to have its entry updated.
	 * @param newHash The new user-hash.
	 *
	 * This function is to be called before the client actually changes its
	 * user-hash, and will update the old entry with the new value. There will
	 * only be added an entry if the new hash is valid.
	 */
	void UpdateClientHash(CUpDownClient *client, const CMD4Hash &newHash);

	/**
	 * Returns the number of listed clients.
	 */
	uint32 GetClientCount() const;

	/**
	 * Deletes all tracked clients.
	 */
	void DeleteAll();

	/**
	 * Replaces a new client-instance with the an already existing client, if one such exist.
	 *
	 * @param client A pointer to the pointer of the new instance.
	 * @param sender The socket associated with the new instance.
	 *
	 * Call this function when a new client-instance has been created. This function will then
	 * compare it against all existing clients and see if we already have an instance matching
	 * the new one. If that is the case, it will delete the new instance and set the pointer to
	 * the existing one.
	 */
	bool AttachToAlreadyKnown(CUpDownClient **client, CClientTCPSocket *sender);

	/**
	 * Finds a client with the specified address and port.
	 *
	 * @param address The address of the client to find. An absent one finds
	 *                nothing: no client is recorded under absence.
	 * @param port The port used by the client.
	 */
	CUpDownClient *FindClientByIP(const CNetworkAddress &address, uint16 port);

	/**
	 * Finds a client with the specified address.
	 *
	 * Returns the first client found if there are several with same address.
	 */
	CUpDownClient *FindClientByIP(const CNetworkAddress &address);

	/**
	 * The 32-bit forms, for the callers that hold a GUI id or an ed2k packet
	 * field rather than an address. Zero means "unknown" here, as it does in
	 * those fields, and finds nothing.
	 */
	CUpDownClient *FindClientByIP(uint32 clientip, uint16 port);
	CUpDownClient *FindClientByIP(uint32 clientip);

	/**
	 * Finds a client with the specified ECID.
	 *
	 * @param clientip The IP of the client to find.
	 *
	 */
	CUpDownClient *FindClientByECID(uint32 ecid) const;

	//! The list-type used to store client addresses and ban time information.
	//! Keyed on the address so an IPv6 peer can be banned at all -- and so that
	//! an absent address, which has no key, cannot be banned by accident.
	typedef std::map<CNetworkAddress, uint64> ClientMap;

	/**
	 * Adds a client to the list of tracked clients.
	 *
	 * @param toadd The client to track.
	 *
	 * This function is used to keep track of clients after they
	 * have been deleted and makes it possible to spot port or hash
	 * changes.
	 */
	void AddTrackClient(CUpDownClient *toadd);

	/**
	 * Checks if a client has changed its user-hash.
	 *
	 * @param address The address of the client. An absent one has no tracked
	 *                entry, so nothing contradicts the new hash.
	 * @param nPort The port of the client.
	 * @param pNewHash The userhash associated with the client.
	 *
	 */
	bool ComparePriorUserhash(const CNetworkAddress &address, uint16 nPort, void *pNewHash);

	/**
	 * Bans an IP address for 2 hours.
	 *
	 * @param address The address from which all clients will be banned. An
	 *                absent address bans nothing.
	 */
	void AddBannedClient(const CNetworkAddress &address);

	/**
	 * Checks if a client has been banned.
	 *
	 * @param address The address to check.
	 * @return True if the address is banned, false otherwise. An absent address
	 *         is never banned -- there is nothing to have banned.
	 */
	bool IsBannedClient(const CNetworkAddress &address);

	/**
	 * Unbans an IP address, if it has been banned.
	 *
	 * @param address The address to unban. An absent address unbans nothing.
	 */
	void RemoveBannedClient(const CNetworkAddress &address);

	/**
	 * Main loop.
	 *
	 * This function takes care of cleaning the various lists and deleting
	 * pending clients on the deletion-queue.
	 */
	void Process();

	/**
	 * This function removes all clients filtered by the current IPFilter.
	 *
	 * Call this function after changing the current IPFiler list, to ensure
	 * that no client-connections to illegal IPs exist. These would otherwise
	 * be allowed to exist, bypassing the IPFilter.
	 */
	void FilterQueues();

	//! The type of the list used to store client-pointers for a couple of tasks.
	typedef std::deque<CClientRef> SourceList;

	/**
	 * Returns a list of clients with the specified user-hash.
	 *
	 * @param hash The userhash to search for.
	 *
	 * This function will return a list of clients with the specified userhash,
	 * provided that the hash is a valid non-empty userhash. Empty hashes will
	 * simply result in nothing being found.
	 */
	SourceList GetClientsByHash(const CMD4Hash &hash);

	/**
	 * Returns a list of clients with the specified IP.
	 *
	 * @param ip The IP-address to search for.
	 *
	 * This function will return a list of clients with the specified address.
	 * An absent address yields no results, as does an address that was never
	 * recorded -- UpdateClientIP() refuses to record an absent one.
	 */
	SourceList GetClientsByIP(const CNetworkAddress &address);

	/**
	 * Returns every client sharing a peer's rate-limit scope.
	 *
	 * The same address for an IPv4 peer, so an IPv4 result is identical to
	 * GetClientsByIP(). For an IPv6 peer it is every client in the same /64:
	 * counting per /128 would let one subscriber take an unbounded number of
	 * slots, one per address, which is the IPv6 shape of the limit this
	 * answers. See PeerIdentity::RateLimitScope().
	 *
	 * @param address The peer to scope. Absent yields nothing.
	 */
	SourceList GetClientsInRateLimitScope(const CNetworkAddress &address);

	/**
	 * The type of the list used to store ed2k IDs. Still 32-bit, because an
	 * ed2k ID is a 32-bit protocol field and not an address: a peer with no
	 * ed2k ID is stored under 0 here on purpose, which is why this map and the
	 * address index cannot share a key type.
	 */
	typedef std::multimap<uint32, CClientRef> IDMap;
	//! The pairs of the ID list.
	typedef std::pair<uint32, CClientRef> IDMapPair;

	/**
	 * The type of the address index.
	 *
	 * Keyed on CNetworkAddress, whose ordering is total with no two distinct
	 * addresses comparing equal, and whose absent state is a key nothing is
	 * ever inserted under. That is what a 32-bit key could not offer: zero was
	 * both 0.0.0.0 and "unknown", and a native IPv6 peer had no key at all.
	 *
	 * Keys go in through PeerIdentity::IndexKey(), so the mapped and native
	 * spellings of one IPv4 address are one entry rather than two identities.
	 */
	typedef std::multimap<CNetworkAddress, CClientRef> AddressMap;
	//! The pairs of the address index.
	typedef std::pair<CNetworkAddress, CClientRef> AddressMapPair;

	/**
	 * Returns a list of all clients.
	 *
	 * @return The complete list of clients.
	 */
	const IDMap &GetClientList();

	/**
	 * Adds a source to the list of dead sources.
	 *
	 * @param client The source to be recorded as dead.
	 */
	void AddDeadSource(const CUpDownClient *client);

	/**
	 * Checks if a source is recorded as being dead.
	 *
	 * @param client The client to evaluate.
	 * @return True if dead, false otherwise.
	 *
	 * Sources that are dead are not to be considered valid
	 * sources and should not be added to partfiles.
	 */
	bool IsDeadSource(const CUpDownClient *client);

	/**
	 * Sends a message to a client, identified by a GUI_ID
	 *
	 * @return Success
	 */
	bool SendChatMessage(uint64 client_id, const wxString &message);

	/**
	 * Stops a chat session with a client.
	 *
	 */
	void SetChatState(uint64 client_id, uint8 state);

	uint8 GetBuddyStatus() const { return m_nBuddyStatus; }
	// This must be used on CreateKadSourceLink and if we ever add the columns
	// on shared files control.
	CUpDownClient *GetBuddy() { return m_pBuddy.GetClient(); }
	uint32 GetBuddyIP();
	uint16 GetBuddyPort();
	bool RequestTCP(Kademlia::CContact *contact, uint8_t connectOptions);
	void RequestBuddy(Kademlia::CContact *contact, uint8_t connectOptions);
	bool IncomingBuddy(Kademlia::CContact *contact, Kademlia::CUInt128 *buddyID);
	void RemoveFromKadList(CUpDownClient *torem);
	void AddToKadList(CUpDownClient *toadd);
	bool DoRequestFirewallCheckUDP(const Kademlia::CContact &contact);

	void AddKadFirewallRequest(uint32 ip);
	bool IsKadFirewallCheckIP(uint32 ip) const;

	// Direct Callback list
	void AddDirectCallbackClient(CUpDownClient *toAdd);
	void RemoveDirectCallback(CUpDownClient *toRemove)
	{
		m_currentDirectCallbacks.remove(CCLIENTREF(toRemove, ""));
	}
	/**
	 * The callback-request throttle. Counted against the peer's rate-limit
	 * scope, not its exact address: see PeerIdentity::RateLimitScope(), which
	 * aggregates IPv6 at /64 because a per-/128 budget under IPv6 throttles
	 * nothing at all.
	 */
	void AddTrackCallbackRequests(const CNetworkAddress &address);
	bool AllowCallbackRequest(const CNetworkAddress &address) const;

protected:
	/*
	 * Avoids unwanted clients to be forever in the client list
	 */
	void CleanUpClientList();

	void ProcessDirectCallbackList();

private:
	/**
	 * Helperfunction which finds a client matching the specified client.
	 *
	 * @param client The client to search for.
	 * @return The matching client or NULL.
	 *
	 * This functions searches through the list of clients and finds the first match
	 * using the same checks as CUpDownClient::Compare, but without the overhead.
	 */
	CUpDownClient *FindMatchingClient(CUpDownClient *client);

	/**
	 * Check if we already know this IP.
	 *
	 * This function is used to determine if the given IP address
	 * is already known.
	 *
	 * @param address The address to check. An absent address is never known.
	 */
	bool IsIPAlreadyKnown(const CNetworkAddress &address);

	/**
	 * Helperfunction which removes the client from the IP-list.
	 */
	void RemoveIPFromList(CUpDownClient *client);
	/**
	 * Helperfunction which removes the client from the ID-list.
	 */
	bool RemoveIDFromList(CUpDownClient *client);
	/**
	 * Helperfunction which removes the client from the hash-list.
	 */
	void RemoveHashFromList(CUpDownClient *client);

	//! The type of the list used to store user-hashes.
	typedef std::multimap<CMD4Hash, CClientRef> HashMap;
	//! The pairs of the Hash-list.
	typedef std::pair<CMD4Hash, CClientRef> HashMapPair;

	//! The map of clients with valid hashes
	HashMap m_hashList;

	//! The map of clients with a known address
	AddressMap m_ipList;

	//! The full lists of clients
	IDMap m_clientList;

	//! This is the map of banned clients.
	ClientMap m_bannedList;
	//! This variable is used to keep track of the last time the banned-list was pruned.
	uint64 m_dwLastBannCleanUp;

	//! This is the map of tracked clients, keyed on address for the same reason
	//! the address index is: a tracked IPv6 peer had no key before.
	std::map<CNetworkAddress, CDeletedClient *> m_trackedClientsList;
	//! This keeps track of the last time the tracked-list was pruned.
	uint64 m_dwLastTrackedCleanUp;

	//! This keeps track of the last time the client-list was pruned.
	uint64 m_dwLastClientCleanUp;

	//! List of unusable sources.
	CDeadSourceList m_deadSources;

	/* Kad Stuff */
	CClientRefSet m_KadSources;
	CClientRef m_pBuddy;
	uint8 m_nBuddyStatus;

	//! Kad's firewall-check window. Kad addresses are 32-bit behind a
	//! documented conversion boundary, so this one stays as it was.
	typedef struct
	{
		uint32 ip;
		uint64 inserted;
	} IpAndTicks;
	typedef std::list<IpAndTicks> IpAndTicksList;
	IpAndTicksList m_firewallCheckRequests;

	//! The ed2k direct-callback window. Holds a rate-limit scope, which is an
	//! address for IPv4 and a /64 prefix for IPv6.
	typedef struct
	{
		CNetworkAddress scope;
		uint64 inserted;
	} ScopeAndTicks;
	typedef std::list<ScopeAndTicks> ScopeAndTicksList;

	typedef CClientRefList DirectCallbackList;
	DirectCallbackList m_currentDirectCallbacks;
	ScopeAndTicksList m_directCallbackRequests;
};

#endif
// File_checked_for_headers
