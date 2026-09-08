//
// This file is part of the aMule Project.
//
// Copyright (c) 2004-2011 Carlo Wood ( carlo@alinoe.com )
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

#ifndef AMULEIPV4ADDRESS_H
#define AMULEIPV4ADDRESS_H

#include "NetworkAddress.h"   // Needed for CNetworkAddress
#include "NetworkFunctions.h" // Needed for Uint32toStringIP

class amuleIPV4Address
{
public:
	amuleIPV4Address();
	amuleIPV4Address(const amuleIPV4Address &a);
	amuleIPV4Address(const class CamuleIPV4Endpoint &ep);
	virtual ~amuleIPV4Address();
	amuleIPV4Address &operator=(const amuleIPV4Address &a);
	amuleIPV4Address &operator=(const class CamuleIPV4Endpoint &a);

	virtual bool Hostname(const wxString &name);

	virtual bool Hostname(uint32 ip)
	{
		// Some people are sometimes fools. The rejection is an explicit
		// absence check rather than `if (!ip)`: the ed2k field the caller
		// holds overloads zero to mean "no address", and this is the boundary
		// where that overload is resolved.
		const CNetworkAddress address = CNetworkAddress::FromIPv4NetworkOrderOrAbsent(ip);
		if (address.IsAbsent()) {
			return false;
		}

		return Hostname(Uint32toStringIP(ip));
	}

	// Set the port to that corresponding to the specified service.
	// Returns true on success, false if something goes wrong (invalid service).
	virtual bool Service(uint16 service);

	// Returns the current service.
	virtual uint16 Service() const;

	// Determines if current address is set to localhost.
	virtual bool IsLocalHost() const;

	// Returns a wxString containing the IP address.
	virtual wxString IPAddress() const;

	// Set address to any of the addresses of the current machine.
	virtual bool AnyAddress();

	// Set the address from the internal address type, family and all. The one
	// way in for an IPv6 address: Hostname(uint32) cannot carry one and
	// Hostname(wxString) would go through a textual round trip.
	bool SetAddress(const CNetworkAddress &address);

	// The address as the internal type, or an absent address when this object
	// still holds asio's default-constructed 0.0.0.0.
	CNetworkAddress GetAddress() const;

	// Whether a socket bound to this address must be opened with IPV6_V6ONLY.
	//
	// This is a bind-time socket option rather than a property of an address,
	// and it lives here because this object is what already travels from the
	// caller that makes the decision (the listener setup, which knows whether
	// it is opening one socket for both families or one per family) all the way
	// down to the bind() call. The alternative was threading a flag through
	// four wrapper constructors -- CListenSocket, CSocketServerProxy,
	// CLibSocketServer and the asio impl -- for every socket type. Meaningless,
	// and ignored, for an IPv4 address.
	void SetV6Only(bool v6Only);
	bool IsV6Only() const;

	const class CamuleIPV4Endpoint &GetEndpoint() const;
	class CamuleIPV4Endpoint &GetEndpoint();

private:
	class CamuleIPV4Endpoint *m_endpoint;
};

#endif // AMULEIPV4ADDRESS_H
// File_checked_for_headers
