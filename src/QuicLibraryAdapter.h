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

#ifndef QUICLIBRARYADAPTER_H
#define QUICLIBRARYADAPTER_H

#include "QuicContext.h" // Needed for IQuicLibrary

/**
 * The only place that calls ngtcp2 or GnuTLS.
 *
 * Everything above this file -- QuicNattProtocol.h, CQuicContext, the frame
 * type policy in NatTraversalPolicy.h, the shared-port routing -- is ordinary
 * C++ that compiles and is unit tested with neither library present. That is
 * deliberate and it is not merely tidiness: QUIC is opt-in (-DENABLE_QUIC, off
 * by default) and is not packageable everywhere aMule ships. Homebrew's
 * libngtcp2 links openssl@3 and no GnuTLS-bound build exists, so macOS builds
 * with QUIC off and reaches peers over uTP. A build without QUIC therefore has
 * to be a build with no QUIC rather than a build that does not compile.
 *
 * Without AMULE_QUIC_TRANSPORT every method here is inert -- CreateEndpoint()
 * returns NULL -- and CQuicContext is simply never configured with one, which
 * is the -DENABLE_QUIC=NO build.
 *
 * ngtcp2's and GnuTLS's headers appear in QuicLibraryAdapter.cpp and nowhere
 * else, and this declaration is deliberately free of them. The same discipline
 * UtpLibraryAdapter.h keeps for libutp, for the same reasons and one further
 * one: master has just spent a change confining Boost.Asio from 156
 * translation units down to a handful, and a public header that pulled in a
 * TLS stack would undo that work in a new direction. The split also mirrors
 * eMuleAI's own -- CQuicNatSocket is the socket-shaped half,
 * CNgTcp2GnuTlsBridge the crypto-and-protocol half -- which the design keeps
 * because it isolates the dependency that is hardest to package.
 *
 * Addresses cross this boundary through CNetworkAddress's host-order accessors
 * and htonl/ntohl rather than by reinterpreting a uint32, so the conversion
 * carries no endianness assumption.
 */
class CQuicLibraryAdapter : public IQuicLibrary
{
public:
	/**
	 * @param owner  the context whose sink outbound datagrams go through.
	 *        ngtcp2 has no send callback with an argument for it -- the
	 *        application is expected to write the packets itself -- so the
	 *        adapter holds it and drains each connection after every read and
	 *        every tick.
	 */
	explicit CQuicLibraryAdapter(CQuicContext *owner)
	: m_owner(owner)
	{
	}

	void *CreateEndpoint() override;
	void DestroyEndpoint(void *endpoint) override;
	bool ProcessDatagram(void *endpoint,
		const std::uint8_t *payload,
		std::size_t length,
		const CNetworkAddress &from,
		std::uint16_t port) override;
	bool AcceptsInboundConnections(void *endpoint) const override;
	void CheckTimeouts(void *endpoint, std::uint64_t nowMs) override;

private:
	CQuicContext *m_owner = nullptr;
};

#endif // QUICLIBRARYADAPTER_H
