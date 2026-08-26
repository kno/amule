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

#ifndef QUICCONTEXT_H
#define QUICCONTEXT_H

#include <cstddef>
#include <cstdint>

#include "NetworkAddress.h"   // Needed for CNetworkAddress
#include "QuicNattProtocol.h" // Needed for EQuicProofResult

/**
 * The QUIC context: aMule's side of ngtcp2.
 *
 * Shaped like CUtpContext deliberately, because it answers the same questions
 * on the same socket: one context per client instance, three inputs (inbound
 * datagrams recognised as QUIC on the shared ed2k UDP port, a periodic tick,
 * and application writes), and a hard split between "the library is linked" and
 * "this end can serve a connection".
 *
 * ngtcp2 and GnuTLS sit behind IQuicLibrary for the same two reasons libutp
 * sits behind IUtpLibrary, and one more that is specific to this transport:
 *
 *   - the shim has to compile in a build configured with -DENABLE_QUIC=NO,
 *     which is the default build and the only one macOS gets;
 *   - the behaviours worth asserting are not observable through a real ngtcp2
 *     without a peer on the network;
 *   - ngtcp2's and GnuTLS's headers must not spread. eMuleAI keeps the same
 *     split -- CQuicNatSocket is the socket-shaped half, CNgTcp2GnuTlsBridge
 *     the crypto-and-protocol half -- and the design keeps it because it
 *     isolates the dependency that is hardest to package.
 *
 * `void *` throughout is the adapter's own endpoint object; the type does not
 * appear here so that this header stays includable with neither library
 * present.
 */

/**
 * Why one QUIC connection ended, in this shim's own vocabulary.
 *
 * The distinction the spec delta requires is the one between the last value
 * and the rest: a peer that failed to prove which ed2k identity it is reached
 * this end and tried, while a timeout or a closed connection is the path. One
 * log line for both would bury the first inside the ordinary noise of the
 * second. The proof result itself carries the detail -- see
 * QuicProofResultName() in QuicNattProtocol.h.
 */
enum EQuicConnectionOutcome
{
	//! The handshake completed and the peer's proof validated.
	QUIC_CONNECTION_ESTABLISHED,
	//! The peer closed, or the connection drained normally.
	QUIC_CONNECTION_CLOSED,
	//! Nothing came back within ngtcp2's idle timeout. About the path.
	QUIC_CONNECTION_TIMED_OUT,
	//! ngtcp2 or GnuTLS refused the handshake -- including an ALPN this path
	//! does not speak. About the peer's protocol, not its identity.
	QUIC_CONNECTION_HANDSHAKE_FAILED,
	//! The handshake completed but the peer proof did not validate. This is
	//! the one that means somebody tried.
	QUIC_CONNECTION_AUTHENTICATION_FAILED
};

/**
 * Is this outcome an authentication failure rather than a transport one?
 *
 * The line is drawn at exactly one value, and where it is drawn matters. A
 * refused handshake -- which includes a rejected ALPN -- stays on the transport
 * side: a peer speaking a different protocol is not a peer claiming to be
 * somebody else, and reporting it as an authentication failure would put
 * ordinary version skew in the same log line as an impersonation attempt.
 *
 * A function rather than a comparison at the call site because the call site is
 * a log statement, and a classification that lives inside a log statement
 * cannot be asserted. QuicContextTest asserts this one.
 */
inline bool IsQuicAuthenticationOutcome(EQuicConnectionOutcome outcome)
{
	return outcome == QUIC_CONNECTION_AUTHENTICATION_FAILED;
}

//! The outcome as it appears in a log line. Distinct for every value: two
//! outcomes under one name would be two events nobody can tell apart.
inline const char *QuicConnectionOutcomeName(EQuicConnectionOutcome outcome)
{
	switch (outcome) {
	case QUIC_CONNECTION_ESTABLISHED:
		return "established";
	case QUIC_CONNECTION_CLOSED:
		return "closed";
	case QUIC_CONNECTION_TIMED_OUT:
		return "timed out";
	case QUIC_CONNECTION_HANDSHAKE_FAILED:
		return "handshake refused";
	case QUIC_CONNECTION_AUTHENTICATION_FAILED:
		return "peer authentication failed";
	}

	// Unreachable for any declared value; a new one added without a case here
	// reads as unknown rather than borrowing another outcome's name.
	return "unknown";
}

/**
 * Where a connection outcome is reported.
 *
 * QuicLibraryAdapter.cpp is the one translation unit that sees ngtcp2's and
 * GnuTLS's headers, and on the same rule UtpLibraryAdapter.cpp follows it must
 * stay clear of aMule's Types.h -- so it cannot include Logger.h and cannot log
 * anything itself. The outcome therefore travels out through this interface to a
 * translation unit that can, exactly as an inbound uTP connection travels out
 * through IUtpConnectionAcceptor to CUtpInboundAcceptor.
 *
 * Optional: a build with no QUIC never has one, and the context does not care.
 */
class IQuicConnectionObserver
{
public:
	virtual ~IQuicConnectionObserver() = default;

	/**
	 * One connection ended, or came up.
	 *
	 * @param outcome  what happened. IsQuicAuthenticationOutcome() is the
	 *        distinction the spec delta requires in the log.
	 * @param proofResult  why, when the outcome is about the proof. The two
	 *        travel together because an outcome alone cannot tell an absent
	 *        proof from one for the wrong identity, and those are different
	 *        events: the first is a peer that does not speak this protocol, the
	 *        second is a peer that does and is lying.
	 */
	virtual void OnQuicConnectionOutcome(EQuicConnectionOutcome outcome,
		EQuicProofResult proofResult,
		const CNetworkAddress &peer,
		std::uint16_t port) = 0;
};

/**
 * Where outbound QUIC datagrams go: the ed2k UDP socket.
 *
 * The sink receives the QUIC payload and is responsible for the 0xB2/0x01
 * framing (WriteQuicFrameHeader, QuicNattProtocol.h), because the framing is a
 * property of the shared port rather than of the context. Identical contract to
 * IUtpDatagramSink, and for the identical reason.
 */
class IQuicDatagramSink
{
public:
	virtual ~IQuicDatagramSink() = default;

	virtual void SendQuicDatagram(const std::uint8_t *payload,
		std::size_t length,
		const CNetworkAddress &to,
		std::uint16_t port) = 0;
};

/**
 * The subset of ngtcp2 and GnuTLS this shim uses.
 *
 * Implemented for real by CQuicLibraryAdapter (QuicLibraryAdapter.h), which is
 * inert unless AMULE_QUIC_TRANSPORT is defined.
 */
class IQuicLibrary
{
public:
	virtual ~IQuicLibrary() = default;

	/**
	 * Create the endpoint: TLS credentials, the ALPN registration, and the
	 * connection table. Returns NULL on failure, which includes every build
	 * without ngtcp2.
	 *
	 * Failure here is a normal outcome rather than an error to report: a
	 * client that cannot bring QUIC up advertises no QUIC capability and
	 * reaches its peers over uTP, which is what the design requires the
	 * fallback to be -- automatic and silent.
	 */
	virtual void *CreateEndpoint() = 0;

	//! Tear the endpoint down, closing every connection on it.
	virtual void DestroyEndpoint(void *endpoint) = 0;

	/**
	 * Feed one inbound datagram to ngtcp2.
	 *
	 * @param payload  the QUIC payload, i.e. past the 0xB2/0x01 framing.
	 * @return true when ngtcp2 claimed the datagram. False means it did not
	 *         look like QUIC for a connection on this endpoint, and the
	 *         caller must let the datagram continue to the ed2k UDP parser
	 *         unmodified.
	 */
	virtual bool ProcessDatagram(void *endpoint,
		const std::uint8_t *payload,
		std::size_t length,
		const CNetworkAddress &from,
		std::uint16_t port) = 0;

	/**
	 * Whether an inbound QUIC handshake arriving on this endpoint would be
	 * answered rather than dropped.
	 *
	 * Asked of the library because only the library knows whether the TLS
	 * credentials came up. This is the difference between a transport that
	 * can serve a peer and one that merely exists, and it is what keeps the
	 * advertised MOD_MISCOPT_NAT_TRAVERSAL_QUIC bit honest.
	 */
	virtual bool AcceptsInboundConnections(void *endpoint) const = 0;

	/**
	 * The periodic pass: ngtcp2's loss detection and idle timers, and the
	 * outbound packets they produce.
	 *
	 * @param nowMs a millisecond tick count.
	 */
	virtual void CheckTimeouts(void *endpoint, std::uint64_t nowMs) = 0;
};

/**
 * One QUIC context per client instance.
 *
 * Free of ngtcp2, GnuTLS, wxWidgets and theApp, so it is includable and
 * testable everywhere the uTP shim is.
 */
class CQuicContext
{
public:
	CQuicContext() = default;

	~CQuicContext() { Reset(); }

	CQuicContext(const CQuicContext &) = delete;
	CQuicContext &operator=(const CQuicContext &) = delete;

	/**
	 * Bind the context to a library and an outbound socket.
	 *
	 * @param library  NULL in a build without ngtcp2, which is the default
	 *                 build. The context is then permanently unavailable and
	 *                 every path through it is inert -- the receive path and
	 *                 the core timer both run in that build too.
	 */
	void Configure(
		IQuicLibrary *library, IQuicDatagramSink *sink, IQuicConnectionObserver *observer = nullptr)
	{
		Reset();
		m_library = library;
		m_sink = sink;
		m_observer = observer;
	}

	//! Whether there is a library to talk to at all. False in every build
	//! configured with -DENABLE_QUIC=NO.
	bool IsAvailable() const { return m_library != nullptr; }

	//! The outbound sink, for the adapter to write framed datagrams through.
	IQuicDatagramSink *GetSink() const { return m_sink; }

	//! Where connection outcomes are reported, or NULL. The adapter finds it
	//! here rather than being handed it separately, so there is one owner of
	//! the pointer and no way for the two to disagree.
	IQuicConnectionObserver *GetObserver() const { return m_observer; }

	/**
	 * Whether this end can serve a QUIC connection: an endpoint exists, and an
	 * inbound handshake on it would be answered rather than dropped.
	 *
	 * This is what gates the advertised MOD_MISCOPT_NAT_TRAVERSAL_QUIC bit and
	 * the localCanServeQuic input to SelectNattFrameType(). IsAvailable() is
	 * not that answer: it says ngtcp2 is linked, which is the equivalent of a
	 * bound socket. A build with ngtcp2 whose TLS credentials failed to come up
	 * answers nothing, and a peer that read the bit would wait out the 1500 ms
	 * window and then fall back -- costing a second and a half per connection
	 * with nothing logged on either side.
	 *
	 * Not const, and it creates the endpoint, for the same reason Tick() does:
	 * the answer must not depend on whether a tick happened to run first, or
	 * the advertised capability would flap for one core-timer period after
	 * every socket reopen.
	 */
	bool CanServeConnections()
	{
		void *endpoint = EnsureEndpoint();
		if (endpoint == nullptr) {
			return false;
		}

		return m_library->AcceptsInboundConnections(endpoint);
	}

	/**
	 * Offer an inbound datagram to ngtcp2.
	 *
	 * @param payload  the QUIC payload, i.e. past the 0xB2/0x01 framing.
	 * @return true when ngtcp2 claimed it. False means the caller must let the
	 *         datagram continue to the ed2k UDP parser unmodified.
	 */
	bool ProcessDatagram(const std::uint8_t *payload,
		std::size_t length,
		const CNetworkAddress &from,
		std::uint16_t port)
	{
		if (!IsUsableEndpointAddress(from)) {
			return false;
		}

		void *endpoint = EnsureEndpoint();
		if (endpoint == nullptr) {
			return false;
		}

		return m_library->ProcessDatagram(endpoint, payload, length, from, port);
	}

	/**
	 * The periodic tick.
	 *
	 * Deliberately unconditional, on the same reasoning as CUtpContext::Tick():
	 * QUIC's loss detection and its idle timer live in this pass, so an
	 * endpoint serviced only when a packet arrives cannot recover a lost
	 * packet on an otherwise idle connection -- the packet that would drive
	 * the recovery is the one that was lost. The endpoint is also created
	 * here, so the guarantee does not depend on a first inbound packet.
	 */
	void Tick(std::uint64_t nowMs)
	{
		void *endpoint = EnsureEndpoint();
		if (endpoint == nullptr) {
			return;
		}

		m_library->CheckTimeouts(endpoint, nowMs);
	}

	//! Drop the endpoint and everything on it. Safe to call when there is none.
	void Reset()
	{
		if (m_endpoint != nullptr && m_library != nullptr) {
			m_library->DestroyEndpoint(m_endpoint);
		}
		m_endpoint = nullptr;
		m_endpointCreationFailed = false;
	}

	/**
	 * Whether this transport carries a peer at this address.
	 *
	 * IPv4 only, matching CUtpContext::IsUsableEndpoint() and for the same
	 * reason: the client UDP socket's send path takes a 32-bit address, so a
	 * native IPv6 peer would be reached at 0.0.0.0 rather than not at all.
	 * Widening this is a change to one predicate, here.
	 */
	static bool IsUsableEndpointAddress(const CNetworkAddress &peer)
	{
		std::uint32_t ip = 0;
		return peer.ToIPv4NetworkOrder(ip) && ip != 0;
	}

private:
	/**
	 * The endpoint, created on first use.
	 *
	 * A failed creation is remembered rather than retried. Bringing QUIC up
	 * fails for reasons that do not change between two calls a hundred
	 * milliseconds apart -- absent TLS credentials, an ngtcp2 that refused its
	 * settings -- and retrying on every core tick would turn a permanent
	 * condition into a permanent stream of work and log lines.
	 */
	void *EnsureEndpoint()
	{
		if (m_library == nullptr || m_endpointCreationFailed) {
			return nullptr;
		}
		if (m_endpoint != nullptr) {
			return m_endpoint;
		}

		m_endpoint = m_library->CreateEndpoint();
		if (m_endpoint == nullptr) {
			m_endpointCreationFailed = true;
		}

		return m_endpoint;
	}

	IQuicLibrary *m_library = nullptr;
	IQuicDatagramSink *m_sink = nullptr;
	IQuicConnectionObserver *m_observer = nullptr;
	void *m_endpoint = nullptr;
	bool m_endpointCreationFailed = false;
};

#endif // QUICCONTEXT_H
