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
#include <cstring>
#include <vector>

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

class CQuicSocketTransport;

/**
 * How a byte-stream transport writes into a validated QUIC connection.
 *
 * The seam that task 2.1 needed and that 3.1 was blocking. ngtcp2 lives in one
 * translation unit and the transport has to stay free of it, so the connection
 * implements this and the transport holds nothing but the interface.
 *
 * Both directions detach, and both are needed. The two objects point at each
 * other and either may die first: the transport is owned by a CClientTCPSocket
 * that the ordinary teardown paths delete, while the connection is owned by the
 * endpoint and dies when ngtcp2 closes it. Whichever goes first clears the
 * other's pointer; one direction alone leaves a dangling pointer on the path
 * that was not taken.
 */
class IQuicStreamWriter
{
public:
	virtual ~IQuicStreamWriter() = default;

	/**
	 * Hand queued bytes to ngtcp2.
	 *
	 * Called only from the core thread, on the tick -- see the threading rule
	 * in CQuicSocketTransport. A partial acceptance is ordinary rather than an
	 * error: the stream's flow-control window is finite and the remainder goes
	 * on the next tick.
	 *
	 * @return how many bytes were taken. Zero means the window is closed.
	 */
	virtual std::size_t WriteQuicStream(const std::uint8_t *data, std::size_t length) = 0;

	//! Close the connection. Idempotent: the transport's destructor and its
	//! Close() may both reach here, and on different paths.
	virtual void CloseQuicStream() = 0;

	//! Forget the transport. Called from the transport's destructor, so nothing
	//! in the connection may call back into it afterwards.
	virtual void DetachStreamTransport() = 0;
};

/**
 * Where a validated QUIC connection becomes an ed2k client connection.
 *
 * The QUIC counterpart of IUtpConnectionAcceptor, and it exists for the same
 * reason: the translation unit that owns the library cannot include Logger.h,
 * theApp or CClientTCPSocket, so the connection has to travel out to one that
 * can. See CQuicInboundAcceptor.
 *
 * Optional. A build with no QUIC never has one, and a context without one
 * refuses to hand any connection upwards -- which is the same fail-closed shape
 * every other seam in this transport has.
 */
class IQuicConnectionAcceptor
{
public:
	virtual ~IQuicConnectionAcceptor() = default;

	/**
	 * Take a QUIC connection whose peer proof has validated.
	 *
	 * **Only ever called after validation.** The 37-byte proof is consumed by
	 * the connection before this is reached, so the first byte the returned
	 * transport ever delivers upwards is the first byte of the ed2k hello --
	 * and an unauthenticated peer never reaches this function at all.
	 *
	 * @param writer  the connection, for the transport to write through. The
	 *        caller retains ownership of it.
	 * @return the transport now bound to the connection, or NULL when the
	 *         connection was refused -- by the IP filter, a ban, or the socket
	 *         limit, on exactly the terms an inbound TCP connection is refused.
	 *         NULL means the caller must close the connection.
	 */
	virtual CQuicSocketTransport *AcceptQuicConnection(
		IQuicStreamWriter *writer, const CNetworkAddress &from, std::uint16_t port) = 0;
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
 * What a QUIC connection from one peer is required to prove.
 *
 * Both fields are learned from that peer's ed2k hello, over TCP, and neither
 * comes from the QUIC connection being validated. That sentence is the entire
 * security argument of the QUIC path and it is the reason this struct sits in
 * the context rather than in the adapter: an expectation exists before its
 * connection does -- the punch goes out first -- and the code that learns it
 * (CUpDownClient, from the hello tags) has no ngtcp2 in scope.
 *
 *   - @c userHash is the peer's ed2k user hash, which the hello carries in its
 *     fixed header.
 *   - @c proofValue is the 16-byte identity value from the peer's CT_MOD_QUIC_IDENT
 *     tag. See QuicProofValue.h for what it is, what it is not, and which end's
 *     value belongs in the proof.
 *
 * A cross-channel check is what makes this authentication rather than theatre:
 * the values travelled over TCP and the peer has to reproduce them over UDP, so
 * a third party that hijacks the punched hole -- the attack this proof exists to
 * stop -- has seen only the half that does not carry them.
 */
struct SQuicPeerExpectation
{
	CNetworkAddress peer;
	std::uint16_t port = 0;
	std::uint8_t userHash[QUIC_NATT_PROOF_VALUE_LENGTH] = {};
	std::uint8_t proofValue[QUIC_NATT_PROOF_VALUE_LENGTH] = {};
};

/**
 * How many expectations are kept at once.
 *
 * A bound is not optional. Expectations are registered while NAT traversal is
 * being negotiated, which a stranger can start, so an unbounded table is memory
 * an unauthenticated peer controls. The bound evicts the oldest rather than
 * refusing the newest, because refusing would let a flood of strangers lock out
 * every peer that negotiated after them -- turning a memory bound into a denial
 * of the transport it protects.
 *
 * 256 is chosen against the traffic rather than the memory: at 40 bytes an
 * entry the whole table is under 11 kB, so the number is really "more
 * simultaneous NAT-T negotiations than a client has", and a client with more
 * than 256 in flight has a connection limit problem before it has this one. An
 * evicted expectation is not a lost connection either -- it is one QUIC
 * handshake that falls back to uTP, automatically and silently.
 */
constexpr std::size_t kMaxQuicExpectations = 256;

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
	void Configure(IQuicLibrary *library,
		IQuicDatagramSink *sink,
		IQuicConnectionObserver *observer = nullptr,
		IQuicConnectionAcceptor *acceptor = nullptr)
	{
		Reset();
		m_library = library;
		m_sink = sink;
		m_observer = observer;
		m_acceptor = acceptor;
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
	 * Where a validated connection becomes an ed2k client connection, or NULL.
	 *
	 * NULL is what a build with no accept path looks like, and it refuses:
	 * without an acceptor a validated connection has nowhere to deliver bytes,
	 * so the adapter closes it rather than accumulating a stream nothing reads.
	 * That is the same shape the uTP context uses -- libutp registers
	 * UTP_ON_ACCEPT only when there is an acceptor -- and it is what keeps the
	 * advertised capability bit honest for QUIC too.
	 */
	IQuicConnectionAcceptor *GetAcceptor() const { return m_acceptor; }

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
	 * Record what a connection from this peer will have to prove.
	 *
	 * Called from the ed2k side once a peer's hello has supplied both values.
	 * Nothing in this function reads the QUIC connection, and that is the
	 * point: an expectation derived from the thing it validates is a validator
	 * that passes everything while looking like authentication, which is worse
	 * than having no QUIC at all.
	 *
	 * @param peer  the peer's address. Absent refuses.
	 * @param port  the UDP port the connection will arrive from. Zero refuses:
	 *        zero is "unknown" rather than a port (see
	 *        PeerIdentity::MatchesUdpSourcePort()), and an expectation stored
	 *        under it would be found by any datagram whose source port could
	 *        not be read.
	 * @param userHash   16 bytes, the peer's ed2k user hash. NULL refuses.
	 * @param proofValue 16 bytes, the peer's advertised identity value. NULL
	 *        refuses -- a peer that advertised none must produce no
	 *        expectation, because an expectation of sixteen zeroes is one any
	 *        third party can satisfy.
	 * @return false when nothing was stored.
	 */
	bool RegisterExpectation(const CNetworkAddress &peer,
		std::uint16_t port,
		const std::uint8_t *userHash,
		const std::uint8_t *proofValue)
	{
		if (userHash == nullptr || proofValue == nullptr || port == 0 || !peer.IsPresent()) {
			return false;
		}

		// Replace in place when this endpoint is already known. A peer that
		// re-handshakes must end up with one entry carrying its current
		// values, not two entries of which a lookup would find the stale one.
		const CNetworkAddress key = peer.Unmapped();
		for (SQuicPeerExpectation &existing : m_expectations) {
			if (existing.port == port && existing.peer == key) {
				std::memcpy(existing.userHash, userHash, QUIC_NATT_PROOF_VALUE_LENGTH);
				std::memcpy(existing.proofValue, proofValue, QUIC_NATT_PROOF_VALUE_LENGTH);
				return true;
			}
		}

		if (m_expectations.size() >= kMaxQuicExpectations) {
			// Oldest first. A vector erase at the front is O(n) over at most
			// 256 entries and happens once per registration past the bound,
			// which is cheaper than the intrusive list that would avoid it and
			// is far easier to read.
			m_expectations.erase(m_expectations.begin());
		}

		SQuicPeerExpectation fresh;
		fresh.peer = key;
		fresh.port = port;
		std::memcpy(fresh.userHash, userHash, QUIC_NATT_PROOF_VALUE_LENGTH);
		std::memcpy(fresh.proofValue, proofValue, QUIC_NATT_PROOF_VALUE_LENGTH);
		m_expectations.push_back(fresh);
		return true;
	}

	/**
	 * What a connection from this peer must prove, or NULL when nothing is
	 * expected from it.
	 *
	 * NULL is the fail-closed answer and it is required, not a convenience:
	 * ValidateQuicNattProof() refuses a NULL expectation, so a peer this end
	 * learned nothing about reaches the proof stage and is closed as an
	 * authentication failure -- after which it falls back to uTP, which the
	 * design requires to be automatic and silent.
	 *
	 * Matching is on the unmapped address, so a hello that arrived over an
	 * IPv4-mapped TCP socket and a datagram that arrived as plain IPv4 are one
	 * peer. Two identities here would mean an expectation registered from the
	 * hello could never be found by the connection it was registered for --
	 * which fails closed, but fails closed *always*, and would look exactly
	 * like a peer that is offline.
	 */
	const SQuicPeerExpectation *FindExpectation(const CNetworkAddress &peer, std::uint16_t port) const
	{
		if (port == 0 || !peer.IsPresent()) {
			return nullptr;
		}

		const CNetworkAddress key = peer.Unmapped();
		for (const SQuicPeerExpectation &existing : m_expectations) {
			if (existing.port == port && existing.peer == key) {
				return &existing;
			}
		}

		return nullptr;
	}

	//! Drop one expectation. Used when a peer is gone, so its slot does not
	//! hold a value for whoever inherits its NAT mapping next.
	void ForgetExpectation(const CNetworkAddress &peer, std::uint16_t port)
	{
		const CNetworkAddress key = peer.Unmapped();
		for (std::size_t i = 0; i < m_expectations.size(); ++i) {
			if (m_expectations[i].port == port && m_expectations[i].peer == key) {
				m_expectations.erase(m_expectations.begin() + (long)i);
				return;
			}
		}
	}

	//! How many expectations are held. For the bound's test; nothing in the
	//! transport branches on it.
	std::size_t CountExpectations() const { return m_expectations.size(); }

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

	/**
	 * What each peer's connection must prove.
	 *
	 * Deliberately NOT cleared by Reset(). Reset() drops the ngtcp2 endpoint,
	 * which happens when the UDP socket reopens; an expectation belongs to a
	 * peer whose ed2k hello is still valid, and clearing it there would refuse
	 * the next connection from every peer that had already negotiated -- with
	 * nothing logged, because a refused QUIC connection falls back to uTP in
	 * silence. The two have different lifetimes and only one of them is the
	 * endpoint's.
	 */
	std::vector<SQuicPeerExpectation> m_expectations;

	IQuicLibrary *m_library = nullptr;
	IQuicDatagramSink *m_sink = nullptr;
	IQuicConnectionObserver *m_observer = nullptr;
	IQuicConnectionAcceptor *m_acceptor = nullptr;
	void *m_endpoint = nullptr;
	bool m_endpointCreationFailed = false;
};

#endif // QUICCONTEXT_H
