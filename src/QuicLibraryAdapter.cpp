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

// ngtcp2's and GnuTLS's headers first and alone, on the same rule
// UtpLibraryAdapter.cpp follows: this translation unit must not pull in
// aMule's Types.h nor any header that does `using namespace std`. QuicContext.h
// and NetworkAddress.h are safe -- between them they include only <cstdint>,
// <cstddef>, <optional>, <string> and Boost.Asio's address type.
//
// No diagnostic pragma wrap around these includes. The project's convention
// (see the -Werror=deprecated block at the top of src/CMakeLists.txt) is to
// wrap a third-party include that trips the gate, and to leave one that does
// not alone -- a pragma with nothing behind it is a suppression nobody can
// later tell is dead. ngtcp2 1.11 and GnuTLS 3.8 compile clean under this
// tree's warning set; if a version bump changes that, the wrap goes here and
// its comment says which header and which warning.

#ifdef AMULE_QUIC_TRANSPORT
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#endif // AMULE_QUIC_TRANSPORT

#include "QuicLibraryAdapter.h"
// Free of aMule's Types.h and of `using namespace std`: it reaches only
// protocol/Protocols.h, which is #defines.
#include "QuicNattProtocol.h" // Needed for the ALPN and the peer proof

#ifdef AMULE_QUIC_TRANSPORT

#include <chrono>
#include <cstring>
#include <memory>
#include <vector>

namespace
{

//! One QUIC packet's worth of room. 1200 is QUIC's minimum required datagram
//! size and this path never grows past the ed2k UDP socket's own MTU
//! assumptions, so a fixed buffer is enough and avoids an allocation per
//! packet on the receive path.
constexpr std::size_t kMaxDatagramSize = 1452;

//! Connection IDs aMule issues. 16 is within QUIC's 1..20 range and is what
//! ngtcp2's own examples use.
constexpr std::size_t kConnectionIdLength = 16;

/**
 * How long a half-open connection may sit before it is dropped.
 *
 * NAT traversal produces handshakes that never complete -- that is its normal
 * failure mode, not an exception -- so an endpoint that kept every one of them
 * would accumulate connection state for every peer that ever punched at it.
 * ngtcp2 enforces this itself through settings.handshake_timeout; the value is
 * named here because it is a policy choice rather than a library default.
 */
constexpr std::uint64_t kHandshakeTimeoutMs = 10000;

//! Idle timeout for an established connection, in milliseconds.
constexpr std::uint64_t kIdleTimeoutMs = 30000;

//! ngtcp2 counts in nanoseconds; aMule's tick counters are milliseconds.
constexpr std::uint64_t MsToNs(std::uint64_t ms)
{
	return ms * 1000000ULL;
}

/**
 * The one clock ngtcp2 sees.
 *
 * ngtcp2 does not read a clock itself: every entry point takes a timestamp,
 * and the library requires that they all come from the same monotonic source.
 * Mixing two -- aMule's GetTickCount64() on one path and something else on
 * another -- would have every timer either fire immediately or never, with no
 * error anywhere. So this function is the source, and no caller passes its own
 * reading. aMule's millisecond tick is what *schedules* the periodic pass; it
 * is not what the pass is measured against.
 *
 * steady_clock rather than system_clock: a wall-clock adjustment during a
 * connection would move loss detection and the idle timer backwards.
 */
std::uint64_t MonotonicNs()
{
	return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
		std::chrono::steady_clock::now().time_since_epoch())
						  .count());
}

bool ToSockAddr(const CNetworkAddress &address, std::uint16_t port, sockaddr_in &out)
{
	std::uint32_t hostOrder = 0;
	if (!address.ToIPv4HostOrder(hostOrder)) {
		return false;
	}

	out = sockaddr_in();
	out.sin_family = AF_INET;
	out.sin_port = htons(port);
	out.sin_addr.s_addr = htonl(hostOrder);
	return true;
}

class CQuicEndpoint;

/**
 * What a QUIC connection from one peer is required to prove.
 *
 * The rendezvous that produced the connection is what knows this: which ed2k
 * identity was being reached, and which nonce that particular exchange agreed
 * on. The endpoint holds the expectations rather than the connections, because
 * an expectation exists before its connection does -- the punch goes out
 * first.
 */
struct SQuicPeerExpectation
{
	CNetworkAddress peer;
	std::uint16_t port = 0;
	std::uint8_t userHash[QUIC_NATT_PROOF_VALUE_LENGTH] = {};
	std::uint8_t nonce[QUIC_NATT_PROOF_VALUE_LENGTH] = {};
};

/**
 * One inbound QUIC connection.
 *
 * The proof is the reason this class exists in the shape it does. TLS
 * authenticates the connection but says nothing about which ed2k client is on
 * the other end -- neither side has a certificate the other can check -- so
 * until the 37-byte proof has validated, this connection is an anonymous peer
 * that completed a handshake. Stream bytes are therefore accumulated into the
 * proof buffer and NOT delivered anywhere, which is the spec delta's "reject
 * payload before proof validation completes" expressed structurally: there is
 * no code path from the receive callback to a consumer that does not pass
 * through m_proofValidated.
 */
class CQuicConnection
{
public:
	/**
	 * ngtcp2's GnuTLS binding finds the ngtcp2_conn through this reference,
	 * which is set as the TLS session's pointer. It must be the first member:
	 * the binding is handed the ngtcp2_crypto_conn_ref and the containing
	 * object is recovered from its user_data, so keeping the two at the same
	 * address costs nothing and removes one way to get the cast wrong.
	 */
	ngtcp2_crypto_conn_ref connRef;

	CQuicConnection(CQuicEndpoint *owner, const CNetworkAddress &peer, std::uint16_t port)
	: connRef{ GetConnFromRef, this }
	, m_owner(owner)
	, m_peer(peer)
	, m_port(port)
	{
	}

	~CQuicConnection()
	{
		if (m_conn != nullptr) {
			ngtcp2_conn_del(m_conn);
		}
		if (m_session != nullptr) {
			gnutls_deinit(m_session);
		}
	}

	CQuicConnection(const CQuicConnection &) = delete;
	CQuicConnection &operator=(const CQuicConnection &) = delete;

	bool IsFor(const CNetworkAddress &peer, std::uint16_t port) const
	{
		return m_port == port && m_peer.Unmapped() == peer.Unmapped();
	}

	bool IsClosed() const { return m_closed; }
	ngtcp2_conn *Conn() const { return m_conn; }
	const CNetworkAddress &Peer() const { return m_peer; }
	std::uint16_t Port() const { return m_port; }
	CQuicEndpoint *Owner() const { return m_owner; }

	/**
	 * Mark the connection unusable and report why.
	 *
	 * Nothing is freed here: the endpoint sweeps closed connections after the
	 * read or tick that closed them, so ngtcp2 is never re-entered on an object
	 * being destroyed.
	 *
	 * The outcome is reported once, on the first close. A connection that hit
	 * an error and then hit its idle timer is one event, and reporting the
	 * second would put a timeout line under an authentication failure -- which
	 * is precisely the confusion the two categories exist to prevent.
	 */
	void MarkClosed(EQuicConnectionOutcome outcome, EQuicProofResult proofResult);

	/**
	 * Take stream bytes from ngtcp2.
	 *
	 * Everything before the proof has validated is proof; nothing else is
	 * accepted, and a proof that fails closes the connection. That ordering is
	 * the requirement -- payload is rejected *before* validation completes,
	 * not examined and discarded afterwards.
	 *
	 * @return true when the bytes were acceptable.
	 */
	bool ReceiveStreamBytes(const std::uint8_t *data, std::size_t length);

	//! Start the server side of the handshake for an inbound Initial packet.
	bool BeginServerHandshake(const ngtcp2_pkt_hd &header, const sockaddr_in &local);

	//! Feed one datagram to ngtcp2 and then drain whatever it wants to send.
	bool ReadPacket(const std::uint8_t *payload, std::size_t length, std::uint64_t nowNs);

	//! Write out whatever ngtcp2 has queued, through the context's sink.
	void DrainOutbound(std::uint64_t nowNs);

	//! ngtcp2's timers, and the packets they produce.
	void HandleExpiry(std::uint64_t nowNs);

private:
	static ngtcp2_conn *GetConnFromRef(ngtcp2_crypto_conn_ref *ref)
	{
		return static_cast<CQuicConnection *>(ref->user_data)->m_conn;
	}

	bool SetUpTlsSession();

	//! Tell the observer, at most once per connection. This translation unit
	//! cannot log -- see IQuicConnectionObserver -- so reporting is all it can
	//! do, and doing it twice would double-count one event.
	void Report(EQuicConnectionOutcome outcome, EQuicProofResult proofResult);

	CQuicEndpoint *m_owner = nullptr;
	CNetworkAddress m_peer;
	std::uint16_t m_port = 0;

	ngtcp2_conn *m_conn = nullptr;
	gnutls_session_t m_session = nullptr;
	ngtcp2_path_storage m_path{};
	sockaddr_in m_localAddress{};
	sockaddr_in m_remoteAddress{};

	//! Bytes received before the proof completed. Bounded by the proof length:
	//! a peer cannot make this grow, because anything past 37 bytes is either
	//! validated payload or a closed connection.
	std::uint8_t m_proof[QUIC_NATT_PROOF_LENGTH] = {};
	std::size_t m_proofBytes = 0;
	bool m_proofValidated = false;
	bool m_closed = false;
	bool m_outcomeReported = false;
};

/**
 * The endpoint: TLS credentials, the ALPN registration, and the connections.
 *
 * One per client instance, matching CQuicContext. The credentials are the
 * expensive part and the part that can fail, which is why a failed
 * CreateEndpoint() is remembered by the context rather than retried.
 */
class CQuicEndpoint
{
public:
	explicit CQuicEndpoint(CQuicContext *owner)
	: m_owner(owner)
	{
	}

	~CQuicEndpoint()
	{
		m_connections.clear();
		if (m_credentials != nullptr) {
			gnutls_certificate_free_credentials(m_credentials);
		}
	}

	CQuicEndpoint(const CQuicEndpoint &) = delete;
	CQuicEndpoint &operator=(const CQuicEndpoint &) = delete;

	/**
	 * Bring the TLS credentials up.
	 *
	 * @return false when anything failed. Failure is a normal outcome here
	 *         rather than an error to report: a client that cannot bring QUIC
	 *         up advertises no QUIC capability and reaches its peers over uTP,
	 *         which is what the design requires -- automatic and silent.
	 */
	bool Initialise();

	//! Whether an inbound handshake would be answered. Credentials up is the
	//! whole of the question: there is no separate accept callback to
	//! register, unlike libutp.
	bool AcceptsInbound() const { return m_credentials != nullptr; }

	gnutls_certificate_credentials_t Credentials() const { return m_credentials; }
	CQuicContext *Owner() const { return m_owner; }

	bool ProcessDatagram(const std::uint8_t *payload,
		std::size_t length,
		const CNetworkAddress &from,
		std::uint16_t port,
		std::uint64_t nowNs);

	void CheckTimeouts(std::uint64_t nowNs);

	//! Put one datagram on the wire through the context's sink, which owns the
	//! 0xB2/0x01 framing because the framing belongs to the shared port.
	void
	Send(const std::uint8_t *packet, std::size_t length, const CNetworkAddress &to, std::uint16_t port);

	/**
	 * What a connection from this peer must prove, or NULL when nothing is
	 * expected from it.
	 *
	 * NULL, always, and this is the one place that changes when it stops being
	 * so -- the same shape as LocalCanDiscoverRendezvousRelay() in
	 * NatTraversalPolicy.h, and for the same kind of reason.
	 *
	 * The gap is specific and is not an oversight. The proof binds a QUIC
	 * connection to the ed2k identity that negotiated the rendezvous, and it
	 * needs two values: that identity's user hash, which the rendezvous does
	 * carry, and the nonce of that particular exchange, which it does not. The
	 * rendezvous message aMule implements is opcode, flags and a 16-byte peer
	 * hash (SNattRendezvousRequest, NatRendezvousProtocol.h) with no field a
	 * nonce could travel in. Inventing one would be a wire-format guess that
	 * eMuleAI would not match, and it would fail exactly the way this whole
	 * protocol fails: silently, with the handshake simply never completing.
	 *
	 * Returning NULL is what keeps that honest. The validator refuses, so an
	 * inbound QUIC connection reaches the proof stage and is closed as an
	 * authentication failure, and the peer falls back to uTP -- which is the
	 * documented behaviour for a peer whose QUIC does not come up, is automatic
	 * and silent, and costs nothing. The alternative -- accepting whatever
	 * arrived as the expectation -- would be a validator that passes everything
	 * while looking like authentication, which is worse than having no QUIC.
	 */
	const SQuicPeerExpectation *FindExpectation(const CNetworkAddress &peer, std::uint16_t port) const;

private:
	CQuicConnection *FindConnection(const CNetworkAddress &from, std::uint16_t port);

	//! Drop every connection that closed during the pass that just ran. Done
	//! between passes rather than inside one, so no ngtcp2 callback can be
	//! running on an object being destroyed.
	void SweepClosed();

	//! Generate the self-signed certificate the handshake needs.
	//!
	//! QUIC requires a server certificate; this path does not require a
	//! *trusted* one, because trust is established by the peer proof rather
	//! than by a certificate authority -- neither aMule nor eMuleAI has an
	//! identity a CA would attest to. A certificate generated at startup and
	//! never persisted is therefore exactly right: it satisfies TLS, and it
	//! deliberately carries no long-lived identifier that would let this
	//! client be recognised across restarts.
	bool GenerateSelfSignedCredentials();

	CQuicContext *m_owner = nullptr;
	gnutls_certificate_credentials_t m_credentials = nullptr;
	std::vector<std::unique_ptr<CQuicConnection>> m_connections;
};

// --- CQuicConnection --------------------------------------------------------

void CQuicConnection::Report(EQuicConnectionOutcome outcome, EQuicProofResult proofResult)
{
	if (m_outcomeReported) {
		return;
	}
	m_outcomeReported = true;

	IQuicConnectionObserver *observer = (m_owner != nullptr && m_owner->Owner() != nullptr)
						    ? m_owner->Owner()->GetObserver()
						    : nullptr;
	if (observer != nullptr) {
		observer->OnQuicConnectionOutcome(outcome, proofResult, m_peer, m_port);
	}
}

void CQuicConnection::MarkClosed(EQuicConnectionOutcome outcome, EQuicProofResult proofResult)
{
	Report(outcome, proofResult);
	m_closed = true;
}

bool CQuicConnection::ReceiveStreamBytes(const std::uint8_t *data, std::size_t length)
{
	if (m_proofValidated) {
		// The handover to the ed2k client layer belongs to the accept path,
		// which this change does not ship -- see the note in
		// CQuicEndpoint::ProcessDatagram(). Until it does, validated bytes are
		// accounted for and dropped rather than being handed to a consumer
		// that does not exist. Dropping them here is visible and bounded;
		// buffering them for a reader that never arrives would not be.
		return true;
	}

	// Before validation there is exactly one thing a peer may send, and it has
	// a fixed length. Anything past it is not payload arriving early, it is a
	// peer that framed something this end does not speak.
	if (length > QUIC_NATT_PROOF_LENGTH - m_proofBytes) {
		MarkClosed(QUIC_CONNECTION_AUTHENTICATION_FAILED, QUIC_PROOF_OVERSIZED);
		return false;
	}

	std::memcpy(m_proof + m_proofBytes, data, length);
	m_proofBytes += length;

	if (m_proofBytes < QUIC_NATT_PROOF_LENGTH) {
		// Still arriving. A proof split across QUIC packets is ordinary.
		return true;
	}

	// The identity this connection is expected to belong to comes from the
	// rendezvous that produced it. When there is no expectation --  which is
	// every connection in this tree today, see FindExpectation() -- the
	// validator is handed NULL and refuses. That is the fail-closed direction
	// and it is deliberate: an expectation invented here would be a validator
	// that passes everything while looking like authentication.
	const SQuicPeerExpectation *expected = m_owner->FindExpectation(m_peer, m_port);
	const EQuicProofResult result = ValidateQuicNattProof(m_proof,
		m_proofBytes,
		(expected != nullptr) ? expected->userHash : nullptr,
		(expected != nullptr) ? expected->nonce : nullptr);

	if (IsQuicAuthenticationFailure(result)) {
		// An authentication failure, not a transport one. The two are
		// different events -- one is the network, the other is a peer that
		// reached this end and failed to prove who it is -- and the reason
		// travels with it so the log line can name which of the five it was.
		// The connection is closed rather than left open for a retry: a peer
		// that can prove who it is gets it right the first time.
		MarkClosed(QUIC_CONNECTION_AUTHENTICATION_FAILED, result);
		return false;
	}

	m_proofValidated = true;
	Report(QUIC_CONNECTION_ESTABLISHED, QUIC_PROOF_VALID);
	return true;
}

bool CQuicConnection::SetUpTlsSession()
{
	if (gnutls_init(&m_session, GNUTLS_SERVER | GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA) !=
		GNUTLS_E_SUCCESS) {
		m_session = nullptr;
		return false;
	}

	if (ngtcp2_crypto_gnutls_configure_server_session(m_session) != 0) {
		return false;
	}

	// TLS 1.3 only. QUIC does not carry any earlier version, and saying so
	// explicitly means a GnuTLS whose default priority string admits TLS 1.2
	// cannot negotiate something this transport would then fail to use.
	if (gnutls_priority_set_direct(m_session,
		    "%DISABLE_TLS13_COMPAT_MODE:NORMAL:-VERS-ALL:+VERS-TLS1.3:"
		    "-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM:"
		    "-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1",
		    nullptr) != GNUTLS_E_SUCCESS) {
		return false;
	}

	// The ALPN, and only this one. GnuTLS refuses the handshake when the
	// client's offer intersects nothing here, which is the spec delta's
	// requirement that a different ALPN be rejected -- expressed by never
	// offering an alternative rather than by comparing strings after the fact.
	// GNUTLS_ALPN_MANDATORY is what turns "no overlap" from a silent
	// no-selection into a failed handshake.
	gnutls_datum_t alpn;
	alpn.data = const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(QUIC_NATT_ALPN));
	alpn.size = static_cast<unsigned int>(QUIC_NATT_ALPN_LENGTH);
	if (gnutls_alpn_set_protocols(m_session, &alpn, 1, GNUTLS_ALPN_MANDATORY) != GNUTLS_E_SUCCESS) {
		return false;
	}

	if (gnutls_credentials_set(m_session, GNUTLS_CRD_CERTIFICATE, m_owner->Credentials()) !=
		GNUTLS_E_SUCCESS) {
		return false;
	}

	gnutls_session_set_ptr(m_session, &connRef);
	return true;
}

/**
 * The ngtcp2 callback table.
 *
 * Almost every entry is one of ngtcp2's own crypto helpers, which is the point
 * of linking the GnuTLS binding: the parts a client could get subtly and
 * silently wrong -- key installation, header protection, key update -- are not
 * written here at all. Only the three that are aMule's business are.
 */
int OnRecvStreamData(ngtcp2_conn *conn,
	std::uint32_t flags,
	std::int64_t stream_id,
	std::uint64_t offset,
	const std::uint8_t *data,
	std::size_t datalen,
	void *user_data,
	void *stream_user_data)
{
	(void)conn;
	(void)flags;
	(void)stream_id;
	(void)offset;
	(void)stream_user_data;

	CQuicConnection *connection = static_cast<CQuicConnection *>(user_data);
	if (connection == nullptr) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	if (!connection->ReceiveStreamBytes(data, datalen)) {
		// Tearing the connection down from inside a callback is what
		// NGTCP2_ERR_CALLBACK_FAILURE means to ngtcp2, and it is the correct
		// answer for a peer that failed to authenticate: nothing further is
		// read from it.
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

void OnRand(std::uint8_t *dest, std::size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
	(void)rand_ctx;
	// GNUTLS_RND_RANDOM rather than NONCE: these bytes are connection IDs and
	// path challenges, which an observer must not be able to predict.
	gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
}

int OnGetNewConnectionId(
	ngtcp2_conn *conn, ngtcp2_cid *cid, std::uint8_t *token, std::size_t cidlen, void *user_data)
{
	(void)conn;
	(void)user_data;

	if (gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	cid->datalen = cidlen;

	// The stateless reset token has to be derivable from a secret this client
	// keeps, so that a reset can still be recognised after the connection
	// state is gone. A per-process random secret is enough: aMule does not
	// survive its own restart as far as QUIC is concerned.
	static std::uint8_t staticSecret[NGTCP2_STATELESS_RESET_TOKENLEN];
	static bool staticSecretReady = false;
	if (!staticSecretReady) {
		if (gnutls_rnd(GNUTLS_RND_RANDOM, staticSecret, sizeof(staticSecret)) != 0) {
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
		staticSecretReady = true;
	}

	if (ngtcp2_crypto_generate_stateless_reset_token(token, staticSecret, sizeof(staticSecret), cid) !=
		0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

bool CQuicConnection::BeginServerHandshake(const ngtcp2_pkt_hd &header, const sockaddr_in &local)
{
	if (!SetUpTlsSession()) {
		return false;
	}

	if (!ToSockAddr(m_peer, m_port, m_remoteAddress)) {
		return false;
	}
	m_localAddress = local;

	ngtcp2_path_storage_init(&m_path,
		reinterpret_cast<const ngtcp2_sockaddr *>(&m_localAddress),
		sizeof(m_localAddress),
		reinterpret_cast<const ngtcp2_sockaddr *>(&m_remoteAddress),
		sizeof(m_remoteAddress),
		nullptr);

	ngtcp2_callbacks callbacks{};
	callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
	callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
	callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
	callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
	callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
	callbacks.recv_stream_data = OnRecvStreamData;
	callbacks.update_key = ngtcp2_crypto_update_key_cb;
	callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
	callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
	callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
	callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
	callbacks.rand = OnRand;
	callbacks.get_new_connection_id = OnGetNewConnectionId;

	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	// Read from the same source every later timestamp comes from. A zero here
	// against a steady_clock that is already hours old would make the
	// handshake timeout expire before the first packet was written.
	settings.initial_ts = MonotonicNs();
	// A half-open connection is the normal failure mode of NAT traversal, not
	// an exception, so the bound is not optional: without it every peer that
	// ever punched at this client would leave connection state behind.
	settings.handshake_timeout = MsToNs(kHandshakeTimeoutMs);
	settings.max_tx_udp_payload_size = kMaxDatagramSize;

	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);
	params.initial_max_streams_bidi = 1;
	params.initial_max_streams_uni = 0;
	// One stream, sized for the proof plus a modest amount of data. The
	// transport does not carry a file transfer in this change; a large window
	// advertised for bytes nobody reads would be a promise this end cannot
	// keep.
	params.initial_max_stream_data_bidi_remote = 64 * 1024;
	params.initial_max_stream_data_bidi_local = 64 * 1024;
	params.initial_max_data = 128 * 1024;
	params.max_idle_timeout = MsToNs(kIdleTimeoutMs);
	params.original_dcid = header.dcid;
	params.original_dcid_present = 1;

	ngtcp2_cid scid;
	scid.datalen = kConnectionIdLength;
	if (gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen) != 0) {
		return false;
	}

	if (ngtcp2_conn_server_new(&m_conn,
		    &header.scid,
		    &scid,
		    &m_path.path,
		    header.version,
		    &callbacks,
		    &settings,
		    &params,
		    nullptr,
		    this) != 0) {
		m_conn = nullptr;
		return false;
	}

	ngtcp2_conn_set_tls_native_handle(m_conn, m_session);
	return true;
}

bool CQuicConnection::ReadPacket(const std::uint8_t *payload, std::size_t length, std::uint64_t nowNs)
{
	if (m_conn == nullptr || m_closed) {
		return false;
	}

	ngtcp2_pkt_info packetInfo{};
	const int result = ngtcp2_conn_read_pkt(m_conn, &m_path.path, &packetInfo, payload, length, nowNs);
	if (result != 0) {
		// Every read error ends this connection. ngtcp2 distinguishes a good
		// many of them, but none is recoverable from here: a draining
		// connection, a failed decryption and a refused handshake all mean
		// the same thing to a NAT-traversal transport whose fallback is to
		// reach the peer over uTP instead.
		//
		// Reported as a refused handshake rather than an authentication
		// failure, and the distinction is the point: a rejected ALPN arrives
		// here, and a peer speaking a different protocol version is not a peer
		// claiming to be somebody else.
		MarkClosed(QUIC_CONNECTION_HANDSHAKE_FAILED, QUIC_PROOF_VALID);
		return true;
	}

	DrainOutbound(nowNs);
	return true;
}

void CQuicConnection::DrainOutbound(std::uint64_t nowNs)
{
	if (m_conn == nullptr || m_closed) {
		return;
	}

	// Bounded rather than "until ngtcp2 says stop". ngtcp2 returns 0 when it
	// has nothing more, so the loop terminates on its own -- but this runs on
	// the socket's receive path, and a bound is what keeps a pathological
	// connection from holding that path for an unbounded time.
	for (int packet = 0; packet < 16; ++packet) {
		std::uint8_t buffer[kMaxDatagramSize];
		ngtcp2_pkt_info packetInfo{};

		const ngtcp2_ssize written = ngtcp2_conn_writev_stream(m_conn,
			&m_path.path,
			&packetInfo,
			buffer,
			sizeof(buffer),
			nullptr,
			NGTCP2_WRITE_STREAM_FLAG_NONE,
			-1,
			nullptr,
			0,
			nowNs);

		if (written < 0) {
			MarkClosed(QUIC_CONNECTION_HANDSHAKE_FAILED, QUIC_PROOF_VALID);
			return;
		}
		if (written == 0) {
			return;
		}

		m_owner->Send(buffer, static_cast<std::size_t>(written), m_peer, m_port);
	}
}

void CQuicConnection::HandleExpiry(std::uint64_t nowNs)
{
	if (m_conn == nullptr || m_closed) {
		return;
	}

	if (ngtcp2_conn_get_expiry(m_conn) > nowNs) {
		return;
	}

	if (ngtcp2_conn_handle_expiry(m_conn, nowNs) != 0) {
		// The idle timeout, the handshake timeout, or loss detection giving
		// up. A fact about the path rather than about the peer -- see
		// EQuicConnectionOutcome. On a NAT-traversed path this is the ordinary
		// outcome rather than an exception, which is exactly why it must not
		// share a log line with an authentication failure.
		MarkClosed(QUIC_CONNECTION_TIMED_OUT, QUIC_PROOF_VALID);
		return;
	}

	DrainOutbound(nowNs);
}

// --- CQuicEndpoint ----------------------------------------------------------

bool CQuicEndpoint::GenerateSelfSignedCredentials()
{
	gnutls_x509_privkey_t key = nullptr;
	gnutls_x509_crt_t certificate = nullptr;
	bool succeeded = false;

	do {
		if (gnutls_x509_privkey_init(&key) != GNUTLS_E_SUCCESS) {
			key = nullptr;
			break;
		}
		if (gnutls_x509_privkey_generate(
			    key, GNUTLS_PK_ECDSA, GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0) !=
			GNUTLS_E_SUCCESS) {
			break;
		}
		if (gnutls_x509_crt_init(&certificate) != GNUTLS_E_SUCCESS) {
			certificate = nullptr;
			break;
		}

		// A deliberately uninformative subject. The certificate exists because
		// TLS requires one, not because anything reads it: authentication is
		// the peer proof. A hostname or user identifier here would be a
		// long-lived identifier travelling in the clear during every
		// handshake.
		if (gnutls_x509_crt_set_dn(certificate, "CN=amule", nullptr) != GNUTLS_E_SUCCESS) {
			break;
		}
		if (gnutls_x509_crt_set_key(certificate, key) != GNUTLS_E_SUCCESS) {
			break;
		}

		unsigned char serial[8];
		if (gnutls_rnd(GNUTLS_RND_NONCE, serial, sizeof(serial)) != 0) {
			break;
		}
		if (gnutls_x509_crt_set_serial(certificate, serial, sizeof(serial)) != GNUTLS_E_SUCCESS) {
			break;
		}

		const time_t now = time(nullptr);
		// A year of validity. The certificate does not outlive the process,
		// so the window only has to be wide enough to absorb a peer whose
		// clock disagrees with ours -- and starting it in the past is what
		// absorbs the disagreement in the direction that would otherwise
		// reject every handshake for the first hour.
		if (gnutls_x509_crt_set_activation_time(certificate, now - 3600) != GNUTLS_E_SUCCESS ||
			gnutls_x509_crt_set_expiration_time(certificate, now + (365 * 24 * 3600)) !=
				GNUTLS_E_SUCCESS) {
			break;
		}
		if (gnutls_x509_crt_set_version(certificate, 3) != GNUTLS_E_SUCCESS) {
			break;
		}
		if (gnutls_x509_crt_sign2(certificate, certificate, key, GNUTLS_DIG_SHA256, 0) !=
			GNUTLS_E_SUCCESS) {
			break;
		}
		if (gnutls_certificate_set_x509_key(m_credentials, &certificate, 1, key) !=
			GNUTLS_E_SUCCESS) {
			break;
		}

		succeeded = true;
	} while (false);

	if (certificate != nullptr) {
		gnutls_x509_crt_deinit(certificate);
	}
	if (key != nullptr) {
		gnutls_x509_privkey_deinit(key);
	}

	return succeeded;
}

bool CQuicEndpoint::Initialise()
{
	if (gnutls_certificate_allocate_credentials(&m_credentials) != GNUTLS_E_SUCCESS) {
		m_credentials = nullptr;
		return false;
	}

	if (!GenerateSelfSignedCredentials()) {
		gnutls_certificate_free_credentials(m_credentials);
		m_credentials = nullptr;
		return false;
	}

	return true;
}

void CQuicEndpoint::Send(
	const std::uint8_t *packet, std::size_t length, const CNetworkAddress &to, std::uint16_t port)
{
	IQuicDatagramSink *sink = (m_owner != nullptr) ? m_owner->GetSink() : nullptr;
	if (sink == nullptr) {
		return;
	}

	sink->SendQuicDatagram(packet, length, to, port);
}

const SQuicPeerExpectation *CQuicEndpoint::FindExpectation(
	const CNetworkAddress &peer, std::uint16_t port) const
{
	(void)peer;
	(void)port;
	return nullptr;
}

CQuicConnection *CQuicEndpoint::FindConnection(const CNetworkAddress &from, std::uint16_t port)
{
	for (std::unique_ptr<CQuicConnection> &connection : m_connections) {
		if (!connection->IsClosed() && connection->IsFor(from, port)) {
			return connection.get();
		}
	}

	return nullptr;
}

void CQuicEndpoint::SweepClosed()
{
	std::size_t kept = 0;
	for (std::size_t i = 0; i < m_connections.size(); ++i) {
		if (!m_connections[i]->IsClosed()) {
			if (kept != i) {
				m_connections[kept] = std::move(m_connections[i]);
			}
			++kept;
		}
	}
	m_connections.resize(kept);
}

bool CQuicEndpoint::ProcessDatagram(const std::uint8_t *payload,
	std::size_t length,
	const CNetworkAddress &from,
	std::uint16_t port,
	std::uint64_t nowNs)
{
	if (payload == nullptr || length == 0 || !AcceptsInbound()) {
		return false;
	}

	CQuicConnection *connection = FindConnection(from, port);
	if (connection != nullptr) {
		const bool claimed = connection->ReadPacket(payload, length, nowNs);
		SweepClosed();
		return claimed;
	}

	// No connection yet: this is only ours if it is an Initial packet that
	// ngtcp2 itself recognises. Anything else on the QUIC frame type is
	// declined rather than guessed at, so it continues to the ed2k UDP parser
	// and is dropped there with a reason.
	ngtcp2_pkt_hd header;
	if (ngtcp2_accept(&header, payload, length) != 0) {
		return false;
	}

	// The local address ngtcp2 records for the path. The client UDP socket
	// binds a wildcard address, and nothing in this transport routes on it --
	// the peer's address is what identifies a connection -- so an unspecified
	// local address is the honest value rather than a fabricated one.
	sockaddr_in local = sockaddr_in();
	local.sin_family = AF_INET;

	std::unique_ptr<CQuicConnection> fresh(new CQuicConnection(this, from, port));
	if (!fresh->BeginServerHandshake(header, local)) {
		// The handshake could not be started: no TLS session, or ngtcp2
		// refused the settings. Declined rather than half-created, so the
		// datagram continues to the ed2k side and nothing is left behind.
		return false;
	}

	CQuicConnection *created = fresh.get();
	m_connections.push_back(std::move(fresh));

	const bool claimed = created->ReadPacket(payload, length, nowNs);
	SweepClosed();
	return claimed;
}

void CQuicEndpoint::CheckTimeouts(std::uint64_t nowNs)
{
	// Over an index rather than an iterator: HandleExpiry() can close a
	// connection, and SweepClosed() runs after the pass rather than during it
	// precisely so nothing is destroyed while ngtcp2 is inside it.
	for (std::size_t i = 0; i < m_connections.size(); ++i) {
		m_connections[i]->HandleExpiry(nowNs);
	}

	SweepClosed();
}

} // namespace

// --- CQuicLibraryAdapter ----------------------------------------------------

void *CQuicLibraryAdapter::CreateEndpoint()
{
	// GnuTLS's global initialisation is idempotent and reference counted since
	// 3.3, and every aMule build that reaches here has exactly one endpoint,
	// so calling it at the one place an endpoint is built is both sufficient
	// and safe.
	if (gnutls_global_init() != GNUTLS_E_SUCCESS) {
		return nullptr;
	}

	std::unique_ptr<CQuicEndpoint> endpoint(new CQuicEndpoint(m_owner));
	if (!endpoint->Initialise()) {
		// Silent by design: a client that cannot bring QUIC up advertises no
		// QUIC capability and reaches its peers over uTP. The user sees a
		// slower path, never an error -- see the design's fallback section.
		return nullptr;
	}

	return endpoint.release();
}

void CQuicLibraryAdapter::DestroyEndpoint(void *endpoint)
{
	delete static_cast<CQuicEndpoint *>(endpoint);
}

bool CQuicLibraryAdapter::ProcessDatagram(void *endpoint,
	const std::uint8_t *payload,
	std::size_t length,
	const CNetworkAddress &from,
	std::uint16_t port)
{
	if (endpoint == nullptr) {
		return false;
	}

	// ngtcp2 counts in nanoseconds against a monotonic clock of the
	// application's choosing. Both this and CheckTimeouts() read MonotonicNs(),
	// which is the whole of that choice -- see the note on that function.
	return static_cast<CQuicEndpoint *>(endpoint)->ProcessDatagram(
		payload, length, from, port, MonotonicNs());
}

bool CQuicLibraryAdapter::AcceptsInboundConnections(void *endpoint) const
{
	if (endpoint == nullptr) {
		return false;
	}

	return static_cast<CQuicEndpoint *>(endpoint)->AcceptsInbound();
}

void CQuicLibraryAdapter::CheckTimeouts(void *endpoint, std::uint64_t nowMs)
{
	(void)nowMs;

	if (endpoint == nullptr) {
		return;
	}

	// aMule's millisecond tick is not ngtcp2's clock, and converting it would
	// introduce a second time source. The caller's tick is what schedules this
	// pass; what the pass is measured against is MonotonicNs(), the same
	// reading ProcessDatagram() uses.
	static_cast<CQuicEndpoint *>(endpoint)->CheckTimeouts(MonotonicNs());
}

#else // !AMULE_QUIC_TRANSPORT

// The -DENABLE_QUIC=NO build, which is the default and the only configuration
// macOS gets. Every method is inert and the translation unit pulls in neither
// ngtcp2 nor GnuTLS, so the file compiles with neither installed. CQuicContext
// is simply never configured with one of these, and a NULL endpoint keeps every
// path through the context on its inert branch.

void *CQuicLibraryAdapter::CreateEndpoint()
{
	return nullptr;
}

void CQuicLibraryAdapter::DestroyEndpoint(void *) {}

bool CQuicLibraryAdapter::ProcessDatagram(
	void *, const std::uint8_t *, std::size_t, const CNetworkAddress &, std::uint16_t)
{
	return false;
}

bool CQuicLibraryAdapter::AcceptsInboundConnections(void *) const
{
	return false;
}

void CQuicLibraryAdapter::CheckTimeouts(void *, std::uint64_t) {}

#endif // AMULE_QUIC_TRANSPORT
