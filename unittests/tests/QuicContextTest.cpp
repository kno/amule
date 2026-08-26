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

// The QUIC context, driven by a fake IQuicLibrary.
//
// The same reasoning as the uTP suites next door: ngtcp2 sits behind an
// interface because a build configured with -DENABLE_QUIC=NO -- which is the
// default, and the only configuration macOS gets -- has no ngtcp2 at all, and
// because none of the behaviours below is observable through a real ngtcp2
// without a peer on the network.
//
// Three of them have no visible failure mode whatsoever:
//
//   - the tick must create the endpoint and run even with no inbound traffic,
//     because QUIC's loss detection lives there and the packet that would
//     drive a recovery on an idle connection is the one that was lost;
//   - a failed endpoint creation must not be retried on every core tick, or a
//     permanent condition becomes a permanent stream of work;
//   - "ngtcp2 is linked" and "this end can serve a connection" must stay
//     different answers, because the advertised capability bit follows the
//     second and a peer that reads it waits out the 1500 ms window for nothing.

#include <muleunit/test.h>

#include <NetworkAddress.h>
#include <QuicContext.h>

#include <cstring>
#include <string>
#include <vector>

using namespace muleunit;

DECLARE_SIMPLE(QuicContext)

namespace
{

//! Records what the context asked of the library, and answers as configured.
class CFakeQuicLibrary : public IQuicLibrary
{
public:
	//! What CreateEndpoint() hands back. Set to false to model a build whose
	//! TLS credentials did not come up.
	bool creationSucceeds = true;
	//! What AcceptsInboundConnections() answers for a created endpoint.
	bool acceptsInbound = true;
	//! What ProcessDatagram() answers.
	bool claimsDatagrams = true;

	int createCalls = 0;
	int destroyCalls = 0;
	int processCalls = 0;
	int timeoutCalls = 0;
	std::uint64_t lastTickMs = 0;
	std::size_t lastPayloadLength = 0;
	std::uint16_t lastPort = 0;

	void *CreateEndpoint() override
	{
		++createCalls;
		if (!creationSucceeds) {
			return nullptr;
		}
		// Any non-null token: the context treats it as opaque.
		return &m_endpointToken;
	}

	void DestroyEndpoint(void *endpoint) override
	{
		++destroyCalls;
		lastDestroyed = endpoint;
	}

	bool ProcessDatagram(void *endpoint,
		const std::uint8_t *payload,
		std::size_t length,
		const CNetworkAddress &from,
		std::uint16_t port) override
	{
		++processCalls;
		lastEndpoint = endpoint;
		lastPayload = payload;
		lastPayloadLength = length;
		lastFrom = from;
		lastPort = port;
		return claimsDatagrams;
	}

	bool AcceptsInboundConnections(void *endpoint) const override
	{
		return endpoint != nullptr && acceptsInbound;
	}

	void CheckTimeouts(void *endpoint, std::uint64_t nowMs) override
	{
		++timeoutCalls;
		lastEndpoint = endpoint;
		lastTickMs = nowMs;
	}

	void *lastEndpoint = nullptr;
	void *lastDestroyed = nullptr;
	const std::uint8_t *lastPayload = nullptr;
	CNetworkAddress lastFrom;

private:
	int m_endpointToken = 0;
};

//! Records the outcome the context's observer was told about.
class CFakeQuicObserver : public IQuicConnectionObserver
{
public:
	int calls = 0;
	EQuicConnectionOutcome lastOutcome = QUIC_CONNECTION_CLOSED;
	EQuicProofResult lastProofResult = QUIC_PROOF_VALID;
	std::uint16_t lastPort = 0;

	void OnQuicConnectionOutcome(EQuicConnectionOutcome outcome,
		EQuicProofResult proofResult,
		const CNetworkAddress &peer,
		std::uint16_t port) override
	{
		++calls;
		lastOutcome = outcome;
		lastProofResult = proofResult;
		lastPeer = peer;
		lastPort = port;
	}

	CNetworkAddress lastPeer;
};

const uint8_t kPayload[4] = { 0xC3, 0x00, 0x00, 0x01 };

} // namespace

// The default build, and the only one macOS gets. A context with no library is
// permanently inert: nothing is created, nothing is asked, and every answer is
// the one that sends the datagram on to the ed2k parser. The receive path and
// the core timer both run in that build, so "inert" has to mean safe rather
// than merely unused.
TEST(QuicContext, WithoutALibraryEverythingIsInertAndSafe)
{
	CQuicContext context;

	ASSERT_FALSE(context.IsAvailable());
	ASSERT_FALSE(context.CanServeConnections());
	ASSERT_FALSE(context.ProcessDatagram(
		kPayload, sizeof(kPayload), CNetworkAddress::FromString("192.0.2.10"), 4662));

	// The tick runs in this build too, and must not reach anything.
	context.Tick(1000);

	// Configuring with an explicit null library is the same state, not a
	// different one: that is what CClientUDPSocket does when ENABLE_QUIC is
	// off.
	context.Configure(nullptr, nullptr);
	ASSERT_FALSE(context.IsAvailable());
	ASSERT_FALSE(context.CanServeConnections());
}

// The endpoint is created once, on first use, and reused. Creating one per
// datagram would restart the TLS credentials on every inbound packet.
TEST(QuicContext, EndpointIsCreatedOnceAndReused)
{
	CFakeQuicLibrary library;
	CQuicContext context;
	context.Configure(&library, nullptr);

	ASSERT_TRUE(context.IsAvailable());
	ASSERT_EQUALS(0, library.createCalls);

	ASSERT_TRUE(context.ProcessDatagram(
		kPayload, sizeof(kPayload), CNetworkAddress::FromString("192.0.2.10"), 4662));
	ASSERT_EQUALS(1, library.createCalls);

	context.Tick(100);
	ASSERT_TRUE(context.CanServeConnections());
	ASSERT_TRUE(context.ProcessDatagram(
		kPayload, sizeof(kPayload), CNetworkAddress::FromString("192.0.2.11"), 4662));

	ASSERT_EQUALS(1, library.createCalls);
	ASSERT_EQUALS(2, library.processCalls);

	// The payload window reaches ngtcp2 unmodified, past the framing bytes
	// the socket stripped.
	ASSERT_TRUE(library.lastPayload == kPayload);
	ASSERT_EQUALS(4u, (unsigned)library.lastPayloadLength);
	ASSERT_EQUALS(4662, (int)library.lastPort);
}

// A failed creation is remembered, not retried. QUIC fails to come up for
// reasons that do not change between two calls a hundred milliseconds apart --
// absent TLS credentials, an ngtcp2 that refused its settings -- so a retry per
// core tick would turn a permanent condition into permanent work, and into a
// log line every 100 ms if anything reported it.
TEST(QuicContext, FailedEndpointCreationIsNotRetried)
{
	CFakeQuicLibrary library;
	library.creationSucceeds = false;

	CQuicContext context;
	context.Configure(&library, nullptr);

	ASSERT_FALSE(context.CanServeConnections());
	ASSERT_EQUALS(1, library.createCalls);

	for (int i = 0; i < 50; ++i) {
		context.Tick((std::uint64_t)(i * 100));
		ASSERT_FALSE(context.ProcessDatagram(
			kPayload, sizeof(kPayload), CNetworkAddress::FromString("192.0.2.10"), 4662));
		ASSERT_FALSE(context.CanServeConnections());
	}

	ASSERT_EQUALS(1, library.createCalls);
	// And nothing was ever handed to a library that has no endpoint.
	ASSERT_EQUALS(0, library.processCalls);
	ASSERT_EQUALS(0, library.timeoutCalls);
}

// "ngtcp2 is linked" and "this end can serve a connection" are different
// questions, and the capability bit follows the second. A build whose TLS
// credentials came up but which answers no inbound handshake must not advertise
// QUIC: the peer would spend the whole 1500 ms window waiting for a capability
// frame that never comes, and neither side would log a reason.
TEST(QuicContext, ServingIsNotTheSameQuestionAsBeingAvailable)
{
	CFakeQuicLibrary library;
	library.acceptsInbound = false;

	CQuicContext context;
	context.Configure(&library, nullptr);

	ASSERT_TRUE(context.IsAvailable());
	ASSERT_FALSE(context.CanServeConnections());

	library.acceptsInbound = true;
	ASSERT_TRUE(context.CanServeConnections());
}

// The tick creates the endpoint and runs with no inbound traffic ever having
// arrived. This is the guarantee with no symptom: QUIC's loss detection and
// idle timer live in this pass, so an endpoint serviced only when a packet
// arrives cannot recover a lost packet on an idle connection -- the packet that
// would drive the recovery is the one that was lost.
TEST(QuicContext, TickRunsAndCreatesTheEndpointWithoutAnyTraffic)
{
	CFakeQuicLibrary library;
	CQuicContext context;
	context.Configure(&library, nullptr);

	context.Tick(500);

	ASSERT_EQUALS(1, library.createCalls);
	ASSERT_EQUALS(1, library.timeoutCalls);
	ASSERT_EQUALS(0, library.processCalls);
	ASSERT_EQUALS(500u, (unsigned)library.lastTickMs);

	context.Tick(600);
	ASSERT_EQUALS(2, library.timeoutCalls);
	ASSERT_EQUALS(600u, (unsigned)library.lastTickMs);
	ASSERT_EQUALS(1, library.createCalls);
}

// A native IPv6 peer is declined rather than reached at 0.0.0.0. The client UDP
// socket's send path takes a 32-bit address, so a connection opened for such a
// peer would send its packets somewhere else entirely -- the same narrowing
// boundary CUtpContext::IsUsableEndpoint() draws.
TEST(QuicContext, NativeIPv6PeersAreDeclinedWithoutReachingTheLibrary)
{
	CFakeQuicLibrary library;
	CQuicContext context;
	context.Configure(&library, nullptr);

	ASSERT_FALSE(context.ProcessDatagram(
		kPayload, sizeof(kPayload), CNetworkAddress::FromString("2001:db8::1"), 4662));
	ASSERT_EQUALS(0, library.processCalls);
	// Declined before the endpoint was even needed.
	ASSERT_EQUALS(0, library.createCalls);

	// An unspecified address is the same refusal, not a crash.
	ASSERT_FALSE(context.ProcessDatagram(
		kPayload, sizeof(kPayload), CNetworkAddress::FromString("0.0.0.0"), 4662));
	ASSERT_EQUALS(0, library.processCalls);

	// An IPv4-mapped address is carried, because it narrows to a real IPv4
	// endpoint: the refusal is about what the socket can address, not about
	// which family the peer announced itself in.
	ASSERT_TRUE(context.ProcessDatagram(
		kPayload, sizeof(kPayload), CNetworkAddress::FromString("::ffff:192.0.2.10"), 4662));
	ASSERT_EQUALS(1, library.processCalls);

	ASSERT_TRUE(CQuicContext::IsUsableEndpointAddress(CNetworkAddress::FromString("192.0.2.10")));
	ASSERT_FALSE(CQuicContext::IsUsableEndpointAddress(CNetworkAddress::FromString("2001:db8::1")));
}

// A datagram ngtcp2 declines must be reported as declined, so the caller lets
// it continue to the ed2k UDP parser. Claiming it would silently drop a frame
// the ed2k side knows how to handle.
TEST(QuicContext, DeclinedDatagramIsReportedAsDeclined)
{
	CFakeQuicLibrary library;
	library.claimsDatagrams = false;

	CQuicContext context;
	context.Configure(&library, nullptr);

	ASSERT_FALSE(context.ProcessDatagram(
		kPayload, sizeof(kPayload), CNetworkAddress::FromString("192.0.2.10"), 4662));
	ASSERT_EQUALS(1, library.processCalls);
}

// Reconfiguring or destroying the context tears the endpoint down exactly once,
// and a later use builds a fresh one. Leaking it would leave ngtcp2 holding the
// old socket's connections after the UDP socket was reopened.
TEST(QuicContext, ResetDestroysTheEndpointAndAllowsAFreshOne)
{
	CFakeQuicLibrary library;

	{
		CQuicContext context;
		context.Configure(&library, nullptr);
		context.Tick(100);
		ASSERT_EQUALS(1, library.createCalls);

		context.Reset();
		ASSERT_EQUALS(1, library.destroyCalls);
		ASSERT_TRUE(library.lastDestroyed != nullptr);

		// Reset does not un-configure: the next use builds a fresh endpoint.
		context.Tick(200);
		ASSERT_EQUALS(2, library.createCalls);
	}

	// The destructor took the second one.
	ASSERT_EQUALS(2, library.destroyCalls);

	// Resetting a context that has no endpoint is a no-op, not a double free.
	CQuicContext empty;
	empty.Reset();
	empty.Reset();
	ASSERT_EQUALS(2, library.destroyCalls);
}

// Task 3.3: the log has to say which of the two happened, and the decision of
// which it is must not live inside a log call. QuicLibraryAdapter.cpp cannot
// include Logger.h -- it is the one translation unit that sees ngtcp2's and
// GnuTLS's headers and must stay clear of aMule's Types.h, exactly as
// UtpLibraryAdapter.cpp stays clear of it -- so the outcome travels out to a
// wx-aware translation unit through IQuicConnectionObserver, and the
// classification is a function this suite can assert.
//
// The distinction is not cosmetic. A transport failure is the network: a
// dropped datagram, a NAT that did not hold, and on a traversed path those are
// constant. An authentication failure is a peer that reached this end and
// failed to prove which ed2k client it is. One "QUIC connection failed" line
// for both buries the second inside the ordinary noise of the first.
TEST(QuicContext, AuthenticationOutcomesAreDistinguishedFromTransportOnes)
{
	ASSERT_TRUE(IsQuicAuthenticationOutcome(QUIC_CONNECTION_AUTHENTICATION_FAILED));

	// Everything else is the path or the protocol, never the peer's identity.
	// A refused handshake -- which includes a rejected ALPN -- is deliberately
	// on this side of the line: a peer speaking a different protocol is not a
	// peer claiming to be somebody else.
	ASSERT_FALSE(IsQuicAuthenticationOutcome(QUIC_CONNECTION_ESTABLISHED));
	ASSERT_FALSE(IsQuicAuthenticationOutcome(QUIC_CONNECTION_CLOSED));
	ASSERT_FALSE(IsQuicAuthenticationOutcome(QUIC_CONNECTION_TIMED_OUT));
	ASSERT_FALSE(IsQuicAuthenticationOutcome(QUIC_CONNECTION_HANDSHAKE_FAILED));

	// And each outcome names itself, distinctly: the log line is the only
	// place a person ever reads these.
	const EQuicConnectionOutcome all[] = { QUIC_CONNECTION_ESTABLISHED,
		QUIC_CONNECTION_CLOSED,
		QUIC_CONNECTION_TIMED_OUT,
		QUIC_CONNECTION_HANDSHAKE_FAILED,
		QUIC_CONNECTION_AUTHENTICATION_FAILED };

	for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); ++i) {
		ASSERT_TRUE(QuicConnectionOutcomeName(all[i]) != nullptr);
		for (size_t j = i + 1; j < sizeof(all) / sizeof(all[0]); ++j) {
			ASSERT_TRUE(strcmp(QuicConnectionOutcomeName(all[i]),
					    QuicConnectionOutcomeName(all[j])) != 0);
		}
	}
}

// The observer is optional and reaches the caller unchanged. Optional because
// a build with no QUIC never has one and the context must not care; unchanged
// because the adapter finds it through the context rather than being handed it
// separately, so there is one owner of the pointer.
TEST(QuicContext, ObserverIsOptionalAndHandedThrough)
{
	CFakeQuicLibrary library;
	CFakeQuicObserver observer;
	CQuicContext context;

	context.Configure(&library, nullptr);
	ASSERT_TRUE(context.GetObserver() == nullptr);

	context.Configure(&library, nullptr, &observer);
	ASSERT_TRUE(context.GetObserver() == &observer);

	// The outcome and its reason travel together: a log line that named the
	// outcome without the proof result could not tell an absent proof from one
	// for the wrong identity.
	context.GetObserver()->OnQuicConnectionOutcome(QUIC_CONNECTION_AUTHENTICATION_FAILED,
		QUIC_PROOF_WRONG_IDENTITY,
		CNetworkAddress::FromString("192.0.2.10"),
		4662);

	ASSERT_EQUALS(1, observer.calls);
	ASSERT_EQUALS((int)QUIC_CONNECTION_AUTHENTICATION_FAILED, (int)observer.lastOutcome);
	ASSERT_EQUALS((int)QUIC_PROOF_WRONG_IDENTITY, (int)observer.lastProofResult);
	ASSERT_EQUALS(4662, (int)observer.lastPort);
}

// --- The expectation table --------------------------------------------------
//
// What an inbound QUIC connection is required to prove, learned from the peer's
// ed2k hello over TCP and held here per peer. This is the source
// CQuicEndpoint::FindExpectation() used not to have, and every test below is
// about the same property from a different side: the expectation must come from
// the hello and from nowhere else, and its absence must refuse rather than wave
// a connection through.

namespace
{

const std::uint8_t kPeerHash[QUIC_NATT_PROOF_VALUE_LENGTH] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

const std::uint8_t kPeerValue[QUIC_NATT_PROOF_VALUE_LENGTH] = {
	0xF1, 0xE2, 0xD3, 0xC4, 0xB5, 0xA6, 0x97, 0x88, 0x79, 0x6A, 0x5B, 0x4C, 0x3D, 0x2E, 0x1F, 0x00
};

} // namespace

// A context nobody told anything has no expectations, so the validator is
// handed NULL and refuses. This is the state the whole change had to preserve
// for peers that advertise nothing, and it is asserted first because it is the
// one that must never regress.
TEST(QuicContext, WithNothingLearnedThereIsNoExpectation)
{
	CQuicContext context;

	ASSERT_TRUE(context.FindExpectation(CNetworkAddress::FromString("192.0.2.10"), 4672) == nullptr);
}

TEST(QuicContext, AnExpectationIsFoundForTheExactEndpointItWasRegisteredFor)
{
	CQuicContext context;
	const CNetworkAddress peer = CNetworkAddress::FromString("192.0.2.10");

	ASSERT_TRUE(context.RegisterExpectation(peer, 4672, kPeerHash, kPeerValue));

	const SQuicPeerExpectation *found = context.FindExpectation(peer, 4672);
	ASSERT_TRUE(found != nullptr);
	ASSERT_EQUALS(0, memcmp(found->userHash, kPeerHash, QUIC_NATT_PROOF_VALUE_LENGTH));
	ASSERT_EQUALS(0, memcmp(found->proofValue, kPeerValue, QUIC_NATT_PROOF_VALUE_LENGTH));
}

// A different port is a different endpoint. Behind a NAT one address is many
// peers, so answering for any port would hand one peer's expectation to
// another's connection -- which is the impersonation this proof exists to stop,
// arriving through the lookup instead of through the wire.
TEST(QuicContext, ADifferentPortIsADifferentEndpoint)
{
	CQuicContext context;
	const CNetworkAddress peer = CNetworkAddress::FromString("192.0.2.10");

	ASSERT_TRUE(context.RegisterExpectation(peer, 4672, kPeerHash, kPeerValue));

	ASSERT_TRUE(context.FindExpectation(peer, 4673) == nullptr);
	ASSERT_TRUE(context.FindExpectation(CNetworkAddress::FromString("192.0.2.11"), 4672) == nullptr);
}

// IPv4-mapped and plain IPv4 are one peer, matching PeerIdentity::IndexKey().
// The hello arrives over a TCP socket that may report either form and the
// datagram arrives over a UDP socket that may report the other, so two
// identities here would mean an expectation registered from the hello could
// never be found by the connection it was for.
TEST(QuicContext, MappedAndPlainIPv4AreTheSameEndpoint)
{
	CQuicContext context;

	ASSERT_TRUE(context.RegisterExpectation(
		CNetworkAddress::FromString("::ffff:192.0.2.10"), 4672, kPeerHash, kPeerValue));

	ASSERT_TRUE(context.FindExpectation(CNetworkAddress::FromString("192.0.2.10"), 4672) != nullptr);
}

// Every incomplete registration is refused, and refused without storing
// anything. A half-registered expectation is worse than none: it would be found
// by a lookup and then compared against uninitialised bytes.
TEST(QuicContext, AnIncompleteRegistrationStoresNothing)
{
	CQuicContext context;
	const CNetworkAddress peer = CNetworkAddress::FromString("192.0.2.10");

	ASSERT_FALSE(context.RegisterExpectation(peer, 4672, nullptr, kPeerValue));
	ASSERT_FALSE(context.RegisterExpectation(peer, 4672, kPeerHash, nullptr));
	// Port zero is "unknown", not a port -- see
	// PeerIdentity::MatchesUdpSourcePort(). An expectation under it would be
	// found by any datagram whose source port could not be read.
	ASSERT_FALSE(context.RegisterExpectation(peer, 0, kPeerHash, kPeerValue));
	ASSERT_FALSE(context.RegisterExpectation(CNetworkAddress::Absent(), 4672, kPeerHash, kPeerValue));

	ASSERT_TRUE(context.FindExpectation(peer, 4672) == nullptr);
	ASSERT_TRUE(context.FindExpectation(peer, 0) == nullptr);
}

// Re-registering the same endpoint replaces rather than accumulates: a peer
// that reconnects with a new key must be reachable under the new value, and a
// table that grew one entry per handshake would be a table a peer could grow
// without bound.
TEST(QuicContext, ReregisteringOneEndpointReplacesItsExpectation)
{
	CQuicContext context;
	const CNetworkAddress peer = CNetworkAddress::FromString("192.0.2.10");

	ASSERT_TRUE(context.RegisterExpectation(peer, 4672, kPeerHash, kPeerValue));
	ASSERT_TRUE(context.RegisterExpectation(peer, 4672, kPeerValue, kPeerHash));

	const SQuicPeerExpectation *found = context.FindExpectation(peer, 4672);
	ASSERT_TRUE(found != nullptr);
	ASSERT_EQUALS(0, memcmp(found->userHash, kPeerValue, QUIC_NATT_PROOF_VALUE_LENGTH));
	ASSERT_EQUALS(1u, (unsigned)context.CountExpectations());
}

TEST(QuicContext, ForgettingAnExpectationRefusesTheNextConnection)
{
	CQuicContext context;
	const CNetworkAddress peer = CNetworkAddress::FromString("192.0.2.10");

	ASSERT_TRUE(context.RegisterExpectation(peer, 4672, kPeerHash, kPeerValue));
	context.ForgetExpectation(peer, 4672);

	ASSERT_TRUE(context.FindExpectation(peer, 4672) == nullptr);
	ASSERT_EQUALS(0u, (unsigned)context.CountExpectations());
}

// The table is bounded. Expectations are registered from inbound handshakes, so
// an unbounded one is memory a stranger controls -- and the bound has to evict
// rather than refuse, or a flood of strangers would lock out every real peer
// registered after it.
TEST(QuicContext, TheTableIsBoundedAndEvictsTheOldestEntry)
{
	CQuicContext context;

	for (unsigned i = 0; i < kMaxQuicExpectations + 8; ++i) {
		// Distinct endpoints, one per port, so nothing here replaces anything.
		ASSERT_TRUE(context.RegisterExpectation(CNetworkAddress::FromString("192.0.2.10"),
			(std::uint16_t)(1024 + i),
			kPeerHash,
			kPeerValue));
	}

	ASSERT_EQUALS((unsigned)kMaxQuicExpectations, (unsigned)context.CountExpectations());
	// The first registrations are gone and the last are present: eviction is by
	// age, so the peers that most recently negotiated are the ones still able
	// to authenticate.
	ASSERT_TRUE(context.FindExpectation(CNetworkAddress::FromString("192.0.2.10"), 1024) == nullptr);
	ASSERT_TRUE(context.FindExpectation(CNetworkAddress::FromString("192.0.2.10"),
			    (std::uint16_t)(1024 + kMaxQuicExpectations + 7)) != nullptr);
}

// Reset() drops the endpoint but must not drop what the ed2k side learned. The
// two have different lifetimes: the endpoint is torn down when the UDP socket
// reopens, while an expectation belongs to a peer whose hello is still valid,
// and clearing it there would refuse the next connection from every peer that
// had already negotiated.
TEST(QuicContext, ResettingTheEndpointKeepsWhatTheHelloTaught)
{
	CFakeQuicLibrary library;
	CQuicContext context;
	context.Configure(&library, nullptr);

	const CNetworkAddress peer = CNetworkAddress::FromString("192.0.2.10");
	ASSERT_TRUE(context.RegisterExpectation(peer, 4672, kPeerHash, kPeerValue));
	ASSERT_TRUE(context.CanServeConnections());

	context.Reset();

	ASSERT_TRUE(context.FindExpectation(peer, 4672) != nullptr);
}
