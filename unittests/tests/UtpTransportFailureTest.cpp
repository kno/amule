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

// "The uTP handshake did not complete" and "this peer refused the connection"
// are different facts about different things, and conflating them costs
// sources. A middlebox that drops UDP toward a peer produces the first for
// every peer behind it; if that is read as the second, a perfectly reachable
// peer is marked dead and removed from the source list, and the only symptom
// is a download that has fewer sources than it should.
//
// eMuleAI keeps the distinction as an explicit flag on the socket
// (CUtpSocket::m_bTransportFailed, srchybrid/eMuleAI/UtpSocket.cpp:593), read
// back through CEMSocket (srchybrid/EMSocket.cpp:191). This is the same
// distinction as a decision the client path can consume, which is what makes
// it assertable without a network: the failure of a transport must never be
// attributable to the peer.

#include <muleunit/test.h>

#include <UtpTransportFailure.h>

using namespace muleunit;

DECLARE_SIMPLE(UtpTransportFailure)

namespace
{

//! What the client would do to a source. Records rather than acts, so the
//! "must not be marked dead" half of the requirement is observable.
struct SSourceRecord
{
	bool markedDead = false;
	bool removedFromSourceList = false;
	bool downloadedOverTcp = false;
};

/**
 * The fallback sequence as the client connection path actually runs it.
 *
 * The sequencing itself is NOT reimplemented here: it comes from
 * DisposeUtpAttempt(), the same production function CUpDownClient::Connect()
 * and CUpDownClient::Disconnected() call. A test that re-derived the decision
 * locally would pass while the client did the opposite, which is the failure
 * mode this whole distinction exists to prevent.
 *
 * @param utpUsable      whether the uTP attempt reached an established state.
 * @param peerRefusesTcp whether the peer refuses the TCP connection that the
 *                       fallback opens.
 */
void RunConnectionAttempt(SSourceRecord &source, bool utpUsable, bool peerRefusesTcp)
{
	CUtpTransportState transport;

	if (utpUsable) {
		transport.OnConnected();
		return;
	}

	// No usable uTP path to this peer: transport failure, not refusal.
	transport.OnTransportFailure();

	SUtpAttemptDisposition disposition =
		DisposeUtpAttempt(transport.GetOutcome(), /* tcpAlreadyAttempted */ false);

	source.markedDead = disposition.markPeerDead;
	source.removedFromSourceList = disposition.dropFromSourceList;

	if (!disposition.tryTcp) {
		return;
	}

	// The uTP attempt is over the moment the TCP dial starts, so a later TCP
	// failure is judged on its own merits -- exactly what the client does.
	transport.Reset();

	if (peerRefusesTcp) {
		// Now the peer itself answered, and this IS about the peer.
		transport.OnPeerRefused();
		SUtpAttemptDisposition refusal =
			DisposeUtpAttempt(transport.GetOutcome(), /* tcpAlreadyAttempted */ true);
		source.markedDead = refusal.markPeerDead;
		return;
	}

	source.downloadedOverTcp = true;
}

} // namespace

// The two outcomes are distinct states, not one failure with a message. A
// single "failed" state is exactly what makes the misattribution possible.
TEST(UtpTransportFailure, TransportFailureAndPeerRefusalAreDifferentStates)
{
	CUtpTransportState fresh;
	ASSERT_EQUALS((int)UTP_ATTEMPT_PENDING, (int)fresh.GetOutcome());
	ASSERT_FALSE(fresh.HasTransportFailed());
	ASSERT_FALSE(fresh.HasPeerRefused());

	CUtpTransportState transport;
	transport.OnTransportFailure();
	ASSERT_EQUALS((int)UTP_ATTEMPT_TRANSPORT_FAILED, (int)transport.GetOutcome());
	ASSERT_TRUE(transport.HasTransportFailed());
	ASSERT_FALSE(transport.HasPeerRefused());

	CUtpTransportState refused;
	refused.OnPeerRefused();
	ASSERT_EQUALS((int)UTP_ATTEMPT_PEER_REFUSED, (int)refused.GetOutcome());
	ASSERT_TRUE(refused.HasPeerRefused());
	ASSERT_FALSE(refused.HasTransportFailed());

	CUtpTransportState connected;
	connected.OnConnected();
	ASSERT_EQUALS((int)UTP_ATTEMPT_CONNECTED, (int)connected.GetOutcome());
	ASSERT_FALSE(connected.HasTransportFailed());

	// A reconnect starts clean: a transport failure that outlived its
	// attempt would suppress every later uTP attempt to that peer.
	transport.Reset();
	ASSERT_EQUALS((int)UTP_ATTEMPT_PENDING, (int)transport.GetOutcome());
	ASSERT_FALSE(transport.HasTransportFailed());
}

// Spec delta, "uTP blocked by an intermediate network": a transport failure may
// never be counted against the peer. This is the assertion the whole
// distinction exists for.
TEST(UtpTransportFailure, TransportFailureIsNeverAttributableToThePeer)
{
	ASSERT_FALSE(MayAttributeToPeer(UTP_ATTEMPT_TRANSPORT_FAILED));

	// And the peer-level refusal still is, so this is a distinction rather
	// than a blanket amnesty that would keep dead peers in every source
	// list forever.
	ASSERT_TRUE(MayAttributeToPeer(UTP_ATTEMPT_PEER_REFUSED));

	ASSERT_FALSE(MayAttributeToPeer(UTP_ATTEMPT_PENDING));
	ASSERT_FALSE(MayAttributeToPeer(UTP_ATTEMPT_CONNECTED));
}

// The fallback itself: transport failure with TCP untried means try TCP.
TEST(UtpTransportFailure, TransportFailureFallsBackToTcp)
{
	ASSERT_EQUALS((int)UTP_FALLBACK_TRY_TCP, (int)DecideFallback(UTP_ATTEMPT_TRANSPORT_FAILED, false));

	// TCP already attempted: there is nothing left to fall back to on this
	// pass, and the source is still kept -- a peer behind a UDP-blocking
	// middlebox is a candidate again on the next attempt.
	ASSERT_EQUALS((int)UTP_FALLBACK_GIVE_UP_KEEP_SOURCE,
		(int)DecideFallback(UTP_ATTEMPT_TRANSPORT_FAILED, true));

	// A peer that answered and refused is not a transport problem, so it
	// does not route through the uTP fallback at all: the existing
	// peer-level rules decide, exactly as they did before uTP existed.
	ASSERT_EQUALS(
		(int)UTP_FALLBACK_PEER_LEVEL_HANDLING, (int)DecideFallback(UTP_ATTEMPT_PEER_REFUSED, false));
	ASSERT_EQUALS(
		(int)UTP_FALLBACK_PEER_LEVEL_HANDLING, (int)DecideFallback(UTP_ATTEMPT_PEER_REFUSED, true));

	// A connection that came up needs no fallback, and a pending one has
	// decided nothing yet.
	ASSERT_EQUALS((int)UTP_FALLBACK_NONE, (int)DecideFallback(UTP_ATTEMPT_CONNECTED, false));
	ASSERT_EQUALS((int)UTP_FALLBACK_NONE, (int)DecideFallback(UTP_ATTEMPT_PENDING, false));
}

// The disposition the client path consumes, in one place. This is the function
// CUpDownClient calls, so the three answers it returns are the three things the
// spec delta constrains: fall back to TCP, do not mark the peer dead, do not
// drop it from the source list.
TEST(UtpTransportFailure, DispositionOfATransportFailureSparesThePeerAndTriesTcp)
{
	SUtpAttemptDisposition first = DisposeUtpAttempt(UTP_ATTEMPT_TRANSPORT_FAILED, false);
	ASSERT_TRUE(first.tryTcp);
	ASSERT_FALSE(first.markPeerDead);
	ASSERT_FALSE(first.dropFromSourceList);

	// TCP already tried on this pass: nothing left to fall back to, and the
	// source is still kept -- a peer behind a UDP-blocking middlebox is a
	// candidate again next time.
	SUtpAttemptDisposition exhausted = DisposeUtpAttempt(UTP_ATTEMPT_TRANSPORT_FAILED, true);
	ASSERT_FALSE(exhausted.tryTcp);
	ASSERT_FALSE(exhausted.markPeerDead);
	ASSERT_FALSE(exhausted.dropFromSourceList);

	// A peer that answered and refused goes to the pre-uTP peer-level rules,
	// which do mark it. No uTP fallback is opened for it.
	SUtpAttemptDisposition refused = DisposeUtpAttempt(UTP_ATTEMPT_PEER_REFUSED, false);
	ASSERT_FALSE(refused.tryTcp);
	ASSERT_TRUE(refused.markPeerDead);

	// Nothing decided, or a connection that came up: no fallback, no mark.
	for (int outcome : { (int)UTP_ATTEMPT_PENDING, (int)UTP_ATTEMPT_CONNECTED }) {
		SUtpAttemptDisposition quiet = DisposeUtpAttempt((EUtpAttemptOutcome)outcome, false);
		ASSERT_FALSE(quiet.tryTcp);
		ASSERT_FALSE(quiet.markPeerDead);
		ASSERT_FALSE(quiet.dropFromSourceList);
	}
}

// Task 4.3: a peer reachable over TCP whose uTP never establishes must still be
// downloaded from, and must still be a source afterwards. Driven through the
// production disposition, not a local restatement of it.
TEST(UtpTransportFailure, UtpBlockedPeerStillDownloadsOverTcp)
{
	SSourceRecord source;
	RunConnectionAttempt(source, /* utpReachable */ false, /* peerRefusesTcp */ false);

	ASSERT_TRUE(source.downloadedOverTcp);
	ASSERT_FALSE(source.markedDead);
	ASSERT_FALSE(source.removedFromSourceList);
}

// The same path with a peer that does refuse the TCP connection: the mark is
// now legitimate. Without this case the test above would pass on a policy that
// simply never marks anything dead.
TEST(UtpTransportFailure, PeerThatRefusesTcpIsStillMarked)
{
	SSourceRecord source;
	RunConnectionAttempt(source, /* utpReachable */ false, /* peerRefusesTcp */ true);

	ASSERT_FALSE(source.downloadedOverTcp);
	ASSERT_TRUE(source.markedDead);
}

// And the case where uTP works: no fallback, nothing marked, no TCP connection
// opened. The transport failure flag must not be set by a successful attempt.
TEST(UtpTransportFailure, ReachableUtpPeerNeitherFallsBackNorIsMarked)
{
	SSourceRecord source;
	RunConnectionAttempt(source, /* utpReachable */ true, /* peerRefusesTcp */ false);

	ASSERT_FALSE(source.downloadedOverTcp);
	ASSERT_FALSE(source.markedDead);
	ASSERT_FALSE(source.removedFromSourceList);
}
