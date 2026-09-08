//
// This file is part of the aMule Project.
//
// Copyright (c) 2003-2026 aMule Team ( https://amule-org.github.io )
//
// The transport-failure distinction is ported from eMule AI's CUtpSocket
// (srchybrid/eMuleAI/UtpSocket.cpp, m_bTransportFailed):
// Copyright (C) 2013 David Xanatos ( XanatosDavid (a) gmail.com / http://NeoLoader.to )
// Copyright (C) 2026 eMule AI
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

#ifndef UTPTRANSPORTFAILURE_H
#define UTPTRANSPORTFAILURE_H

/**
 * Why a uTP connection attempt ended, and what the client may conclude from it.
 *
 * "The uTP handshake never completed" and "the peer refused the connection" are
 * facts about different things. The first is about the path -- a middlebox
 * dropping UDP, a NAT that did not hold, a firewall rule -- and says nothing
 * whatsoever about the peer. The second is about the peer.
 *
 * Conflating them costs sources, silently. Everything behind one UDP-blocking
 * middlebox produces the first outcome; read as the second, every one of those
 * peers is marked dead and dropped from the source list, and the only symptom
 * is a download with fewer sources than it should have. Nothing logs, because
 * from the client's point of view it did the ordinary thing with a failed
 * connection.
 *
 * eMuleAI keeps this as an explicit flag on the socket and reads it back
 * through CEMSocket (srchybrid/EMSocket.cpp:191). Here it is a small state plus
 * two pure decisions, so the rule that matters -- a transport failure is never
 * attributable to the peer -- is a function the client path calls rather than a
 * convention it is expected to remember.
 */
enum EUtpAttemptOutcome
{
	//! Nothing has been decided yet.
	UTP_ATTEMPT_PENDING,
	//! The uTP connection came up.
	UTP_ATTEMPT_CONNECTED,
	//! uTP could not be established: timeout, reset, or a path that drops it.
	//! Says nothing about the peer.
	UTP_ATTEMPT_TRANSPORT_FAILED,
	//! The peer answered and refused. This one IS about the peer.
	UTP_ATTEMPT_PEER_REFUSED
};

//! What the client should do next.
enum EUtpFallbackAction
{
	//! Nothing to fall back from.
	UTP_FALLBACK_NONE,
	//! Transport failure with TCP not yet tried: try TCP for this peer.
	UTP_FALLBACK_TRY_TCP,
	//! Transport failure with nothing left to try on this pass. The source is
	//! still kept: a peer behind a UDP-blocking middlebox is a candidate
	//! again next time.
	UTP_FALLBACK_GIVE_UP_KEEP_SOURCE,
	//! The peer itself refused, so the existing peer-level rules decide --
	//! exactly as they did before uTP existed.
	UTP_FALLBACK_PEER_LEVEL_HANDLING
};

/**
 * The state of one uTP connection attempt.
 *
 * Lives on the uTP side of a connection and is read by the client path. Reset
 * on reconnect: a transport failure that outlived its attempt would suppress
 * every later uTP attempt to that peer.
 */
class CUtpTransportState
{
public:
	CUtpTransportState() = default;

	void Reset() { m_outcome = UTP_ATTEMPT_PENDING; }

	void OnConnected() { m_outcome = UTP_ATTEMPT_CONNECTED; }
	void OnTransportFailure() { m_outcome = UTP_ATTEMPT_TRANSPORT_FAILED; }
	void OnPeerRefused() { m_outcome = UTP_ATTEMPT_PEER_REFUSED; }

	EUtpAttemptOutcome GetOutcome() const { return m_outcome; }

	bool HasTransportFailed() const { return m_outcome == UTP_ATTEMPT_TRANSPORT_FAILED; }
	bool HasPeerRefused() const { return m_outcome == UTP_ATTEMPT_PEER_REFUSED; }

private:
	EUtpAttemptOutcome m_outcome = UTP_ATTEMPT_PENDING;
};

/**
 * May this outcome be counted against the peer -- marking it dead, dropping it
 * from a source list, or anything else that treats the peer as the cause?
 *
 * False for a transport failure, always. That is the requirement, and it is a
 * function rather than a comment because a caller that forgets it produces no
 * symptom anyone can find.
 */
inline bool MayAttributeToPeer(EUtpAttemptOutcome outcome)
{
	return outcome == UTP_ATTEMPT_PEER_REFUSED;
}

/**
 * What to do after a uTP attempt.
 *
 * @param tcpAlreadyAttempted  whether a TCP connection to this peer has
 *                             already been tried on this pass.
 */
inline EUtpFallbackAction DecideFallback(EUtpAttemptOutcome outcome, bool tcpAlreadyAttempted)
{
	switch (outcome) {
	case UTP_ATTEMPT_TRANSPORT_FAILED:
		return tcpAlreadyAttempted ? UTP_FALLBACK_GIVE_UP_KEEP_SOURCE : UTP_FALLBACK_TRY_TCP;

	case UTP_ATTEMPT_PEER_REFUSED:
		return UTP_FALLBACK_PEER_LEVEL_HANDLING;

	case UTP_ATTEMPT_PENDING:
	case UTP_ATTEMPT_CONNECTED:
		break;
	}

	return UTP_FALLBACK_NONE;
}

/**
 * Everything the client connection path needs to know after a uTP attempt, in
 * one value.
 *
 * The three fields are the three things the spec delta constrains, and they are
 * returned together on purpose. `MayAttributeToPeer` and `DecideFallback` are
 * each correct alone, but a caller has to remember to consult both, and the
 * cost of forgetting the first one is invisible: sources quietly disappear. So
 * the client asks one question and gets one answer.
 */
struct SUtpAttemptDisposition
{
	//! Open a TCP connection to this peer instead.
	bool tryTcp = false;
	//! Add the peer to the dead-source list. False for every transport
	//! failure, always -- that is the requirement.
	bool markPeerDead = false;
	//! Remove the peer from the download's source list. Same rule.
	bool dropFromSourceList = false;
};

/**
 * Decide what happens to a peer after a uTP attempt.
 *
 * Called from CUpDownClient::Connect() to route the fallback, and from
 * CUpDownClient::Disconnected() to decide whether the peer may be blamed. Both
 * call sites read the same answer, so the two cannot drift apart.
 *
 * @param tcpAlreadyAttempted  whether a TCP connection to this peer has
 *                             already been tried on this pass.
 */
inline SUtpAttemptDisposition DisposeUtpAttempt(EUtpAttemptOutcome outcome, bool tcpAlreadyAttempted)
{
	SUtpAttemptDisposition disposition;

	switch (DecideFallback(outcome, tcpAlreadyAttempted)) {
	case UTP_FALLBACK_TRY_TCP:
		disposition.tryTcp = true;
		break;

	case UTP_FALLBACK_PEER_LEVEL_HANDLING:
		// The peer answered and refused, so the rules that predate uTP
		// apply unchanged -- including marking it dead.
		disposition.markPeerDead = MayAttributeToPeer(outcome);
		disposition.dropFromSourceList = MayAttributeToPeer(outcome);
		break;

	case UTP_FALLBACK_GIVE_UP_KEEP_SOURCE:
	case UTP_FALLBACK_NONE:
		// Nothing left to try, or nothing went wrong. Either way the peer
		// keeps its place: a transport failure taught us nothing about it.
		break;
	}

	return disposition;
}

#endif // UTPTRANSPORTFAILURE_H
