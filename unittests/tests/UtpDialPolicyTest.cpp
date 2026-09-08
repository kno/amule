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

// Whether a peer is dialled over uTP or over TCP, and -- when it is not --
// whether anything failed.
//
// This is first a characterisation of the path that has nothing to do with
// uTP. The overwhelming majority of ed2k peers do not advertise
// MOD_MISCOPT_NAT_TRAVERSAL, and for every one of them the connection must be
// the connection aMule made before uTP existed: no uTP attempt, and no
// transport failure recorded, because nothing was attempted and so nothing
// failed. A transport failure recorded there would not break the dial -- the
// fallback still reaches TCP -- it would quietly change what happens to the
// peer afterwards, since Connect() and Disconnected() both branch on it. That
// is the regression with no symptom, and it is why the decision is a function
// with a test rather than a few conditions inside CUpDownClient::Connect().
//
// The second half is the reverse: every reason this end cannot use uTP for a
// peer that did advertise it -- no libutp in the build, an address family this
// transport does not carry yet, no address at all -- is a fact about our side
// of the path and must be recorded as a transport failure, so the peer is
// dialled over TCP and keeps its place in the source list.

#include <muleunit/test.h>

#include <NetworkAddress.h>
#include <UtpDialPolicy.h>

using namespace muleunit;

DECLARE_SIMPLE(UtpDialPolicy)

namespace
{

const CNetworkAddress Peer4()
{
	return CNetworkAddress::FromString("192.0.2.10");
}

const CNetworkAddress Peer6()
{
	return CNetworkAddress::FromString("2001:db8::1");
}

} // namespace

// The characterisation that matters most in this change: an ordinary ed2k peer.
// It never claimed uTP, so nothing is attempted, nothing failed, and the dial
// is the TCP dial aMule has always made. Both flags false is the whole
// assertion -- `recordTransportFailure` true here would leave the peer on a
// path where Connect() logs a fallback and Disconnected() refuses to blame it,
// for a connection where uTP was never involved.
TEST(UtpDialPolicy, PeerWithoutTheCapabilityTakesThePreUtpTcpPath)
{
	const SUtpDialDecision decision = DecideUtpDial(false, true, false, Peer4());

	ASSERT_FALSE(decision.attemptUtp);
	ASSERT_FALSE(decision.recordTransportFailure);
	ASSERT_TRUE(decision.refusal == UTP_DIAL_PEER_DOES_NOT_ADVERTISE_UTP);
}

// Same answer with no context at all, which is every default build: the peer
// did not ask for uTP, so the absence of uTP is not a failure of anything.
TEST(UtpDialPolicy, PeerWithoutTheCapabilityIsUnaffectedByTheBuildConfiguration)
{
	const SUtpDialDecision withUtp = DecideUtpDial(false, true, false, Peer4());
	const SUtpDialDecision withoutUtp = DecideUtpDial(false, false, false, Peer4());

	ASSERT_FALSE(withUtp.attemptUtp);
	ASSERT_FALSE(withoutUtp.attemptUtp);
	ASSERT_FALSE(withUtp.recordTransportFailure);
	ASSERT_FALSE(withoutUtp.recordTransportFailure);
	ASSERT_TRUE(withUtp.refusal == withoutUtp.refusal);
}

// The peer advertises uTP and this build has no libutp. That is a property of
// our side of the path, so it is a transport failure: the peer is dialled over
// TCP and keeps its place. Blaming it would cost a source for a decision the
// user made at configure time.
TEST(UtpDialPolicy, NoContextIsATransportFailureAndNotThePeersFault)
{
	const SUtpDialDecision decision = DecideUtpDial(true, false, false, Peer4());

	ASSERT_FALSE(decision.attemptUtp);
	ASSERT_TRUE(decision.recordTransportFailure);
	ASSERT_TRUE(decision.refusal == UTP_DIAL_NO_CONTEXT);
}

// IPv4-only staging, deliberately, even though address widening has landed:
// adding a transport and an address family in one change makes a stall
// impossible to attribute. The family rule is CUtpContext::IsUsableEndpoint()
// and is read from there rather than restated, so enabling IPv6 uTP later
// moves this test with the predicate instead of leaving it asserting the old
// answer.
TEST(UtpDialPolicy, AnUncarriedAddressFamilyIsATransportFailure)
{
	const SUtpDialDecision decision = DecideUtpDial(true, true, false, Peer6());

	ASSERT_FALSE(decision.attemptUtp);
	ASSERT_TRUE(decision.recordTransportFailure);
	ASSERT_TRUE(decision.refusal == UTP_DIAL_ADDRESS_FAMILY_NOT_CARRIED);
}

// No address to dial is the same class of answer, and must not fault.
TEST(UtpDialPolicy, AnAbsentAddressIsATransportFailure)
{
	const SUtpDialDecision decision = DecideUtpDial(true, true, false, CNetworkAddress::Absent());

	ASSERT_FALSE(decision.attemptUtp);
	ASSERT_TRUE(decision.recordTransportFailure);
	ASSERT_TRUE(decision.refusal == UTP_DIAL_ADDRESS_FAMILY_NOT_CARRIED);
}

// A socket that reaches peers through a proxy is not dialled over uTP: uTP rides
// the ed2k UDP socket and negotiates nothing with SOCKS or HTTP CONNECT, so the
// SYN would go somewhere the proxy was never told about. Ours, not the peer's --
// the user configured the proxy -- so it is a transport failure and the peer
// keeps its place.
TEST(UtpDialPolicy, AProxiedSocketIsNotDialledOverUtp)
{
	const SUtpDialDecision decision = DecideUtpDial(true, true, true, Peer4());

	ASSERT_FALSE(decision.attemptUtp);
	ASSERT_TRUE(decision.recordTransportFailure);
	ASSERT_TRUE(decision.refusal == UTP_DIAL_PROXY_IN_USE);
}

// A proxy still changes nothing for a peer that never asked for uTP: that
// connection is the pre-uTP one whatever this end is configured with.
TEST(UtpDialPolicy, AProxyDoesNotDisturbAPeerThatNeverAskedForUtp)
{
	const SUtpDialDecision decision = DecideUtpDial(false, true, true, Peer4());

	ASSERT_FALSE(decision.attemptUtp);
	ASSERT_FALSE(decision.recordTransportFailure);
	ASSERT_TRUE(decision.refusal == UTP_DIAL_PEER_DOES_NOT_ADVERTISE_UTP);
}

// And the one case where uTP is actually dialled. Nothing has failed yet, so
// no transport failure is recorded: the attempt reports its own outcome
// through OnUtpConnected() or OnUtpTransportFailure().
TEST(UtpDialPolicy, AnAdvertisedPeerOnACarriedFamilyIsDialledOverUtp)
{
	const SUtpDialDecision decision = DecideUtpDial(true, true, false, Peer4());

	ASSERT_TRUE(decision.attemptUtp);
	ASSERT_FALSE(decision.recordTransportFailure);
	ASSERT_TRUE(decision.refusal == UTP_DIAL_ATTEMPT);
}

// The two flags are never both set. `attemptUtp` means the attempt is in
// flight and will report its own outcome; recording a failure at the same time
// would make Connect() fall back to TCP underneath a live uTP dial.
TEST(UtpDialPolicy, AttemptAndTransportFailureAreMutuallyExclusive)
{
	const bool flags[2] = { false, true };
	const CNetworkAddress peers[3] = { Peer4(), Peer6(), CNetworkAddress::Absent() };

	for (int a = 0; a < 2; ++a) {
		for (int c = 0; c < 2; ++c) {
			for (int x = 0; x < 2; ++x) {
				for (int p = 0; p < 3; ++p) {
					const SUtpDialDecision decision =
						DecideUtpDial(flags[a], flags[c], flags[x], peers[p]);
					ASSERT_FALSE(decision.attemptUtp && decision.recordTransportFailure);
				}
			}
		}
	}
}
