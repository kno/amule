# Tasks: uTP transport

## 1. Dependency

- [x] 1.1 Add libutp to the CMake build with a bundled-or-system option
- [x] 1.2 Confirm the license notice is carried, including David Xanatos's copyright on ported code

## 2. Context plumbing

- [x] 2.1 Create one `utp_context` per client instance
- [x] 2.2 Wire the send callback to the existing ed2k UDP socket
- [x] 2.3 Offer inbound datagrams to the uTP context before the ed2k UDP parser
- [x] 2.4 Drive the context from a periodic tick independent of traffic
- [x] 2.5 Unit test: classification order both ways; idle retransmission fires

## 3. Stream interface

- [x] 3.1 Present the interface the client already consumes for TCP
- [x] 3.2 Implement the write buffer with growth and shrink thresholds
- [x] 3.3 Port the duplex-transfer detection and trim behaviour
- [x] 3.4 Cap growth at the documented maximum
- [x] 3.5 Unit test: duplex trim, blocked-write growth, growth ceiling

## 4. Fallback

- [x] 4.1 Add an explicit transport-failure state distinct from peer refusal
- [x] 4.2 Fall back to TCP on transport failure without marking the peer dead
- [x] 4.3 Unit test: a uTP transport failure routes to TCP and keeps the source

## 5. Staging

- [x] 5.1 Ship IPv4-only first; keep the family generic in the interface
- [~] 5.2 Enable IPv6 uTP — **DEFERRED, gate rewritten.** See below.

### 5.2 deferral record

The original wording was *"enable IPv6 uTP only after IPv4 uTP is stable in real
use"*. That gate cannot be satisfied from this tree at all: there is no deployment,
no users and no weeks of traffic to observe, so the task would stay open forever by
construction rather than by neglect. It is replaced by a gate that can actually
close.

**What is already done.** The whole uTP path is family-agnostic — it works in terms
of `CNetworkAddress`, which carries either family. The IPv4 restriction lives in
exactly one predicate:

```cpp
// src/UtpContext.h
static bool IsUsableEndpoint(const CNetworkAddress &address) { return address.IsIPv4(); }
```

All three deciding sites read it rather than restating the rule: the outbound dial
(`UtpDialPolicy.h`), outbound socket creation (`CreateOutboundSocket`) and inbound
datagram classification (`ProcessDatagram`). Task 5.1 was built this way on purpose,
so enabling IPv6 is a change to one predicate, not a change to the transport.

**The replacement gate.** Enable IPv6 uTP when both hold:

1. An IPv4 uTP transfer has completed between two aMule instances. This has never
   happened — not once. Not for want of code, but for want of a peer-discovery
   path: two containers on one podman network reach each other directly, yet no
   reachable ED2K server will hand them each other as sources. It needs
   cross-bootstrapped `nodes.dat` or a local ED2K server, which is shared
   infrastructure the live tests for this change and for `amule-nat-rendezvous`
   need anyway.
2. libutp has been confirmed to handle `sockaddr_in6` at the vendored commit. It
   uses `utp_packedsockaddr` internally and ships `libutp_inet_ntop.{cpp,h}` for
   address formatting, so this is a reading exercise against
   `src/extern/libutp`, not a guess.

**Why not simply turn it on now.** The proposal's reasoning holds: *"Adding a new
transport and a new address family in one change makes a stall impossible to
attribute."* And the proposal separately warns that a port omitting the
write-buffer thresholds "will appear to work in single-direction tests and stall
under real load". If that stall arrives with IPv6 also newly enabled, there is no
way to tell which of the two caused it. That is the same attribution discipline
`openspec/BASELINE.md` exists to protect.

**Recommended order:** land `amule-nat-rendezvous`, build the peer-discovery path,
then flip the predicate and verify against both families.

## 6. Capability advertisement

- [x] 6.1 Gate the advertised `MOD_MISCOPT_NAT_TRAVERSAL` bit on whether this
      end can serve a uTP connection, not on whether uTP was compiled in
- [x] 6.2 Unit test: uTP present but unable to serve advertises nothing; able to
      serve advertises the bit

## 7. Live transport

Task 3.1 asked for "the interface the client already consumes for TCP", and that
interface was delivered: `CUtpStream` presents Write/Read with the TCP side's
retry convention. Nothing substituted it under `CClientTCPSocket`, so uTP
carried no data, and no task in sections 1-6 named that substitution or the
inbound accept path. That is a hole in this breakdown rather than in the
implementation of 3.1, and it is recorded here rather than folded into 3.1 so
the plan shows where it was found.

- [x] 7.1 Decide the dial from one testable policy: whether the peer advertises
      uTP, whether this end has a context, and whether the transport carries
      that address family
- [x] 7.2 Unit test: a peer that does not advertise uTP takes the pre-uTP TCP
      path with no transport failure recorded; every "this end cannot" answer
      records one
- [x] 7.3 Substitute `CUtpStream` under `CClientTCPSocket`, so an outbound
      connection to a peer advertising `MOD_MISCOPT_NAT_TRAVERSAL` is carried
      over uTP and the stack above the socket is unchanged
- [x] 7.4 Unit test: application bytes cross a uTP transport in both directions;
      a timeout is a transport failure and a refusal is the peer's
- [x] 7.5 Register `UTP_ON_ACCEPT` and hand the accepted connection to the ed2k
      accept path, so an inbound uTP attempt is served rather than dropped
- [x] 7.6 Unit test: the capability word is absent while the accept path is
      unwired and carries `MOD_MISCOPT_NAT_TRAVERSAL` once it is wired
- [x] 7.7 Register the libutp callbacks the transport cannot work without:
      clock, random and MTU, accounting for the two shared-port framing bytes

## Building and testing this change

Do not assume a host toolchain. The supported route is the container:

```sh
packaging/linux/build.sh dev        # configures all three apps + tests, builds, runs ctest
```

Nothing is installed on the host. Compare any test failure against the
pre-existing failures in `openspec/BASELINE.md` before attributing it to this
change — see `openspec/changes/README.md`.

## Apply notes (2026-08-23)

### libutp is vendored

`src/extern/libutp`, from <https://github.com/transmission/libutp> at commit
`490874c44a2ecf914404b0a20e043c9755fff47b` (version 3.4, MIT). No vendored file
is patched; `src/extern/libutp/AMULE_PROVENANCE.md` records the pinned commit,
what was omitted from the upstream tree and why, and how to reproduce it.
Upstream names its target `libutp`, so `cmake/libutp.cmake` was adapted to that
name and still publishes the `Utp::Utp` alias -- adapting our side rather than
patching theirs keeps the next version bump a copy instead of a merge.

`packaging/linux/dev/Dockerfile` now configures `-DENABLE_UTP=YES`, because a
verification build with it off never compiles a single call to `utp_*`. The
default in `cmake/options.cmake` stays OFF: uTP is opt-in for users.

### 4.2 is wired

The connection path now classifies and routes uTP outcomes:

- `CUpDownClient::ConnectOverUtp()` (`src/BaseClient.cpp`) decides whether uTP
  is on the table for a peer, keyed on the peer's advertised
  `MOD_MISCOPT_NAT_TRAVERSAL` bit, and reports a transport failure when this end
  cannot use uTP for it.
- `CUpDownClient::Connect()` consults `GetUtpDisposition()` and falls back to the
  TCP dial, clearing the transport state as it does so -- so a TCP failure after
  a uTP one is judged on TCP's terms. When TCP was already tried it returns
  `true` (not `false`, which means "client deleted" to `TryToConnect()`), which
  is what keeps the source.
- `CUpDownClient::Disconnected()` skips `CClientList::AddDeadSource()` while the
  outcome is a transport failure, so a uTP failure that arrives on an
  already-open socket cannot mark the peer dead either.
- `DisposeUtpAttempt()` (`src/UtpTransportFailure.h`) is the single decision both
  call sites read, and it is what `UtpTransportFailureTest` drives.

The **dial is now live** -- see the 2026-08-23 (later) notes below. What 4.2
established is unchanged by it: `ConnectOverUtp()` still reports every "this end
cannot" answer through `OnUtpTransportFailure()`, and the fallback route it takes
is the one a real dial timeout now takes.

### 4.3's title was corrected

It read "uTP-blocked peer still downloads over TCP", which promised coverage of
a download. The test asserts the disposition of the attempt -- fall back to TCP,
do not mark dead, do not drop the source -- through the production
`DisposeUtpAttempt()` rather than a test-local restatement of it. The title now
says that. A real download over a real fallback needs the dial, i.e. 3.1.

### Still open

- **5.2 is a later change by construction** -- it asks for IPv6 uTP only after
  IPv4 uTP is stable in real use, which has not happened. `CUtpContext::
  IsUsableEndpoint()` is the one predicate that stages it, and the outbound dial,
  the inbound accept and the datagram path all read it rather than restating the
  family rule.

### Two things a reviewer should look at

- **`CT_MOD_MISCOPTIONS` is emitted, and the uTP bit follows the ability to
  serve.** The earlier apply made the word non-zero on `-DENABLE_UTP=YES` alone,
  so such a build advertised `MOD_MISCOPT_NAT_TRAVERSAL` while it could not serve
  a single uTP connection -- exactly the "advertising a capability you do not
  have" hazard `PeerCapabilities.h` warns about. That protocol decision has been
  taken the other way, matching the precedent of the IPv6 bit, which follows
  *verified* inbound connectivity rather than a bound socket. See section 6.

  The gate is `CUtpContext::CanServeConnections()`: a context exists AND
  `IUtpLibrary::AcceptsInboundConnections()` says an inbound attempt would be
  handled. `CUtpLibraryAdapter` answers from its own registration of
  `UTP_ON_ACCEPT`, which is deliberately not registered yet -- so today an
  `-DENABLE_UTP=YES` build advertises nothing, and registering the callback when
  the dial lands (3.1) is what turns the bit on.

  `LocalAdvertisedModMiscOptions()` is gone; the compile-time function is now
  `AdvertisableModMiscOptions()`, the *ceiling* rather than the word. The
  `static_assert` that tied "non-zero word" to "tag emitted and `tagcount`
  incremented" could not survive a runtime word: the guarantee is now structural
  (one const word, one `bModMiscOptionsTagCounted` bool read by both sites) plus
  a surviving `static_assert` that the ceiling stays inside
  `MOD_MISCOPT_KNOWN_MASK` and two `wxASSERT`s -- that the word never exceeds the
  ceiling, and that the count and the emission still agree.
- **`UtpLibraryAdapter` was split into a header and a `.cpp`.** libutp's
  `utp_types.h` defines `int64` as `int64_t` and `byte` as `unsigned char` at
  global scope; aMule's `Types.h` defines `int64` as `uint64_t`, and
  `SHAHashSet.h` does `using namespace std` so `byte` also collides with
  `std::byte`. The two cannot coexist in one translation unit in either order.
  `UtpLibraryAdapter.cpp` is now the only TU that includes libutp's headers and
  it includes none of aMule's. No upstream file was touched.

## Apply notes, phase 7 (2026-08-23, later)

### The breakdown had a hole, and this is it

Task 3.1 reads "Present the interface the client already consumes for TCP", and
that is exactly what the earlier apply delivered: `CUtpStream` presents
Write/Read with the TCP side's retry convention. **Nothing substituted it under
`CClientTCPSocket`**, so uTP carried no data at all, and outside its own header
`CUtpStream` appeared only in comments acknowledging the gap. The substitution
and the inbound accept path were named by no task in sections 1-6.

That is a defect in this plan, not in the implementation of 3.1. Section 7 was
added rather than widening 3.1, so the record shows where the plan was short.

### How the stream is substituted

`CLibSocket` (`src/LibSocket.h`) is the seam, and it is the right one because
nothing above it touches the asio socket: `CProxySocket`,
`CEncryptedStreamSocket`, `CEMSocket` and `CClientTCPSocket` consume
`Read`/`Write`/`IsConnected`/`IsOk`/`BlocksRead`/`BlocksWrite`/`Close` and the
peer accessors, and nothing else. A wrapper carrying a
`CUtpSocketTransport` (`src/UtpSocketTransport.h`) routes exactly those calls
through it; everything above is unchanged, obfuscation included.

Two properties carry the substitution and neither is obvious:

- **The would-block contract is exact.** `CEMSocket` reads `BlocksRead()` and
  `BlocksWrite()` *before* `LastError()` (`src/EMSocket.cpp:240`, `:658`), so
  "nothing right now" has to be a zero return with the blocks flag set and
  `LastError()` still zero. Reporting an error there turns every closed send
  window into a dropped connection, which looks exactly like a bad peer.
- **`utp_write()` is only ever called from the thread that owns libutp.**
  `CEMSocket::SendFileAndControlData()` runs on the upload throttler's thread, so
  `CUtpSocketTransport::Write()` only queues -- under the transport's own mutex,
  because libutp's callbacks arrive on the core thread -- and the queue is handed
  to libutp on the core tick. libutp is not thread-safe and would corrupt its
  per-context state with no reliable symptom.

Events go back up as the same four `CoreNotify_LibSocket*` posts the asio reactor
uses (`CUtpSocketNotifier`, `src/LibSocketAsio.cpp`), deferred rather than
direct: libutp's callbacks fire from inside `utp_process_udp()` and
`utp_check_timeouts()`, and the client code they would re-enter closes sockets --
including the `utp_socket` libutp is standing on.

### How the accept callback is registered

`UTP_ON_ACCEPT` is registered by `CUtpLibraryAdapter::CreateContext()`, **and
only when the context has an acceptor** (`CUtpContext::HasInboundAcceptor()`).
libutp answers an inbound SYN as soon as that callback exists, so registering it
with nowhere to put the connection would complete a handshake and then drop it --
worse for the peer than never answering, because it looks like a working client.
The registration and the claim `AcceptsInboundConnections()` makes are set
together, in one statement, so they cannot disagree; `CanServeConnections()` is
unchanged.

The acceptor is `CUtpInboundAcceptor`, owned by `CClientUDPSocket` and passed to
`Configure()` inside the existing `#ifdef AMULE_UTP_TRANSPORT`. It applies the
admission tests `CListenSocket::AcceptFrom()` applies -- shutdown, connection
limit, IP filter, ban list -- and then builds an ordinary `CClientTCPSocket`,
which registers itself in the same socket list and counts in the same statistics.

One ownership rule is written down because getting it wrong is a use-after-free:
`utp_close()` is not safe to call twice on one socket, so **whoever refuses a
connection closes it**. The acceptor owns the socket from the moment it is
called, refusal included; the context closes only what it declines before the
acceptor is reached; the `UTP_ON_ACCEPT` callback closes nothing.

### Callbacks libutp has no defaults for

`utp_call_get_milliseconds()` and its siblings return **zero** when unregistered
(`src/extern/libutp/utp_callbacks.cpp`). The previous apply registered only
`UTP_SENDTO`, so its context had a clock frozen at zero, connection IDs that were
all zero and an MTU ceiling of zero. Nothing asserts and nothing logs; the
transport simply never works. `UTP_GET_MILLISECONDS`, `UTP_GET_MICROSECONDS`,
`UTP_GET_RANDOM`, `UTP_GET_UDP_MTU` and `UTP_GET_UDP_OVERHEAD` are now
registered. libutp ships `utp_default_*` implementations, but in a header it does
not install, so they are written out in the adapter rather than depended on --
that also keeps `USE_SYSTEM_LIBUTP=YES` working. No vendored file was touched.

The MTU and overhead are two bytes tighter than a plain UDP socket's, because
every uTP datagram on this port carries the `OP_UDPRESERVEDPROT2` /
`OP_NATT_FRAME_UTP` frame header that lets uTP and ed2k UDP share it. Reporting
the untightened figures would have libutp build datagrams two bytes over the path
MTU and read the resulting fragmentation as congestion.

### A bug the tests found

`UtpSocketTransportTest.AClosedWindowBlocksAndTheReopenIsAnnounced` failed on
first run: after `utp_write` answered zero, `CUtpStream`'s zero-write backoff
survived libutp's explicit `UTP_STATE_WRITABLE`, so the connection sat idle for
up to `UTP_ZERO_WRITE_RETRY_MAX_MS` after being told it could send. The backoff
exists to stop the pump polling a closed window; an explicit notification that
the window opened makes holding it wrong. `CUtpStream::OnWindowOpened()` retires
it, and the transport calls it on both `UTP_STATE_CONNECT` and
`UTP_STATE_WRITABLE`.

### The capability bit is now set, and that is the point

`CanServeConnections()` can be true for a real reason for the first time, so an
`-DENABLE_UTP=YES` build now advertises `MOD_MISCOPT_NAT_TRAVERSAL`. That is the
behaviour section 6 was written for. `UtpInboundAcceptTest` asserts both sides of
it through `AdvertisedModMiscOptions()`: the word is `0` with the accept path
unwired and `0x00000002` with it wired. The count and the tag still move together
through the one `bModMiscOptionsTagCounted` bool that
`CUpDownClient::SendHelloTypePacket()` reads at `src/BaseClient.cpp:1196` and
`:1340`, with the `wxASSERT` at `:1339` tying it back to the word -- untouched by
this phase.

### One thing found on the way

`CSocketClientProxy::Connect()` routes through the proxy state machine when a
proxy is configured, and uTP rides the ed2k UDP socket -- it negotiates nothing
with SOCKS or HTTP CONNECT. A proxied socket is therefore never dialled over uTP:
`DecideUtpDial()` takes `GetUseProxy()` and answers `UTP_DIAL_PROXY_IN_USE`,
which is a transport failure, so the peer falls back to TCP through the proxy and
keeps its place. The user configured the proxy; that is ours, not the peer's.

### What defends the TCP path

- `DecideUtpDial()` (`src/UtpDialPolicy.h`) is the whole dial decision, and
  `UtpDialPolicyTest` pins the case that matters: a peer that does not advertise
  uTP comes out with **both** flags clear, which is the pre-uTP connection
  exactly. A transport failure recorded there would not break the dial -- the
  fallback still reaches TCP -- it would change what `Connect()` and
  `Disconnected()` do to the peer afterwards, and nothing would log.
- Every intercepting method in `CLibSocket` is `if (m_utpTransport) {...}`
  followed by the call it always made, so a wrapper without a transport is
  byte-identical. Nothing attaches one unless this build has libutp *and* the
  peer advertised uTP.
- The encryption setup moved from the TCP branch to just above the transport
  choice, so a uTP connection is obfuscated on the same terms. The TCP path sees
  the identical pair of calls in the identical order, because `ConnectOverUtp()`
  is a no-op for a peer that did not advertise uTP.
