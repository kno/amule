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
- [ ] 5.2 Enable IPv6 uTP only after IPv4 uTP is stable in real use

## 6. Capability advertisement

- [x] 6.1 Gate the advertised `MOD_MISCOPT_NAT_TRAVERSAL` bit on whether this
      end can serve a uTP connection, not on whether uTP was compiled in
- [x] 6.2 Unit test: uTP present but unable to serve advertises nothing; able to
      serve advertises the bit

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

What is still not live is the **dial**: `ConnectOverUtp()` has no established
uTP connection to succeed with, because substituting `CUtpStream` under
`CClientTCPSocket` for a real connection is the remaining half of 3.1. So in an
`-DENABLE_UTP=YES` build a peer advertising uTP takes the fallback immediately
and is reached over TCP -- byte-for-byte the behaviour of the default build. When
the dial lands it reports its timeout through `OnUtpTransportFailure()` and needs
no other change.

### 4.3's title was corrected

It read "uTP-blocked peer still downloads over TCP", which promised coverage of
a download. The test asserts the disposition of the attempt -- fall back to TCP,
do not mark dead, do not drop the source -- through the production
`DisposeUtpAttempt()` rather than a test-local restatement of it. The title now
says that. A real download over a real fallback needs the dial, i.e. 3.1.

### Still open

- **5.2 is a later change by construction** -- it asks for IPv6 uTP only after
  IPv4 uTP is stable in real use, which has not happened.
- **3.1 delivers the interface, not the substitution.** `CUtpStream` presents the
  Write/Read/Close surface the client consumes for TCP and is driven in tests.
  Substituting it under `CClientTCPSocket` for real connections is the dial
  described above.

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
