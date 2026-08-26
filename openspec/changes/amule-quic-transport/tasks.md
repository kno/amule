# Tasks: QUIC NAT-T transport

## 0. Decision gate (blocks everything below)

- [x] 0.1 Maintainer decision: adopt ngtcp2 plus a TLS stack, or decline this change
      -- adopted 2026-08-26
- [x] 0.2 Select the TLS backend; record the rationale in design.md
      -- GnuTLS. Matches eMuleAI's own pairing, and Debian packages only the
      GnuTLS binding (`libngtcp2-crypto-gnutls-dev`), never the OpenSSL one
- [x] 0.3 Confirm packaging viability across the platforms aMule ships on
      -- measured, not assumed: viable on Debian trixie and MSYS2 mingw-w64;
      NOT viable on macOS, where Homebrew's `libngtcp2` links `openssl@3` and
      no GnuTLS-bound build is packaged. macOS ships QUIC off and falls back to
      uTP. See the table in design.md

## 1. Build integration

- [x] 1.1 Add ngtcp2 and the chosen TLS stack as optional CMake dependencies
      -- `cmake/ngtcp2.cmake`, three pkg-config modules (`libngtcp2`,
      `libngtcp2_crypto_gnutls`, `gnutls`) published as one target,
      `Quic::Ngtcp2`. A minimum of 1.0.0 is enforced and the bound is
      load-bearing: Ubuntu 22.04 packages ngtcp2 0.1.0, whose API this code
      cannot build against, and without the bound that fails as unresolved
      symbols rather than as a version message
- [x] 1.2 Make QUIC a build-time option, defaulting off until proven
      -- `ENABLE_QUIC`, OFF in `cmake/options.cmake`, forced off in a build with
      no core. Defines `AMULE_QUIC_TRANSPORT` for `amuled` and `amule` only
- [x] 1.3 Verify the client builds and traverses over uTP with QUIC disabled
      -- `packaging/linux/build.sh dev` (the default configuration, QUIC off):
      builds all three apps and passes 65/65 ctest. The uTP path is unchanged by
      this change and is pinned in that configuration by
      `UtpDatagramRoutingTest.WithoutAQuicContextQuicFramesFallThroughToEd2k`,
      `WithNeitherTransportEverythingIsEd2k` and
      `NatTraversalPolicy.BuildWithoutQuicUsesTheLegacyFrameTypeWithNoWait` --
      a QUIC-less build rides frame type `0x00` with no wait at all. Live
      traversal itself was verified in `amule-nat-rendezvous` and this change
      does not touch it

## 2. Transport

- [x] 2.1 Implement the QUIC socket half, shaped like the existing stream interface
      -- complete. `CQuicContext` (`src/QuicContext.h`) was already there, shaped
      like `CUtpContext`; what was missing was the byte-stream handoff, which was
      blocked on 3.1 having no expectation source and is unblocked now that it
      has one.
      Added: `CQuicSocketTransport` (`src/QuicSocketTransport.h`), the QUIC twin
      of `CUtpSocketTransport`, and `CQuicInboundAcceptor`
      (`src/QuicInboundAcceptor.{h,cpp}`), the twin of `CUtpInboundAcceptor`,
      which hands a validated connection to a `CClientTCPSocket` on exactly the
      admission tests `CListenSocket::AcceptFrom()` applies.
      `CQuicConnection::ReceiveStreamBytes()` no longer drops post-proof bytes:
      it delivers them to the transport, and `CQuicConnection` implements
      `IQuicStreamWriter` so the transport can write back on the stream the peer
      opened -- the peer's stream, because a connection carrying two streams
      would look like two connections to everything above the socket.
      Two things are worth recording because neither is obvious from the code:
        * **`CLibSocket` now routes one pointer, not two.** It named
          `CUtpSocketTransport` at fifteen sites; a second concrete type would
          have doubled them into fifteen pairs of branches that must never
          drift, in the one file where a drift reads as a connection that
          receives bytes and never sends them. `IStreamTransport`
          (`src/StreamTransport.h`) is that one surface, both transports
          implement it, and `IUtpSocketEvents` became `IStreamTransportEvents`
          because both post the same four `CoreNotify_LibSocket*` events.
          `HasUtpTransport()` survives as a question distinct from
          `HasStreamTransport()`: its one caller is asking whether a uTP dial is
          already in flight, and answering yes for a QUIC connection would
          suppress a dial that should have happened.
        * **A deadlock had to be designed out rather than tested out.**
          `CQuicSocketTransport::OnQuicTick()` calls into ngtcp2 with its own
          mutex held, and that call can fail and close the connection. So
          `MarkClosed()` deliberately does not notify the transport --
          `~CQuicConnection()` does, after `SweepClosed()` runs at the end of the
          pass, by which time the mutex is released. The rule is written at both
          ends, because at either end alone it reads as an omission.
      Not carried by this transport yet: an *outbound* QUIC dial. The transport
      and the writer are direction-agnostic, but nothing constructs one for a
      dial, because a dial has to send a proof and which value belongs in its
      second field is 3.1's unresolved directional question. Wiring a dial to a
      guessed field would produce a handshake that fails silently, which is the
      failure mode this change keeps refusing to build.

- [x] 2.2 Implement the ngtcp2/TLS bridge as a separate unit
      -- `src/QuicLibraryAdapter.{h,cpp}` behind `IQuicLibrary`, mirroring
      eMuleAI's `CNgTcp2GnuTlsBridge` / `CQuicNatSocket` split. Measured from
      the QUIC-on build's own dependency graph: ngtcp2 and GnuTLS headers reach
      1 distinct source file (2 objects, the `amule` and `amuled` copies) out of
      575. Public headers pull in neither, and `boost/asio` still reaches the
      same 3 sources it did at `cbb3710`
- [x] 2.3 Offer ALPN `ed2k-ai-natt-quic-v1`; reject any other value
      -- one protocol registered with `GNUTLS_ALPN_MANDATORY`, so a mismatch
      fails the handshake rather than completing with nothing selected.
      Verified against GnuTLS 3.8.9, not merely asserted: a client offering
      `-v2`, `h3` or the bare prefix is refused with "No common application
      protocol could be negotiated", while `ed2k-ai-natt-quic-v1` completes and
      is the selected protocol
- [x] 2.4 Insert QUIC into the shared-port classification order after uTP
      -- `RouteInboundDatagram()` in `src/UtpDatagramRouting.h` now takes three
      consumers. The other two are undisturbed: a `0x00` frame is never offered
      to ngtcp2 and a `0x01` frame is never offered to libutp, because the frame
      type selects the transport rather than trial and error
- [x] 2.5 Unit test: ALPN rejection; classification order for all three consumers
      -- `QuicNattProtocolTest.OnlyTheOneAlpnIsAccepted` (including the prefix,
      the appended, the version-bumped and the case-changed near misses), and
      four order suites in `UtpDatagramRoutingTest`:
      `QuicFrameReachesTheQuicContextAfterUtpDeclines`,
      `DeclinedDatagramVisitsUtpThenQuicThenEd2k`,
      `WithoutAQuicContextQuicFramesFallThroughToEd2k`,
      `DatagramDeclinedByAllThreeIsDroppedWithoutError`

## 3. Authentication

- [x] 3.1 Build and validate the 37-byte `EAQN1` proof
      -- complete, including the expectation source this task previously had to
      leave absent. `BuildQuicNattProof()` / `ValidateQuicNattProof()` in
      `src/QuicNattProtocol.h`, with the two 16-byte values compared without an
      early exit so a guess cannot be timed.
      **The gap is closed and the earlier reading was the error.** This task
      recorded that the proof's second field looked like a per-exchange nonce,
      that the rendezvous message had no field to carry one, and that
      `CQuicEndpoint::FindExpectation()` therefore had to keep returning NULL.
      The nonce reading was wrong, not the wire. Measured against a real eMuleAI
      v1.6.0 on 2026-08-26, three times and with a negative control:
        * it sends tag `0xBF`, `TAGTYPE_HASH16`, exactly 16 bytes of
          high-entropy data, in its `OP_HELLOANSWER`;
        * the bytes were byte-identical across three separate sessions
          (`04eeb1423ad7582a3d9ad69e47ce6fb6`), so the value is stable per
          install and cannot be a nonce;
        * it sends the tag with **no gate at all** -- see 4.4, which corrects a
          second earlier reading.
      So the second field is a stable peer identity value that travels in the
      ed2k hello, the wire had the field all along, and this is what was built:
        * `CQuicProofValue` and the derivation of this client's own value,
          `src/QuicProofValue.{h,cpp}`. Ours is SHA-256 over a domain separator
          and the *public* half of the secure-identification key, truncated to
          16 bytes -- stable across restarts because `cryptkey.dat` is, and safe
          to publish because that half is already sent in the clear to every
          peer that completes a secure-identification exchange. No key means no
          value, no tag, and no peer able to authenticate a connection from this
          client, which is the fail-closed direction.
        * `CT_MOD_QUIC_IDENT` (0xBF) parsed into `CUpDownClient` and advertised
          back, gated in `SendHelloTypePacket()`.
        * the expectation table on `CQuicContext`, filled in by
          `CUpDownClient::RegisterQuicExpectation()` from the peer's hello, and
          `CQuicEndpoint::FindExpectation()` forwarding to it. The table is
          bounded at 256 and evicts the oldest: expectations are registered
          while a stranger can still be negotiating, so an unbounded one is
          memory an unauthenticated peer controls, and refusing rather than
          evicting would let a flood lock out every real peer behind it.
      **What makes it authentication is that it is cross-channel**, and the
      safety constraint is structural rather than asserted: both halves of an
      expectation come from the peer's ed2k hello over TCP, and no code path
      derives either from the QUIC connection being validated. `FindExpectation()`
      in the adapter has no expectation of its own to derive one into -- it only
      forwards. A third party that hijacks a punched UDP mapping has seen the UDP
      half and not the TCP one.
      **Failing closed on absence is preserved, which was the point of the
      original refusal.** A peer that advertised no `0xBF` value produces no
      expectation, `FindExpectation()` returns NULL, `ValidateQuicNattProof()`
      refuses a NULL expectation, and the connection is closed as an
      authentication failure -- after which the peer falls back to uTP,
      automatically and silently. `CQuicProofValue` keeps "absent"
      distinguishable from "sixteen zero bytes" for exactly this reason: an
      expectation of sixteen zeroes is one any third party can satisfy.
      **What the proof does NOT prove, stated because a later reader will
      otherwise assume more.** The value is stable and derived from public key
      material, so it is an identity rather than a secret: anyone who has ever
      handshaked with a peer, or observed one of its cleartext hellos, knows that
      peer's value permanently. The property is "the attacker must have obtained
      the impersonated peer's ed2k hello", not "the attacker must break a fresh
      challenge", and a captured proof does replay against an attacker who
      already had that hello. A per-exchange nonce would be strictly stronger; it
      is also not what eMuleAI implements, and a proof neither side could
      complete would authenticate nothing at all. It is still strictly better
      than what it replaces, which was that no inbound QUIC connection could
      authenticate under any circumstances. Documented at the value itself in
      `src/QuicProofValue.h`, which is where a rendezvous nonce would land if the
      message ever grows a field for one.
      **The directional ambiguity, resolved explicitly and still unconfirmed.**
      When this end sends a proof, the second field carries the value *the sender
      itself advertised* -- `kQuicProofValueDirection ==
      QUIC_PROOF_VALUE_SENDER_ADVERTISED` in `src/QuicProofValue.h`. The reason
      is the proof's other field: `BuildQuicNattProof()` takes the sender's own
      ed2k user hash, so read sender-side throughout the record says one thing --
      "I am this ed2k identity, and here is the value that identity published" --
      and the recipient's expectation is then entirely peer-side. A record whose
      two fields described different ends is one neither end could describe in a
      sentence. Both directions are unguessable to a third party, so both are
      defensible; only one interoperates, and the evidence does not say which.
      Reversing it is changing that one initialiser: every call site goes through
      `SelectQuicProofValue()` or `ExpectedQuicProofValueFromPeer()`, and
      `QuicProofValueTest.SelectionFollowsTheDirectionAndNothingElse` exercises
      both branches, so the other direction is not untested code the day it is
      needed. See 4.4 for why the experiment that would settle it still cannot
      run.

- [x] 3.2 Reject payload before proof validation completes
      -- structural rather than checked: there is no code path from
      `recv_stream_data` to a consumer that does not pass through
      `m_proofValidated`, and bytes past the 37-byte record before validation
      close the connection rather than being buffered
- [x] 3.3 Distinguish authentication failure from transport failure in logs
      -- two separate lines in `CClientUDPSocket::OnQuicConnectionOutcome()`,
      the authentication one at `AddDebugLogLineC`. The bridge cannot log at all
      (it is the one TU that sees ngtcp2's headers and so cannot include
      `Logger.h`, exactly as `UtpLibraryAdapter.cpp` cannot), so the outcome
      travels out through `IQuicConnectionObserver` -- the same route
      `IUtpConnectionAcceptor` takes. The classification is
      `IsQuicAuthenticationOutcome()`, a function rather than a condition inside
      the log call, because a classification inside a log call cannot be
      asserted. A refused handshake -- which is where a rejected ALPN lands --
      is deliberately a transport outcome: a peer speaking a different protocol
      version is not a peer claiming to be somebody else
- [x] 3.4 Unit test: absent, truncated, wrong-magic and wrong-identity proofs
      -- `QuicNattProtocolTest.AbsentTruncatedAndWrongMagicProofsAreRejected`
      (every length from 1 to 36, the oversized case, and a flipped byte at each
      of the five magic positions) and `ProofForAnotherIdentityIsRejected` (a
      flipped byte at each of the 32 identity and nonce positions, plus the two
      fields swapped). `EveryProofRejectionIsAnAuthenticationFailure` pins that
      no refusal is reported as a transport error and that no two reasons share
      a name.
      Extended for the expectation source this change added, in
      `QuicProofValueTest` and the new expectation suites in `QuicContextTest`:
      expectation absent -> refused (`WithNothingLearnedThereIsNoExpectation`,
      `ADefaultValueIsAbsentAndExposesNoBytes`,
      `SelectionOfAnAbsentValueIsNull`); present and matching -> accepted, and
      present and mismatched -> `QUIC_PROOF_WRONG_IDENTITY`
      (`ProofForAnotherIdentityIsRejected`, which sweeps every byte of both
      fields); a wrong-length tag rejected without storing
      (`EveryWrongLengthIsRefusedWithoutStoring`, every length from 0 to 32 plus
      NULL, and `ARefusedWriteLeavesAnEarlierValueIntact`). The "tag absent from
      a hello stores nothing" case is structural rather than a test: the parse
      arm is inside `if (temptag.IsHash())`, so a tag that is not there is a
      `case` that never runs

## 4. Fallback

- [x] 4.1 Skip the wait entirely for peers without the QUIC capability bit
      -- `SelectNattFrameType()` in `src/NatTraversalPolicy.h` tests both
      capability inputs before it looks at the clock, so a peer that never
      claimed QUIC and a build that cannot serve it both ride `0x00`
      immediately. `NatTraversalPolicy.PeerWithoutQuicIsNotWaitedForAtAll` and
      `BuildWithoutQuicUsesTheLegacyFrameTypeWithNoWait`
- [x] 4.2 Fall back to uTP after 1500 ms when the capability frame is lost
      -- the same function, now taking `quicCapabilityFrameSeen`. The seam and
      `kNattFrameTypeFallbackWaitMs` were left in place by
      `amule-nat-rendezvous`; what this change adds is the other half of the
      rule. Without it the 1500 ms was a lifetime rather than a wait: a
      *confirmed* QUIC exchange dropped back to uTP at the boundary, which is
      the one outcome neither side can diagnose.
      `ConfirmedQuicSurvivesTheFallbackBoundary` and
      `QuicFrameTypeIsPreferredForFifteenHundredMilliseconds`
- [x] 4.3 Keep the fallback invisible in user-facing state
      -- `SNattFrameTypeDecision::surfacesFailure`, always false and enumerated
      over every reason by
      `NatTraversalPolicy.NoFrameTypeOutcomeIsEverAUserVisibleFailure`, so a new
      reason cannot be added without deciding the question. On a platform without
      the dependency `LocalCanServeQuicNatTraversal()` is false whatever the
      runtime answer, which is what makes the macOS case silent rather than a
      failure
- [ ] 4.4 Interop check against eMuleAI over QUIC, then with QUIC disabled
      -- STILL PARTIAL, and the boundary has moved. The ed2k half is now
      confirmed in both directions; the QUIC half remains unreachable, for a
      reason that is a property of the interop target rather than of this code.

      Confirmed against the running eMuleAI v1.6.0 and its `eMuleAI.exe`, from
      the earlier session: `CT_MOD_MISCOPTIONS` = `0x0000001F`; the `EAQN1` magic
      and the ALPN `ed2k-ai-natt-quic-v1` both appear verbatim in the binary; its
      GnuTLS priority string admits the same four ciphers this change offers over
      a subset of our groups, so the intersection can never be empty; an ed2k
      handshake over native IPv6 completes between the two implementations; its
      certificate CN is `eMuleAI QUIC NAT-T` against our `CN=amule`, left
      divergent on purpose.

      Newly confirmed, and this is what unblocked 2.1 and 3.1: tag `0xBF`,
      `TAGTYPE_HASH16`, 16 bytes, `04eeb1423ad7582a3d9ad69e47ce6fb6`,
      byte-identical across three sessions, alongside `0xAA` = `0x1F` and `0xAD`
      carrying its IPv6 address.

      **Correction to this task's earlier record.** It said eMuleAI sends that
      tag "only once the peer has advertised `CT_MOD_MISCOPTIONS`". That is
      wrong, and it was wrong because every probe until now had carried a
      capability word. With the negative control -- an `OP_HELLO` with no
      `CT_MOD_MISCOPTIONS` tag at all -- the answer was byte-identical and still
      carried `0xBF`. So **eMuleAI gates the tag on nothing.** aMule deliberately
      does not copy that: the value is a stable per-install identifier, and
      broadcasting one to every peer greeted would correlate this installation
      across addresses and sessions for no benefit, since only an
      eMuleAI-family peer can use it. Our gates are documented at the emission
      site in `BaseClient.cpp` and cost nothing in interoperability, because
      eMuleAI advertises all five capability bits itself.

      Not reached: the QUIC half, still, and no part of the NAT-T exchange. A
      **real** QUIC Initial was sent this time rather than a hand-built frame
      variant: 1200 bytes generated by aioquic, offering
      `ed2k-ai-natt-quic-v1`, inside the `0xB2`/`0x01` framing, to its IPv6 UDP
      `4672`. No reply. Two controls went alongside -- the same Initial unframed,
      and a framed Initial offering `h3` -- and both were equally silent, so
      **this run distinguishes nothing**: it does not show the framing is wrong
      and it does not show the ALPN is right. It is consistent with the earlier
      finding that this client emits no UDP whatsoever (150 s filtered and 60 s
      unfiltered on its own network namespace showed only Docker gateway
      broadcasts; its Kad never connects and it opens only `udp6 :::4672`). No
      positive control was available for its UDP receive path, so "no reply"
      cannot be separated from "nothing listening".

      Still unproven, therefore: `0x40` (`CONNECT_OPT_NATT_RELAYED`), whether the
      certificate CN matters, and -- the one that would change code --
      `kQuicProofValueDirection`. Settling it needs an eMuleAI whose QUIC
      endpoint answers a datagram, which this build does not appear to be. The
      cheapest next experiment is two aMule instances built with
      `-DENABLE_QUIC=YES` on opposite sides of a NAT: that proves this tree
      self-consistent, and says nothing about eMuleAI

## Building and testing this change

Do not assume a host toolchain. The supported route is the container:

```sh
packaging/linux/build.sh dev        # QUIC off (the default): all three apps + tests, ctest
packaging/linux/build.sh dev-quic   # QUIC on, -DENABLE_QUIC=YES
```

`dev-quic` is a separate image on a different distribution, and the reason is
measured rather than stylistic. The `dev` image is built on Ubuntu 22.04, which
packages ngtcp2 **0.1.0** -- a pre-1.0 API this code cannot build against.
Debian trixie packages 1.11.0 with the GnuTLS binding, and is what the runtime
image ships from, so `dev-quic` verifies QUIC on the distribution QUIC actually
ships from. Its ctest run is gating, unlike `dev`'s: there is no baseline to
discover there, every suite is expected to pass.

Nothing is installed on the host. Compare any test failure against the
pre-existing failures in `openspec/BASELINE.md` before attributing it to this
change — see `openspec/changes/README.md`.
