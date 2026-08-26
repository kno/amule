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

- [ ] 2.1 Implement the QUIC socket half, shaped like the existing stream interface
      -- PARTIAL, and the missing part is blocked rather than skipped. Present:
      `CQuicContext` (`src/QuicContext.h`), shaped like `CUtpContext` -- one
      endpoint per client instance, lazy creation, a tick independent of
      traffic, `IsAvailable()` and `CanServeConnections()` kept as separate
      answers -- plus the connection table, the inbound handshake, and framed
      datagrams in and out through the shared socket.
      Absent: the equivalent of `CUtpSocketTransport` / `CUtpInboundAcceptor`,
      i.e. handing a validated byte stream to a `CClientTCPSocket`. That is
      blocked on 3.1's expectation source below: no connection can authenticate
      in this tree, so a stream nothing can reach would be dead code that no
      test could exercise. `CQuicConnection::ReceiveStreamBytes()` names the
      seam
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
      -- `BuildQuicNattProof()` / `ValidateQuicNattProof()` in
      `src/QuicNattProtocol.h`, with the two 16-byte values compared without an
      early exit so a guess cannot be timed.
      One gap, stated because it changes what QUIC does at runtime: the
      *expectation* has no source. The proof binds a connection to the identity
      that negotiated the rendezvous and needs that identity's user hash, which
      `SNattRendezvousRequest` does carry, and the nonce of that exchange, which
      it does not -- the message is opcode, flags and a 16-byte hash and has no
      field a nonce could travel in (`src/NatRendezvousProtocol.h`). Inventing
      one would be a wire-format guess eMuleAI would not match, and defaulting
      the expectation to whatever arrived would be a validator that passes
      everything while looking like authentication. So
      `CQuicEndpoint::FindExpectation()` returns NULL, the validator refuses,
      and an inbound QUIC connection is closed as an authentication failure --
      the peer then falls back to uTP, automatically and silently. This is the
      same shape as `LocalCanDiscoverRendezvousRelay()` in
      `amule-nat-rendezvous` task 4.9: one function, gated off, with the reason
      written down.
      Measured against a real eMuleAI v1.6.0 on 2026-08-26, which narrows the
      gap and may remove it: the assumption above is that the second proof field
      is a per-exchange nonce. eMuleAI sends, in its `OP_HELLOANSWER` and only
      once the peer has advertised `CT_MOD_MISCOPTIONS`, a tag `0xBF` carrying
      exactly 16 bytes of high-entropy data. Three properties fit the second
      proof field: the length matches `QUIC_NATT_PROOF_VALUE_LENGTH`, it appears
      only when NAT-T capability is claimed, and it is absent otherwise. One
      property argues against a nonce reading: it was byte-identical across
      three separate sessions, so it is a value stable per install -- plausibly
      a key fingerprint, since that build keeps a `cryptkey.dat`.
      If the second field is a stable peer identity rather than a nonce, then it
      does travel and this gap is a misreading rather than a missing wire field.
      That is a hypothesis, not a finding. The experiment that settles it needs
      2.1 finished: build the proof with the peer's `0xBF` value as the second
      field and see whether eMuleAI accepts the connection. Until then
      `FindExpectation()` still returns NULL, because a validator fed a guess is
      the "passes everything while looking like authentication" failure this
      task refused in the first place
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
      a name

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
      -- PARTIAL. A real eMuleAI v1.6.0 was obtained and run on 2026-08-26, so
      the "no eMuleAI build" half of the original blocker is gone. What that
      reached, and what it did not, in full because the negative half is the
      part a later reader needs:

      Confirmed against the running client and its `eMuleAI.exe`, so these are
      no longer this change's guesses:
        * `CT_MOD_MISCOPTIONS` = `0x0000001F` -- every bit of
          `MOD_MISCOPT_KNOWN_MASK`, so the phase-1 bit assignment holds.
        * The `EAQN1` magic and the ALPN `ed2k-ai-natt-quic-v1` both appear
          verbatim in the binary. Task 2.3's ALPN is right.
        * Its GnuTLS priority string admits AES-128-GCM, AES-256-GCM,
          CHACHA20-POLY1305 and AES-128-CCM -- the same four this change offers,
          in the same order -- over SECP256R1, X25519 and SECP384R1, a subset of
          ours. The cipher and group intersection can never be empty.
        * An ed2k handshake over native IPv6 completes between the two
          implementations: a hand-built `OP_HELLO` to its `4662` answered with
          `OP_HELLOANSWER` in cleartext.
        * Its certificate CN is `eMuleAI QUIC NAT-T`; this end sends `CN=amule`.
          Left divergent on purpose (`QuicLibraryAdapter.cpp`): neither side has
          a CA, authentication is the proof, and a stable identifier in the CN
          would travel in the clear on every handshake.

      Not reached: the QUIC half, and no part of the NAT-T exchange. That client
      emitted no UDP at all -- 150 s filtered and 60 s unfiltered on its own
      network namespace showed only Docker gateway broadcasts. Its Kad never
      connected, and it opens only `udp6 :::4672` with no IPv4 socket, while
      this tree opens one per family, so IPv4 Kad nodes are unreachable for it.
      Eight `OP_UDPRESERVEDPROT2` frame variants sent to that port drew no
      reply, which is also what this tree does with a capability frame, so it
      distinguishes nothing.

      Still unproven, therefore: `0x40` (`CONNECT_OPT_NATT_RELAYED`), the
      `EAQN1` field semantics of 3.1, and whether the certificate CN matters

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
