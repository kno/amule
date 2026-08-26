# Tasks: rendezvous and hole punching

Reconciled against the tree. A ticked box means the code exists AND a test
asserts it; `src/Nat*.h` are header-only and free of theApp and of wxWidgets, so
every bound in them is assertable without a network.

## 1. Relay side (do first -- it is the security-relevant half)

- [x] 1.1 Parse `OP_RENDEZVOUS` (`0xA0`) -- `ParseRendezvousRequest()`
- [x] 1.2 Reject requests whose endpoint hint does not match the source address
- [x] 1.3 Rate-limit relaying per requester -- `CRendezvousRelayLimiter`
- [x] 1.4 Unit test: third-party hint rejected, no packet emitted toward the named address
- [x] 1.5 Unit test: relay rate limit enforced
- [x] 1.6 Forward the OBSERVED endpoint, never the claimed one
- [x] 1.7 Mark the forwarded message `CONNECT_OPT_NATT_RELAYED`, and refuse to
      relay a message that already carries it
- [x] 1.8 The other direction: `AcceptRelayedRendezvous()` -- what this client
      may act on when a relay forwards a rendezvous to it

## 2. Requester side

- [x] 2.1 Send `OP_RENDEZVOUS` with a `CONNECT_OPT_NATT_ENDPOINT_HINT` (`0x20`) hint
- [x] 2.2 Parse and emit `OP_NATT_ENDPOINT_HINT` (`0xAA`)
- [x] 2.3 Treat the hint as one candidate alongside known addresses -- `CNattCandidateSet`
- [x] 2.4 Unit test: known addresses still attempted when the hint is stale

## 3. Hole punch

- [x] 3.1 Implement `OP_HOLEPUNCH` (`0xA1`) bursts with bounded count and spacing
- [x] 3.2 Enforce 5 attempts and a 120 s total budget
- [x] 3.3 Apply the 60 s backoff and keep the source queued --
      `DisposeExhaustedHolePunch()`
- [x] 3.4 Cancel remaining attempts on success
- [x] 3.5 Unit test: exhaustion path, source retention, cancellation on success

## 4. Integration

- [x] 4.1 Gate initiation on the peer's advertised traversal capability --
      `DecideRendezvousInitiation()`
- [x] 4.2 Implement the 1500 ms wait before falling back to the legacy uTP frame
      type -- `SelectNattFrameType()`
- [x] 4.3 Dispatch the three control opcodes out of the `OP_NATT_FRAME_UTP`
      branch of `CClientUDPSocket::ProcessReservedProt2Frame()`, past the point
      libutp declined the datagram -- `ProcessNattControlFrame()`
- [x] 4.4 Fall back to callback and buddy when traversal is unavailable or
      exhausted -- carried as `NATT_ALT_CALLBACK_OR_BUDDY` and
      `fallBackToCallbackOrBuddy`, and never as a `Connect()` false that
      `TryToConnect()` reads as "deleted"
- [ ] 4.5 Interop check against eMuleAI: LowID to LowID in both directions
      -- NOT POSSIBLE HERE. There is no eMuleAI build, no NAT lab, and two aMule
      containers on one podman network have nothing to traverse. `0x40`
      (`CONNECT_OPT_NATT_RELAYED`) is the one value this change picks rather
      than inherits, so it is what such a check would contradict first.
- [x] 4.6 Hold the exchanges in flight -- `CNatRendezvousManager`, capped,
      keyed by user hash because the address is what a NAT rewrites
- [x] 4.7 Poll the schedules from `CamuleApp::OnCoreTimer` --
      `CClientUDPSocket::ServiceNatRendezvous()`
- [x] 4.8 Dial the punched mapping: when a punch was observed for a peer,
      `CUpDownClient::ConnectOverUtp()` dials that endpoint rather than the
      advertised one, and `ConnectionEstablished()` cancels the punch
- [x] 4.9 Requester-side relay discovery is gated off and the gap is pinned by a
      test -- `LocalCanDiscoverRendezvousRelay()` returns false, so this build
      answers a relayed rendezvous but cannot choose a relay to ask. A usable
      relay must be reachable by us AND able to reach the firewalled peer, and
      the second condition is not knowable from this side: the peer is
      firewalled, so it is reachable only by hosts it is already connected to,
      and `CClientList` holds ours and not theirs.

## Building and testing this change

Do not assume a host toolchain. The supported route is the container:

```sh
packaging/linux/build.sh dev        # configures all three apps + tests, builds, runs ctest
```

Nothing is installed on the host. Compare any test failure against the
pre-existing failures in `openspec/BASELINE.md` before attributing it to this
change -- see `openspec/changes/README.md`.
