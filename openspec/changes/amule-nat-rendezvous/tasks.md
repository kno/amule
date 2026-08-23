# Tasks: rendezvous and hole punching

## 1. Relay side (do first — it is the security-relevant half)

- [ ] 1.1 Parse `OP_RENDEZVOUS` (`0xA0`)
- [ ] 1.2 Reject requests whose endpoint hint does not match the source address
- [ ] 1.3 Rate-limit relaying per requester
- [ ] 1.4 Unit test: third-party hint rejected, no packet emitted toward the named address
- [ ] 1.5 Unit test: relay rate limit enforced

## 2. Requester side

- [ ] 2.1 Send `OP_RENDEZVOUS` with a `CONNECT_OPT_NATT_ENDPOINT_HINT` (`0x20`) hint
- [ ] 2.2 Parse and emit `OP_NATT_ENDPOINT_HINT` (`0xAA`)
- [ ] 2.3 Treat the hint as one candidate alongside known addresses
- [ ] 2.4 Unit test: known addresses still attempted when the hint is stale

## 3. Hole punch

- [ ] 3.1 Implement `OP_HOLEPUNCH` (`0xA1`) bursts with bounded count and spacing
- [ ] 3.2 Enforce 5 attempts and a 120 s total budget
- [ ] 3.3 Apply the 60 s backoff and keep the source queued
- [ ] 3.4 Cancel remaining attempts on success
- [ ] 3.5 Unit test: exhaustion path, source retention, cancellation on success

## 4. Integration

- [ ] 4.1 Gate initiation on the peer's advertised traversal capability
- [ ] 4.2 Implement the 1500 ms wait before falling back to the legacy uTP frame type
- [ ] 4.3 Establish the uTP connection over the punched mapping
- [ ] 4.4 Fall back to callback and buddy when traversal is unavailable or exhausted
- [ ] 4.5 Interop check against eMuleAI: LowID to LowID in both directions

## Building and testing this change

Do not assume a host toolchain. The supported route is the container:

```sh
packaging/linux/build.sh dev        # configures all three apps + tests, builds, runs ctest
```

Nothing is installed on the host. Compare any test failure against the
pre-existing failures in `openspec/BASELINE.md` before attributing it to this
change — see `openspec/changes/README.md`.
