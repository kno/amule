# Tasks: Kad protocol catch-up

## 1. Version step

- [ ] 1.1 Read the 0x09 and 0x0a protocol deltas out of eMuleAI's kademlia sources
- [ ] 1.2 Implement AICH hash carriage on keyword storage and search results
- [ ] 1.3 Gate AICH carriage on the peer's advertised version
- [ ] 1.4 Raise `KADEMLIA_VERSION` to `0x0a` in `src/include/protocol/kad2/Constants.h`
- [ ] 1.5 Unit test: mixed-version publish and search, 0x08 peer unaffected

## 2. Adaptive timing

- [ ] 2.1 Add a bounded response-time sample store keyed by peer address
- [ ] 2.2 Compute mean and variance; derive the ceiling; clamp to a documented maximum
- [ ] 2.3 Replace fixed Kad request timeouts with the derived ceiling
- [ ] 2.4 Unit test: cold start with zero and one sample; rising and falling distributions

## 3. Identity protections

- [ ] 3.1 Track (address, ID, last-change) with a one-hour minimum change interval
- [ ] 3.2 Add the problematic-node list with a 300 s horizon
- [ ] 3.3 Add the per-IP ban with a four-hour ceiling, layered over existing banning
- [ ] 3.4 Enforce one node per IP, keyed by Kad version
- [ ] 3.5 Bound all three tables and evict by last-reference age
- [ ] 3.6 Unit test: rotation rejected, post-interval change accepted, eviction under load

## 4. Integration

- [ ] 4.1 Confirm the new layer composes with `PacketTracking` rather than duplicating it
- [ ] 4.2 Verify no existing routing-zone test regresses

## Building and testing this change

Do not assume a host toolchain. The supported route is the container:

```sh
packaging/linux/build.sh dev        # configures all three apps + tests, builds, runs ctest
```

Nothing is installed on the host. Compare any test failure against the
pre-existing failures in `openspec/BASELINE.md` before attributing it to this
change — see `openspec/changes/README.md`.
