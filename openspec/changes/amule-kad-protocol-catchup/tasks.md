# Tasks: Kad protocol catch-up

## 1. Version step

- [x] 1.1 Read the 0x09 and 0x0a protocol deltas out of eMuleAI's kademlia sources
- [x] 1.2 Implement AICH hash carriage on keyword storage and search results
- [x] 1.3 Gate AICH carriage on the peer's advertised version
- [x] 1.4 Raise `KADEMLIA_VERSION` to `0x0a` in `src/include/protocol/kad2/Constants.h`
- [x] 1.5 Unit test: mixed-version publish and search, 0x08 peer unaffected

## 2. Adaptive timing

- [x] 2.1 Add a bounded response-time sample store keyed by peer address
- [x] 2.2 Compute mean and variance; derive the ceiling; clamp to a documented maximum
- [x] 2.3 Replace fixed Kad request timeouts with the derived ceiling
- [x] 2.4 Unit test: cold start with zero and one sample; rising and falling distributions

## 3. Identity protections

- [x] 3.1 Track (address, ID, last-change) with a one-hour minimum change interval
- [x] 3.2 Add the problematic-node list with a 300 s horizon
- [x] 3.3 Add the per-IP ban with a four-hour ceiling, layered over existing banning
- [x] 3.4 Enforce one node per IP, keyed by Kad version
      — **Implemented and tested as `CSafeKad::IsBadNode(..., onlyOneNodePerIP, ...)`, but
      deliberately passed `false` at both production call sites.** `CRoutingBin` already caps
      the routing table at `MAX_CONTACTS_IP` (1) Kad ID per address plus `MAX_CONTACTS_SUBNET`
      (10) per /24 (`RoutingBin.cpp:51-52`, `CheckGlobalIPLimits`). Switching this on would be a
      second, weaker copy of a rule the bin already enforces better — see task 4.1. eMuleAI
      reaches the same conclusion: `CSafeKad2::IsBadNode` defaults the flag to `true` and its
      only call site passes `false`.
- [x] 3.5 Bound all three tables and evict by last-reference age
- [x] 3.6 Unit test: rotation rejected, post-interval change accepted, eviction under load

## 4. Integration

- [x] 4.1 Confirm the new layer composes with `PacketTracking` rather than duplicating it
      — Confirmed; the three layers are disjoint. `CPacketTracking` rate-limits packets per
      (IP, opcode) and escalates to `CClientList::AddBannedClient`. `CRoutingBin` caps contacts
      per IP and per /24 subnet. `CSafeKad` covers what neither does: a node that behaves
      politely while rotating its Kad ID. Its ban is Kad-routing-local and separate from
      `CClientList`'s eD2k-wide ban, which has its own lifetime and triggers. Recorded in
      `SafeKad.h` and at the `CRoutingZone::AddUnfiltered` hook.
- [x] 4.2 Verify no existing routing-zone test regresses
      — There is no dedicated routing-zone suite in `unittests/tests/`. The broader check holds:
      all 37 pre-existing suites behave exactly as at the baseline, with the same single
      pre-existing failure (`FileDataIOTest`, SEGFAULT — `openspec/BASELINE.md`).

## Building and testing this change

Do not assume a host toolchain. The supported route is the container:

```sh
packaging/linux/build.sh dev        # configures all three apps + tests, builds, runs ctest
```

Nothing is installed on the host. Compare any test failure against the
pre-existing failures in `openspec/BASELINE.md` before attributing it to this
change — see `openspec/changes/README.md`.
