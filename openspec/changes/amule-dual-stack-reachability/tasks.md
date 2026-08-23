# Tasks: dual-stack reachability

## 1. Listeners

- [ ] 1.1 Create ed2k TCP listeners for both families
- [ ] 1.2 Create ed2k UDP sockets for both families
- [ ] 1.3 Attempt a dual-stack socket first; fall back to one socket per family
- [ ] 1.4 Log a bind failure once per family per start, not per retry
- [ ] 1.5 Unit test: single-family host, dual-stack rejection fallback

## 2. Outbound

- [ ] 2.1 Select family from the target endpoint
- [ ] 2.2 Implement cross-family fallback when a peer advertises both
- [ ] 2.3 Do not mark a peer dead until every advertised family has failed
- [ ] 2.4 Unit test: fallback ordering and dead-peer accounting

## 3. IP filter

- [ ] 3.1 Extend rule storage and matching to IPv6 prefixes
- [ ] 3.2 Normalise IPv4-mapped addresses to their IPv4 form before matching
- [ ] 3.3 Unit test: mapped-address bypass attempt is blocked; IPv6 prefix rule matches

## 4. Advertisement

- [ ] 4.1 Track verified inbound IPv6 connectivity separately from bound state
- [ ] 4.2 Emit `SupportsIPv6`, `CT_MOD_IP_V6` and `"ip6"` only when verified
- [ ] 4.3 Surface IPv4 and IPv6 reachability separately in the UI
- [ ] 4.4 Interop check against an IPv6-reachable eMuleAI build

## Building and testing this change

Do not assume a host toolchain. The supported route is the container:

```sh
packaging/linux/build.sh dev        # configures all three apps + tests, builds, runs ctest
```

Nothing is installed on the host. Compare any test failure against the
pre-existing failures in `openspec/BASELINE.md` before attributing it to this
change — see `openspec/changes/README.md`.
