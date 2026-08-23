# Tasks: address widening

## 1. Type introduction

- [ ] 1.1 Select `asio::ip::address` as the internal type; record the decision in design.md
- [ ] 1.2 Add named, byte-order-explicit conversions to and from `uint32`
- [ ] 1.3 Make the IPv6-to-32-bit conversion fail explicitly rather than truncate
- [ ] 1.4 Add an absent-address representation distinct from the all-zero address
- [ ] 1.5 Unit test: mapped-vs-native comparison, total ordering, failed narrowing

## 2. Characterisation tests first

- [ ] 2.1 Capture current behaviour of IP filter matching
- [ ] 2.2 Capture current behaviour of client-list address comparison
- [ ] 2.3 Capture current address serialisation on the wire
- [ ] 2.4 Hold these tests unchanged through the whole refactor

## 3. Socket backend

- [ ] 3.1 Remove the `ip::tcp::v4()` pins at `LibSocketAsio.cpp:541`, `:785`, `:2183`
- [ ] 3.2 Remove the `address_v4` pins at `:2160`, `:2237`
- [ ] 3.3 Derive family from configuration or target address
- [ ] 3.4 Unit test: family selection for v4 and v6 targets

## 4. Subsystem migration

- [ ] 4.1 Migrate client list to the new type
- [ ] 4.2 Migrate IP filter to the new type
- [ ] 4.3 Leave the Kad interface on `uint32` behind a documented conversion boundary
- [ ] 4.4 Audit every former zero-sentinel test and convert it to an explicit absence check

## 5. Cleanup

- [ ] 5.1 Retire conversion helpers with no remaining callers
- [ ] 5.2 Confirm no new abstraction duplicates `asio::ip::address`

## Building and testing this change

Do not assume a host toolchain. The supported route is the container:

```sh
packaging/linux/build.sh dev        # configures all three apps + tests, builds, runs ctest
```

Nothing is installed on the host. Compare any test failure against the
pre-existing failures in `openspec/BASELINE.md` before attributing it to this
change — see `openspec/changes/README.md`.
