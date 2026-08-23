# Tasks: Recognise eMuleAI peers

## 1. Capability model

- [ ] 1.1 Add a capability bitfield type with the five documented bits and a reserved mask
- [ ] 1.2 Unit test: round-trip every bit, assert exact positions against a fixture
- [ ] 1.3 Store parsed peer capabilities on the client record

## 2. Vendor tags

- [ ] 2.1 Parse `CT_MOD_IP_V6` (`0xAE`) and `CT_MOD_SVR_IP_V6` (`0xAF`)
- [ ] 2.2 Parse the `"ip6"` and `"bi6"` string tags
- [ ] 2.3 Ignore unrecognised `CT_MOD_*` tags without aborting the handshake
- [ ] 2.4 Emit only implemented capabilities — after this change, none of the new ones
- [ ] 2.5 Unit test: unknown-tag tolerance, and that no unimplemented bit is emitted

## 3. Frame demultiplexing

- [ ] 3.1 Dispatch `OP_UDPRESERVEDPROT2` on the first payload byte
- [ ] 3.2 Register handlers for `0x00`, `0x01`, `0x02`, `0x03`, `0xFF`; drop everything else
- [ ] 3.3 Guard the empty-payload case before reading the type byte
- [ ] 3.4 Exempt dropped known-but-unsupported frames from flood accounting
- [ ] 3.5 Unit test: truncated payload, unknown type, each known type reaching its handler

## 4. Surface

- [ ] 4.1 Show negotiated peer capabilities in client details
- [ ] 4.2 Debug-log unknown frame types at a rate-limited level

## Building and testing this change

Do not assume a host toolchain. The supported route is the container:

```sh
packaging/linux/build.sh dev        # configures all three apps + tests, builds, runs ctest
```

Nothing is installed on the host. Compare any test failure against the
pre-existing failures in `openspec/BASELINE.md` before attributing it to this
change — see `openspec/changes/README.md`.
