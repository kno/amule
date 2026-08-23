# Tasks: Recognise eMuleAI peers

## 1. Capability model

- [x] 1.1 Add a capability bitfield type with the five documented bits and a reserved mask
- [x] 1.2 Unit test: round-trip every bit, assert exact positions against a fixture
- [x] 1.3 Store parsed peer capabilities on the client record

## 2. Vendor tags

- [x] 2.1 Parse `CT_MOD_IP_V6` (`0xAE`) and `CT_MOD_SVR_IP_V6` (`0xAF`)
- [x] 2.2 Parse the `"ip6"` and `"bi6"` string tags
- [x] 2.3 Ignore unrecognised `CT_MOD_*` tags without aborting the handshake
- [x] 2.4 Emit only implemented capabilities — after this change, none of the new ones
- [x] 2.5 Unit test: unknown-tag tolerance, and that no unimplemented bit is emitted

## 3. Frame demultiplexing

- [x] 3.1 Dispatch `OP_UDPRESERVEDPROT2` on the first payload byte
- [x] 3.2 Register handlers for `0x00`, `0x01`, `0x02`, `0x03`, `0xFF`; drop everything else
- [x] 3.3 Guard the empty-payload case before reading the type byte
- [x] 3.4 Exempt dropped known-but-unsupported frames from flood accounting
- [x] 3.5 Unit test: truncated payload, unknown type, each known type reaching its handler

## 4. Surface

- [x] 4.1 Show negotiated peer capabilities in client details
- [x] 4.2 Debug-log unknown frame types at a rate-limited level
- [x] 4.3 Expose the negotiated peer capabilities as an External Connection tag
      on the per-client tag set, rendered by 4.1 from the same source of truth
      rather than a parallel path. This exists to make 4.1 verifiable in a
      headless environment: the Client Details dialog lives only in `amule` and
      `amulegui`, neither of which starts without an X server, so without an EC
      tag the display in 4.1 ships with no way to observe it. EC tag layer only
      -- no display added to `amuleweb` or `amulecmd`, and reading the tag back
      is a verification concern.
- [x] 4.4 Unit test: the EC tag encoding -- exact tag code, word round-trip,
      reserved bits never crossing the protocol, and an absent tag staying
      distinct from an advertised-nothing word

## Building and testing this change

Do not assume a host toolchain. The supported route is the container:

```sh
packaging/linux/build.sh dev        # configures all three apps + tests, builds, runs ctest
```

Nothing is installed on the host. Compare any test failure against the
pre-existing failures in `openspec/BASELINE.md` before attributing it to this
change — see `openspec/changes/README.md`.
