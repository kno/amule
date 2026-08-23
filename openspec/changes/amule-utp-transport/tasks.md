# Tasks: uTP transport

## 1. Dependency

- [ ] 1.1 Add libutp to the CMake build with a bundled-or-system option
- [ ] 1.2 Confirm the license notice is carried, including David Xanatos's copyright on ported code

## 2. Context plumbing

- [ ] 2.1 Create one `utp_context` per client instance
- [ ] 2.2 Wire the send callback to the existing ed2k UDP socket
- [ ] 2.3 Offer inbound datagrams to the uTP context before the ed2k UDP parser
- [ ] 2.4 Drive the context from a periodic tick independent of traffic
- [ ] 2.5 Unit test: classification order both ways; idle retransmission fires

## 3. Stream interface

- [ ] 3.1 Present the interface the client already consumes for TCP
- [ ] 3.2 Implement the write buffer with growth and shrink thresholds
- [ ] 3.3 Port the duplex-transfer detection and trim behaviour
- [ ] 3.4 Cap growth at the documented maximum
- [ ] 3.5 Unit test: duplex trim, blocked-write growth, growth ceiling

## 4. Fallback

- [ ] 4.1 Add an explicit transport-failure state distinct from peer refusal
- [ ] 4.2 Fall back to TCP on transport failure without marking the peer dead
- [ ] 4.3 Unit test: uTP-blocked peer still downloads over TCP

## 5. Staging

- [ ] 5.1 Ship IPv4-only first; keep the family generic in the interface
- [ ] 5.2 Enable IPv6 uTP only after IPv4 uTP is stable in real use

## Building and testing this change

Do not assume a host toolchain. The supported route is the container:

```sh
packaging/linux/build.sh dev        # configures all three apps + tests, builds, runs ctest
```

Nothing is installed on the host. Compare any test failure against the
pre-existing failures in `openspec/BASELINE.md` before attributing it to this
change — see `openspec/changes/README.md`.
