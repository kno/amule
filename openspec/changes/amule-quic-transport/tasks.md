# Tasks: QUIC NAT-T transport

## 0. Decision gate (blocks everything below)

- [ ] 0.1 Maintainer decision: adopt ngtcp2 plus a TLS stack, or decline this change
- [ ] 0.2 Select the TLS backend; record the rationale in design.md
- [ ] 0.3 Confirm packaging viability across the platforms aMule ships on

## 1. Build integration

- [ ] 1.1 Add ngtcp2 and the chosen TLS stack as optional CMake dependencies
- [ ] 1.2 Make QUIC a build-time option, defaulting off until proven
- [ ] 1.3 Verify the client builds and traverses over uTP with QUIC disabled

## 2. Transport

- [ ] 2.1 Implement the QUIC socket half, shaped like the existing stream interface
- [ ] 2.2 Implement the ngtcp2/TLS bridge as a separate unit
- [ ] 2.3 Offer ALPN `ed2k-ai-natt-quic-v1`; reject any other value
- [ ] 2.4 Insert QUIC into the shared-port classification order after uTP
- [ ] 2.5 Unit test: ALPN rejection; classification order for all three consumers

## 3. Authentication

- [ ] 3.1 Build and validate the 37-byte `EAQN1` proof
- [ ] 3.2 Reject payload before proof validation completes
- [ ] 3.3 Distinguish authentication failure from transport failure in logs
- [ ] 3.4 Unit test: absent, truncated, wrong-magic and wrong-identity proofs

## 4. Fallback

- [ ] 4.1 Skip the wait entirely for peers without the QUIC capability bit
- [ ] 4.2 Fall back to uTP after 1500 ms when the capability frame is lost
- [ ] 4.3 Keep the fallback invisible in user-facing state
- [ ] 4.4 Interop check against eMuleAI over QUIC, then with QUIC disabled

## Building and testing this change

Do not assume a host toolchain. The supported route is the container:

```sh
packaging/linux/build.sh dev        # configures all three apps + tests, builds, runs ctest
```

Nothing is installed on the host. Compare any test failure against the
pre-existing failures in `openspec/BASELINE.md` before attributing it to this
change — see `openspec/changes/README.md`.
