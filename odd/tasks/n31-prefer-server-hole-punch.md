# N31: prefer server hole punch

Authorized implementation for the server capability-routing change.

## Specs

S1. "pues adelante con N31"
S2. When the connected server announces `0x20000`, prefer the `0x60` LowID hole-punch request.
S3. Do not send `0xA6` on servers that announce `0x20000`, and never send both requests for one target.

## Tasks

T1 — S1-S3 — inline — done — Mapped the `0x60` and `0xA6` request policies.
T2 — S2-S3 — inline — done — Prefer `0x60` for a server advertising both flags; suppress `0xA6`; regression tests added.
T3 — S1-S3 — inline — pending — Verify supported builds and record the work-unit commit.

## Log

L1. "pues adelante con N31"
L2. Implemented the policy and unit-test changes locally; verification is blocked because Podman cannot connect to its VM at `127.0.0.1:53665`.
L3. Podman was restored. The QUIC container build passed 182/182 tests on Debian Trixie/aarch64.
