# Delta for transport-quic

## ADDED Requirements

### Requirement: Exact wire identity

The QUIC NAT-T path MUST use frame type `0x01` inside `OP_UDPRESERVEDPROT2` and
ALPN `ed2k-ai-natt-quic-v1`. No other ALPN value MUST be offered or accepted for
this path.

#### Scenario: Peer offering a different ALPN

- GIVEN an inbound QUIC handshake offering an ALPN other than `ed2k-ai-natt-quic-v1`
- WHEN the handshake is processed
- THEN it MUST be rejected
- AND the client MUST NOT fall back to an unauthenticated path

### Requirement: Proof validation before payload

The 37-byte peer proof — magic `EAQN1` followed by two 16-byte values — MUST be
validated before any application payload from the connection is accepted.

#### Scenario: Missing or malformed proof

- GIVEN a completed QUIC handshake whose proof is absent, truncated, or carries the wrong magic
- WHEN the first payload arrives
- THEN the connection MUST be closed
- AND no payload MUST be delivered to the client

#### Scenario: Proof for a different identity

- GIVEN a proof that does not correspond to the ed2k identity that negotiated the rendezvous
- WHEN validation runs
- THEN the connection MUST be closed
- AND the event MUST be logged as an authentication failure, not a transport error

### Requirement: Silent fallback to uTP

When a peer has not advertised QUIC support, or 1500 ms elapse without a QUIC
capability frame, the client MUST use uTP frame type `0x00` without surfacing an
error.

#### Scenario: Peer without QUIC

- GIVEN a peer advertising traversal support but not `SupportsNatTraversalQuic`
- WHEN traversal begins
- THEN the client MUST use the uTP frame type immediately
- AND MUST NOT wait the 1500 ms window

#### Scenario: Capability frame lost

- GIVEN a peer that advertised QUIC support but whose capability frame does not arrive
- WHEN 1500 ms have elapsed
- THEN the client MUST fall back to uTP
- AND the user-visible state MUST show a connected peer, not a failure

### Requirement: Shared port classification order

QUIC, uTP and ed2k UDP MUST share one port, classified in a fixed documented
order.

#### Scenario: Datagram declined by uTP

- GIVEN an inbound datagram the uTP context declines
- WHEN classification continues
- THEN it MUST be offered to the QUIC context before the ed2k UDP parser
- AND a datagram declined by all three MUST be dropped without error

### Requirement: Optional at build time

QUIC support MUST be a build-time option, and the client MUST be fully functional
with it disabled.

#### Scenario: Built without QUIC

- GIVEN a build configured without QUIC support
- WHEN the client negotiates traversal
- THEN it MUST NOT advertise `SupportsNatTraversalQuic`
- AND LowID-to-LowID traversal MUST still work over uTP
