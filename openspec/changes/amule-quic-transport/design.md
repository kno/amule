# Design: QUIC NAT-T

## Why QUIC at all

uTP already traverses and already carries data. QUIC buys a modern congestion
controller, authenticated transport, connection migration, and stream
multiplexing over one mapping. On a NAT-traversed path — where the mapping is
fragile and the round-trip is often poor — migration and loss recovery are the
properties that matter.

## Shape

QUIC packets ride inside `OP_UDPRESERVEDPROT2` frame type `0x01`, on the same UDP
port as ed2k UDP and uTP. Classification therefore has three consumers on one
port, and the order is: uTP context, QUIC context, ed2k UDP parser.

The TLS bridge is a separate concern from the socket. eMuleAI splits it that way —
`CQuicNatSocket` is the socket-shaped half, `CNgTcp2GnuTlsBridge` is the
crypto-and-protocol half — and the split is worth preserving because it isolates
the dependency that is hardest to package.

## Peer authentication

The 37-byte proof (`EAQN1` + two 16-byte values) is what ties the QUIC connection
to the ed2k identity that negotiated it. Without it, an observer of the rendezvous
exchange could complete the handshake in the peer's place. The proof must be
validated before any payload is accepted, not after the handshake completes.

## Fallback path

If the peer has not advertised `SupportsNatTraversalQuic`, or 1500 ms elapse
without a QUIC capability frame, the client uses uTP frame type `0x00`. The
fallback must be automatic and silent — a user should never see a QUIC failure,
only a slower path.

## TLS stack selection

Open question, and a maintainer decision rather than an engineering one. GnuTLS
matches eMuleAI and is therefore the lowest-risk choice for interoperability
testing. OpenSSL is more widely packaged but its QUIC API history is more
complicated. This must be settled before implementation, because ngtcp2's crypto
binding differs per backend.

## Rejected alternative

Vendoring a QUIC implementation to avoid the dependency. Rejected: QUIC is
security-relevant code with an active vulnerability history, and vendoring shifts
patch responsibility onto the aMule maintainers indefinitely.
