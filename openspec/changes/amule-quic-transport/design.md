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

Settled: **ngtcp2 with the GnuTLS crypto backend**. Decided 2026-08-26; this
section previously carried it as an open maintainer question.

GnuTLS matches eMuleAI, which builds the same pairing as `CNgTcp2GnuTlsBridge`,
so interoperability is tested against the implementation this change exists to
interoperate with rather than against a second guess at it.

The packaging survey below then made the choice narrower than a preference.
Availability of the crypto backends, measured per platform rather than assumed:

| Platform | ngtcp2 | GnuTLS backend | OpenSSL backend |
| --- | --- | --- | --- |
| Debian trixie (the runtime image) | `libngtcp2-dev` 1.11.0 | `libngtcp2-crypto-gnutls-dev` 1.11.0 | not packaged |
| Homebrew (macOS) | `libngtcp2` 1.25.0 | absent — the formula links `openssl@3` | via that formula |
| MSYS2 mingw-w64 (Windows installers) | present | present | present |

Debian packages only the GnuTLS binding, so on the platform the container image
ships from, GnuTLS is not merely the better choice but the only one available
without building ngtcp2 from source. Vendoring is not open to us either: the
rejected-alternative section below rules it out, and that reasoning holds
whichever backend is chosen.

The cost is macOS. Homebrew's `libngtcp2` links OpenSSL, so a GnuTLS build there
would need ngtcp2 from source, which is the vendoring this design rejects. macOS
therefore builds with QUIC off and reaches peers over uTP, which the fallback
above already requires to be automatic and silent -- a macOS user loses no
capability, only the faster path. This is a starting position, not a permanent
one: adding an OpenSSL backend later is additive, and `ENABLE_QUIC` is per-platform.

That ordering also fits task 1.2, which defaults QUIC off until proven. Linux
first, where the dependency is packaged and the interop target lives.

## Rejected alternative

Vendoring a QUIC implementation to avoid the dependency. Rejected: QUIC is
security-relevant code with an active vulnerability history, and vendoring shifts
patch responsibility onto the aMule maintainers indefinitely.
