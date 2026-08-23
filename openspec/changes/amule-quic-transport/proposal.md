# Proposal: QUIC NAT-T transport

## Intent

Add QUIC as a NAT-traversal data transport alongside uTP, matching eMuleAI's
ngtcp2-based implementation.

## Deliberately last, and optional

Everything in `amule-nat-rendezvous` already works over uTP. QUIC is an upgrade to
the data path, not a prerequisite for LowID-to-LowID connectivity. If this change
is never implemented, aMule still reaches functional parity on traversal.

## The cost is packaging, not protocol

aMule currently links **no TLS library at all** — its `CMakeLists.txt` pulls in
Boost and nothing cryptographic of this kind. QUIC therefore means adopting two
new dependencies before a single packet moves:

- ngtcp2 — the QUIC implementation
- a TLS stack ngtcp2 supports — eMuleAI uses GnuTLS
  (`srchybrid/eMuleAI/NgTcp2GnuTlsBridge.cpp`, 1161 lines)

For a project that ships across as many platforms and distributions as aMule, that
packaging burden is the dominant cost, and it falls on people who are not writing
the networking code. This warrants an explicit maintainer decision before any
implementation work starts.

## Wire elements that must match exactly

| Element | Value |
| --- | --- |
| frame type | `0x01` inside `OP_UDPRESERVEDPROT2` |
| ALPN | `ed2k-ai-natt-quic-v1` |
| proof magic | `EAQN1` |
| proof length | 37 bytes (5 + 16 + 16) |
| capability bit | `SupportsNatTraversalQuic` |
| legacy fallback wait | 1500 ms |

A mismatch in any of these fails the handshake with no diagnostic — the peer
simply never completes. This is the argument for a written specification before
implementation, not after.

## Dependencies

Requires `amule-nat-rendezvous`.
New dependencies: ngtcp2, plus a TLS stack.
