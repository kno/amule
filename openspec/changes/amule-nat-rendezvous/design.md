# Design: rendezvous and hole punching

## Roles

Three parties: the two firewalled peers, and a mutually reachable third party that
relays the rendezvous request. The third party never carries payload — it carries
one signalling message so that both peers learn when to punch.

## Sequence

1. **A** wants **B**, both LowID. A knows a peer **R** that can reach B.
2. A sends `OP_RENDEZVOUS` to R, naming B and A's own endpoint hint.
3. R validates the request and forwards it to B.
4. Both A and B send `OP_HOLEPUNCH` to the other's hinted endpoint, repeatedly,
   until one arrives or the attempt budget is exhausted.
5. On success, the uTP connection is established over the now-open mapping.

## Where the bounds attach

- **Per attempt**: a hole-punch burst is bounded in packet count and spacing.
- **Per rendezvous**: at most 5 attempts, 120 s total before the source is
  considered temporarily unreachable.
- **After failure**: 60 s backoff, during which the source stays queued rather
  than being discarded.

The backoff is why a failed traversal does not cost the source. Dropping it turns
a transient NAT condition into a permanently lost peer.

## Relay validation

R must not forward a rendezvous request that names an endpoint unrelated to the
requester, and must rate-limit how often it will relay for any one requester.
Without both, R becomes a packet reflector: an attacker names a victim's address
as its own endpoint hint and has R direct traffic at it.

This validation is the single most security-relevant part of the change, and it
lives on the relaying side — the side that gets no benefit from the traversal.

## Endpoint hints

`OP_NATT_ENDPOINT_HINT` (`0xAA`) carries the observed external endpoint. It is a
hint, not an authority: a peer's own view of its external address is frequently
wrong behind symmetric NAT, so the hint is one candidate among the addresses
already known, not a replacement for them.

## What is not attempted

Symmetric-NAT-to-symmetric-NAT traversal. When both mappings are
address-and-port-dependent, the punch cannot converge without port prediction.
The attempt budget is what stops the client from trying forever in that case,
and the correct outcome is falling back to the existing callback and buddy paths.
