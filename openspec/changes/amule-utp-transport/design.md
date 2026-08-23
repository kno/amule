# Design: uTP transport shim

## The problem

aMule's client code consumes a socket. eMuleAI's consumes a socket that may have
layers beneath it. uTP is naturally a layer: it is a stream protocol carried over
UDP datagrams, so it needs to sit between the client and a UDP socket that is
already in use for ed2k UDP traffic.

## Shape

One `utp_context` per client instance, not per connection. The context is driven
by three inputs:

- **Inbound datagrams** — the existing ed2k UDP socket receives a datagram,
  recognises it as uTP, and feeds it to the context.
- **A periodic tick** — libutp requires regular timer processing; without it,
  retransmission and congestion control stop.
- **Application writes** — buffered, because libutp accepts writes only when its
  own window allows.

Outbound datagrams leave through the same UDP socket via the send callback, so
uTP and ed2k UDP share one port. This is what makes uTP usable for NAT traversal
later: the hole punched for ed2k UDP is the hole uTP uses.

## Demultiplexing

Inbound classification happens before the ed2k UDP parser. A datagram is offered
to the uTP context first; only if the context declines it does it continue to the
ed2k path. Getting this order wrong silently breaks either uTP or ed2k UDP
depending on which way it is inverted.

## Write buffering

The buffer grows when writes block at capacity and shrinks when a duplex transfer
is detected, so that a socket carrying traffic in both directions does not hold a
large buffer in each. Port the thresholds and the duplex heuristic together;
either alone changes behaviour under load.

## Failure semantics

A uTP connection that fails to establish MUST be distinguishable from a peer that
refused, so the client can fall back to TCP rather than marking the peer dead.
eMuleAI tracks this as an explicit transport-failure flag on the socket.

## Rejected alternative

Building a general socket-layer abstraction for aMule first, mirroring
`CAsyncSocketEx`. Rejected: it is a large refactor whose only current consumer is
uTP, and Asio already provides composition through its own idioms.
