# Proposal: uTP as a transport

## Intent

Add libutp and expose a stream interface over uTP, so that ed2k client
connections can run over uTP as an alternative to TCP.

## Gap being closed

aMule has no uTP: no `utp_` symbol, no `libutp` reference anywhere in the tree.
eMuleAI has `CUtpSocket`, 1930 lines, over libutp.

## Structural difference that shapes the work

eMuleAI gets this almost free because its MFC socket stack has a layer concept —
`CUtpSocket` is a `CAsyncSocketExLayer`, and the rest of the client neither knows
nor cares which layer is underneath. aMule has no layer abstraction: its Asio
backend hands out sockets directly. So the port needs an Asio-side shim that owns
a `utp_context`, is fed datagrams from the existing UDP socket, and presents the
same interface the client already consumes for TCP.

That shim is the actual design work in this change. The libutp integration itself
is mechanical.

## Do not skip the buffer heuristics

`CUtpSocket` carries write-buffer growth and shrink logic, duplex-transfer
detection, and blocked-write accounting. These are not incidental — they are what
keeps a simultaneous upload and download over one uTP socket from stalling. A
minimal port that omits them will appear to work in single-direction tests and
stall under real load.

## Staging

Ship IPv4-only first even though `amule-address-widening` has landed. Adding a new
transport and a new address family in one change makes a stall impossible to
attribute.

## Dependencies

Requires `amule-address-widening`. Blocks `amule-nat-rendezvous`.
New dependency: libutp.
