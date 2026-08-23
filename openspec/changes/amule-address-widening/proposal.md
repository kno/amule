# Proposal: Widen the internal address type

## Intent

Replace aMule's pervasive `uint32` IPv4 representation with a family-agnostic
address type, and remove the hardcoded IPv4 assumptions from the Asio socket
backend.

## Why this is the real cost

Everything downstream of here — dual-stack, uTP over v6, QUIC, endpoint hints —
depends on being able to represent an address that is not four bytes. aMule stores
and compares IPs as `uint32` across Kademlia, the client list and the IP filter,
so this is the one genuinely invasive change in the set.

The Asio backend pins the family in three places:
`src/LibSocketAsio.cpp` uses `ip::tcp::v4()` at lines 541, 785 and 2183, and
`address_v4` at 2160 and 2237.

## Approach

Prefer `asio::ip::address` over porting eMuleAI's `CAddress`. aMule's backend
already owns the primitive, it handles v4-mapped addresses, and it comes with
comparison and string conversion. Porting `CAddress`
(`srchybrid/eMuleAI/Address.h`) would introduce a parallel abstraction over the
same capability.

## Sequencing

Do not start this before `amule-peer-capability-recognition` and
`amule-kad-protocol-catchup` have shipped. Both are cheap, both are independent,
and both become harder to review if they land on top of an in-flight addressing
refactor.

## Explicitly out of scope

Kad addressing. Kad stays IPv4 for now — eMuleAI's Kad is also still IPv4, so
widening it here would put aMule ahead of the reference implementation with
nothing to interoperate with.

## Risk

This is a wide, mechanical diff with a narrow behavioural surface. The danger is
silent semantic change at call sites that currently rely on `uint32` ordering,
byte order, or the sentinel value zero. Every such site needs an explicit
decision, not a mechanical substitution.

## Dependencies

Blocks `amule-dual-stack-reachability`, `amule-utp-transport`,
`amule-nat-rendezvous`, `amule-quic-transport`.
