# Design: address widening

## Decision

Adopt `asio::ip::address` as the internal address type. Rejected: porting
`CAddress` from eMuleAI.

Rationale — aMule already links Boost.Asio and already depends on its address
types inside `LibSocketAsio.cpp`. `asio::ip::address` provides the v4/v6 variant,
v4-mapped handling, ordering and string conversion that `CAddress` implements by
hand. Introducing `CAddress` would mean two abstractions over one capability, and
would import an MFC-shaped API into a wxWidgets codebase.

## Boundary strategy

The refactor is staged rather than atomic:

1. **Introduce** the new type and a conversion pair to and from `uint32`.
2. **Push the boundary outward** subsystem by subsystem — sockets first, then
   client list, then IP filter — keeping `uint32` at every unconverted edge.
3. **Retire** the conversion helpers only where no caller remains.

Kad keeps `uint32` throughout, so the conversion boundary sits permanently at the
Kad interface for this change. That is deliberate, not an unfinished edge.

## Sentinel handling

`uint32` zero currently doubles as "no address" in several places. The new type
has a distinct default-constructed state, so each site must choose between an
explicit optional and a documented unspecified-address value. A blanket mapping of
zero onto the default-constructed address would erase the distinction.

## Byte order

`uint32` IPs in aMule are stored in host or network order depending on the call
site, with `wxUINT32_SWAP_ALWAYS` appearing at conversion points such as
`src/kademlia/net/PacketTracking.cpp:225`. Every conversion introduced by this
change MUST state its byte-order expectation in the signature, not in a comment.

## Verification

Mechanical breadth with narrow behaviour means the test strategy is
characterisation: capture current behaviour of address comparison, filtering and
serialisation before the refactor, then hold those tests unchanged through it.
