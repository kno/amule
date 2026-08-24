# Proposal: Dual-stack reachability

## Intent

Listen and connect over both address families for ed2k TCP and UDP, extend the IP
filter to IPv6, and advertise IPv6 reachability using the vendor tags implemented
in `amule-peer-capability-recognition`.

## Gap being closed

aMule has no IPv6 at all: `AF_INET6` appears zero times in `src/`. eMuleAI carries
40 references across 13 files, concentrated in the socket layer —
`AsyncSocketEx.cpp` 17, `ClientUDPSocket.cpp` 14, `ListenSocket.cpp` 12,
`IPFilter.cpp` 4.

## Why this is tractable

Boost.Asio supports both families natively. Once `amule-address-widening` has
removed the `v4()` pins from `LibSocketAsio.cpp`, this becomes configuration and
advertisement rather than new transport machinery. That is a real advantage aMule
has over eMuleAI here: eMuleAI had to grow dual-stack support inside an MFC socket
layer.

## First externally visible win

This is the first change in the set whose effect a user can observe, and the first
that is directly testable against an eMuleAI build — an IPv6-reachable aMule and
an IPv6-reachable eMuleAI should find and connect to each other without any
NAT traversal involved.

## Scope

In scope: dual-stack listeners, family-aware outbound connection, IPv6 in the IP
filter, IPv6 advertisement via `CT_MOD_IP_V6` and `"ip6"`, IPv6 in the
low-ID/firewalled determination.

Out of scope: Kad over IPv6, and any NAT traversal. Kad stays IPv4.

## Dependencies

Requires `amule-address-widening` and `amule-peer-capability-recognition`.
