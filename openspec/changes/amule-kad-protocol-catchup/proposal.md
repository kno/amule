# Proposal: Kad protocol catch-up, 0x08 to 0x0a

## Intent

Move aMule's Kademlia implementation from protocol version `0x08` to `0x0a`, then
add the two protections eMuleAI layers on top of the standard set.

## Gap being closed

aMule declares `KADEMLIA_VERSION 0x08 /* 0.49b */` in
`src/include/protocol/kad2/Constants.h:29`. eMuleAI declares `0x0a` in
`srchybrid/Opcodes.h:86`. Two generations:

| Version | Adds |
| --- | --- |
| `0x09` | AICH hashes on keyword storage |
| `0x0a` | current eMuleAI level |

## What aMule already has

This is not a protection vacuum. aMule carries the standard 0.49b defences and
they must not be replaced:

- packet-rate banning — `src/kademlia/net/PacketTracking.cpp:225`
- UDP key challenge and contact verification — `src/kademlia/net/KademliaUDPListener.cpp:679`
- `ipVerified` propagation through routing-zone insertion

## What is genuinely missing

Two additive layers from eMuleAI, neither of which changes the wire format:

- `CFastKad` — estimates a response-time ceiling from the mean and variance of up
  to 100 samples (`srchybrid/eMuleAI/FastKad.h`). aMule uses fixed timeouts.
- `CSafeKad2` — per-node identity-change rate limiting (minimum one hour between
  ID changes), a problematic-node list with a 300 s horizon, a per-IP ban with a
  four-hour ceiling, and one-node-per-IP enforcement keyed by Kad version. All
  tables are bounded at 10000 / 10000 / 1000 entries
  (`srchybrid/eMuleAI/SafeKad.h`).

## Why early

Fully independent of the addressing refactor and of every transport change. It is
the best value per hour in the set, and it lands in a subsystem where aMule
already has a test harness (`unittests/`, muleunit).

## Scope

Out of scope: IPv6 inside Kad. Neither client has it — eMuleAI's Kad still keys on
`uint32` IPs, and `CSafeKad2` indexes by `uint32 uIP`. Kad stays IPv4 here.

## Dependencies

None. Blocks nothing.
