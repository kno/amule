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

## Post-merge correction: identity-rotation escalation

`CSafeKad::IsBadNode()` refused an unverified identity change against a
verified (or pre-0x08) tracked entry without recording it, so the address never
climbed the problematic-then-banned ladder that the "Rapid identity rotation"
scenario requires. An attacker arriving unverified was therefore refused every
time at no cost and could retry indefinitely.

The refusal is unchanged — it is stricter than the spec asks for, deliberately.
What was added is the bookkeeping: a refused change inside
`MIN_ID_CHANGE_INTERVAL` now escalates through the same `Escalate()` helper
`TrackNode()` uses, so one rejection is always exactly one step and the two
paths cannot double-count. A refused change *past* the interval is not rotation,
only unverifiable, and does not escalate: banning a legacy client that
reinstalled once would be the protection misfiring.

Covered by `unittests/tests/SafeKadTest.cpp`; the literal wire values of
`CT_MOD_MISCOPTIONS`, `CT_MOD_IP_V6`, `CT_MOD_SVR_IP_V6`, `TAG_IPV6` and
`TAG_SERVINGBUDDYIPV6` are now pinned in `unittests/tests/PeerCapabilitiesTest.cpp`.
