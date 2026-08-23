# Proposal: Recognise eMuleAI peers

## Intent

Teach aMule to read and advertise the eMuleAI vendor capability extensions, and
to demultiplex `OP_UDPRESERVEDPROT2` by frame type. This buys interoperability
before any transport or addressing work begins.

## Why first

- No new dependency, no addressing change, no protocol generation jump.
- aMule already parses `OP_UDPRESERVEDPROT2` (`src/EncryptedDatagramSocket.cpp:162`
  and `:374`), so the demux point exists.
- Without it aMule treats every NAT-T frame an eMuleAI peer sends as malformed
  traffic, which feeds its own packet-rate banning
  (`src/kademlia/net/PacketTracking.cpp:225`).

## Gap being closed

aMule has no `CT_MOD_*` tag family at all — `grep CT_MOD src/` returns nothing.
eMuleAI carries them in `srchybrid/Opcodes.h:700-722`:

| Element | Value | Meaning |
| --- | --- | --- |
| `CT_MOD_IP_V6` | `0xAE` | client IPv6 address |
| `CT_MOD_SVR_IP_V6` | `0xAF` | server IPv6 address |
| `TAG_IPV6` | `"ip6"` | unfirewalled IPv6 |
| `TAG_SERVINGBUDDYIPV6` | `"bi6"` | buddy IPv6 |
| `SupportsExtendedXS` | bit 0 | extended source exchange |
| `SupportsNatTraversal` | bit 1 | legacy uTP NAT-T |
| `SupportsIPv6` | bit 2 | IPv6 support |
| `SupportsServingBuddyPull` | bit 3 | buddy-info pull |
| `SupportsNatTraversalQuic` | bit 4 | QUIC NAT-T |

## Scope

In scope: tag parse/emit, misc-options bitfield parse/emit, frame-type demux with
unknown-type drop, capability display in client details.

Out of scope: acting on any advertised capability. aMule advertises only what it
actually implements — which after this change is nothing new.

## Risk

Bit positions must match `UModMiscOptions` exactly. A one-bit offset inverts
negotiation silently: aMule would claim QUIC support it does not have and peers
would open handshakes that never complete. This is the single highest-risk detail
in the change and has no runtime signal when wrong.

## Dependencies

None. Blocks `amule-nat-rendezvous` and `amule-quic-transport`.
