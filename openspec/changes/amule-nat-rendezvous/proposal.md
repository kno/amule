# Proposal: Rendezvous and hole punching

## Intent

Let two firewalled (LowID) peers connect directly to each other, by implementing
the rendezvous and hole-punch exchange over the uTP frame type.

## Why this is the payoff

No stock eMule-family client can do this. A LowID peer today reaches HighID peers
via server callback or Kad buddy, but two LowID peers simply never meet — which,
on a network where a large share of peers are behind NAT, removes a substantial
fraction of possible source pairs.

aMule has nothing here: no `rendezvous`, no `holepunch`, no equivalent token
anywhere in `src/`.

## Wire elements

From `srchybrid/Opcodes.h`:

| Element | Value |
| --- | --- |
| `OP_RENDEZVOUS` | `0xA0` |
| `OP_HOLEPUNCH` | `0xA1` |
| `OP_NATT_ENDPOINT_HINT` | `0xAA` |
| `CONNECT_OPT_NATT_ENDPOINT_HINT` | `0x20` |
| `CONNECT_OPT_NAT_TRAVERSAL_UTP` | `0x80` |
| rendezvous max attempts | `5` |
| rendezvous timeout | `120 s` |
| rendezvous backoff | `60 s` |

## Safety, not tuning

The bounded attempts, timeout and backoff are load-bearing. A rendezvous exchange
asks a third party to send packets to an address the requester supplies — an
unbounded or unvalidated version of that is a traffic amplification and reflection
vector. Any implementation that treats the bounds as tunable performance knobs has
misread them.

## Over uTP first

QUIC is not required. The uTP frame type (`0x00`) carries this exchange, and uTP
already shares the ed2k UDP port, so the punched hole is the hole uTP uses.
`amule-quic-transport` is an upgrade on top, not a prerequisite.

## Dependencies

Requires `amule-peer-capability-recognition` and `amule-utp-transport`.
Blocks `amule-quic-transport`.
