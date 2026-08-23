# Archive report: amule-address-widening

Archived 2026-08-23. Change 3 of the network-parity set.

## Outcome

`apply: complete` (19 of 19 tasks), `verify: complete`, `archive: complete`.

Promoted `specs/network-addressing/spec.md` into the consolidated tree at
`openspec/specs/network-addressing/spec.md`. Delta framing stripped from the
promoted copy; the copy under this directory keeps it as the historical record of
the delta as authored. The two differ in exactly two header lines.

The delta was purely additive, so no destructive-merge warning applied. Checked
against `build-baseline`, `kademlia` and `peer-capability-negotiation` for
contradiction or duplication: none. This change touched Kad code that `kademlia`
covers, but the two specs constrain different things — `kademlia` the protocol on
the wire, `network-addressing` the internal representation behind a boundary that
deliberately keeps Kad on `uint32`.

## What this change delivered

No new user-visible capability. Its acceptance criterion was that nothing changed.
What it bought is that byte order now lives in a function name rather than in a
comment beside a bare `wxUINT32_SWAP_ALWAYS`, and that an absent address is
distinguishable from `0.0.0.0`.

## One deliberate behaviour change

`CClientList::AddBannedClient` / `IsBannedClient` / `RemoveBannedClient` used to
accept the literal `0`, ban the key `0.0.0.0` and increment the banned-client
statistic, so any client with an unknown address read back as banned. They now
ignore an absent address and log it. Mandated by task 4.4 and by the spec's
requirement that paths formerly testing against zero test absence explicitly. No
test covered the old behaviour.

## Carried forward — read this before touching address code

**The byte-identical comparison was produced after this change was archived.**
Two measurements, both against a fixed `nodes.dat` fixture of 161 contacts:

*Serialisation, network disabled.* Records for the contacts present in both the
baseline and the post-change output were compared byte for byte: 150 in common,
**0 records differing** in address, ports or version. Record size is 34 bytes in
both builds.

*The wire, network enabled.* 21 distinct UDP destinations were captured with
tcpdump and cross-checked against the fixture read in both byte orders: **19 of 21
match the normal reading, 0 match the reversed reading.** Had any conversion in
this change inverted byte order, that result would be exactly inverted.

**A trap for anyone repeating this.** The count of contacts read from an identical
`nodes.dat` is NOT a valid basis for comparing two builds. It varies run to run
within one build — the baseline alone produced 141, 141 and 161 across three runs.
aMule generates a random Kad ID at startup and the routing tree buckets contacts by
XOR distance from it, so per-bin capacity drops different contacts each time. A
single-sample comparison of those counts reads as an 11-contact regression that
does not exist. Compare records keyed by client ID instead.

**`AddressCharacterisationTest` is not, by itself, a safety net.** It builds its
range table and queries it through the same conversion, so a symmetric byte-order
error cancels out and every assertion still passes. The literal pins in
`NetworkAddressTest` — `0xC0000201` host order against `0x010200C0` ed2k order for
192.0.2.1 — are what actually catch that class of defect. Deleting them as
redundant would leave the change with no defence while the suite stayed green.

**`IsIPv4Mapped()` is hand-rolled on purpose.** Boost removed
`address_v6::to_v4()` and `is_v4_mapped()` after 1.66. The octet test follows
RFC 4291 section 2.5.5.2 and was checked against it. Do not "simplify" it back to
the asio call.

**Storage waiting for a later change.** `src/updownclient.h` holds raw
`uint8_t m_modIPv6[16]` and `m_modServerIPv6[16]`, read and dropped with no
routing, left there by `amule-peer-capability-recognition`.
`amule-dual-stack-reachability` will likely want its own address type there rather
than building on those arrays.
