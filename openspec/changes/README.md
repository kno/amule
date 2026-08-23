# Change set: network parity with eMuleAI

**Read this before picking up any change in this directory.** Listing the
directory gives you alphabetical order, which is not execution order — it puts
`amule-address-widening` first, and that change should be third.

Execution order is declared in two machine-readable places, and they agree:

- `order:` in each `state.yaml` — `0` is the gate, `1..7` are the parity phases
- `depends_on:` / `blocks:` in each `state.yaml` — direct edges only, and exact
  inverses of each other

Where the two disagree, `depends_on` wins: it is the real constraint, `order` is
one valid resolution of it.

## Order

| # | Change | Hard dependencies | Cost |
| --- | --- | --- | --- |
| 0 | `amule-baseline-build` | none — **gate** | must pass first |
| 1 | `amule-peer-capability-recognition` | 0 | low |
| 2 | `amule-kad-protocol-catchup` | 0 | medium |
| 3 | `amule-address-widening` | 0 (see below) | the real cost |
| 4 | `amule-dual-stack-reachability` | 3, 1 | medium |
| 5 | `amule-utp-transport` | 3 | high |
| 6 | `amule-nat-rendezvous` | 1, 5 | high |
| 7 | `amule-quic-transport` | 6 | highest, optional |

```
                  ┌─► 1 peer-capability ─┬──────────► 6 nat-rendezvous ─► 7 quic
0 BASELINE ───────┤                      │                    ▲
   (gate)         ├─► 3 address-widening ┼─► 4 dual-stack     │
                  │                      └─► 5 utp ───────────┘
                  └─► 2 kad-catchup   (no further edges)
```

Nothing starts until 0 passes. That is the whole point of it being a node in the
graph rather than a line of advice: an agent following `depends_on` cannot skip it.

## Change 0 is not optional

`amule-baseline-build` proves the **unmodified** tree builds and tests on this
machine, and records the result in `openspec/BASELINE.md`.

Skip it and the first red build is unattributable: wrong change, broken
environment, or drift since the last success all look identical. Worse, an agent
that cannot tell them apart starts "fixing" code that was never broken.

Two specific traps it defuses:

- The `build_command` in `config.yaml` was derived by reading `CMakeLists.txt` and
  **has never been executed**. It is marked UNVERIFIED there. Change 0 confirms or
  corrects it.
- Tests that are *already* failing upstream must be recorded as already failing.
  Otherwise the first change touching that area gets blamed.

If the baseline cannot be reached, the correct outcome is to report the
environment failure and stop — not to edit source until something goes green.

## Three things the graph does not tell you

**Changes 1, 2 and 3 depend only on the gate, so once 0 passes they are all startable.** 1 and 2 in particular can run in parallel. They are
numbered 1 and 2 only because something had to be. If two agents are available,
these are the two to hand out simultaneously.

**Change 3 declares no hard dependency but carries `sequence_after: [1, 2]`.**
That field is advisory, not a constraint: 3 is technically startable at any time.
The reason to hold it is review, not correctness — 3 is a wide mechanical diff
across Kad, the client list and the IP filter, and landing 1 or 2 on top of it
in flight makes both harder to review. `sequence_after` is not part of any
documented OpenSpec schema, so no tooling will enforce it. A human decided it;
a human can override it.

**Change 7 is `apply: blocked`.** Not by a dependency — by task gate 0.1, a
maintainer decision on adopting ngtcp2 plus a TLS stack. Do not start
implementation to "unblock" it. Everything change 6 delivers already works over
uTP; 7 is an upgrade, and the set reaches functional parity without it.

## Why the directories are not numbered

Numbering identities (`01-amule-...`) was considered and rejected. The change
name is the identity: `config.yaml`, the proposals and the archive path
(`changes/archive/YYYY-MM-DD-{change-name}/`) all reference it. A number baked
into the identity becomes wrong the first time the order changes, and fixing it
means renaming directories and chasing every cross-reference. Sequence is
metadata, so it lives in `state.yaml`.

## Building and testing any change here

The container is the supported route:

```sh
packaging/linux/build.sh dev
```

It configures monolithic + daemon + remotegui plus tests, builds, and runs
`ctest`, installing nothing on the host. Do not narrow the target set — a change
can compile in two of the three apps and break the third (`CLAUDE.md`).

The bare `cmake`/`ctest` commands in `CLAUDE.md`'s Build and Test sections assume
dependencies installed on the machine. They are fine if you have them; they fail
on a missing `cmake` or wxWidgets, which is the normal state on macOS.

## Scope reminder

Every change in this set targets **this** repository. The analysis of record they
are derived from — the capability matrix and the file/line evidence behind every
claim — is `docs/network-parity-amule.md` in the eMuleAI repository, not here.
