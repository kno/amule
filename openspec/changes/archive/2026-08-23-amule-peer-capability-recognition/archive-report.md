# Archive Report: amule-peer-capability-recognition

**Archived**: 2026-08-23
**Archive path**: `openspec/changes/archive/2026-08-23-amule-peer-capability-recognition/`
**Mode**: openspec (filesystem)

## Verification of state.yaml against artifacts

`state.yaml` reported `apply: complete`, `verify: complete`, `archive: pending`,
plus a `verification:` block. Cross-checked against the artifacts before
archiving:

- `tasks.md` sections 1-4 are entirely checked (`[x]`); there is no unchecked
  or partially-implemented task in this change.
- `proposal.md`'s scope ("tag parse/emit, misc-options bitfield parse/emit,
  frame-type demux with unknown-type drop, capability display in client
  details") matches the four task sections and the `confirmed:` list in
  `state.yaml`'s `verification:` block one-for-one.
- The delta spec's three requirements (vendor capability tag round-trip,
  misc-options bit order, reserved-protocol frame demultiplexing) are each
  covered by a task and a paired unit test per `config.yaml`'s
  `tasks:` rule ("every wire-format task carries a paired unittests/ task").
- `verification.outstanding` lists exactly one open item — a runtime
  frame-demux test against a second container sending crafted datagrams —
  which is explicitly scoped as future work, not a gap in this change's own
  claims.

Conclusion: no contradiction between `state.yaml` and the artifacts. The
change is verified and archivable.

## Spec promotion

`openspec/specs/` held only `build-baseline/` before this archive. The delta
spec (`specs/peer-capability-negotiation/spec.md`) contains a single
`## ADDED Requirements` section — confirmed by grep before promotion — no
`MODIFIED`/`REMOVED`/`RENAMED` sections, so no destructive delta was present
and no warning-and-confirm step was needed.

Promoted via mechanical `cp` (never Read→Write) to
`openspec/specs/peer-capability-negotiation/spec.md`, containing three
requirements: vendor capability tag round-trip, misc-options bit order,
reserved-protocol frame demultiplexing.

The promoted copy had its delta framing stripped: title changed from
`# Delta for peer-capability-negotiation` to `# peer-capability-negotiation`,
and the heading from `## ADDED Requirements` to `## Requirements`. No
requirement or scenario text was changed. The archived copy under
`changes/archive/2026-08-23-amule-peer-capability-recognition/specs/` retains
its original delta framing unchanged, as the historical record of the delta
as authored.

Readback (`diff` between the promoted spec and the archived delta spec):

```
1c1
< # peer-capability-negotiation
---
> # Delta for peer-capability-negotiation
3c3
< ## Requirements
---
> ## ADDED Requirements
```

Only the two framing lines differ, confirming the requirement/scenario bodies
are byte-identical between the promoted and archived copies.

## Cross-change consistency check

Checked this change's requirements against `amule-kad-protocol-catchup`
(archived alongside it) and against `build-baseline` for contradiction or
duplication. Both changes touch `src/include/tags/FileTags.h` and
`src/kademlia/kademlia/Search.cpp`, but their delta specs address disjoint
capabilities (`peer-capability-negotiation` vs `kademlia`) and disjoint
requirement subject matter (vendor capability tags and frame demux vs.
Kad protocol version and node protection). No contradiction or duplication
found.

## Archive move

`openspec/changes/amule-peer-capability-recognition/` copied to
`openspec/changes/archive/2026-08-23-amule-peer-capability-recognition/` via
mechanical `cp -R`, verified byte-identical with `diff -r` (empty), then the
original directory was removed with `rm -rf` (plain filesystem operations —
`git mv`/`git add` were deliberately not used, per the instruction to leave
everything as unstaged working-tree changes).

One line was then edited in the archived copy's `state.yaml`: `archive:
pending` -> `archive: complete`, recording that this change is now archived.
This is the only difference between the original change folder's `state.yaml`
and the archived copy's `state.yaml`.

Post-move check: `openspec/changes/amule-peer-capability-recognition/` no
longer exists. `openspec/changes/amule-address-widening/` and the other
change directories were not touched (confirmed via `git status --porcelain`
showing no entries under `amule-address-widening/`).

## Hard constraints honored

- `openspec/BASELINE.md` and `openspec/config.yaml` were not modified
  (confirmed via `git diff --stat`, empty).
- `openspec/changes/amule-address-widening/` was not touched.
- No source code, `CMakeLists.txt`, `unittests/`, or `packaging/` files were
  modified.
- No `git add`, `git commit`, or `git push` was run. All changes remain in
  the working tree.
- No build was run.

## Result

- **Status**: archived, complete
- **Destructive delta**: none found (pure `ADDED Requirements`)
- **State.yaml vs artifacts**: no contradiction found
- **Cross-change conflict**: none found against `amule-kad-protocol-catchup`
  or `build-baseline`
