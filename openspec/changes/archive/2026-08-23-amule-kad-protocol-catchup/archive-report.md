# Archive Report: amule-kad-protocol-catchup

**Archived**: 2026-08-23
**Archive path**: `openspec/changes/archive/2026-08-23-amule-kad-protocol-catchup/`
**Mode**: openspec (filesystem)

## Verification of state.yaml against artifacts

`state.yaml` reported `apply: complete`, `verify: complete`, `archive: pending`,
plus a `verification:` block including a `corrected_post_merge` entry.
Cross-checked against the artifacts before archiving:

- `tasks.md` sections 1-4 are entirely checked (`[x]`); there is no unchecked
  or partially-implemented task in this change.
- `proposal.md`'s "Post-merge correction: identity-rotation escalation"
  section matches `state.yaml`'s `corrected_post_merge` entry: a refused
  rapid identity rotation now escalates to the problematic list via the same
  `Escalate()` helper `TrackNode()` uses, closing a gap where an attacker
  could retry indefinitely at no cost. Both artifacts describe the same fix
  and the same test coverage (`unittests/tests/SafeKadTest.cpp`).
- The delta spec's four requirements (protocol version advertisement,
  adaptive response-time ceiling, identity-change rate limiting, bounded
  protection state) are each covered by a task section and a paired unit
  test, per `config.yaml`'s `tasks:` rule.
- `verification.outstanding` lists two open items — the 0x08 -> 0x0a wire
  step not yet captured with tcpdump, and no unit test for the on-disk
  keyword-index v4 format — both scoped as future work, not gaps in this
  change's own claims.

Conclusion: no contradiction between `state.yaml` and the artifacts. The
change is verified and archivable.

## Spec promotion

The delta spec (`specs/kademlia/spec.md`) contains a single
`## ADDED Requirements` section — confirmed by grep before promotion — no
`MODIFIED`/`REMOVED`/`RENAMED` sections, so no destructive delta was present
and no warning-and-confirm step was needed.

Promoted via mechanical `cp` (never Read→Write) to
`openspec/specs/kademlia/spec.md`, containing four requirements: protocol
version advertisement, adaptive response-time ceiling, identity-change rate
limiting, bounded protection state.

The promoted copy had its delta framing stripped: title changed from
`# Delta for kademlia` to `# kademlia`, and the heading from
`## ADDED Requirements` to `## Requirements`. No requirement or scenario text
was changed. The archived copy under
`changes/archive/2026-08-23-amule-kad-protocol-catchup/specs/` retains its
original delta framing unchanged, as the historical record of the delta as
authored.

Readback (`diff` between the promoted spec and the archived delta spec):

```
1c1
< # kademlia
---
> # Delta for kademlia
3c3
< ## Requirements
---
> ## ADDED Requirements
```

Only the two framing lines differ, confirming the requirement/scenario bodies
are byte-identical between the promoted and archived copies.

## Cross-change consistency check

Checked this change's requirements against `amule-peer-capability-recognition`
(archived alongside it) and against `build-baseline` for contradiction or
duplication. Both changes touch `src/include/tags/FileTags.h` and
`src/kademlia/kademlia/Search.cpp`, but their delta specs address disjoint
capabilities (`kademlia` vs `peer-capability-negotiation`) and disjoint
requirement subject matter (Kad protocol version and node protection vs.
vendor capability tags and frame demux). No contradiction or duplication
found.

## Archive move

`openspec/changes/amule-kad-protocol-catchup/` copied to
`openspec/changes/archive/2026-08-23-amule-kad-protocol-catchup/` via
mechanical `cp -R`, verified byte-identical with `diff -r` (empty), then the
original directory was removed with `rm -rf` (plain filesystem operations —
`git mv`/`git add` were deliberately not used, per the instruction to leave
everything as unstaged working-tree changes).

One line was then edited in the archived copy's `state.yaml`: `archive:
pending` -> `archive: complete`, recording that this change is now archived.
This is the only difference between the original change folder's `state.yaml`
and the archived copy's `state.yaml`.

Post-move check: `openspec/changes/amule-kad-protocol-catchup/` no longer
exists. `openspec/changes/amule-address-widening/` and the other change
directories were not touched (confirmed via `git status --porcelain`
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
- **Cross-change conflict**: none found against
  `amule-peer-capability-recognition` or `build-baseline`
