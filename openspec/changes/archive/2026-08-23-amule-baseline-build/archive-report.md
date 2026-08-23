# Archive Report: amule-baseline-build

**Archived**: 2026-08-23
**Archive path**: `openspec/changes/archive/2026-08-23-amule-baseline-build/`
**Mode**: openspec (filesystem)

## Verification of state.yaml against artifacts

`state.yaml` reported `apply: complete`, `verify: complete`, `archive: pending`.
Cross-checked against the artifacts before archiving:

- `openspec/BASELINE.md` records a PASS compile (491/491 targets, three apps:
  `amule`, `amuled`, `amulegui`) and 36/37 tests passing, with `FileDataIOTest`
  (SEGFAULT) recorded as a pre-existing failure — consistent with
  `state.yaml`'s `baseline:` block (`compile: pass`, `tests: 36/37`,
  `known_failing: [FileDataIOTest]`).
- `tasks.md` Outcome section confirms the same commit and test result.
- `packaging/linux/build.sh` carries a working-tree diff of +85 lines (the
  `dev` target), and `packaging/linux/dev/Dockerfile` exists — consistent with
  the proposal's stated deliverable.
- `config.yaml`'s `apply`/`verify` blocks already carry the corrected
  container commands (no `UNVERIFIED` marker), matching tasks 4.1–4.3.

Conclusion: the change is verified and archivable. No contradiction between
`state.yaml` and the artifacts was found on the core claims (compile/test
result, commit, deliverables).

## Findings (non-blocking)

1. **No dedicated `verify-report.md` artifact exists** in the change folder.
   The openspec convention (`sdd-verify` → `verify-report.md`) was not
   followed literally; instead, the verification evidence lives directly in
   `openspec/BASELINE.md` (commit, toolchain, compile/test results, digest)
   and in the `tasks.md` Outcome section. For this specific change, that
   substitution is reasonable — `BASELINE.md` *is* the deliverable being
   verified — but it is a deviation from the stated file convention and is
   recorded here for traceability.

2. **Image digest discrepancy between artifacts.** `openspec/BASELINE.md`
   (line 16) and `state.yaml` (`baseline.image_digest`) both record
   `sha256:8b5f950ec30d93d83a444d22e52b7c5ea1d1632b97972327479fba46c81ca7b0`.
   `tasks.md`'s Outcome section instead cites
   `sha256:28acd8529250bcbc72a9d332524d855964461813879e5b2cde2ae5c9df8f5362`.
   `BASELINE.md` itself explains an earlier attempt omitted `BUILD_DAEMON` and
   was re-run, which is consistent with two digests existing across the
   change's history. `BASELINE.md` and `state.yaml` — the two higher-ranked,
   mutually consistent records — are treated as authoritative here; the
   `tasks.md` digest is stale and not corrected in place, per the mechanical,
   append-only nature of this archive pass.

3. **Tasks 5.1 and 5.2 in `tasks.md` remain unchecked** (`- [ ]`):
   "sync the dev image's dependency list with `appimage/Dockerfile` if it
   changes upstream" and "consider offering the `dev` target upstream."
   `tasks.md` explicitly documents, directly beneath the checklist, that these
   are intentionally left open as ongoing maintenance/upstream-contribution
   suggestions and are "not part of establishing this baseline." They are not
   implementation tasks required to close this change's deliverable (a
   recorded, reproducible baseline), and the change's own Outcome section
   confirms that deliverable was completed. Archived as-is, with this
   exception recorded here rather than silently checking the boxes or
   silently ignoring them.

4. **Stale cross-reference confirmed, not corrected.** `openspec/config.yaml`
   and `openspec/changes/README.md` both cite `CLAUDE.md:21` for the
   "build all three apps" rule. No `CLAUDE.md` exists in this tree; the actual
   rule is in `AGENTS.md` (the "Always build monolithic + daemon + remotegui
   before declaring a change done" line, near line 21). Per the launch
   instructions, this stale reference was not "fixed" by creating a
   `CLAUDE.md` — it is only recorded as a finding. It lives in files outside
   this change's own artifacts (`config.yaml`, `README.md`), so correcting it
   is out of scope for this archive pass.

## Spec promotion

`openspec/specs/` was empty before this archive — first change ever archived
in this set. The delta spec contained only an `## ADDED Requirements` section
(no `MODIFIED`/`REMOVED`/`RENAMED`), confirmed by grep before promotion — no
destructive delta was present, so no warning-and-confirm step was needed.

Promoted via mechanical `cp`/`mv` (never Read→Write) to:

- `openspec/specs/build-baseline/spec.md` — six requirements: baseline
  precedes modification, baseline requires no host toolchain, recorded
  baseline contents, baseline validity is commit-scoped, failure attribution
  on every change.

Readback (`diff -r` between change-folder delta and promoted main spec):

```
(empty — no differences)
```

## Archive move

`openspec/changes/amule-baseline-build/` → `openspec/changes/archive/2026-08-23-amule-baseline-build/`,
via `git mv` (note: `openspec/` is untracked in git, so git silently fell back
to a plain filesystem `mv`; confirmed via `git status --porcelain openspec`
showing only `?? openspec/` before and after, i.e. still fully untracked).

Readback (`diff -r` between a pre-move snapshot and the archived tree):

```
(empty — no differences)
```

Post-move check: `openspec/changes/amule-baseline-build/` no longer exists.
Other change directories (`amule-peer-capability-recognition`,
`amule-kad-protocol-catchup`, `amule-address-widening`,
`amule-dual-stack-reachability`, `amule-utp-transport`,
`amule-nat-rendezvous`, `amule-quic-transport`) and
`openspec/changes/README.md` were not touched.

## Hard constraints honored

- `openspec/BASELINE.md` was not modified — still at its original path,
  still naming commit `36e28e73836f95e0391fdf26f349cfd9d57b7edf`.
- No other change directory under `openspec/changes/` was modified.
- No source code, `CMakeLists.txt`, or files under `src/`, `unittests/`, or
  `packaging/` were modified.
- No `git add`, `git commit`, or `git push` was run. All changes remain in the
  working tree (`openspec/` is untracked; `git status --porcelain openspec`
  shows only `?? openspec/`).
- No build was run.

## Task Completion Gate

Implementation tasks in `tasks.md` (sections 1–4) are all checked. Section 5
(2 tasks) is explicitly documented in the artifact itself as intentional
future maintenance, not implementation scope for this change — see Finding 3.
Archived without stale-checkbox reconciliation (nothing was checked off by
this archive pass); the exception is recorded transparently instead.

## Native Review Receipt Gate

No `reviewGate` was present in any status surfaced to this agent; receipt-driven
development is not in play for this repository/candidate. Archive proceeds
under ordinary repository policy.

## Result

- **Status**: archived, complete
- **Destructive delta**: none found (pure `ADDED Requirements`)
- **State.yaml vs artifacts**: no contradiction on core claims; four
  non-blocking findings recorded above
