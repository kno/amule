# Proposal — shared-files part availability bar (amule-org/amule#1220)

Inputs, treated as settled and not re-derived here: `context.md`,
`exploration.md`, `decisions.md`.

**Parity position** (`openspec/config.yaml` `rules.proposal`): this change closes
no eMuleAI parity gap. `state.yaml` records `order: null`; it is a standalone
response to upstream issue #1220. `depends_on: []` — no other change in this set
is a prerequisite, and none blocks on it.

## Intent

The shared-files bar column is unreadable and undocumented:

- **The label names neither thing the column draws.** `_("Obtained Parts")`
  (`src/SharedFilesCtrl.cpp:157`) is the header of a cell that draws either a
  hashing bar (`:643-657`) or a per-part source-count fade (`:658-678`).
  "Obtained" describes the download case, which this list never shows.
- **The palette is a third inline copy.** The fade lives at
  `src/SharedFilesCtrl.cpp:671`, `src/DownloadListCtrl.cpp:1000-1001` and
  `src/webapi/static/js/components.js:388`, and the three do not agree
  (`exploration.md` §3: no endpoint matches; saturation 11 vs 10).
- **It has no legend.** The two client-list bar columns got one in #1218; this
  one was left out, and `PartBarLegend.h` structurally cannot express it
  (`exploration.md` §2).

Success: the column says what it encodes, one definition of the fade serves all
three surfaces, and a user can open a legend that is provably the same palette
the renderer uses.

## Scope

### In scope

1. **Rename to `Source Availability`** (decision 1). New msgid; 40 catalogues
   gain an untranslated entry. The persistence letter `P`
   (`src/SharedFilesCtrl.cpp:182`) MUST NOT change.
2. **One column, legend selected per mode** (decision 2), following
   `views/shared-detail.js:124-132`.
3. **Extend the legend key space and selector.** `LegendForColumn`
   (`src/PartBarLegend.h:150`) takes `GenericColumnEnum`, while
   `COLUMN_SHARED_PART` is a plain `#define` = 8 (`src/SharedFilesCtrl.h:40`) in
   a different, overlapping space — a wrong-key call **compiles silently**.
   Replace it with a typed key plus a row-mode argument so the wrong key is a
   compile error and decision 2 is expressible.
4. **Resolve the two palette collisions** (below) before merging palettes.
5. **Single-source the fade and unify endpoints** with the Web UI winning
   (decision 3), saturation converged to one constant.
6. **Fix the span off-by-one** (decision 4) with a test that fails against
   today's code.
7. **Add the legend affordance**: one row context-menu entry after
   `src/SharedFilesCtrl.cpp:260`, one `EVT_MENU` row, reusing
   `ShowInfoGridDialog` (`src/InfoGridDialog.h:48-53`) with a gradient swatch.
   Guard with `IsColumnHidden` — `FindBarLegendColumn` is not reusable here.
8. **Fix our own stale comment**: `unittests/tests/CMakeLists.txt:1971-1975`
   describes "the two legends the `?` beside the bar column headers opens" and
   "where the `?` is clickable". That affordance does not exist — #1218 shipped
   a row context-menu entry and header clicks only sort. Verified in the tree.

### Out of scope

- **The #1221/#1246 context-menu sharing hazard.** `OnItemRightClicked`
  (`src/SharedFilesCtrl.cpp:187-333`) builds its menu inline; there is no
  `BuildSharedFileContextMenu`, so no builder is shared and the hazard does not
  apply (`exploration.md` §4).
- **The dead red tail at `src/SharedFilesCtrl.cpp:677`.** `FillRange` discards
  it by invariant (`src/BarShader.cpp:113-119`, availability vector kept exactly
  `GetPartCount()` long on every path). Unreachable, not a state. Removing it is
  a separate judgement and is NOT to be "fixed" here.
- Dark-theme values for the GUI (it has none), and any change to the client-list
  `Availability` column, which means a different quantity.
- Weblate translation of the new msgid.

## The palette collisions, as scope items

`PartBarLegend.h:31` states the header's invariant: exactly one copy of each
colour. Merging the shared-files locals in violates it two ways.

| Collision | Evidence | Resolution proposed | Cost |
|---|---|---|---|
| `crFlatPending{255,255,100}` ("not yet hashed, flat") is byte-identical to `kNextPending{255,255,100}` ("next part that will be asked") | `src/SharedFilesCtrl.cpp:643-657`, `src/PartBarLegend.h:87` | Add a distinct semantic constant with the same RGB, and scope the one-copy invariant **per legend** rather than globally. The two colours never appear in the same legend. | Header comment + test scoping only. **Zero pixel change.** `NoTwoRowsOfALegendShareAColour` stays true because it is already a per-legend assertion. |
| `crProgress{0,224,0}` vs `kBoth{0,192,0}` — both mean "we have this part, shaded"; the difference has no recorded reason | `src/SharedFilesCtrl.cpp:643-657`, `src/PartBarLegend.h:75` | Shared files adopt `kBoth`. | The hashing bar goes slightly darker green. Cheaper side to move: hashing is transient and rare (`src/ThreadTasks.cpp:179`, `:693`). Moving `kBoth` instead would change every client list for every user. |

Keeping two greens under two constants is rejected: it preserves the drift that
single-sourcing exists to end.

## The third copy of the fade — decision

`src/DownloadListCtrl.cpp:1000-1001`: the local is named `blue` but passed as the
**green** argument of `Set(r,g,b)` (`src/MuleColour.h:76-80`). Verified in the
tree.

**In scope for single-sourcing.** It computes the same quantity — sources per
part — and a per-call-site endpoint parameter would re-create in code exactly
the divergence decision 3 removes. Consequence, flagged for the user: the
Downloads list's per-part source shading changes colour too, which is wider than
#1220's text. The misnaming is fixed by the extraction itself, since the local
disappears.

## Capabilities

### New capabilities

- `shared-file-availability-bar`: what the shared-files bar column encodes in
  each mode, its colour mapping and span geometry, its label, and the legend
  that explains it. No existing spec covers the part-bar legend (#1218 shipped
  without one), so changes to `PartBarLegend.h` are captured here.

### Modified capabilities

None.

## Approach

Extract to a wx-free, header-only module (the `webapi/PartIndex.h` /
`PartBarLegend.h` pattern already established here), then have the renderer and
the legend both read it:

1. `SourceAvailabilityColour(count)` — pure `count -> BarColour`, unified
   endpoints, one saturation constant shared with `AVAIL_FULL`.
2. `SpansFor(partCount, fileSize)` — pure geometry, inclusive `end`, matching
   `src/GenericClientListCtrl.cpp:1015-1016` and `src/DownloadListCtrl.cpp:1009`.
3. `ModeFor(hashingProgress, partCount)` — predicate over integers, not
   `CKnownFile*`, so mode precedence is assertable.
4. Typed legend key + row mode, replacing `LegendForColumn`.
5. GUI and Web UI both adopt; `components.js:388`'s comment (wrong channel,
   wrong saturation) is corrected.

Note the fade has **no flat variant** (`bFlat` is unused at
`src/SharedFilesCtrl.cpp:658-678`), so the availability legend shows one row set
under both bar preferences.

## Affected areas

| Area | Impact | Description |
|---|---|---|
| `src/PartBarLegend.h` | Modified | typed key, row-mode selector, availability palette, collision resolution |
| new wx-free header | New | fade, spans, mode predicate |
| `src/SharedFilesCtrl.cpp` / `.h` | Modified | label, adopt extraction, legend menu entry |
| `src/DownloadListCtrl.cpp` | Modified | adopt single-sourced fade |
| `src/webapi/static/js/components.js` | Modified | endpoints, saturation constant, comment |
| `po/amule.pot` + 40 catalogues | Modified | new msgid (generated) |
| `unittests/tests/` | New + Modified | new suite; stale `?` comment at `CMakeLists.txt:1971-1975` |

## Delivery

`delivery_strategy: auto-chain`, `review_budget_lines: 800`.

- **Decision needed before apply: Yes** — the Downloads-list colour change above.
- **Chained PRs recommended: Yes**
- **800-line budget risk: Medium** (High if the `.po` churn is counted as
  authored)

| Slice | Content | Forecast (authored) |
|---|---|---|
| A | Pure header + failing-then-passing tests (spans, fade, mode, saturation literal); new suite in `unittests/tests/CMakeLists.txt` + the stale `?` comment fix. No renderer touched, so no pixels move. | 300–400 |
| B | `PartBarLegend.h`: typed key, mode-aware selector, availability palette, both collisions resolved. Tests extended. | 150–250 |
| C | GUI adoption: `SharedFilesCtrl` uses the header, legend rows, context-menu entry, gradient swatch. Pixels move here. | 200–300 |
| D | Convergence: GUI adopts Web UI endpoints, `AVAIL_FULL` single-sourced, `DownloadListCtrl` adopts, `components.js` comment. | 80–150 |
| E | Rename to `Source Availability` + `./scripts/update-po.sh` (40 catalogues) + `./scripts/check-potfiles.sh`. | ~15 authored; `.po` churn large but generated |

Ordering rationale: A is pure logic and independently reviewable; B changes no
renderer; C is the first slice that changes what a user sees; D is the
cross-surface convergence, isolated so a colour regression bisects to one PR; E
is isolated so the authored msgid change is reviewable apart from the
regeneration churn. Slice E's `.po` output is generated by a checked-in script —
excluded from authored risk count, included in snapshot identity.

## Verification

`context.md`: strict TDD; build/test via `packaging/linux/build.sh dev`;
`openspec/BASELINE.md` names `36e28e73` while HEAD has moved — **re-establishing
the baseline is a hard gate before any source edit**.

The `exploration.md` §6 distinction is binding: an assertion that restates the
code's own assumption goes green whether or not the feature exists. That is what
#1218 shipped. **No assertion of that kind is proposed.**

### Assertable headless, each against an independent literal

1. Fade as `count -> colour`: endpoints and saturation spelled out as literals,
   never recomputed from the formula; green monotonically non-increasing.
2. Mode precedence and the hashing clamp, over `(hashingProgress, partCount)`.
3. Span geometry: `spans[i].end == spans[i+1].start - 1` and
   `spans.back().end == fileSize - 1`. **This property fails against today's
   code** — it is decision 4's proof.
4. Palette: the collision resolutions above, plus per-legend colour uniqueness
   under both bar preferences.
5. Legend row content, order, and which legend each column and mode gets.
6. GUI/Web UI saturation agreement as two hand-maintained literals — no harness
   reads a JS constant from C++.

### Not verifiable in this environment — must not be claimed

No display session. The gradient swatch (needs `wxMemoryDC`, and whether it
*looks* like the bar is a human judgement), `ShowInfoGridDialog` opening and
layout, the context-menu entry appearing and being guarded, `CBarShader` output,
and anything reading `thePrefs::UseFlatBar()` in situ. Every colour change in
slices C and D is in this set: correctness of the *values* is testable, the
*appearance* is not.

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Persistence letter `P` changed with the label; saved layouts discarded | Low | Explicit spec requirement; `p`/`P` are distinct entries in the string at `src/SharedFilesCtrl.cpp:182` |
| Merging palettes breaks `NoTwoRowsOfALegendShareAColour` | Med | Resolve both collisions in slice B before any merge; scope uniqueness per legend |
| Endpoint unification lands a colour users dislike, unverifiable here | High | Decision 3 accepted it; isolate in slice D so it reverts alone |
| Downloads-list colour change exceeds #1220's remit | Med | Flagged above as an open question before apply |
| Span fix changes drawing for every shared file with no visual check | Med | Property test + isolated slice A/C boundary |
| 40 untranslated catalogue entries visible until Weblate catches up | High | Accepted in decision 1; isolated slice E |
| `modernize-loop-convert` Tier-2 clang-tidy gate has already failed once here | Med | Avoid raw index loops in the new header |
| Stale baseline blocks apply | High | Re-run `packaging/linux/build.sh dev` first; do not modify source to make a build pass |

## Rollback

Each slice is one revert. Slice E additionally needs `./scripts/update-po.sh`
re-run after the revert (regeneration is content-idempotent apart from
`POT-Creation-Date`, which CI strips). Reverting C or D restores the previous
colours with no data migration: nothing persists but the column letter `P`,
which never moves.

## Dependencies

None. No new third-party dependency; the new header pulls in nothing beyond
`<cstdint>`/`<cstddef>`, matching `PartBarLegend.h:45-48`.

## Success criteria

- [ ] Column header reads `Source Availability`; persistence letter `P` unchanged.
- [ ] Legend opens from the shared-files row context menu and is selected per mode.
- [ ] Exactly one definition of the fade, read by GUI, Downloads list and Web UI;
      one saturation constant.
- [ ] Both palette collisions resolved; per-legend colour uniqueness asserted.
- [ ] A wrong-key call to the legend selector no longer compiles.
- [ ] Span property test passes; the same test fails on the parent commit.
- [ ] `./scripts/check-potfiles.sh` exits 0; `ctest` fully green
      (`known_failing_tests: []`).
- [ ] `unittests/tests/CMakeLists.txt` no longer describes a clickable `?`.

## Proposal question round

The interactive round was already held; its four answers are `decisions.md` and
are not reopened. Two items were decided by this phase and need user
confirmation before apply, not before spec:

1. **The Downloads list changes colour too.** Single-sourcing the fade
   (`src/DownloadListCtrl.cpp:1000-1001`) means it adopts the unified endpoints.
   Accept, or keep that list on its current numbers at the cost of a per-call-site
   endpoint parameter that re-creates the drift?
2. **`crProgress` → `kBoth`**, so the hashing bar goes from `0,224,0` to
   `0,192,0` rather than moving `kBoth` and changing every client list. Accept?

Neither blocks `sdd-spec` or `sdd-design`; both must be settled before slice C.
