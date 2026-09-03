# Tasks: shared-files source-availability bar (#1220)

Slice boundaries follow `design.md` "slice A/B boundary moves": A = `PartBarSpans.h`,
B = all of `PartBarLegend.h`. C, D, E as `proposal.md`.

**Appearance is unverified in this environment.** No display session. For the gradient
swatch, the dialog, the menu entry and `CBarShader` output, a task is done when the
*values handed to the renderer* are asserted — never when something "looks right".

## Review Workload Forecast

| Field | Value |
|---|---|
| Estimated changed lines | 750–1150 authored (+ generated `.po` churn, excluded) |
| Delivery strategy | auto-chain |
| Suggested split | A → B → C → D → E |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High
800-line budget risk: Medium

Decisions still open: (1) `crProgress{0,224,0}` → `kBoth{0,192,0}` — settled before
slice C, not before A/B; (2) chain strategy. Decision 5 already settled the
Downloads-list colour change, so that one is closed.

### Suggested Work Units

| Unit | Goal | PR | Focused test command | Runtime harness | Rollback boundary |
|---|---|---|---|---|---|
| A | `PartBarSpans.h` + suite | 1 | `ctest --test-dir build -R PartBarSpansTest --output-on-failure` | N/A — wx-free, no renderer touched | new header + new suite; nothing adopts it |
| B | `PartBarLegend.h` palette/fade/typed key | 2 | `ctest --test-dir build -R PartBarLegendTest --output-on-failure` | N/A — header-only | one header + one test file |
| C | GUI adoption, legend menu | 3 | `packaging/linux/build.sh dev` | N/A — no display session | `SharedFilesCtrl`, `PartBarLegendUI` |
| D | Downloads list + Web UI convergence | 4 | `ctest --test-dir build -R PartBarLegendTest` | N/A — no display session | `DownloadListCtrl.cpp`, `components.js` |
| E | Rename + i18n regeneration | 5 | `./scripts/check-potfiles.sh` | N/A — string + generated catalogues | one label line + regenerated `.po` |

## Phase 0: Hard gate (before any source edit)

- [ ] 0.1 Confirm `openspec/BASELINE.md` names HEAD. It names `36e28e73`; HEAD is
      `a8da5183`. Re-establish with `packaging/linux/build.sh dev` on the
      **unmodified** tree and update `BASELINE.md`.
- [ ] 0.2 If the unmodified tree does not build: report the environment failure and
      STOP. Do not modify source to make the build pass (`config.yaml` apply
      precondition).
- [ ] 0.3 Cut the code branch from `upstream/master`, not the fork's `master`, so no
      `openspec/` tree enters an upstream PR (`context.md`). SDD artifacts stay on
      the fork's `master`.

## Phase 1: Slice A — `src/PartBarSpans.h` (geometry + mode)

- [ ] 1.1 Add `PartBarSpansTest` to `unittests/tests/CMakeLists.txt`, mirroring
      `PartBarLegendTest` at `:1976-1993` (exec, `add_test`, `src` include,
      `muleunit`+`mulecommon`).
- [ ] 1.2 **RED (decision 4's proof).** Create `src/PartBarSpans.h` with `SpansFor`
      transcribing today's **exclusive** end from `src/SharedFilesCtrl.cpp:666-667`.
      Create `unittests/tests/PartBarSpansTest.cpp` asserting
      `spans[i].end == spans[i+1].start - 1`, `spans.back().end == fileSize - 1`, and
      exactly `partCount` spans. Run the suite — it MUST fail. Capture the output.
- [ ] 1.3 **GREEN.** Change to `end = min(start + PARTSIZE, fileSize) - 1`
      (`src/BarShader.cpp:121-124`, `src/GenericClientListCtrl.cpp:1015-1016`). Re-run
      → green. Nothing adopts the header yet, so no pixel moves in this slice.
- [ ] 1.4 **RED → GREEN** `ModeFor(hashingProgress, partCount)`: `partCount == 0` →
      `None` for every progress including `> 0`; `(4, 9)` → `Hashing` with the hashed
      count clamped to `4`.
- [ ] 1.5 Implement per design's open question: `constexpr` index→span accessor plus a
      thin non-`constexpr` filler. No raw index loops — `modernize-loop-convert` has
      already failed this project's Tier-2 gate once.
- [ ] 1.6 Fix `unittests/tests/CMakeLists.txt:1971-1975`. It describes "the `?` beside
      the bar column headers" and "where the `?` is clickable"; #1218 shipped a row
      context-menu entry and header clicks only sort.

## Phase 2: Slice B — `src/PartBarLegend.h`

- [ ] 2.1 **RED** in `PartBarLegendTest.cpp`: fade as independent literals, never
      recomputed — `n=1`→`(166,212,238)`, `n=5`→`(113,181,225)`, `n=9`→`(60,151,211)`,
      `n=10`/`n=11`/`n=1000`→`(47,143,208)`; monotone non-increase per channel;
      `colour(0) == (255,0,0)` and `!= colour(1)`.
- [ ] 2.2 **GREEN** `kAvailFull = 10`, `lo`/`hi`, `SourceAvailabilityColour(n)` as
      `floor((2*(lo*9 + d*k) + 9) / 18)`, `k = min(n-1, kAvailFull-1)`.
- [ ] 2.3 **RED → GREEN** availability palette + `AvailabilityPartColour`. Add distinct
      `kFlatHashPending` (same RGB as `kNextPending`), shared files adopt `kBoth`, and
      scope the uniqueness invariant **per legend** in the `:31` header comment.
- [ ] 2.4 **RED → GREEN** `enum class SharedFilesBarColumn` + the
      `LegendForColumn(SharedFilesBarColumn, BarMode)` overload beside `:150`. Assert
      legend rows, order and colours against `spec.md`'s table under both bar
      preferences.
- [ ] 2.5 Extend the per-legend uniqueness test (`PartBarLegendTest.cpp:152`) to the
      two new legends, shaded and flat.
- [ ] 2.6 Exhaustive id test: all 15 shared-files `#define` ids and all 16
      `GenericColumnEnum` values, pinning the `5`/`6`/`8` cross-space collision a
      deliberate `static_cast` would still reach.
- [ ] 2.7 Cross-surface pin: read `AVAIL_FULL = (\d+)` from
      `src/webapi/static/js/components.js:389` and `--piece-avail(-lo)?: #(hex)` from
      `src/webapi/static/css/app.css:29-30` via `SRCDIR`
      (`unittests/tests/CMakeLists.txt:562-564`); compare to `kAvailFull` and both
      endpoints. Two foreign files — not a restatement of either side's assumption.

## Phase 3: Slice C — GUI adoption (blocked on the `kBoth` confirmation)

- [ ] 3.1 Create `src/PartBarLegendUI.{h,cpp}`; move `MakeLegendSwatch`,
      `AddLegendRow`, `ShowPartBarLegend` out of the anonymous namespace at
      `src/GenericClientListCtrl.cpp:112-156`; `ShowBarLegend` forwards.
- [ ] 3.2 `MakeGradientLegendSwatch()` — endpoints from `SourceAvailabilityColour(1)`
      and `(kAvailFull)`, one `wxDC::GradientFillLinear` over 16x16. **Done = the two
      endpoint values are the asserted ones.** Whether wx drew a gradient is unverified
      here.
- [ ] 3.3 `src/SharedFilesCtrl.cpp:658-678` adopts `SourceAvailabilityColour` and
      `SpansFor`; `:643-657` adopts `kBoth` and `kFlatHashPending`. Pixels move here.
- [ ] 3.4 Row context-menu entry after `src/SharedFilesCtrl.cpp:260` + `EVT_MENU` row,
      guarded by `IsColumnHidden` (`FindBarLegendColumn` is not reusable). Menu
      appearance and the dialog opening are unverified here.

## Phase 4: Slice D — convergence

- [ ] 4.1 **RED → GREEN** both-call-sites test: `n` in `{0,1,2,5,9,10,11,1000}` against
      the same literal table. Enforcement is the arity of `SourceAvailabilityColour(n)`
      — no `lo`/`hi` parameters, so divergence requires a reviewable signature change.
      Stated plainly: no headless test can observe two renderers; the literals plus the
      arity are the guard.
- [ ] 4.2 `src/DownloadListCtrl.cpp:1000-1001` → `SourceAvailabilityColour`; the
      misnamed `blue` local disappears with the duplicate. Spans stay gap-bounded
      (`:997-1010`) — `SpansFor` is **not** adopted here.
- [ ] 4.3 Correct the comment at `src/webapi/static/js/components.js:384-388` (wrong
      channel, wrong saturation).

## Phase 5: Slice E — rename and i18n

- [ ] 5.1 `src/SharedFilesCtrl.cpp:157` `_("Obtained Parts")` → `_("Source
      Availability")`.
- [ ] 5.2 Assert the persistence letter string at `src/SharedFilesCtrl.cpp:182` is
      byte-unchanged (`git diff` shows no hunk on that line). `p` and `P` are distinct
      entries; a saved layout runtime load is not verifiable headlessly, so the
      unchanged-byte assertion is the completion criterion.
- [ ] 5.3 Run `./scripts/update-po.sh` (`po/amule.pot` + 40 catalogues).
- [ ] 5.4 Verify idempotency: re-run and confirm zero `msgid`/`msgstr` lines change and
      only `POT-Creation-Date` moves; revert that churn before committing.
- [ ] 5.5 `./scripts/check-potfiles.sh` MUST exit 0.

## Phase 6: Gates

- [ ] 6.1 clang-format 18 on every changed file (`podman run --rm -i -v "$PWD:/w" -w /w
      ghcr.io/jidicula/clang-format:18 --dry-run --Werror <file>` — `-i` is required or
      zero files are checked).
- [ ] 6.2 clang-tidy Tier-2 on changed lines. Exposed new code: `SpansFor`'s filler
      (1.5), `PartBarLegendUI.cpp` row loops (3.1), the cross-surface pin's `<fstream>`
      parse (2.7).
- [ ] 6.3 `packaging/linux/build.sh dev` — monolithic + daemon + remotegui. `ctest`
      fully green; `known_failing_tests: []`, so any red is attributable here. Identify
      failures by NAME, never by index.
