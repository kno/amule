# Design: shared-files source-availability bar (#1220)

Inputs settled, not re-derived: `context.md`, `exploration.md`, `decisions.md`,
`proposal.md`, `specs/shared-file-availability-bar/spec.md`.

## Technical Approach

Two wx-free compile units carry every decision, one wx unit carries the drawing.
`src/PartBarSpans.h` (new) owns geometry and mode; `src/PartBarLegend.h` gains the
availability palette, the fade, a typed key and a mode-aware selector;
`src/PartBarLegendUI.{h,cpp}` (new) lifts the legend widgets out of the anonymous
namespace at `src/GenericClientListCtrl.cpp:112-156` so both lists share them.
Everything unverifiable here collapses into one toolkit call.

## Architecture Decisions

### Decision: typed key by distinct scoped enum, added as an overload

**Choice** — `enum class SharedFilesBarColumn { SourceAvailability; }` in
`partbar`, plus `LegendForColumn(SharedFilesBarColumn, BarMode)` alongside the
existing `LegendForColumn(GenericColumnEnum)` (`src/PartBarLegend.h:150`). Two
distinct scoped enums have no conversion, so passing the other list's id is a
compile error. The numeric `#define`s (`src/SharedFilesCtrl.h:32-48`) never enter
the header.

**Cost to existing call sites: zero.** `src/GenericClientListCtrl.cpp:696`, `:749`
and `unittests/tests/PartBarLegendTest.cpp:173-182` compile unchanged.

**Rejected** — making `GenericColumnEnum` a scoped enum: 285 column-id sites in
one CMake file alone and every `TranslateCIDToName` switch would need qualifying,
for no gain over the overload.

**Residual, stated**: a deliberate `static_cast<GenericColumnEnum>(column)` still
compiles. It is covered by test, not by types: today ids 5, 6 and 8 collide across
the two spaces (`COLUMN_SHARED_AREQ`=5=`ColumnUserProgress`,
`COLUMN_SHARED_TRA`=6=`ColumnUserAvailable`, `COLUMN_SHARED_PART`=8=
`ColumnUserQueueRankLocal`), so a cast-through call returns a bar legend for two
text columns and none for the bar column. Exhaustive assertion over all
shared-files ids pins that.

### Decision: mode is an argument, so the selector stays `constexpr` and pure

**Choice** — `ModeFor(hashingProgress, partCount) -> BarMode` in
`src/PartBarSpans.h`, `constexpr` over two integers; the selector takes the
resulting `BarMode`. No row state, no `CKnownFile*`, no runtime lookup.

**Rejected** — a callback or registry giving the header access to row state; it
would drag the GUI into a header whose whole point is being reachable without one.

### Decision: the fade is integer arithmetic, with a tie-freeness proof

**Choice** — per channel, with `k = min(n-1, kAvailFull-1)`, `lo=(166,212,238)`,
`hi=(47,143,208)`, `d = hi-lo`, `kAvailFull = 10`:

```cpp
// round(lo + d*k/9) == floor((2*(lo*9 + d*k) + 9) / 18); numerator stays
// positive (its minimum is hi*9), so C++ truncating division is floor.
constexpr BarColour SourceAvailabilityColour(unsigned n);   // n >= 1
```

**Bit-identical to the spec table, and to JS, by construction**: `lo*9 + d*k`
over a denominator of 9 can never have fractional part 1/2, so no half-way case
exists and the rounding mode is irrelevant — `Math.round`
(`components.js:405-407`), `std::lround` and banker's rounding all agree. Checked:
`n=5` gives `(113,181,225)`; `n>=10` gives `(47,143,208)`.

**Rejected** — `constexpr` floating point plus `std::round` (not `constexpr` before
C++23, and would make agreement a convention rather than a proof).

`n = 0` is not on the fade: a discrete `kZeroSources{255,0,0}`.

**Arity is the enforcement for decision 5.** The function takes `n` and nothing
else — no `lo`/`hi` parameters — so neither `SharedFilesCtrl` nor
`DownloadListCtrl` can diverge without adding a parameter, which is a reviewable
signature change rather than a silent colour drift.

### Decision: gradient swatch is one `wxDC::GradientFillLinear` call

**Choice** — `MakeGradientLegendSwatch()` beside `MakeLegendSwatch`, both moved to
`src/PartBarLegendUI.cpp`. It reads its two endpoints from
`SourceAvailabilityColour(1)` and `SourceAvailabilityColour(kAvailFull)` — the same
calls the FewSources/ManySources legend rows and the renderer make — then issues
one gradient fill over a 16x16 `wxBitmap`. `ShowInfoGridDialog`
(`src/InfoGridDialog.h:48-53`) is untouched: a `wxStaticBitmap` is a
`wxStaticBitmap`.

**What is left unverifiable is exactly that one call** — whether wx drew a linear
gradient between two colours already asserted correct. No branch, no arithmetic,
no state.

### Decision: geometry convention is inclusive `end`; the shared-files list moves

`CBarShader::FillRange` treats `end` as inclusive (`src/BarShader.cpp:121-124`);
`src/GenericClientListCtrl.cpp:1015-1016` and `src/DownloadListCtrl.cpp:1009`
already subtract one. `SpansFor(partCount, fileSize)` yields
`start = PARTSIZE*i`, `end = min(start+PARTSIZE, fileSize) - 1`, so the last span
ends at `fileSize-1`. `src/SharedFilesCtrl.cpp:664-667` is the outlier and adopts
it; its property test fails on the parent commit.

**`DownloadListCtrl` does not adopt `SpansFor`** — its spans are gap-bounded
(`:997-1010`), not uniform per-part. Decision 5 unifies the colour only.

### Decision: `AVAIL_FULL` is a hand-maintained pin with a lexical guard

Nothing generates one side from the other and there is no JS build step (no
`package.json` under `src/webapi/static/`). Honest answer: hand-maintained. Made
to fail loudly by a test that reads the *other* surface's source text —
`AVAIL_FULL = (\d+)` from `src/webapi/static/js/components.js:389` and
`--piece-avail(-lo)?: #(hex)` from `src/webapi/static/css/app.css:29-30` — and
compares against `partbar::kAvailFull` and the two endpoint constants. Precedent
in tree: `SRCDIR=${CMAKE_CURRENT_SOURCE_DIR}`
(`unittests/tests/CMakeLists.txt:562-564`). It reads two different files, so it is
not a restatement of either one's assumption. Cost: `<fstream>` in the suite (no
wx — `TextFileTest` uses `CPath`, we will not) and brittleness to reformatting,
mitigated by whitespace-tolerant regex and a failure message naming both files.

### Decision: palette collisions

| Collision | Resolution | Pixel cost |
|---|---|---|
| `crFlatPending{255,255,100}` vs `kNextPending{255,255,100}` (`src/SharedFilesCtrl.cpp:645`, `src/PartBarLegend.h:87`) | distinct `kFlatHashPending` with the same RGB; uniqueness scoped **per legend**. `NoTwoRowsOfALegendShareAColour` (`PartBarLegendTest.cpp:152`) is already per-legend and stays true. | none |
| `crProgress{0,224,0}` vs `kBoth{0,192,0}` (`:646`, `PartBarLegend.h:75`) | shared files adopt `kBoth` | hashing bar darkens; transient and rare |

### Decision: slice A/B boundary moves

The proposal put the fade in slice A and the palette in slice B. They are one
unit — splitting them creates two colour homes for one commit, which is the drift
being removed. **Slice A = `PartBarSpans.h` (geometry + mode) and its tests.
Slice B = all of `PartBarLegend.h`: palette, fade, typed key, mode-aware
selector, both collisions.** Slices C, D, E unchanged.

## Data Flow

    (hashingProgress, partCount) ─ModeFor()─→ BarMode ─┬─→ LegendForColumn(key, mode)
                                                       └─→ GetItemBarFill branch
    availability[i] = n ──SourceAvailabilityColour(n)──┬─→ CMuleColour → CBarShader
                                                       ├─→ legend rows (1, kAvailFull)
                                                       └─→ gradient swatch endpoints
    (partCount, fileSize) ──SpansFor()──→ {start, end(inclusive)}[]

## File Changes

| File | Action | Description |
|---|---|---|
| `src/PartBarSpans.h` | Create | `SpansFor`, `BarMode`, `ModeFor`, hashed-part clamp. `<cstdint>`/`<cstddef>` only |
| `src/PartBarLegend.h` | Modify | availability palette, `kAvailFull`, `SourceAvailabilityColour`, `AvailabilityPartState`, typed key, selector overload, two legend orders, collisions |
| `src/PartBarLegendUI.h/.cpp` | Create | `MakeLegendSwatch`, `MakeGradientLegendSwatch`, `AddLegendRow`, `ShowPartBarLegend` |
| `src/GenericClientListCtrl.cpp` | Modify | helpers move out; `ShowBarLegend` forwards |
| `src/SharedFilesCtrl.cpp/.h` | Modify | label, adopt header, menu entry after `:260` + `EVT_MENU`, guard with `IsColumnHidden` |
| `src/DownloadListCtrl.cpp` | Modify | `:1000-1001` → `SourceAvailabilityColour`; misnamed `blue` disappears |
| `src/webapi/static/js/components.js` | Modify | comment at `:384-388` (wrong channel, wrong saturation) |
| `unittests/tests/PartBarSpansTest.cpp` | Create | geometry, mode, clamp |
| `unittests/tests/PartBarLegendTest.cpp` | Modify | fade literals, legend rows, id-space exhaustion, cross-surface pin |
| `unittests/tests/CMakeLists.txt` | Modify | new suite; stale `?` comment at `:1971-1975` |
| `po/amule.pot` + 40 catalogues | Modify | generated, slice E |

## Interfaces / Contracts

```cpp
namespace partbar {
enum class SharedFilesBarColumn { SourceAvailability };
enum class BarMode { None, SourceAvailability, Hashing };
enum class AvailabilityPartState { ZeroSources, FewSources, ManySources };
enum class HashingPartState { Hashed, NotYetHashed };

constexpr BarMode ModeFor(std::uint16_t hashingProgress, std::uint16_t partCount);
constexpr BarColour SourceAvailabilityColour(unsigned sources);          // sources >= 1
constexpr BarColour AvailabilityPartColour(AvailabilityPartState, bool flat);
constexpr BarLegendKind LegendForColumn(SharedFilesBarColumn, BarMode);  // new overload
}
```

## Testing Strategy

| Layer | What | Approach |
|---|---|---|
| Unit (wx-free) | fade endpoints, `n=5`, saturation at 10, monotone non-increase | independent literals, never recomputed |
| Unit | span adjacency, last byte, count | `spans[i].end == spans[i+1].start - 1`; **fails on parent commit** |
| Unit | mode precedence, `partCount=0`, clamp | integer pairs |
| Unit | typed key | all 15 shared-files ids and all 16 `GenericColumnEnum` values |
| Unit | per-legend uniqueness, both preferences | extend `PartBarLegendTest.cpp:152` |
| Unit | cross-surface pin | read `components.js` + `app.css` via `SRCDIR` |
| Compile | wrong-key rejection | asserted by review of the two enum types; a negative-compile harness does not exist in this tree |
| **Not verifiable here** | gradient bitmap, dialog, menu entry, `CBarShader` output, `UseFlatBar()` in situ, every appearance change in C and D | no display session — must not be claimed |

## Threat Matrix

N/A — no routing, shell, subprocess, VCS/PR automation, executable-file
classification, or process-integration boundary. The cross-surface pin test reads
two files under `SRCDIR` read-only, with no path from external input.

## Migration / Rollout

No migration. Persistence letter `P` (`src/SharedFilesCtrl.cpp:182`) never moves,
so saved layouts survive. Each slice reverts alone; E needs
`./scripts/update-po.sh` re-run after revert.

## Open Questions

- [ ] Not blocking design; blocking slice C — the two proposal confirmations:
      Downloads-list colour change, and `crProgress` → `kBoth`.
- [ ] `constexpr` `SpansFor` cannot return `std::vector`; it will be a `constexpr`
      index-to-span accessor plus a thin non-`constexpr` filler, to keep the header
      dependency-free and avoid the `modernize-loop-convert` Tier-2 gate.
