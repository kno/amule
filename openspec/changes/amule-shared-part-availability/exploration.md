# Exploration — shared-files part availability bar (amule-org/amule#1220)

Phase: explore. Read-only; no source file was modified.

## 1. What `CSharedFilesCtrl::GetItemBarFill` draws

`src/SharedFilesCtrl.cpp:630-681`. Column gate `COLUMN_SHARED_PART`
(`src/SharedFilesCtrl.h:40`, id 8, persistence letter `P`, registered at
`src/SharedFilesCtrl.cpp:157`). Early-out when `GetPartCount()==0`. Mode switch on
`file->GetHashingProgress() > 0` at `:643`.

### Mode A — hashing (`:643-657`)

| Local | RGB | Role |
|---|---|---|
| `crPending` | 255,208,0 | not yet hashed, shaded |
| `crFlatPending` | 255,255,100 | not yet hashed, flat |
| `crProgress` | 0,224,0 | hashed, shaded |
| `crFlatProgress` | 0,150,0 | hashed, flat |

`GetHashingProgress()` is a **count of hashed parts**, not a byte offset
(`src/ThreadTasks.cpp:179`, `:693`; `src/KnownFile.cpp:1991`). Reachable for a
complete share via "Verify Local Data".

### Mode B — source availability (`:658-678`)

Reduces, with `n = list[i]`, to:

    n == 0  -> (255, 0, 0)
    n >= 1  -> (0, max(0, 210 - 22*(n-1)), 255)

`CMuleColour` is `(r,g,b)` (`src/MuleColour.h:76-80`), so **the fading channel is
green; blue is pinned at 255**.

| n | RGB | |
|---|---|---|
| 0 | 255,0,0 | red |
| 1 | 0,210,255 | brightest |
| 5 | 0,122,255 | |
| 10 | 0,12,255 | **not** saturated |
| >= 11 | 0,0,255 | pure blue |

**Saturation is n = 11**, computed: `210-22*(n-1) <= 0` iff `n >= 11.55`; at n=10
green is still 12. The commonly repeated "around 10" is off by one.

`bFlat` is **unused in this branch** — the fade is the only bar fill in the tree
with no flat variant, so a legend under `UseFlatBar()` has nothing distinct to show.

### Dead code: the red tail (`:677`)

`CBarShader::FillRange` drops a span when `start >= end || start >= m_FileSize`
(`src/BarShader.cpp:113-119`), and the availability vector is kept exactly
`GetPartCount()` long on every path (`src/KnownFile.cpp:663`, `:769-770`,
`:1749-1751`, `:1842-1844`; `src/ThreadTasks.cpp:123-124`;
`src/amule-remote-gui.cpp:2382-2387`). So `end+1 > fileSize-1` always and the tail
is always discarded. Treat as dead code, not a documented state.

### Off-by-one span geometry, inconsistent with the other two bars

`:666-667` uses `end = PARTSIZE*(i+1)` while `FillRange` treats `end` as inclusive
and increments internally (`src/BarShader.cpp:121-124`). Adjacent spans overlap by
one byte and the last runs past `fileSize-1`. The other two lists subtract one:
`src/GenericClientListCtrl.cpp:1015-1016` and `src/DownloadListCtrl.cpp:1009`.
Any extraction must pick a convention.

## 2. `PartBarLegend.h` cannot express this bar

The header (`src/PartBarLegend.h:25-173`) offers `BarColour`, eight palette
constants, two **closed enums of discrete states**, two `state -> colour`
functions, `LegendForColumn`, and two fixed row-order arrays.

Structural gaps:

1. **No continuous mapping.** Every entry point is `state -> colour` over a closed
   enum. A fade over an unbounded source count is not a state.
2. **No multi-mode column.** `LegendForColumn` is `constexpr` on the column id
   alone, with no access to row state.
3. **Wrong key space.** It takes `GenericColumnEnum`; `COLUMN_SHARED_PART` is a
   plain `#define` = 8 in a different, overlapping space
   (`src/SharedFilesCtrl.h:40`). A wrong-key call **compiles silently**.
4. **Single-colour swatches only.** `MakeLegendSwatch`
   (`src/GenericClientListCtrl.cpp:112-121`) fills one rectangle from one
   `BarColour`. No gradient primitive.
5. **Palette collisions, measured:**

| shared-files local | RGB | partbar constant | verdict |
|---|---|---|---|
| `crPending` | 255,208,0 | `kPending` | same value, same meaning |
| `crFlatPending` | 255,255,100 | `kNextPending` | **same value, different meaning** |
| `crProgress` | 0,224,0 | none (`kBoth` is 0,192,0) | **drift: two greens** |
| `crFlatProgress` | 0,150,0 | `kFlatBoth` | same value |
| red / fade | — | none | no equivalent |

`PartBarLegendTest` pins `{255,255,100}` as `NextRequested`, so merging the
palettes without resolving that collision makes
`NoTwoRowsOfALegendShareAColour` false by construction.

### The fade exists in three places

`src/SharedFilesCtrl.cpp:671`, `src/DownloadListCtrl.cpp:1000-1001` (where the
local is named `blue` but passed as the **green** argument), and
`src/webapi/static/js/components.js:388`.

## 3. Web UI comparison — drifted, and that is the finding

| theme | few sources | many sources |
|---|---|---|
| light | `#a6d4ee` = 166,212,238 | `#2f8fd0` = 47,143,208 |
| dark | `#2d6f96` = 45,111,150 | `#4bb4e6` = 75,180,230 |
| **GUI** | **0,210,255** | **0,0,255** |

- Direction agrees (intensity rises with sources).
- **Saturation disagrees by one**: `AVAIL_FULL = 10`
  (`src/webapi/static/js/components.js:389`) versus the GUI's 11.
- **No endpoint matches.**
- Dark theme inverts perceived luminance relative to the GUI.
- The comment at `components.js:388` names the wrong channel and the wrong
  saturation — same misnomer as `DownloadListCtrl.cpp:1000`.

So got3nks's "the correct model already exists in this repo" is half true: the
**concept** exists, the **values** do not agree. Unifying them changes pixels on
one surface or the other.

The Web UI has already shipped both affordances: a gradient legend
(`app.css:820-823`) plus a separate hashing legend
(`components.js:562-593`), with the same mode precedence.

## 4. The affordance

`CSharedFilesCtrl::OnItemRightClicked` (`src/SharedFilesCtrl.cpp:187-333`, bound at
`:100`) builds its menu **inline and from scratch** — there is no
`BuildSharedFileContextMenu`, so it shares no builder with anything. **The
#1221/#1246 sharing hazard does not apply here.**

An entry goes after `:260`, before `PopupMenu` at `:325`, plus one `EVT_MENU` row.
There is **no reusable guard**: `FindBarLegendColumn` is a `CGenericClientListCtrl`
member and depends on `LegendForColumn`, which does not accept
`COLUMN_SHARED_PART`. `IsColumnHidden` does live on the shared base and is usable.

`ShowInfoGridDialog` (`src/InfoGridDialog.h:48-53`) is reusable as-is and is
neutral about what widget occupies the left cell, so a gradient bitmap fits.

## 5. The name — occurrences, i18n cost, candidates (no choice made)

Occurrences: `src/SharedFilesCtrl.cpp:157` (the only `_()`), plus comments at
`:146`, `src/SharedFilesCtrl.h:216`, `src/webapi/Api.cpp:2811`,
`src/webapi/Refresher.cpp:1255-1259`, `components.js:421`,
`docs/CHANGELOG.md:7176`; and `po/amule.pot` + 40 catalogues.

**The persistence letter `P` (`src/SharedFilesCtrl.cpp:182`) is a saved user
setting.** The label may change; the letter may not, or saved layouts are lost.
Note `p` and `P` are distinct entries in that string.

**Measured i18n mitigation:** `msgid "Availability"` already exists and is
translated in **33 of 40** catalogues (`po/es.po` -> "Disponibilidad"), versus 34
for `"Obtained Parts"`. Reusing it costs one translation, not forty.

| Candidate | Right | Wrong |
|---|---|---|
| Availability | accurate for mode B; 33/40 already translated | bare noun; silent on hashing; collides conceptually with the client-list "Availability", which means one peer's parts |
| Part Availability | unambiguous granularity | new msgid; silent on hashing |
| Source Availability | names the encoded quantity exactly | new msgid; long for the 120px default; silent on hashing |
| Sources per part | most literally true; makes a legend near self-explanatory | new msgid; phrasing unlike every other label; silent on hashing |
| keep Obtained Parts | zero i18n cost, no disruption | leaves the issue's primary complaint standing |

### One column or two

- Hashing is **transient and rare** for a share (`src/ThreadTasks.cpp:179`, `:693`,
  reset at `:184`, `:190`, `:193`, `:761`).
- The Web UI does **not** merge them: one slot, two components
  (`shared-detail.js:124-132`).
- The Downloads list shows hashing inside **Progress**, where progress belongs
  (`src/DownloadListCtrl.cpp:969-980`). There is **no precedent** for a
  hashing-only column.
- A second column needs: a new `COLUMN_SHARED_*` id (the `#define`s at
  `src/SharedFilesCtrl.h:33-45` are sequential, so anything but appending
  renumbers), a free persistence letter, a second `AddBarColumn`, a second branch
  in `GetItemBarFill`, and a column blank almost always.
- A shared column with a mode-aware legend needs a legend that can depend on row
  state, which `LegendForColumn` cannot express.

## 6. Testable headless, and not

The precedent is `PartBarLegendTest` (`unittests/tests/PartBarLegendTest.cpp`),
header-only and wx-free, which already encodes the rule at `:56-58`: expected
values are **spelled out** rather than read from the same place the renderer reads
them.

**The #1218 distinction, explicitly.** Two kinds of assertion are available and
only one is worth writing:

- One that **restates the code's own assumption** — reads the value from where
  production reads it, or asserts an affordance the code merely believes it has.
  Goes green whether or not the feature exists. This is what happened in #1218.
- One that **pins a behaviour against an independent literal**, so test and code
  disagree the moment either changes.

**The trap is still live in the tree:** `unittests/tests/CMakeLists.txt:1971-1975`
describes "the two legends the `?` beside the bar column headers opens" and says
the suite checks "where the `?` is clickable". **No such affordance exists** — the
shipped design is a row context-menu entry, and header clicks only sort. A comment
documenting a replaced design, merged in #1218. Ours to fix.

**Assertable headless**, each against an independent literal:

1. The fade as a pure `count -> colour` function: n=1 -> 0,210,255; n=10 -> 0,12,255;
   n=11 -> 0,0,255; green monotonically non-increasing. **Saturation 11 as a
   literal** — recomputing the formula inside the test would be the bad kind.
2. Mode precedence and the hashing clamp, if the mode choice is extracted as a
   predicate over `(hashingProgress, partCount)` rather than a `CKnownFile*`.
3. Span geometry, if extracted to `(partCount, fileSize) -> {start,end}[]`. This
   turns the off-by-one into a test: `spans[i].end == spans[i+1].start - 1` is a
   property **the current code fails**.
4. Palette single-sourcing: the drift table above as assertions, and colour
   uniqueness under both bar preferences.
5. Legend row content, order, and which column gets which legend.
6. GUI/Web UI saturation agreement as two literals. No existing harness reads a JS
   constant from C++, so this would be hand-maintained.

**Not verifiable here at all:** the gradient swatch (needs `wxMemoryDC`, and
whether it *looks* like the bar is a human judgement), `ShowInfoGridDialog`
opening and layout, the context-menu entry appearing and being guarded correctly,
`CBarShader` output, and anything reading `thePrefs::UseFlatBar()` in situ.

## Risks

1. Renaming costs 40 catalogues unless `"Availability"` is reused; the persisted
   letter `P` must not change.
2. `crFlatPending` is byte-identical to `kNextPending`, which means something else.
3. `crProgress(0,224,0)` vs `kBoth(0,192,0)` is unexplained pre-existing drift;
   unifying changes pixels somewhere and someone must choose.
4. `LegendForColumn` keys on a different id space; a wrong call compiles silently.
5. The fade has no flat variant.
6. Fixing the span off-by-one changes drawing for every shared file and cannot be
   verified visually here.
7. GUI/Web UI saturation (11 vs 10) and fully drifted endpoints make "make them
   agree" a product decision with visible consequences on both surfaces.
8. No display session: swatch, dialog and menu entry unverifiable. Claiming the
   legend "works" here would repeat #1218.
9. `openspec/BASELINE.md` names `36e28e73` while HEAD has moved; re-establishing
   the baseline is a hard gate before any source edit.

## Ready for proposal

Yes, with two decisions deliberately not made here: **the column name** (five
candidates with measured i18n cost) and **whether the hashing mode shares the
column or gets its own**.
