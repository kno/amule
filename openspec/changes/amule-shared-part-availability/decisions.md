# Product decisions — #1220

Collected from the user in the interactive proposal round. These are inputs to
propose/design, not conclusions drawn by any phase.

## 1. Column name: **Source Availability**

Chosen over reusing the already-translated `"Availability"` msgid. Accepted cost:
a new msgid, so all 40 catalogues carry an untranslated entry until Weblate
catches up (`"Availability"` would have cost one translation instead of forty —
the user chose precision over that saving).

Rejected: `Availability` (bare noun, and collides conceptually with the
client-list column of the same name, where it means one peer's parts);
`Part Availability`; keeping `Obtained Parts`.

Constraint that survives regardless: the persistence letter `P`
(`src/SharedFilesCtrl.cpp:182`) must NOT change, or saved column layouts are
discarded. Only the label moves.

## 2. Modes: **one column, legend selected per mode**

Follows the Web UI, which keeps one slot and swaps the component
(`src/webapi/static/js/views/shared-detail.js:124-132`).

Consequence accepted: `LegendForColumn` is `constexpr` on the column id alone and
cannot depend on row state, so the legend selector must be extended. That is the
structural work this decision buys.

Rejected: a second column (hashing is transient and rare, so it would be blank
almost always, and there is no precedent in the tree); legend-only with no
structural change.

## 3. Fade: **unify GUI and Web UI**

The two have drifted — no endpoint matches and saturation differs (GUI 11, Web UI
10). The user chose one definition over documenting the divergence.

**Which surface cedes was not specified by the user. Orchestrator decision: the
Web UI's endpoints win and the GUI adopts them.** Reasoning, open to being
overruled:

- The Web UI's fade is already themed for light and dark with custom properties
  built for the purpose (`app.css:26-30`, `:56-57`, `:79-80`); the GUI's is a
  hardcoded formula duplicated in three places.
- The issue itself points at the Web UI as "the correct model".
- Adopting the GUI's `0,210,255 -> 0,0,255` into the Web UI would need a second
  set of dark-theme values invented from nothing, since the GUI has no dark theme.

Consequence accepted: **GUI users will see the availability bar change colour.**
Saturation must also converge; the Web UI's `AVAIL_FULL = 10` and the GUI's 11
cannot both survive.

## 4. Span off-by-one: **in scope, with a test**

`src/SharedFilesCtrl.cpp:666-667` uses an exclusive `end` where
`CBarShader::FillRange` treats it as inclusive, so adjacent spans overlap by one
byte and the last runs past `fileSize-1`. The other two bars subtract one
(`src/GenericClientListCtrl.cpp:1015-1016`, `src/DownloadListCtrl.cpp:1009`).

Extracting the geometry to a pure function turns this from an observation into a
test that **currently fails**. Fixing it while the code is open was judged cheaper
than returning.

Consequence accepted: drawing changes for every shared file, and it cannot be
verified visually in this environment.

## Standing limit that applies to all four

No display session. The gradient swatch, the dialog, the menu entry and
`CBarShader` output are not verifiable here. Anything claiming otherwise repeats
the #1218 failure, where a green test sat on a dead affordance.

## 5. Third copy of the fade: **unify `DownloadListCtrl` too, with tests**

`src/DownloadListCtrl.cpp:1000-1001` holds the fade a third time, with the local
named `blue` while being passed as the **green** argument of `Set(r,g,b)`
(`src/MuleColour.h:76-80`). The proposal asked for a decision because unifying it
changes the Downloads list's availability colours as well, which is beyond what
#1220 asked for.

**User decision: unify it, with tests.**

Consequence accepted: the Downloads list's per-part availability colours change
for every user, in the same way and by the same amount as the Shared Files list.
That is now a deliberate part of the change rather than collateral, and the PR
body must say so — a reviewer looking at an issue titled "Obtained Parts" will
not expect the Downloads list to move unless it is stated.

Scope effect: after this, the fade has **one** definition. The misnamed `blue`
local disappears with the duplicate rather than being renamed in place.

Test requirement: the Downloads list's adoption is covered by the same
`count -> colour` literals as the Shared Files list, so a divergence between the
two call sites becomes a failing assertion rather than a visual difference nobody
measures.

## 6. Hashing green: **Shared Files adopt `kBoth{0,192,0}`**

`src/SharedFilesCtrl.cpp:646` uses `crProgress{0,224,0}` while
`src/PartBarLegend.h:75` has `kBoth{0,192,0}` for the same meaning ("we have this
part, shaded"), with no recorded reason for the difference.

**User decision: Shared Files adopt `kBoth`.** The hashing bar goes slightly
darker green.

Cheaper side by measurement: hashing is transient and rare for a share — it needs
`GetHashingProgress() > 0`, set only while a hashing or re-hash task runs
(`src/ThreadTasks.cpp:179`, `:693`) and reset on completion (`:184`, `:190`,
`:193`, `:761`). Moving `kBoth` the other way would have changed every client
list for every user, in a column people look at daily.

Rejected: keeping two constants. That preserves exactly the drift single-sourcing
exists to end, and contradicts the header's stated invariant at
`src/PartBarLegend.h:31` that there is exactly one copy of each colour.

Blocks slice C only. Slices A and B do not depend on it.

## 7. Chain strategy: **`stacked-to-main`**

Each PR targets the previous slice's branch or `master` in sequence, merged in
order A → B → C → D → E.

Chosen over a tracker branch because it matches how this project actually merges:
#1203, #1204, #1218 and #1219 all went in individually. A tracker branch would
ask the maintainer to review and merge in a shape they do not currently use, for
no gain the ordering does not already give.
