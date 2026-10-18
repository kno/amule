# Delta for shared-file-availability-bar

Every requirement below is stated over **values handed to the renderer**, never
over pixels: there is no display session here (`context.md`). Expected values are
independent literals, not re-derivations of the code's own formula
(`exploration.md` §6).

## ADDED Requirements

### Requirement: Source-count colour fade

For a part with `n >= 1` sources, the bar colour MUST be a total function of `n`
alone, with **one** definition serving the GUI shared-files list, the GUI
downloads list and the Web UI. Per decision 3 the Web UI's endpoints win and the
GUI adopts them: the fade runs from `lo = (166,212,238)` at `n = 1` to
`hi = (47,143,208)`, componentwise `round(lo + (hi - lo) * f)` with
`f = min(1, (n-1)/9)` and halves rounded away from zero. **Saturation converges
to 10** — the GUI's former `11` and its former endpoints `(0,210,255) -> (0,0,255)`
(`src/SharedFilesCtrl.cpp:671`) do not survive.

#### Scenario: Endpoints and saturation as literals

- GIVEN the colour function
- WHEN it is evaluated
- THEN `n=1` MUST be `(166,212,238)`, `n=5` MUST be `(113,181,225)`
- AND `n=10`, `n=11` and `n=1000` MUST each be exactly `(47,143,208)`

#### Scenario: Monotonic non-increase

- GIVEN any `1 <= n < m`
- WHEN both colours are computed
- THEN every channel of `colour(m)` MUST be `<=` the same channel of `colour(n)`

### Requirement: Zero sources is a distinct state

`n = 0` MUST NOT be a point on the fade. It MUST map to `(255,0,0)`, unchanged by
this change.

#### Scenario: No source holds the part

- GIVEN `n = 0`
- WHEN the colour is computed
- THEN it MUST be `(255,0,0)`
- AND it MUST NOT equal `colour(1)`

### Requirement: Bar mode selection

Mode MUST be decided from the integer pair `(hashingProgress, partCount)` alone —
never from a file object — where `hashingProgress` is a **count of hashed parts**
(`src/ThreadTasks.cpp:179`, `src/KnownFile.cpp:1991`), not a byte offset.

| `partCount` | `hashingProgress` | Mode |
|---|---|---|
| `0` | any | none — no bar drawn |
| `> 0` | `0` | source availability |
| `> 0` | `> 0` | hashing |

#### Scenario: Reported progress exceeds the file

- GIVEN `partCount = 4` and `hashingProgress = 9`
- WHEN the mode is selected
- THEN the mode MUST be hashing
- AND the hashed part count MUST clamp to `4`, so no hashed span falls outside the file

#### Scenario: No parts

- GIVEN `partCount = 0`
- WHEN the mode is selected
- THEN it MUST be "none" for every `hashingProgress`, including `> 0`

### Requirement: Span geometry

Spans MUST be derived from `(partCount, fileSize)` as a pure sequence with an
**inclusive** `end`, matching `src/GenericClientListCtrl.cpp:1015-1016` and
`src/DownloadListCtrl.cpp:1009`.

#### Scenario: Adjacent spans do not overlap

- GIVEN any `partCount >= 2` and a matching `fileSize`
- WHEN the spans are produced
- THEN `spans[i].end == spans[i+1].start - 1` MUST hold for every `i`
- AND **this property fails against today's code**, which uses an exclusive
  `end = PARTSIZE*(i+1)` at `src/SharedFilesCtrl.cpp:666-667`; that failure is the
  proof decision 4 exists for

#### Scenario: Last span ends at the last byte

- GIVEN `partCount` spans over `fileSize`
- WHEN the last span is inspected
- THEN `spans.back().end` MUST equal `fileSize - 1`
- AND the sequence MUST contain exactly `partCount` spans

### Requirement: Column label and persisted letter

The column header MUST read `Source Availability`, replacing `Obtained Parts`
(`src/SharedFilesCtrl.cpp:157`). The persistence letter `P`
(`src/SharedFilesCtrl.cpp:182`) MUST NOT change; `p` and `P` are distinct entries
in that string.

#### Scenario: Saved layout survives the rename

- GIVEN a column layout saved before this change, containing `P`
- WHEN it is loaded after the rename
- THEN the same column MUST be restored with the same visibility and width
- AND no saved layout entry MUST be discarded

### Requirement: Legend rows per mode

One column carries two legends, selected by the row's mode (decision 2). Rows are
identified by state, not by translated text. Order is normative.

| Mode | Rows, in order | Shaded | Flat (`UseFlatBar()`) |
|---|---|---|---|
| availability | ZeroSources | `255,0,0` | `255,0,0` |
| | FewSources | `166,212,238` | `166,212,238` |
| | ManySources | `47,143,208` | `47,143,208` |
| hashing | Hashed | `0,192,0` | `0,150,0` |
| | NotYetHashed | `255,208,0` | `255,255,100` |

The fade has no flat variant (`bFlat` is unused at
`src/SharedFilesCtrl.cpp:658-678`), so the availability legend MUST present the
same rows and colours under both bar preferences.

#### Scenario: Legend follows the row's mode

- GIVEN the availability column
- WHEN the row is hashing (`hashingProgress > 0`)
- THEN the hashing legend MUST be selected
- AND when the row is not hashing, the availability legend MUST be selected

#### Scenario: Legend colours are the renderer's colours

- GIVEN the availability legend
- WHEN its FewSources and ManySources rows are read
- THEN they MUST equal `colour(1)` and `colour(10)` respectively
- AND both MUST also match the literals in the table above

#### Scenario: Wrong-key legend lookup

- GIVEN the legend selector
- WHEN it is called with a column id from a different id space
- THEN that call MUST NOT compile (`COLUMN_SHARED_PART` is a plain `#define` = 8,
  `src/SharedFilesCtrl.h:40`, and such a call compiles silently today)

### Requirement: Per-legend colour uniqueness

Within a single legend, under either bar preference, no two rows MAY share a
colour. Uniqueness is scoped **per legend**, not globally, because
`crFlatPending{255,255,100}` and `kNextPending{255,255,100}` are byte-identical
with different meanings and never appear in the same legend
(`src/PartBarLegend.h:87`).

#### Scenario: Both preferences

- GIVEN each legend in turn
- WHEN its rows are enumerated under shaded and then under flat
- THEN the colours MUST be pairwise distinct in each enumeration

### Requirement: Both GUI call sites agree

The shared-files list and the downloads list MUST produce identical colours for
identical source counts (decision 5). The downloads list's per-part availability
colours therefore change for every user — deliberately, not as collateral — even
though #1220 is titled "Obtained Parts".

#### Scenario: Call sites compared

- GIVEN `n` in `{0, 1, 2, 5, 9, 10, 11, 1000}`
- WHEN both call sites are asked for the colour of `n`
- THEN the two colours MUST be equal for every `n`
- AND for `n >= 1` they MUST equal the literals of the fade requirement, so a
  divergence is a failing assertion rather than an unmeasured visual difference
