# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

aMule — eD2k/Kad P2P client. C++ / wxWidgets / Boost.Asio / Crypto++, built with CMake.

## Commands

### Build

Two supported routes. If you do not have the dependencies installed on your
machine — or you are on macOS — skip to **Build without a host toolchain** below
and use the container; the host commands here will simply fail on a missing
`cmake` or wxWidgets.

```sh
cmake -B build -DBUILD_MONOLITHIC=YES -DBUILD_DAEMON=YES -DBUILD_REMOTEGUI=YES -DBUILD_TESTING=YES
cmake --build build -j"$(nproc)"
```

All build options live in `cmake/options.cmake`; `cmake -LAH -B build` lists them. Only
`BUILD_MONOLITHIC` (→ `amule`) and `BUILD_ED2K` are ON by default. Opt in explicitly to
`BUILD_DAEMON` (`amuled`), `BUILD_REMOTEGUI` (`amulegui`), `BUILD_AMULECMD`, `BUILD_WEBSERVER`
(`amuleweb`), `BUILD_AMULEAPI`, `BUILD_TESTING`, or `BUILD_EVERYTHING=YES`.

**Always build monolithic + daemon + remotegui before declaring a change done.** A change can
compile in two of the three and break the third — see the preprocessor split below. CI
(`.github/workflows/ccpp.yml`) builds all targets on Linux, macOS and Windows and is the
authoritative dependency reference.

### Build without a host toolchain

If you do not want cmake, wxWidgets, libupnp and friends installed on your
machine — or you are on macOS, where the exact dependency set is awkward — build
in a container instead:

```sh
packaging/linux/build.sh dev          # host arch; add x86_64|aarch64 to cross
```

This configures all three apps plus tests, builds, and runs `ctest`. Nothing is
installed on the host and nothing leaves the image. It sits alongside the
existing packaging containers (`packaging/linux/static/`, `appimage/`) and reads
the same pinned versions from `packaging/linux/versions.env`; unlike those two it
runs tests, and unlike `static/` it includes the GUI.

Its dependency list is copied from `appimage/Dockerfile` — **keep the two in
sync**. Two entries there are deliberate and easy to "fix" wrongly: wxWidgets and
libupnp are built from source because Ubuntu 22.04's packages are unusable
(no wx 3.2.x; libupnp only on the ancient 1.8.x line).

Needs a container VM with enough memory to build wxWidgets from source — 2 GiB is
not enough, 8 GiB is comfortable.

### Baseline before changing anything

Before modifying source, establish that the **unmodified** tree builds and tests
here, and record it. Otherwise the first red build is unattributable: wrong
change, broken environment, and drift all look identical.

`openspec/BASELINE.md` holds the current record — commit, image digest,
toolchain, and the list of tests that **already fail**. Check a failure against
that list before attributing it to your change.

Known failing on unmodified upstream code (aarch64, commit `36e28e73`):

| Test | Mode |
| --- | --- |
| `FileDataIOTest` | SEGFAULT |

Whether that is arm64-specific is unknown. CI is the reference for what a green
run looks like elsewhere.

The `ctest` layer in the dev image is **non-gating on purpose** — a pre-existing
failure must not make the baseline unobtainable. The compile step still fails
hard, so "does not compile" and "compiles but a test fails" stay distinguishable.
Do not make it gating.

### Test

These assume a host build tree. In the container route, `packaging/linux/build.sh dev`
already runs the full suite; to iterate on one suite, get a shell in the image
(`podman run --rm -it amule-dev:aarch64`) and run the same commands against
`/src/build`.

```sh
ctest --test-dir build --output-on-failure --timeout 10       # all
ctest --test-dir build -R '^CTagTest$' --output-on-failure    # one suite
./build/unittests/tests/CTagTest                              # or run the binary directly
```

Every file in `unittests/tests/` is its own executable + its own `add_test()` (~34 suites), each
linking only the TUs it needs — see `unittests/tests/CMakeLists.txt`. Tests use the in-tree
`unittests/muleunit/` framework: `TEST(Case, Name)` macros self-register into a global registry, so
**there is no way to run a single `TEST()` case** — one binary always runs all of its cases. Under
`MULEUNIT` all logging macros compile to no-ops.

### Lint / format

```sh
clang-format --dry-run --Werror <files>            # CI pins clang-format 18
```

Two clang-tidy tiers, and the distinction matters:

- `.clang-tidy` — curated bug checks enforced on the **whole tree**, must stay green.
- `.clang-tidy-new-code` — broader modernization checks applied **only to changed lines** via
  `clang-tidy-diff.py` on the PR patch. New code is held to a stricter standard than its
  surroundings; its header documents what is deliberately excluded and why.

CI pins clang-tidy to LLVM 21 and clang-format to LLVM 18 — do not assume parity.

### Generated files — do not hand-edit

- `src/libs/ec/cpp/ECCodes.h`, `ECTagTypes.h` — exist **only in the build tree**, generated from
  `src/libs/ec/abstracts/*.abstract` by a CMake script. Edit the `.abstract` files.
- `src/Parser.cpp`, `src/Scanner.cpp`, `src/IPFilterScanner.cpp` — bison/flex output from the
  adjacent `.y`/`.l`; regenerated at build time if bison/flex are installed, otherwise the
  checked-in `.cpp` is used.
- `config.h` — from `config.h.cm`. `src/icons/icon_data.c` — from `src/icons/embed_icons.py`.
- `po/*.po`, `po/amule.pot` — `./scripts/update-po.sh` (must run from the repo root);
  `scripts/check-potfiles.sh` validates `po/POTFILES.in` and fails CI in both directions.
- `src/muuli_wdr.cpp/.h` are **no longer generated** — wxDesigner is gone and these are
  hand-maintained (with `// clang-format off`). Some in-tree comments still claim otherwise.

### Gotchas

wxWidgets ≥3.2 (unicode build), Crypto++ ≥8.1, Boost ≥1.70 (`docs/INSTALL.md` understates this).
Linux GUI/daemon builds hard-fail configure without `glib-2.0` pkg-config — delete `build/` and
reconfigure after installing it. 32-bit builds need `libatomic`. Windows CI uses MSYS2 CLANG64
with `-G Ninja` and builds `libupnp` from source.

**Container/host environment traps** (all four cost a debugging session at least
once):

- `packaging/linux/build.sh` resolves the arch with a `case` on `uname -m` that
  expects `aarch64`/`x86_64`. macOS reports `arm64`, so invoking any target with
  `host` on a Mac leaves the container platform empty. `build_dev` normalises it;
  `build_appimage`, `build_static`, `build_flatpak` and `validate` still do not.
- `docker` is frequently only a shell alias for `podman`. Aliases do not exist in
  the non-interactive shell that runs `build.sh`, so resolve a real binary.
- podman's `buildx` shim (buildah) rejects `--load`. Not needed: buildx's default
  docker driver already writes to the local image store.
- `RUN` layers execute under `/bin/sh` (dash), which has no `set -o pipefail`.
- Never capture a build through `| tee` when you care about the exit status — the
  pipeline reports tee's success and a failed build looks green.

## Architecture

### One tree, three apps, two orthogonal macros

`cmake/source-vars.cmake` defines exactly three source lists, and **which list a `.cpp` belongs to
is the architectural decision**:

| list | condition | contents |
|---|---|---|
| `CORE_SOURCES` | monolithic or daemon | the P2P engine: `amule.cpp`, `BaseClient.cpp`, `DownloadQueue.cpp`, `ExternalConn.cpp`, `ECSpecialCoreTags.cpp`, all of `kademlia/` |
| `GUI_SOURCES` | monolithic or remotegui | `amuleDlg.cpp`, `muuli_wdr.cpp`, `PrefsUnifiedDlg.cpp`, every `*Ctrl/*Wnd/*Dialog.cpp` |
| `COMMON_SOURCES` | all three | `KnownFile.cpp`, `PartFile.cpp`, `Preferences.cpp`, `ECSpecialMuleTags.cpp`, `GuiEvents.cpp`, `Statistics.cpp` |

So `amule` = COMMON+CORE+GUI, `amuled` = COMMON+CORE, `amulegui` = COMMON+GUI.

- `CLIENT_GUI` (set only for `amulegui`) means **there is no core** — no `CamuleApp`, no queues, no
  sockets to peers.
- `AMULE_DAEMON` (set only for `amuled`) means **there is no GUI** — no windows, `wxAppConsole`.
- Monolithic defines **neither**. The two are orthogonal; guard core-only code with
  `#ifndef CLIENT_GUI`, never with `AMULE_DAEMON`.

There is no `theApp` base class and no macro. Each build declares its own global of its own type
(`amule.h:799`, `:836`, `amule-remote-gui.h:1231`), and `amule.h:803` `#include`s
`amule-remote-gui.h` in the `#else` of `#ifndef CLIENT_GUI`. Every file just writes
`#include "amule.h"` and gets whichever app its target implies.

`CamuleApp` and `CamuleRemoteGuiApp` are **duck-typed siblings, not a hierarchy**: both publish
members named `downloadqueue`, `sharedfiles`, `clientlist`, `serverlist`… with different types
(`CDownloadQueue*` vs `CDownQueueRem*`, etc.), which is what lets shared GUI code write
`theApp->downloadqueue->…` unchanged. Members with no remote analogue (`uploadqueue`,
`clientudp`, `ECServerHandler`, `m_AsioService`, `uploadBandwidthThrottler`) simply do not exist on
the remote app — touching them from `COMMON_SOURCES`/`GUI_SOURCES` without a guard breaks
`amulegui`. Core globals are created in `CamuleApp::OnInit` (`amule.cpp:682`, `:867-989`) and
`ReinitializeNetwork`; remote mirrors in `CamuleRemoteGuiApp::Startup()`.

The remote GUI's engine is `CRemoteContainer<T,I,G>` (`amule-remote-gui.h:146`) — a request state
machine that holds `list<T*>` + `map<I,T*>` and reconciles against EC replies, polled round-robin
by `OnPollTimer` (`amule-remote-gui.cpp:333`) for only the visible notebook page.

`amulecmd`, `amuleweb` and `amuleapi` are a **different family** — standalone `wxApp`s deriving
from `CaMuleExternalConnector` (`ExternalConnector.h:132`) that link only `ec + mulecommon +
mulesocket`. `amulegui` is the only EC client that reuses the full GUI source tree.

### EC (External Connection) protocol

Opcodes and tag names come from `src/libs/ec/abstracts/ECCodes.abstract` (sections `ECOpCodes`,
`ECTagNames`), generated into the build tree. Wire objects live in `src/libs/ec/cpp/`
(`CECTag`, `CECPacket`, `CECSocket`, `CRemoteConnect`). Every EC-visible object gets a
process-unique id from `CECID` (`ECID.h:34`) — that id is the map key on both ends.

Per-object tag trees are declared in `ECSpecialTags.h` and defined in two places by build:
`src/ECSpecialCoreTags.cpp` (core-only, reads real objects) and `src/ECSpecialMuleTags.cpp`
(all three — the remote GUI must both send and apply prefs). `CValueMap`
(`ECSpecialTags.h:60`) is the incremental-update filter: it only emits a tag when the value
actually changed, so **its failure mode is silence**. `CKnownFile::m_ecGen` + `MarkECChanged()`
(`KnownFile.h:260`) is the coarser generation counter that lets updates skip unchanged files.

To expose a new datum to remote clients: add the tag to `ECCodes.abstract`; emit it in the right
`CEC_*_Tag` ctor in `ECSpecialCoreTags.cpp` honouring `detail_level`; call `MarkECChanged()` at
every mutation site if it can change; parse it in the matching `CRemoteContainer` subclass and
store it in a `#ifdef CLIENT_GUI` field; then update the other EC clients that need it
(`src/webapi/Refresher.cpp`, `src/webserver/src/php_amule_lib.cpp`, `src/TextClient.cpp`).
Additive tags do not need a protocol-version bump — a missing tag conventionally means
"old daemon" and is a distinct third state. Document in `docs/EC_Protocol.md`.

### Domain objects and lifetime

`CAbstractFile` → `CKnownFile` (`+ CECID`) → `CPartFile`. `CKnownFileList` is the canonical owner
of `CKnownFile*`; `CSharedFileList` is constructed *with* it and only indexes. `CDownloadQueue`
and `CServerList` are `CObservableQueue<>` so list controls can subscribe.

Clients are refcounted: **never hold a raw `CUpDownClient*` across anything that can yield.** Use
`CClientRef` (`ClientRef.h:61`), which links/unlinks in its ctor/dtor, and reach fields through the
`WRAPC` forwarders after validating with `GetClientChecked()`. Deletion is two-phase
(`Safe_Delete()` → `CS_DYING` → lazy unlink), and that whole machinery is `#ifndef CLIENT_GUI`.
For stale file pointers the equivalent check is `CKnownFileList::IsKnownFile()` — both are
pointer-value comparisons that are safe on freed memory.

### Networking

Boost.Asio is unconditional: `LibSocket.cpp` is a licence header plus
`#include "LibSocketAsio.cpp"`. Stack, bottom-up:
`CLibSocket → CProxySocket → CEncryptedStreamSocket → CEMSocket → CClientTCPSocket`
(UDP mirrors it through `CEncryptedDatagramSocket` / `CMuleUDPSocket`). Obfuscation therefore sits
below the eD2k protocol layer and is transparent to it.

**Asio callbacks never run core code.** They post through `CoreNotify_LibSocket*` (`GuiEvents.h:696`),
which always `wxQueueEvent`s to the main thread — the core P2P engine is effectively
single-threaded there.

The two throttlers are deliberately asymmetric: upload is a real `wxThread` with a condvar (push
model); download is *not* a thread but a `Get()` singleton with an atomic byte budget refilled per
`DownloadQueue` tick and reserved/refunded per socket read (pull model — asio decides when bytes
arrive). Leftover download budget is discarded each tick, so `MaxDownload` is a literal cap.

### Threading rules

Background threads exist only for blocking I/O and hashing (`CPartFileWriteThread`,
`CPartFileHashThread`, `CUploadDiskIOThread`, `CMediaProbeThread`, `CFreeSpaceThread`,
`CAsyncDNS`, `CAsioServiceThread`, plus `CThreadScheduler` draining `CThreadTask`s from
`ThreadTasks.h`). `CSharedDirWatcher` and `CHTTPDownloadThread` are *not* threads despite
appearances — they are `wxEvtHandler`s.

1. Nothing off the main thread may touch `theApp->*`, wx windows, or `CKnownFile`/`CPartFile`
   state. Marshal via a `Notify_*`/`CoreNotify_*` macro (`GuiEvents.h:539-707`) or a
   `wxQueueEvent` of a typed event from `InternalEvents.h`.
2. Notifier arguments are deep-copied — **but pointers are copied as pointers.** By the time the
   main thread runs the event the pointee may be freed. Hence the `DropReferencesTo(file)`
   protocol: any new cache holding a `CKnownFile*` must implement it and hook into
   `MuleNotify::KnownFileBeingDestroyed` (`GuiEvents.cpp:1023`) — read that function before adding
   any cross-cutting "object is going away" hook. It is the model for fanning out to all three
   builds' subscriber sets in one place.
3. Naming: `Notify_*` = core→GUI, `CoreNotify_*` = GUI→core (an action request) plus socket
   callbacks, `NotifyAlways_*` = queued unconditionally (needed because sockets notify before
   `amulegui` has any window).
4. Fields a worker writes must be atomic (`m_ecGen` is `std::atomic<uint64>` for exactly this
   reason).
5. `amuled -f` forks before `wxEntry()`, so worker threads must not be constructed earlier
   than `OnInit`.

### Kademlia

`src/kademlia/` is an eMule port kept in namespace `Kademlia::` with eMule's own style (its own
`Defines.h`, `Error.h`, `wxCHECK`-based static accessors) — do not "aMule-ify" it. Everything is
reached statically through `CKademlia` (`Kademlia.h:66`), and all accessors are null-tolerant so
callers need no "is Kad up" guard. It is driven from `CamuleApp::OnCoreTimer`
(`amule.cpp:2005` → `CKademlia::Process()`), with the lost-connection/restart recovery right after.
On-disk state: `nodes.dat`, `preferencesKad.dat`.

### Directory map

- `src/libs/common` (`mulecommon`) — `CFormat`, `CPath`, string/file helpers, backtraces. Linked by
  everything including the EC-only tools.
- `src/libs/ec` — `abstracts/` (protocol source of truth + generator) and `cpp/` (the `ec` lib).
- `src/include/{common,protocol,tags}` — header-only constants: widget/menu ids, eD2k & Kad wire
  constants, eD2k meta-tag ids.
- `src/libwebcommon` (`webcommon`) — credentials/JWT/etag/JSON shared by `amuleapi` and the core;
  owns the `amuleapi-passwords` format and the EC token `amuled` hands its spawned `amuleapi`.
- `src/webserver` — `amuleweb`, the legacy web UI, including a bison/flex **PHP interpreter** that
  runs the templates in `src/webserver/default/`.
- `src/webapi` — the modern `amuleapi` REST+SSE daemon (Boost.Beast). `Api.cpp` is the largest file
  in the tree; `static/` is a build-step-free preact+htm SPA using a browser import map.
- `src/utils` — independent side tools behind their own `BUILD_*` options (`alc`, `alcc`, `cas`,
  `wxCas`, `fileview`) plus dev scripts.
- `src/extern` — effectively empty; only a `.clang-tidy` with `Checks: '-*'`.
- `src/kademlia` — see above. `src/api` does not exist.

### Adding a preference (non-obvious)

`CPreferences` is table-driven. `BuildItemList` (`Preferences.cpp:1274`) registers `Cfg_*` objects
into `s_CfgList`, **keyed by wxWidgets control ID** — and its first act is to redefine
`NewCfgItem` so that under `AMULE_DAEMON` (which has no widgets) the same table is reused with a
synthetic running counter (`Preferences.cpp:1277-1280`). A preference is therefore three coupled
things: a static backing variable, an `amule.conf` key string, and a widget ID.

1. Add the static backing variable and `thePrefs::GetX()/SetX()` in `src/Preferences.h`.
2. Add one `NewCfgItem(IDC_YOURTHING, (new Cfg_Bool("/Section/Key", s_yourThing, default)));` line
   in `BuildItemList`. Persistence is then automatic. Use `s_MiscList` / `Cfg_Transient` for
   non-persisted or widget-less values.
3. `#define IDC_YOURTHING` in `src/muuli_wdr.h` and create the control with that ID in the
   relevant `PreferencesXxxTab()` in `src/muuli_wdr.cpp`.
4. A new page = a `PrefsPage` row in `pages[]` (`PrefsUnifiedDlg.cpp:358`); that table is itself
   `#ifdef`-conditional per build.
5. Remote visibility: add the tag to `ECCodes.abstract`, emit it in the right `EC_PREFS_*` block of
   `CEC_Prefs_Packet`'s ctor and consume it in `CEC_Prefs_Packet::Apply()`
   (`ECSpecialMuleTags.cpp`). Some prefs (e.g. tray settings) are deliberately amulegui-local and
   in no mask.

Binding is implicit and by ID, and a wrong/missing ID **fails silently apart from a log line** —
grep for `Failed to transfer data from Cfg to Widget` when a new preference "doesn't stick".

## Conventions

- Classes take a `C` prefix (`CPartFile`, `CKademlia`); apps are `Camule…`; remote mirrors end in
  `Rem`; EC tag classes are `CEC_Xxx_Tag`. Legacy exceptions exist
  (`UploadBandwidthThrottler`, `ExternalConn`) — do not imitate them, do not rename them either.
- Members `m_`, statics `s_`. Old core code has un-prefixed public members (`CPartFile::status`);
  leave them alone.
- `wxString` in app code, `CPath` for paths (never a raw `wxString`). New literals are bare
  `"…"`; `wxT()` survives in older files.
- Formatting is **`CFormat` with `operator%`** (`src/libs/common/Format.h`), not `printf` or
  `wxString::Format`.
- i18n: `_()` at runtime, `wxTRANSLATE()` in static tables, `wxPLURAL()` for plurals. **A new file
  with translatable strings must be added to `po/POTFILES.in`** or `check-potfiles.sh` fails CI.
  A `// TRANSLATORS:` comment reaches the catalog.
- Logging: `AddLogLineN/C` (+ `…S` variants also to stdout, `…F` logfile-only) and
  `AddDebugLogLineN/C(type, str)` with a `DebugType`. The `…N` debug form compiles away unless
  `__DEBUG__` **and** is runtime-gated by `theLogger.IsEnabled(type)`; the `…C` forms always log.
- Asserts: `wxASSERT`/`wxCHECK` in app code, `EC_ASSERT` in `libec` (so it stays usable outside a
  wx app). `CamuleApp::OnAssertFailure` is compiled in release too, because Debian/Ubuntu ship wx
  with `wxDEBUG_LEVEL=1`.
- `.clang-format` uses **tabs**, `IndentWidth 8`, `ColumnLimit 110`, and `SortIncludes: false` —
  include order is meaningful and hand-maintained, with `// Needed for X` justification comments.
- `src/CMakeLists.txt` promotes `-Wdeprecated*` and (under Clang)
  `-Winconsistent-missing-override` to **errors** for project sources: a class must mark all or
  none of its overrides.
- Conventional commits; comments routinely cite the issue/PR number. `.git-blame-ignore-revs`
  covers the formatting sweeps.

## Planned work: network parity with eMuleAI

`openspec/` holds a dependency-ordered set of eight changes bringing this tree to
parity with eMuleAI's connectivity stack: IPv6, uTP, QUIC NAT traversal,
LowID-to-LowID rendezvous, and a two-generation Kad catch-up.

**Read `openspec/changes/README.md` first.** Listing that directory gives
alphabetical order, which is not execution order. Change `0` is the build-baseline
gate above; every other change depends on it.

The analysis those specs derive from — the capability matrix with file/line
evidence for every claim — lives in the eMuleAI repository, not here.

## Reading order for a new contributor

`cmake/source-vars.cmake` → `src/amule.h` (`:141`, `:363`, `:752`, `:803`, `:811`) →
`amule-remote-gui.h:146` (`CRemoteContainer`) → `GuiEvents.h:466-520` + `GuiEvents.cpp:91-114` →
`src/libs/ec/abstracts/ECCodes.abstract` → `src/ECSpecialCoreTags.cpp` →
`src/amule.cpp:1960-2060` (`OnCoreTimer`, the heartbeat of the core).
