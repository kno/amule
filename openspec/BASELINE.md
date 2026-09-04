# Build baseline

> **Two records live in this file.** The first is the *attribution* baseline: the
> unmodified upstream tree at `36e28e73`, which is what tells you whether a failure
> is yours or was already there. The second, at the end, is the current *reference
> point* after phases 1-5, which changed a build input and therefore could not
> extend the first. Neither replaces the other. Use the attribution baseline to
> judge blame and the reference point to judge regression.

Established by `amule-baseline-build` (change 0). **Valid only for the commit
named below.** If the tree moves, re-establish it before further implementation
and keep this record rather than overwriting it.

## Subject

| | |
| --- | --- |
| Commit | `36e28e73836f95e0391fdf26f349cfd9d57b7edf` |
| Repository | github.com/kno/amule (fork of amule-org/amule) |
| Tree state | clean except untracked `openspec/` and `packaging/linux/dev/`, and modified `packaging/linux/build.sh` — none of which are compiled |
| Command | `packaging/linux/build.sh dev` |
| Container image | built as `localhost/amule-dev:aarch64` — see the warning below |
| Durable tag | `localhost/amule-baseline:36e28e73` |
| Image digest | `sha256:8b5f950ec30d93d83a444d22e52b7c5ea1d1632b97972327479fba46c81ca7b0` |
| Host toolchain used | none — everything ran in the container |

### Validity beyond the build commit

This record was produced by building the tree at `36e28e73`. That stays the
build-of-record and is not rewritten.

It remains valid for any descendant commit that changes **no build input**. The
compiled sources, `CMakeLists.txt`, `cmake/`, `unittests/` and
`packaging/linux/dev/Dockerfile` are build inputs. `openspec/`, `AGENTS.md`,
`.gitignore` and this file are not.

Commit `255e5c7` ("docs(openspec): track the network-parity change set and dev
container") is such a descendant. It only began tracking files that were already
present in the working tree when the baseline was built — the Dockerfile's
`COPY . /src` copies untracked files, and `openspec/`, `packaging/linux/dev/` and
the patched `build.sh` were all verified present inside the baseline image. Not one
byte the compiler consumed changed, so the compile and test results below still
hold and no rebuild was performed.

`AGENTS.md` postdates the baseline image and was therefore *not* inside it. It is
documentation, referenced by neither `Dockerfile` nor `CMakeLists.txt`, so it is
not a build input either.

**When this does not apply:** the moment any commit touches a build input, this
record is stale. Re-establish it with `packaging/linux/build.sh dev` and add a new
record rather than editing this one.

## Toolchain

| Component | Version |
| --- | --- |
| Base | Ubuntu 22.04.5 LTS |
| Architecture | `aarch64` (`linux/arm64`, native on an Apple Silicon host — no emulation) |
| Compiler | g++ (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0 |
| CMake | 3.22.1 |
| wxWidgets | 3.2.6 (built from source — Ubuntu 22.04 does not package 3.2.x) |
| libupnp | 22.0.4 (built from source — Ubuntu ships only the 1.8.x line) |
| libboost-dev | 1.74.0.3ubuntu7 |
| libcrypto++-dev | 8.6.0-2ubuntu1 |
| libgd-dev | 2.3.0-2ubuntu2.3 |
| libmaxminddb-dev | 1.5.2-1build2 |

Configured with `-DBUILD_TESTING=YES -DBUILD_MONOLITHIC=YES -DBUILD_DAEMON=YES
-DBUILD_REMOTEGUI=YES` — all three apps, per the project rule in `AGENTS.md:21`:
the preprocessor split means a change can compile in two of the three and break
the third, so a baseline covering only two is not a baseline for anything a
change will be judged against.

An earlier attempt omitted `BUILD_DAEMON` and was re-run; the digest above is
the three-app build.

## Compile result

**PASS.** All targets built with no errors. Confirmed present in the image:

| Binary | Path |
| --- | --- |
| `amule` (monolithic GUI) | `/src/build/src/amule` |
| `amuled` (daemon) | `/src/build/src/amuled` |
| `amulegui` (remote GUI) | `/src/build/src/amulegui` |

## Test result

**36 of 37 pass. One pre-existing failure.**

```
97% tests passed, 1 tests failed out of 37
Total Test time (real) = 2.73 sec

The following tests FAILED:
	  6 - FileDataIOTest (SEGFAULT)
```

### Pre-existing failures — the attribution baseline

| # | Test | Mode |
| --- | --- | --- |
| 6 | `FileDataIOTest` | SEGFAULT |

**`FileDataIOTest` segfaults on unmodified upstream code.** Any later change that
sees this test fail has NOT caused it. Do not attribute it, do not block on it,
and do not "fix" it as part of a parity change.

It is worth investigating on its own merits — a segfaulting test is a real
defect, and `FileDataIO` is I/O code that several parity changes will touch.

### Resolved 2026-08-24 — and the guess below was wrong

The two questions this section originally left open were:

- *Whether it is architecture-specific.* It proposed an `x86_64` run under QEMU to
  find out.
- *Whether upstream CI sees it.*

**It is not architecture-specific.** It is static initialisation order, and the
proposed `x86_64` run would have reproduced the same crash and taught us nothing.

The test held its path as a file-scope `const CPath`. `CPath`'s constructor
converts through `wxConvFileName`, which wxWidgets assigns from a dynamic
initialiser in `strconv.cpp`, and relative order between translation units is
unspecified. With wxWidgets linked statically — which this image does — the
executable's `.init_array` entries run before the library's, so the file-scope
`CPath` dereferences a null `wxConvFileName` and the process dies before any test
body runs. Fixed in `91bd513` with a function-local static, which the standard
guarantees is initialised on first use. Seven test cases and 197 assertions before
and after; none removed, none weakened.

That also answers the second question: a dynamically linked wxWidgets initialises
in a different order, so upstream CI may legitimately never have seen it.

**The record above stays as written.** `FileDataIOTest` did segfault at
`36e28e73`, and that is what makes it the attribution baseline's honest data point.
What changed is that the tree is now fully green, so from `91bd513` onward **any**
failing test is attributable to the change that introduced it — a stronger
position than a tolerated red.

## Reproducing

```
packaging/linux/build.sh dev          # host arch
```

### The build tag is not stable — use the durable tag

`build_dev` writes a fixed tag, `amule-dev:<arch>`. Every later run of
`packaging/linux/build.sh dev` — including runs made while implementing a change —
**overwrites it**, and the previous image is left untagged and becomes eligible for
`podman image prune`. The tag therefore names "whatever was built last", not this
baseline.

This was observed on 2026-08-23: an implementation build moved
`amule-dev:aarch64` to `sha256:bb0790d8...` while this record still named
`sha256:8b5f950e...`. The baseline image survived only as a dangling image and was
rescued with a tag that no build writes:

```
podman tag <image-id> amule-baseline:36e28e73
```

Consequences for anyone using this record:

- To run the baseline, address it by the durable tag or by digest, never by
  `amule-dev:aarch64`:
  ```
  podman run --rm amule-baseline:36e28e73 /src/build/src/amuled --version
  ```
- Do not `podman image prune` while this baseline matters — an untagged baseline
  is one prune away from unreproducible without a full rebuild.
- Measuring anything against `amule-dev:aarch64` risks measuring a change's code
  while believing it is the baseline.

Nothing is installed on the host. Requirements: a container runtime whose VM has
enough memory to build wxWidgets from source — 2 GiB is not enough, 8 GiB is
comfortable.

## Notes on getting here

Three failures preceded this record, none of them in aMule's code. They are
listed because they are exactly what a baseline is for — each one would have been
misattributed to a code change if it had surfaced mid-implementation:

1. `docker buildx --load` is rejected by podman's buildx shim (buildah).
2. `docker` existed only as a shell alias for `podman`, so it was absent inside
   the non-interactive shell running `build.sh`.
3. `uname -m` reports `arm64` on macOS where the script's arch case expected
   `aarch64`, leaving the container platform empty.

A fourth was in the dev image itself: `set -o pipefail` is unsupported by
`/bin/sh` (dash), which is the default shell for a `RUN` layer.

### Upstream finding, not fixed here

The arch-normalisation gap in (3) exists in five places in `packaging/linux/build.sh`
(lines 75, 167, 243, 384, 485), affecting `build_appimage`, `build_static`,
`build_flatpak` and `validate`. All of them fail the same way when invoked with
`host` on a macOS host. Only `build_dev` was fixed, to keep the diff scoped. This
is worth an upstream issue.

---

# Reference point after phases 1-5

**This is not a baseline of unmodified code.** It is the reference the remaining
changes are measured against. The attribution baseline above still stands and is
still the only thing that can tell you a failure predates this work.

## Why a second record exists

The "Validity beyond the build commit" rule above says this file goes stale the
moment a commit touches a build input, and that the fix is a new record rather than
an edit to the old one. `amule-utp-transport` did exactly that: it added
`-DENABLE_UTP=YES` to `packaging/linux/dev/Dockerfile`, so the verification build
compiles the uTP adapter. That was deliberate and it paid for itself immediately —
with `ENABLE_UTP=OFF` the build had been hiding a typedef collision between
libutp's global `int64`/`byte` and `src/Types.h` plus `std::byte`, invisible until
the adapter was actually compiled.

## Subject

| | |
| --- | --- |
| Commit | `f989cb5` (merge of phases 4 and 5) |
| Durable tag | `localhost/amule-phases1-5:f989cb5` |
| Image digest | `sha256:78ac496ce6ea2bac2c65088b24d445036688fc717e2ca3b3501aefe776bad3a5` |
| Command | `packaging/linux/build.sh dev` |
| Build configuration | as before, plus `-DENABLE_UTP=YES` |
| Toolchain | unchanged from the attribution baseline above |

## Result

**Three apps built. 54 of 55 tests pass.**

```
98% tests passed, 1 tests failed out of 55

The following tests FAILED:
	  9 - FileDataIOTest (SEGFAULT)
```

`src/extern/libutp/libutp.a` (86 KB) is present, so uTP genuinely compiled rather
than being configured away.

`FileDataIOTest` is the same pre-existing SEGFAULT as at `36e28e73`. It was never
attributable to any change in this set, and it has since been diagnosed and fixed
in `91bd513` — see "Resolved 2026-08-24" above. Builds from that commit onward are
expected to be **fully green**, so treat any failing test as attributable.

## Reading the test count

37 at the attribution baseline, 55 here. The suites each change added:

| Change | Suites added |
| --- | --- |
| `amule-peer-capability-recognition` | 3 |
| `amule-kad-protocol-catchup` | 3 |
| `amule-address-widening` | 2 |
| `amule-dual-stack-reachability` | 5 + 1 for the peer-identity widening |
| `amule-utp-transport` | 5 |

A change whose total does not move added no paired unit tests, which the
`tasks.md` rule requires. Identify failures **by name**: adding a suite renumbers
ctest, so `FileDataIOTest` was test 6 in one branch and test 9 in another, and
comparing indices manufactures regressions that do not exist.

## Addressing the images

Never `amule-dev:aarch64`. `build_dev` writes that fixed tag on every run, so it
names whatever was built last — including another agent's branch. Both records here
are reachable by durable tag or by digest:

```
podman run --rm amule-baseline:36e28e73    /src/build/src/amuled --version   # attribution
podman run --rm amule-phases1-5:f989cb5    /src/build/src/amuled --version   # reference
```

## Why a third record exists

The second record was taken at `f989cb5`. HEAD has since moved through two
upstream integrations (31 commits, then 24), and `packaging/linux/build.sh dev`
— the only route that produces a record — could not run at all: it passed
`WX_TARBALL_URL` and `WX_SHA256`, which upstream #1238 retired from
`versions.env` when it moved wxWidgets to a pinned git commit. Under `set -u`
that aborted before podman was invoked.

That target is fork-only, so #1238 updated the appimage and static targets it
could see and stranded this one. Fixed in `078045842` by fetching the pinned SHA
the way the other two already do.

Recorded here rather than replacing either earlier record. The attribution
baseline at `36e28e73` still answers "was this failure already there"; this one
answers "did I regress it" for work starting now.

## Subject

| | |
|---|---|
| Commit | `9e76ae434` |
| Tree | unmodified at the time of the run |
| Image digest | `sha256:94949affb0fce4d6306efce0437cb1ebab8016f25c372f045b8e3bc94888d8aa` |
| Route | `packaging/linux/build.sh dev`, aarch64, `platform=linux/arm64`, `cli=podman` |

## Toolchain

| | |
|---|---|
| cmake | 3.22.1 |
| c++ | Ubuntu 11.4.0-1ubuntu1~22.04.3 (GCC 11.4.0) |
| wxWidgets | 3.2.12 — built from git at `WX_COMMIT`, not a release tarball |
| libupnp | 22.0.4 |
| libboost-dev | 1.74.0.3ubuntu7 |
| libcrypto++-dev | 8.6.0-2ubuntu1 |
| libgd-dev | 2.3.0-2ubuntu2.3 |
| libmaxminddb-dev | 1.5.2-1build2 |

## Result

Build exit 0. **78 of 78 ctest suites passed, 0 failed.** No pre-existing
failures at this commit, so the two the attribution baseline records as
pre-existing are resolved and nothing has replaced them.

Suites are identified by name in this project, never by index: the count moves
as suites are added, and an index that meant one suite last week means another
this week.
