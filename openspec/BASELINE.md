# Build baseline

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
Two things are unknown and should not be assumed:

- **Whether it is architecture-specific.** This baseline is `aarch64` only.
  Confirming or ruling out an arm64-specific cause needs an `x86_64` run
  (`packaging/linux/build.sh dev x86_64`), which requires binfmt and runs under
  QEMU emulation.
- **Whether upstream CI sees it.** If upstream CI is x86_64-only and green, that
  is evidence for an arm64-specific fault.

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
