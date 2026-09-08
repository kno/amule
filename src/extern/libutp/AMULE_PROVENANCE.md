# Vendored libutp — provenance

This directory is a **vendored copy of third-party code**. It is not aMule code.
Do not add aMule copyright headers to any file here, and do not reformat or
"clean up" the sources: every local edit makes the next version bump harder and
makes this note less true.

## Upstream

| | |
|---|---|
| Project | libutp — the uTP (Micro Transport Protocol) reference implementation |
| Upstream URL | <https://github.com/transmission/libutp> |
| Pinned commit | `490874c44a2ecf914404b0a20e043c9755fff47b` (2024-11-16) |
| Version | 3.4 (`project(libutp VERSION 3.4 ...)`) |
| License | MIT — "Copyright (c) 2010-2013 BitTorrent, Inc.", see `LICENSE` |
| Vendored size | 5143 lines of C/C++ across the sources and headers below |

### Why `transmission/libutp` and not `bittorrent/libutp`

Two forks of the same code exist and the choice is not obvious, so it is recorded
rather than left to be re-derived. `bittorrent/libutp` is the original and is the
one other ports of this work pin, but it has seen no maintenance in years.
`transmission/libutp` is the fork Transmission actually ships and keeps building:
it carries the CMake packaging this vendoring relies on, the `libutp/` include
prefix used throughout, and fixes the original never received. The licence is the
same MIT and the copyright line still names BitTorrent, Inc., so nothing about
attribution changes with the choice.

Anyone comparing this tree against a port that pins `bittorrent/libutp` should
expect the sources to differ, and should not treat that as drift in either copy.

MIT code inside a GPL-2-or-later project is fine, but only for as long as the
notice travels with the code. `LICENSE` is copied verbatim and must stay that
way. `docs/THIRDPARTY.md` records the same attribution at the repository level.

## Reproducing this tree

```sh
git clone https://github.com/transmission/libutp /tmp/libutp
git -C /tmp/libutp checkout 490874c44a2ecf914404b0a20e043c9755fff47b

# Everything that the CMake target needs, plus the licence and readme.
cd /tmp/libutp
mkdir -p <amule>/src/extern/libutp/include/libutp
cp include/libutp/utp.h include/libutp/utp_types.h \
   <amule>/src/extern/libutp/include/libutp/
cp CMakeLists.txt LICENSE README.md config.cmake.in \
   libutp_inet_ntop.cpp libutp_inet_ntop.h \
   utp_api.cpp utp_callbacks.cpp utp_callbacks.h \
   utp_hash.cpp utp_hash.h utp_internal.cpp utp_internal.h \
   utp_packedsockaddr.cpp utp_packedsockaddr.h utp_templates.h \
   utp_utils.cpp utp_utils.h \
   <amule>/src/extern/libutp/
```

## Local patches

**None.** Every file here is byte-identical to the pinned upstream commit.

There was one mismatch to reconcile: upstream declares its library target as
`libutp` (`add_library(libutp ...)`, with `OUTPUT_NAME utp`), whereas
`cmake/libutp.cmake` originally required a target literally named `utp` and
raised `FATAL_ERROR` otherwise. That was fixed **on the aMule side** — the
bundled branch of `cmake/libutp.cmake` now looks for `libutp` and aliases it as
`Utp::Utp` — deliberately, rather than by editing the vendored
`CMakeLists.txt`. Call sites still link `Utp::Utp` and did not change.

## What was deliberately left out of the upstream tree

Vendor what builds, not the whole repository:

| Omitted | Why |
|---|---|
| `.git/` | This is a vendored snapshot, not a submodule. The pinned commit above is the record. |
| `.github/`, `.gitignore` | Upstream CI and ignore rules; meaningless inside this tree. |
| `libutp.vcxproj`, `libutp-2012.vcxproj.filters`, `prop_sheets/` | Visual Studio project files. aMule builds libutp through `add_subdirectory` and the vendored `CMakeLists.txt`. |
| `Makefile` | Upstream's hand-rolled standalone build. Not the route aMule uses. |
| `ucat.c` | The `ucat` sample program. Built only under `LIBUTP_BUILD_PROGRAMS`, which defaults to `LIBUTP_STANDALONE_BUILD` and is therefore OFF when added as a subdirectory. |
| `parse_log.py` | An upstream log-analysis helper, unused by the build. |

`libutp_inet_ntop.{cpp,h}` **are** kept even though they are compiled only under
`WIN32`: they are listed in the vendored `CMakeLists.txt`, so dropping them
would break a Windows build for no gain.

`config.cmake.in` is kept for the same reason — it is consumed by the upstream
install block, which is disabled in our subdirectory build but is part of the
file set the vendored `CMakeLists.txt` refers to.

## How it is built here

`cmake/libutp.cmake`, bundled branch: `add_subdirectory(... EXCLUDE_FROM_ALL)`,
then `add_library(Utp::Utp ALIAS libutp)`. `LIBUTP_STANDALONE_BUILD` evaluates
false because this is not the top-level project, so upstream's `-Werror`,
install rules, and `ucat` are all off. Third-party code compiling with warnings
is expected; if a compile flag is ever needed to build it, set it in
`cmake/libutp.cmake` against the `libutp` target — not in these sources.
