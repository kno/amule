# SDD context — amule-shared-part-availability

Recorded by `sdd-init`. This file and this directory are ordinary tracked
paths in the fork, same as `openspec/changes/amule-quic-transport` and the
archived changes — commit them normally.

**Real invariant**: `openspec/` artifacts belong to the fork only. `upstream/
master` carries no `openspec/` tree (verified: `git ls-tree upstream/master`
and `git ls-tree` of upstream-PR branches such as `feat/webui-file-clients`
and `feat/webui-download-button` return zero entries for it). Any branch
intended for an upstream PR MUST be cut from `upstream/master`, not from a
branch that includes `openspec/`, so it never carries these files. This is a
delivery-path constraint, not a git-exclusion rule — do not add anything to
`.gitignore` or `.git/info/exclude` for this.

## Project

- Repo: `github.com/kno/amule` (fork), upstream `github.com/amule-org/amule`.
- Stack: C++ (C++17, `CMAKE_CXX_STANDARD 17` required), wxWidgets GUI,
  Boost.Asio socket backend, CMake build, cross-platform (built here on macOS).
- HEAD at init time: `ea399c8c1374c2964b516b124c3d1a5fc0a23252`.
  `openspec/BASELINE.md` currently names `36e28e73` (2026-08-22) — HEAD has
  moved since. Per `openspec/config.yaml` apply preconditions this is a HARD
  GATE: re-establish the baseline (`packaging/linux/build.sh dev`) before any
  source file is modified for this change.

## Build & test (verified, not guessed)

- Canonical build/test path is the container recipe:
  `packaging/linux/build.sh dev` — do not assume a host toolchain.
- Host-only out-of-tree recipe that has been made to work directly on macOS
  (no container) for wx-free logic:
  `cmake -B /tmp/<name> -S . -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=YES -DBUILD_MONOLITHIC=YES -DCMAKE_PREFIX_PATH=/opt/homebrew -DCMAKE_CXX_FLAGS=-I/opt/homebrew/include -DCMAKE_C_FLAGS=-I/opt/homebrew/include`
  A bare in-source `cmake .` configure fails on Boost/cryptopp discovery on
  this host. `rm -rf build` has previously failed against held files, hence
  out-of-tree builds.
- Test runner: `ctest` (invoked as `ctest --test-dir build --output-on-failure`
  inside the container, or `ctest --test-dir /tmp/<name>` for the host
  out-of-tree build). **Identify failing suites by NAME, never by index** —
  indices shift as suites are added.
- `docker` on this machine is a **fish alias for `podman`**; scripts and Bash
  invocations must call `podman` directly, never rely on the alias.
- clang-format is pinned to major version 18 and CI enforces it:
  `podman run --rm -i -v "$PWD:/w" -w /w ghcr.io/jidicula/clang-format:18 --dry-run --Werror <file>`.
  The image entrypoint already is the `clang-format` binary — do not pass
  `clang-format` again as an argument.
- clang-tidy runs in CI in two tiers; the Tier-2 changed-lines gate has
  already failed once on `modernize-loop-convert` for this project. Avoid
  writing new code that trips obvious modernize/readability-loop-convert
  patterns.
- i18n: any user-visible string change requires running
  `./scripts/update-po.sh` (rewrites 40 catalogues) and
  `./scripts/check-potfiles.sh` must exit 0. Regeneration is
  content-idempotent — a re-run only changes `POT-Creation-Date`, which the
  CI workflow's drift check strips before comparing.
- No display session is available in this environment: wxWidgets dialogs
  cannot be opened or screenshotted. GUI layout/interaction is a standing
  verification limitation here — only logic factored into wx-free headers is
  locally verifiable (host TDD pattern already used elsewhere in this repo).

## Process

- Strict TDD is enabled for this session: write a failing test first, then
  the implementation.
- `execution_mode`: interactive
- `artifact_store`: openspec
- `delivery_strategy`: auto-chain
- `review_budget_lines`: 800
