# Proposal: Establish a build baseline

## Intent

Prove that the unmodified tree builds and passes its own tests on the machine
doing the work, and record that result, before any parity change is started.

## Why this gates everything

Without a recorded baseline, the first failure in any later change is
unattributable. An agent that cannot build change 5 has no way to distinguish:

- the change is wrong
- the environment was never able to build this project
- the environment could build it yesterday and something drifted

All three produce the same red output. The first is worth debugging; the other
two waste the entire session and, worse, invite "fixes" to working code.

## This is not hypothetical

The `build_command` currently recorded in `openspec/config.yaml` was derived by
reading `CMakeLists.txt`. It has never been executed. As of writing, on the
machine where these artifacts were authored, it **cannot** be executed:

| Tool | State |
| --- | --- |
| `cmake` | not installed |
| `wxwidgets` | not installed |
| `pkg-config` | not installed |
| `libupnp` | not installed |
| `libmaxminddb` | not installed |
| `cryptopp` | not installed |
| `boost` | 1.90.0 present |
| compiler | Apple clang 21.0.0 present |

So the very first thing an agent would have hit is a toolchain failure with no
prior successful build to compare against — exactly the ambiguity this change
removes.

## No host toolchain required

The baseline runs in a container, so establishing it installs nothing on the
host. aMule already ships container builds for packaging (`static/`,
`appimage/`), but neither runs tests and the static one excludes the GUI — so
this change adds `packaging/linux/dev/Dockerfile` and a `build.sh dev` target
that build with `BUILD_TESTING=YES` and run `ctest`. A successful image build
*is* the baseline evidence, and the recorded image digest is more reproducible
than a list of host package versions.

The dependency list is copied from `appimage/Dockerfile`, which tracks the CI
Ubuntu job, rather than guessed — including the two non-obvious cases where
Ubuntu 22.04's packages are unusable and the pinned version is built from
source instead (wxWidgets 3.2.x, libupnp 22.x).

## Deliverable

A recorded, reproducible baseline: `openspec/BASELINE.md` carrying the commit,
the toolchain versions, the exact configure and build invocation, the test
result, and any pre-existing failures. Pre-existing failures matter as much as
successes: a test that was already red must be known to be already red, or the
first change to touch that area will be blamed for it.

## Scope

In scope: making the unmodified tree build, recording how, recording what already
fails, and correcting `config.yaml` if the recorded commands prove wrong.

Out of scope: fixing anything that the baseline reveals to be broken upstream.
That is a finding to report, not work to absorb into this change.

## Dependencies

None. Blocks every other change in this set.
