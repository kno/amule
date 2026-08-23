# build-baseline

## Requirements

### Requirement: Baseline precedes modification

No source file MAY be modified for any change in this set until a baseline build
of the unmodified tree has been recorded.

#### Scenario: Agent starts work with no baseline on record

- GIVEN no `openspec/BASELINE.md` exists, or the one present names a different commit
- WHEN an agent begins any change in this set
- THEN it MUST establish the baseline first
- AND MUST NOT edit any source file before the baseline is recorded

#### Scenario: Baseline cannot be achieved

- GIVEN the unmodified tree does not build in the current environment
- WHEN the cause is a missing or broken toolchain
- THEN the agent MUST report the environment failure and STOP
- AND MUST NOT begin implementation work
- AND MUST NOT modify source in an attempt to make the build succeed

### Requirement: Baseline requires no host toolchain

Establishing the baseline MUST NOT require installing compilers, build tools or
library development packages on the host.

#### Scenario: Host has no build toolchain

- GIVEN a host with a container runtime but no cmake, wxWidgets or pkg-config
- WHEN the baseline is established
- THEN it MUST complete using only the container runtime
- AND no package MUST be installed on the host

#### Scenario: Container resources insufficient

- GIVEN a container VM with too little memory to build wxWidgets from source
- WHEN the baseline build fails on resource exhaustion
- THEN the failure MUST be reported as an environment limit, not a code failure
- AND MUST NOT be recorded as a pre-existing test failure

### Requirement: Recorded baseline contents

`openspec/BASELINE.md` MUST record the commit, the operating system and compiler
versions, every dependency version the build resolved, the exact configure and
build invocation used, and the test outcome.

#### Scenario: Pre-existing test failure

- GIVEN the baseline test run has failures on the unmodified tree
- WHEN the baseline is recorded
- THEN each failing test MUST be listed by name as pre-existing
- AND a later change MUST NOT be judged to have caused a listed failure

#### Scenario: Recorded command proves wrong

- GIVEN the `build_command` in `config.yaml` does not work
- WHEN a working invocation is found
- THEN `config.yaml` MUST be corrected to the working invocation
- AND the discrepancy MUST be noted in the baseline record

### Requirement: Baseline validity is commit-scoped

A baseline MUST be treated as valid only for the commit it names.

#### Scenario: Upstream moved

- GIVEN a recorded baseline naming commit A
- WHEN the working tree is now at commit B
- THEN the baseline MUST be re-established before further implementation
- AND the previous record MUST be retained rather than overwritten

### Requirement: Failure attribution on every change

Before reporting a build or test failure inside a change, the agent MUST
establish whether the same failure occurs on the unmodified baseline.

#### Scenario: Failure that also occurs on baseline

- GIVEN a test fails while a change is in progress
- WHEN the same test is listed as a pre-existing failure in the baseline
- THEN the failure MUST NOT be attributed to the change
- AND the change MUST NOT be blocked on it
