# Tasks: establish a build baseline

The whole point of this change is to prove the tree builds **without installing
a toolchain on the host**. Everything below runs in a container.

## 1. Container runtime

- [x] 1.1 Confirm a container runtime is available and its VM is running
      (`podman machine list`, or Docker Desktop)
- [x] 1.2 Confirm it has enough resources — wxWidgets builds from source, so
      2 GiB is not enough. 8 GiB / 8 CPUs is comfortable
- [x] 1.3 Confirm the target arch is the host arch, so no QEMU emulation is
      involved (`uname -m` vs the container platform)

## 2. Baseline build and test

- [x] 2.1 Confirm the working tree is clean and record the commit SHA
- [x] 2.2 Run `packaging/linux/build.sh dev`
- [x] 2.3 N/A — the compile layer passed (491/491 targets)
- [x] 2.4 If it fails at the `ctest` layer, that is a **test** failure — capture
      every failing test name; these become the pre-existing-failure list
- [x] 2.5 Honoured — no source was modified to make either layer pass. An environment or
      upstream failure is a finding to report, not work to absorb

## 3. Record

- [x] 3.1 Capture `/baseline-toolchain.txt` from the image (the `dev` target
      prints it on success)
- [x] 3.2 Record the image digest — more reproducible than host package versions
- [x] 3.3 Write `openspec/BASELINE.md`: commit SHA, image digest, toolchain
      provenance, the exact command, and pass/fail/skip counts
- [x] 3.4 List pre-existing failures prominently — they are the attribution
      baseline for every later change
- [x] 3.5 State explicitly that the record is valid only for the named commit

## 4. Correct the recorded commands

- [x] 4.1 `openspec/config.yaml` carries `build_command` / `test_command` marked
      UNVERIFIED — they were read out of `CMakeLists.txt`, never executed
- [x] 4.2 Replace them with the container invocation that actually worked, and
      drop the UNVERIFIED marker
- [x] 4.3 Note any discrepancy between what was recorded and what worked

## 5. Keep the dev image honest

- [ ] 5.1 `packaging/linux/dev/Dockerfile` copies its dependency list from
      `appimage/Dockerfile`. If that list changes upstream, sync it
- [ ] 5.2 Consider offering the `dev` target upstream — it is useful to aMule
      independently of this parity work

## Outcome

Baseline established 2026-08-23 at commit `36e28e73`. Compile PASS (491/491
targets). Tests 36/37, with `FileDataIOTest` segfaulting pre-existing. Record in
`openspec/BASELINE.md`; image digest
`sha256:28acd8529250bcbc72a9d332524d855964461813879e5b2cde2ae5c9df8f5362`.

Tasks 5.1 and 5.2 remain open on purpose — they are ongoing maintenance, not
part of establishing this baseline.
