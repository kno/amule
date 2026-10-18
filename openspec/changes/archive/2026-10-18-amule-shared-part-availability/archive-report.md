# Archive report: amule-shared-part-availability

Archived 2026-10-18.

## Outcome

Implemented and merged upstream in amule-org/amule:

- #1218 "fix(gui): name the two chunk-bar columns apart, and explain their colours", merged 2026-08-31 as `821e34e8b`.
- #1282 "feat(gui): name the shared-files bar for what it shows, and give it a legend", merged 2026-09-04 as `5c3df561c`.

Related: #1204 (amuleapi part indices). Issue #1220 is closed.

## Verification

Tasks 1-5 were checked during apply. Tasks 6.1-6.3 (clang-format 18, clang-tidy Tier-2, monolithic + daemon + remotegui build with ctest) are marked done on the evidence of upstream CI on the merged PR heads: #1218 (`12746c561`) and #1282 (`19d7d7376`) each passed 14/14 checks, including Check clang-format, clang-tidy whole tree (Tier-1), clang-tidy changed lines (Tier-2) and the CMake builds. They were not re-run locally for this archive.

## Specs

The delta spec `specs/shared-file-availability-bar/spec.md` is promoted to `openspec/specs/shared-file-availability-bar/spec.md` as a standalone capability spec. Its ADDED requirements become its requirements; no existing spec was modified.
