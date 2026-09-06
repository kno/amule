#! /bin/bash
#
# The checks CI runs that do not need a full build, run locally against the
# working tree. Every one of them exists because it caught something the
# container baseline did not: see the comment on each.
#
# Usage:
#   scripts/preflight.sh            # everything
#   scripts/preflight.sh ec         # one check by name: ec | format | i18n
#
# Exit status is the number of checks that failed, so a caller can gate on it.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

CLANG_FORMAT_IMAGE="ghcr.io/jidicula/clang-format:18"

FAILED=0

# Resolve a container CLI. `docker` is frequently only a shell alias for
# podman, which does not exist in this non-interactive bash.
resolve_container_cli () {
	if command -v docker >/dev/null 2>&1; then
		echo docker
	elif command -v podman >/dev/null 2>&1; then
		echo podman
	else
		echo ""
	fi
}

# Files this working tree changes against its merge base with upstream, which
# is the set CI judges. Falls back to the diff against HEAD when there is no
# upstream remote configured.
changed_files () {
	local base
	if git rev-parse --verify -q upstream/master >/dev/null; then
		base="$(git merge-base HEAD upstream/master)"
		git diff --name-only --diff-filter=ACMR "${base}" -- "$@"
	else
		git diff --name-only --diff-filter=ACMR HEAD -- "$@"
	fi
}

# --------------------------------------------------------------------------
# EC tag table
#
# Two tags may not share a value. The generated header switches over every
# one of them, so a collision is a duplicate case -- but only in the
# translation unit that carries the switch, which several build
# configurations do not compile at all. It reached CI once as a clang-tidy
# error after a local build passed.
#
# The total is checked as well as the collisions. Replacing the table
# wholesale with one from another branch drops this fork's own tags, and a
# shorter table has no duplicates either: absence looks exactly like health.
# --------------------------------------------------------------------------
check_ec () {
	echo "EC tag table"
	local abstract="src/libs/ec/abstracts/ECCodes.abstract"
	if [ ! -f "${abstract}" ]; then
		fail "${abstract} not found"
		return
	fi

	local out
	out="$(python3 - "${abstract}" <<'PY'
import collections, re, sys

values = collections.defaultdict(list)
for line in open(sys.argv[1], encoding="utf-8"):
    m = re.match(r"\s*(EC_TAG_[A-Z0-9_]+)\s+(0x[0-9a-fA-F]+)\s*$", line)
    if m:
        values[m.group(2).lower()].append(m.group(1))

dups = {k: v for k, v in values.items() if len(v) > 1}
total = sum(len(v) for v in values.values())
for value, names in sorted(dups.items()):
    print(f"DUP {value} {' '.join(names)}")
print(f"TOTAL {total}")
PY
)" || { fail "could not read the tag table"; return; }

	local total
	total="$(awk '/^TOTAL /{print $2}' <<<"${out}")"
	local dups
	dups="$(grep '^DUP ' <<<"${out}")"

	if [ -n "${dups}" ]; then
		fail "duplicate tag values"
		sed 's/^DUP /        /' <<<"${dups}"
		return
	fi

	# Absence is the other way this table breaks, and it does not look like
	# breakage: a table with tags missing has no duplicates either. Taking
	# this file wholesale from a branch cut off upstream drops every tag the
	# fork added, and the collision check above stays green while doing it.
	# Printing the total is not enough -- it was, and a mutilated table read
	# as healthy. So the names are compared against the committed ones.
	local lost
	lost="$(comm -23 \
		<(git show HEAD:"${abstract}" 2>/dev/null | grep -oE 'EC_TAG_[A-Z0-9_]+' | sort -u) \
		<(grep -oE 'EC_TAG_[A-Z0-9_]+' "${abstract}" | sort -u))"

	if [ -n "${lost}" ]; then
		fail "$(wc -l <<<"${lost}" | tr -d ' ') tag(s) present in HEAD have disappeared"
		sed 's/^/        /' <<<"${lost}"
		echo "        a tag is wire format: removing one is a protocol change, not a cleanup"
	else
		pass "${total} tags, no duplicates, none lost against HEAD"
	fi
}

# --------------------------------------------------------------------------
# clang-format
#
# Checked on the files this branch changes, whole-file, exactly as
# clang-format.yml does. Renaming a symbol to a longer one silently unaligns
# every trailing comment it appears in, which is how five files reached CI
# unformatted after a rename that touched seventeen.
# --------------------------------------------------------------------------
check_format () {
	echo "clang-format"
	local cli
	cli="$(resolve_container_cli)"
	if [ -z "${cli}" ]; then
		fail "no container CLI found (looked for docker, podman)"
		return
	fi

	# Not mapfile: this has to run under the bash 3.2 macOS ships, where that
	# builtin does not exist. It failed there while the summary still read
	# "all checks passed", which is worse than having no check at all.
	# The same scope clang-format.yml uses: src and unittests, minus
	# src/extern. That directory holds vendored third-party code kept
	# byte-identical to upstream (see src/extern/libutp/AMULE_PROVENANCE.md);
	# reformatting it to satisfy this check would break that guarantee, which
	# is why CI excludes it rather than fixing it.
	local files=()
	local line
	while IFS= read -r line; do
		case "${line}" in
			src/extern/*) continue ;;
			src/*|unittests/*) files+=("${line}") ;;
		esac
	done < <(changed_files '*.h' '*.cpp' '*.c')

	if [ "${#files[@]}" -eq 0 ]; then
		pass "no C/C++ files changed"
		return
	fi

	local bad=()
	local f
	for f in "${files[@]}"; do
		[ -f "${f}" ] || continue
		# --Werror turns a diff into a non-zero status. Diagnostics go to
		# stderr, so they are deliberately not discarded: silencing them
		# turns a violation into a silent pass.
		if ! "${cli}" run --rm -i \
			-v "${REPO_ROOT}:/w" -w /w \
			"${CLANG_FORMAT_IMAGE}" \
			--style=file:/w/.clang-format --dry-run --Werror "${f}" 2>/dev/null; then
			bad+=("${f}")
		fi
	done

	if [ "${#bad[@]}" -gt 0 ]; then
		fail "${#bad[@]} of ${#files[@]} changed files are unformatted"
		printf '        %s\n' "${bad[@]}"
		echo "        fix: ${cli} run --rm -i -v ${REPO_ROOT}:/w -w /w ${CLANG_FORMAT_IMAGE} --style=file:/w/.clang-format -i <file>"
	else
		pass "${#files[@]} changed files formatted"
	fi
}

# --------------------------------------------------------------------------
# Translation catalogs
#
# i18n.yml regenerates and fails on any content drift. Regenerating before a
# later edit renames a user-facing string leaves the catalogs describing the
# old source, which is green locally and red in CI.
#
# The tree must be clean of catalog changes first, or this cannot tell drift
# it found from drift that was already staged for commit.
# --------------------------------------------------------------------------
check_i18n () {
	echo "translation catalogs"
	if ! command -v xgettext >/dev/null 2>&1 || ! command -v msgmerge >/dev/null 2>&1; then
		fail "gettext not installed (need xgettext and msgmerge)"
		return
	fi

	if [ -n "$(git status --porcelain -- po/)" ]; then
		fail "po/ has uncommitted changes; commit or stash them first"
		return
	fi

	if ! bash scripts/update-po.sh >/dev/null 2>&1; then
		fail "scripts/update-po.sh returned non-zero"
		git checkout -- po/ 2>/dev/null
		return
	fi

	# POT-Creation-Date moves on every run and is not content.
	local drift
	drift="$(git diff --name-only -- po/ | while read -r f; do
		if git diff -U0 -- "${f}" | grep -qE '^[+-][^+-]' \
			&& git diff -U0 -- "${f}" | grep -E '^[+-][^+-]' | grep -qvE '^[+-]"POT-Creation-Date'; then
			echo "${f}"
		fi
	done)"

	if [ -n "${drift}" ]; then
		fail "catalogs out of sync with source"
		sed 's/^/        /' <<<"${drift}"
		echo "        fix: bash scripts/update-po.sh && git add po/"
	else
		pass "catalogs in sync"
		git checkout -- po/ 2>/dev/null
	fi
}

usage () {
	echo "usage: $0 [ec|format|i18n]" >&2
	exit 2
}

# Every check must report. A check that dies -- an unset variable, a builtin
# this bash does not have -- reaches the summary having incremented nothing,
# and silence then reads as success. Counting what was expected against what
# reported makes that impossible: an aborted check is a failure, not a pass.
EXPECTED=0
REPORTED=0
pass () { printf '  \033[32mOK\033[0m    %s\n' "$1"; REPORTED=$((REPORTED + 1)); }
fail () { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAILED=$((FAILED + 1)); REPORTED=$((REPORTED + 1)); }

run_check () {
	EXPECTED=$((EXPECTED + 1))
	"$1"
}

case "${1:-all}" in
	all)    run_check check_ec; run_check check_format; run_check check_i18n ;;
	ec)     run_check check_ec ;;
	format) run_check check_format ;;
	i18n)   run_check check_i18n ;;
	-h|--help) usage ;;
	*)      echo "unknown check '${1}'" >&2; usage ;;
esac

echo
if [ "${REPORTED}" -ne "${EXPECTED}" ]; then
	echo "preflight: ${EXPECTED} check(s) requested but only ${REPORTED} reported -- one aborted"
	exit 1
fi
if [ "${FAILED}" -eq 0 ]; then
	echo "preflight: all ${EXPECTED} checks passed"
else
	echo "preflight: ${FAILED} of ${EXPECTED} check(s) failed"
fi
exit "${FAILED}"
