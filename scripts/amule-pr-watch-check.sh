#!/usr/bin/env bash
# Report actionable activity in upstream threads and failed Actions runs in the fork.
# Silence means that every query completed and there is nothing new to report.
set -u

DIR=${STATE_DIR:-"$(cd "$(dirname "$0")" && pwd)"}
UPSTREAM_REPO=${UPSTREAM_REPO:-amule-org/amule}
FORK_REPO=${FORK_REPO:-kno/amule}
SELF=${SELF:-kno}
INTERVAL=${INTERVAL:-1800}
MERGED_WINDOW_DAYS=${MERGED_WINDOW_DAYS:-7}
FORK_RUN_WINDOW_DAYS=${FORK_RUN_WINDOW_DAYS:-7}
FAILS=0

emit() { printf '%s\n' "$*"; }

atomic_write() {
    local path=$1 value=$2 temporary
    temporary=$(mktemp "$DIR/.amule-watch.XXXXXX") || return 1
    if ! printf '%s' "$value" >"$temporary"; then
        return 1
    fi
    if ! mv -f "$temporary" "$path"; then
        return 1
    fi
}

cutoff_days_ago() {
    python3 - "$1" <<'PY'
import datetime
import sys
print((datetime.datetime.now(datetime.timezone.utc) -
       datetime.timedelta(days=int(sys.argv[1]))).strftime('%Y-%m-%dT%H:%M:%SZ'))
PY
}

open_prs() {
    gh pr list --repo "$UPSTREAM_REPO" --author "$SELF" --state open \
        --json number -q '.[].number' 2>/dev/null
}

involved_issues() {
    gh search issues --repo "$UPSTREAM_REPO" --involves "$SELF" --state open \
        --json number -q '.[].number' 2>/dev/null
}

recent_merged() {
    local cutoff
    cutoff=$(cutoff_days_ago "$MERGED_WINDOW_DAYS") || return 1
    gh pr list --repo "$UPSTREAM_REPO" --author "$SELF" --state merged --limit 60 \
        --json number,mergedAt \
        -q ".[] | select(.mergedAt != null and .mergedAt > \"$cutoff\") | .number" \
        2>/dev/null
}

number_list() {
    printf '%s\n' "$@" | grep -E '^[0-9]+$' | sort -un
}

contains_number() {
    printf '%s\n' "$1" | grep -qx "$2"
}

check_comments() {
    local n=$1 last rows newest id author body created
    last=$(cat "$DIR/last-$n.at" 2>/dev/null || true)
    rows=$(gh api "repos/$UPSTREAM_REPO/issues/$n/comments" --paginate \
        --jq '.[] | "\(.created_at)\t\(.id)\t\(.user.login)"' 2>/dev/null) || return 1
    [ -z "$rows" ] && return 0
    newest=$(printf '%s\n' "$rows" | cut -f1 | sort | tail -1)

    while IFS=$'\t' read -r created id author; do
        [ -z "$created" ] && continue
        if [ -n "$last" ] && ! [ "$created" \> "$last" ]; then
            continue
        fi
        [ "$author" = "$SELF" ] && continue
        body=$(gh api "repos/$UPSTREAM_REPO/issues/comments/$id" --jq .body 2>/dev/null) || return 1
        body=$(printf '%s' "$body" | tr '\n' ' ' | cut -c1-220)
        emit "COMENTARIO NUEVO en #$n por @$author: $body"
    done <<<"$rows"

    atomic_write "$DIR/last-$n.at" "$newest"
}

check_reviews() {
    local n=$1 last rows newest ids id alert
    last=$(cat "$DIR/rev-$n.id" 2>/dev/null || true)
    rows=$(gh api "repos/$UPSTREAM_REPO/pulls/$n/reviews" --paginate \
        --jq '.[] | select(.state != "COMMENTED") | .id' 2>/dev/null) || return 1
    newest=$(printf '%s\n' "$rows" | tail -1)
    [ -z "$newest" ] && return 0
    [ "$newest" = "$last" ] && return 0
    if [ -n "$last" ] && printf '%s\n' "$rows" | grep -qx "$last"; then
        ids=$(printf '%s\n' "$rows" | awk -v last="$last" 'seen { print } $0 == last { seen=1 }')
    else
        ids=$rows
    fi
    for id in $ids; do
        alert=$(gh api "repos/$UPSTREAM_REPO/pulls/$n/reviews/$id" \
            --jq "select(.user.login != \"$SELF\") | \"REVISION en el PR #$n por @\(.user.login): \(.state)\"" \
            2>/dev/null) || return 1
        [ -n "$alert" ] && emit "$alert"
    done
    atomic_write "$DIR/rev-$n.id" "$newest"
}

check_pr() {
    local n=$1 previous current output rc checks seen signature
    current=$(gh pr view "$n" --repo "$UPSTREAM_REPO" --json mergeable -q .mergeable 2>/dev/null) || return 1
    previous=$(cat "$DIR/state-$n.txt" 2>/dev/null || true)
    if [ "$current" != "$previous" ]; then
        atomic_write "$DIR/state-$n.txt" "$current" || return 1
        if [ "$current" = "CONFLICTING" ]; then
            emit "CONFLICTO en el PR #$n: master ha avanzado y ya no fusiona. Hace falta rebase con verificacion local."
        elif [ "$previous" = "CONFLICTING" ] && [ "$current" = "MERGEABLE" ]; then
            emit "PR #$n vuelve a fusionar limpio."
        fi
    fi

    output=$(gh pr checks "$n" --repo "$UPSTREAM_REPO" \
        --json name,bucket,completedAt,link \
        --jq '.[] | select(.bucket == "fail") | [.name, .completedAt, .link] | @tsv' \
        2>/dev/null)
    rc=$?
    if [ "$rc" -ne 0 ] && [ -z "$output" ]; then
        return 1
    fi
    signature=$(printf '%s\n' "$output" | awk 'NF' | LC_ALL=C sort)
    checks=$(printf '%s\n' "$signature" | awk 'NF { count++ } END { print count+0 }')
    seen=$(cat "$DIR/ci-$n.txt" 2>/dev/null || true)
    if [ "$seen" != "$signature" ]; then
        atomic_write "$DIR/ci-$n.txt" "$signature" || return 1
        if [ "$checks" -gt 0 ]; then
            emit "CI EN ROJO en el PR #$n: $checks comprobacion(es) fallando."
        fi
    fi
}

check_fork_runs() {
    local cutoff seen rows current_rows snapshot created id workflow title branch event url conclusion jobs job_list
    cutoff=$(cutoff_days_ago "$FORK_RUN_WINDOW_DAYS") || return 1
    seen=$(cat "$DIR/fork-runs.seen" 2>/dev/null || true)
    rows=$(gh api --paginate \
        "repos/$FORK_REPO/actions/runs?per_page=100&created=%3E%3D$cutoff" \
        --jq '.workflow_runs[] | select(.status == "completed" and (.event == "push" or .event == "workflow_dispatch")) | [.created_at, .id, .name, .display_title, .head_branch, .event, .html_url, .conclusion] | @tsv' \
        2>/dev/null) || {
        emit "AVISO: no se pudieron consultar las ejecuciones Actions del fork $FORK_REPO."
        return 1
    }
    snapshot=$(printf '%s\n' "$rows" | cut -f2 | grep -E '^[0-9]+$' | sort -un) || snapshot=""
    current_rows=$(printf '%s\n' "$rows" | awk -F '\t' '
        NF {
            key=$3 SUBSEP $5
            if (!(key in latest) || $1 > latest[key]) {
                latest[key]=$1
                row[key]=$0
            }
        }
        END { for (key in row) print row[key] }
    ')

    while IFS=$'\t' read -r created id workflow title branch event url conclusion; do
        [ -z "$created" ] && continue
        if [ -n "$seen" ] && printf '%s\n' "$seen" | grep -Fqx -- "$id"; then
            continue
        fi
        [ "$conclusion" = "failure" ] || continue
        jobs=$(gh api --paginate "repos/$FORK_REPO/actions/runs/$id/jobs?per_page=100" \
            --jq '.jobs[] | select(.conclusion == "failure") | .name' 2>/dev/null) || {
            emit "AVISO: no se pudieron consultar los trabajos fallidos de la ejecucion $id ($url)."
            return 1
        }
        job_list=$(printf '%s\n' "$jobs" | awk 'NR == 1 { out=$0; next } { out=out ", " $0 } END { print out }')
        [ -n "$job_list" ] || job_list="no disponibles"
        emit "ACTION EN ROJO en $FORK_REPO: run $id; workflow: $workflow; titulo: $title; rama: $branch; evento: $event; URL: $url; trabajos fallidos: $job_list"
    done <<<"$current_rows"

    atomic_write "$DIR/fork-runs.seen" "$snapshot"
}

run_round() {
    local ok=1 prs issues targets merged n
    if prs=$(open_prs); then :; else
        emit "AVISO: no se pudieron descubrir los PR abiertos del upstream."
        ok=0
        prs=""
    fi
    if issues=$(involved_issues); then :; else
        emit "AVISO: no se pudieron descubrir los issues abiertos relacionados del upstream."
        ok=0
        issues=""
    fi
    targets=$(number_list "$prs" "$issues")

    for n in $targets; do
        check_comments "$n" || ok=0
        if contains_number "$prs" "$n"; then
            check_reviews "$n" || ok=0
            check_pr "$n" || ok=0
        fi
    done

    if merged=$(recent_merged); then
        merged=$(number_list "$merged")
        for n in $merged; do
            contains_number "$targets" "$n" && continue
            check_comments "$n" || ok=0
            check_reviews "$n" || ok=0
        done
    else
        emit "AVISO: no se pudieron descubrir los PR fusionados recientes del upstream."
        ok=0
    fi

    check_fork_runs || ok=0
    [ "$ok" = 1 ]
}

while true; do
    if run_round; then
        FAILS=0
        round_ok=1
    else
        round_ok=0
        FAILS=$((FAILS + 1))
        if [ "${ONCE:-0}" = 1 ]; then
            emit "AVISO: la ronda del vigilante no pudo consultar GitHub por completo. No se informa silencio fiable."
        elif [ "$FAILS" -ge 3 ]; then
            emit "AVISO: el vigilante lleva $FAILS rondas sin poder consultar GitHub (token caducado o red). No esta vigilando por completo."
            FAILS=0
        fi
    fi
    if [ "${ONCE:-0}" = 1 ]; then
        [ "$round_ok" = 1 ] && exit 0
        exit 1
    fi
    sleep "$INTERVAL"
done
