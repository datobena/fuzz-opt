#!/usr/bin/env bash
# Onboard several OSS-Fuzz projects as upstream targets, PARALLEL at a time.
#
#   tools/onboard_upstream_batch.sh <work-dir> <project>[:<srcdir>] ...
#
# Each `onboard_upstream.py run` gets its own 5-CPU cpuset carved from 0-39 in
# order (slot 0 = 0-4, slot 1 = 5-9, ...), so concurrent builds never share a
# core. ":<srcdir>" overrides the $SRC clone dir (e.g. tink-cc:tink-cc).
# Env: PARALLEL (default 8, at most 8), SANITIZERS (all|address, default all),
#      OSS_FUZZ (the OSS-Fuzz checkout), COMMIT (default origin/master; resolved
#      to one sha up front so every project is vendored from the same commit).
#      COMPILE_TIMEOUT (seconds per compile, default 21600), RETRY_FAILED=1
#      (re-attempt non-address sanitizers recorded compile_failed).
# Logs: <work-dir>/<project>/batch.log. Every step is resumable: re-running the
# same command skips what is already done.
set -u
[ $# -ge 2 ] || { echo "usage: $0 <work-dir> <project>[:<srcdir>] ..." >&2; exit 2; }
WORK=$(realpath -m "$1"); shift
HERE=$(cd "$(dirname "$0")/.." && pwd)
PARALLEL=${PARALLEL:-8}
SANITIZERS=${SANITIZERS:-all}
COMPILE_TIMEOUT=${COMPILE_TIMEOUT:-21600}
RETRY=(); [ "${RETRY_FAILED:-0}" = 1 ] && RETRY=(--retry-failed)
OSS_FUZZ=${OSS_FUZZ:-/home/sefcom/asu/project/oss-fuzz}
COMMIT=$(git -C "$OSS_FUZZ" rev-parse --verify "${COMMIT:-origin/master}^{commit}") || exit 2
if [ "$PARALLEL" -lt 1 ] || [ "$PARALLEL" -gt 8 ]; then
    echo "PARALLEL must be 1..8 (eight 5-CPU slots in 0-39)" >&2; exit 2
fi
mkdir -p "$WORK"
echo "onboarding $# projects from oss-fuzz $COMMIT, $PARALLEL at a time -> $WORK"

declare -A SLOT_PID=()   # slot -> pid
run_one() {  # slot spec
    local slot=$1 spec=$2 p=${2%%:*} srcdir=""
    [ "$spec" != "$p" ] && srcdir=${spec#*:}
    local lo=$((slot * 5)) hi=$((slot * 5 + 4))
    mkdir -p "$WORK/$p"
    python3 "$HERE/tools/onboard_upstream.py" run --project "$p" --work "$WORK" \
        --sanitizers "$SANITIZERS" --oss-fuzz "$OSS_FUZZ" --commit "$COMMIT" \
        --cpuset "$lo-$hi" --compile-timeout "$COMPILE_TIMEOUT" "${RETRY[@]}" \
        ${srcdir:+--srcdir "$srcdir"} \
        >"$WORK/$p/batch.log" 2>&1
}

for spec in "$@"; do
    slot=""
    while [ -z "$slot" ]; do
        for ((s = 0; s < PARALLEL; s++)); do
            pid=${SLOT_PID[$s]:-}
            if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
                [ -n "$pid" ] && wait "$pid"
                slot=$s; break
            fi
        done
        [ -z "$slot" ] && wait -n
    done
    run_one "$slot" "$spec" &
    SLOT_PID[$slot]=$!
    echo "  started ${spec%%:*} on cpus $((slot * 5))-$((slot * 5 + 4))"
done
wait

for spec in "$@"; do
    p=${spec%%:*}
    python3 - "$WORK/$p/onboard_result.json" "$p" <<'PY'
import json, sys
path, p = sys.argv[1], sys.argv[2]
try:
    r = json.load(open(path))
except (OSError, ValueError):
    print(f"{p:24s} no result (see batch.log)")
    raise SystemExit
sans = " ".join(f"{s}={v.get('status')}({len(v.get('harnesses') or [])})"
                for s, v in r.get("sanitizers", {}).items())
print(f"{p:24s} {r.get('status', '?'):16s} {sans} {r.get('reason', '')}".rstrip())
PY
done
