#!/usr/bin/env bash
# Authoritative full-corpus replay comparison for selinux secilc-fuzzer.
# The raw 14,141-file corpus contains crashers (e.g. cil_fill_ipaddr SEGV) that
# abort libFuzzer -runs=0, so we first crash-filter it against the baseline
# binary (build_corpus.py --duration 0, no grow) into a crash-free snapshot,
# exactly as the pipeline does, then replay all three binaries on that snapshot:
#   baseline (byte-identical for both experiments) vs nk1-opt vs Fable-5-opt.
set -uo pipefail
exec >>/tmp/fable_replay.log 2>&1
cd /home/sefcom/asu/project/test/benchmark

SKDIR="$HOME/.claude/skills/profile-once-fuzz-folds/scripts"
ROOT="results/fable-selinux/selinux-CVE-2021-36085"
CORPUS="$ROOT/seed_corpus/merged"
BASE="$ROOT/baseline/bin"
FABLE="$ROOT/optimized/bin"
NK1="results/new-kube-1/selinux-CVE-2021-36085/optimized/bin"
WORK="$ROOT/replay_full"
SNAP="$WORK/fixed_full"
say(){ echo "[replay $(date -u +%FT%TZ)] $*"; }
rm -rf "$WORK"; mkdir -p "$WORK"

say "STEP 1: crash-filter full corpus ($(find "$CORPUS" -type f | wc -l) files) vs baseline (duration=0)"
python3 "$SKDIR/build_corpus.py" --out-dir "$BASE" --corpus-dir "$CORPUS" \
  --evolving-corpus-dir "$WORK/evolving" --snapshot-dir "$SNAP" \
  --artifact-dir "$WORK/artifacts" --fuzz-target secilc-fuzzer \
  --duration 0 --filter-timeout 3600
say "filter rc=$? -> snapshot $(find "$SNAP" -type f 2>/dev/null | wc -l) files"

say "STEP 2A: baseline + Fable-opt on crash-free snapshot (repeats=3)"
python3 "$SKDIR/replay_timing.py" --baseline-out-dir "$BASE" --out-dir "$FABLE" \
  --corpus-dir "$SNAP" --fuzz-target secilc-fuzzer --repeats 3 --run-timeout 3600 \
  --output /tmp/fable_replay_fable.json
say "2A rc=$?"

say "STEP 2B: nk1-opt on crash-free snapshot (repeats=3)"
python3 "$SKDIR/replay_timing.py" --out-dir "$NK1" \
  --corpus-dir "$SNAP" --fuzz-target secilc-fuzzer --repeats 3 --run-timeout 3600 \
  --output /tmp/fable_replay_nk1.json
say "2B rc=$?"

python3 - <<'PY'
import json
try:
    A=json.load(open('/tmp/fable_replay_fable.json'))
    base=A['baseline']['median_time_s']; fab=A['optimized']['median_time_s']; n=A.get('corpus_file_count')
    B=json.load(open('/tmp/fable_replay_nk1.json')); nk1=(B.get('optimized') or B.get('baseline'))['median_time_s']
    print(f"[replay-result] snapshot_files={n}")
    print(f"[replay-result] baseline   median_s={base:.2f}")
    print(f"[replay-result] nk1-opt    median_s={nk1:.2f}  speedup={base/nk1:.4f}x")
    print(f"[replay-result] fable-opt  median_s={fab:.2f}  speedup={base/fab:.4f}x")
except Exception as e:
    print("[replay-result] ERROR:", e)
PY
say "DONE"
