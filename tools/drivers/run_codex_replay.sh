#!/usr/bin/env bash
# Authoritative full-corpus replay of the Codex-optimized selinux binary, on the
# SAME crash-free 13,761-file snapshot used for the Fable/nk1 comparison (baseline
# is byte-identical across all three experiments, so the snapshot is valid).
set -uo pipefail
exec >>/tmp/codex_replay.log 2>&1
cd /home/sefcom/asu/project/test/benchmark
SKDIR="$HOME/.claude/skills/profile-once-fuzz-folds/scripts"
SNAP="results/fable-selinux/selinux-CVE-2021-36085/replay_full/fixed_full"
BASE="results/codex-selinux/selinux-CVE-2021-36085/baseline/bin"
CODEX="results/codex-selinux/selinux-CVE-2021-36085/optimized/bin"
say(){ echo "[creplay $(date -u +%FT%TZ)] $*"; }

say "START codex-opt full-corpus replay ($(find "$SNAP" -type f | wc -l) files, repeats=3)"
python3 "$SKDIR/replay_timing.py" --baseline-out-dir "$BASE" --out-dir "$CODEX" \
  --corpus-dir "$SNAP" --fuzz-target secilc-fuzzer --repeats 3 --run-timeout 3600 \
  --output /tmp/codex_replay.json
say "replay rc=$?"

python3 - <<'PY'
import json
try:
    d=json.load(open("/tmp/codex_replay.json"))
    b=d["baseline"]["median_time_s"]; o=d["optimized"]["median_time_s"]
    print(f"[creplay-result] snapshot_files={d.get('corpus_file_count')}")
    print(f"[creplay-result] baseline  median_s={b:.2f}  times={['%.1f'%t for t in d['baseline']['times_s']]}")
    print(f"[creplay-result] codex-opt median_s={o:.2f}  times={['%.1f'%t for t in d['optimized']['times_s']]}")
    print(f"[creplay-result] codex speedup = {b/o:.4f}x  (replay_timing: {d.get('replay_speedup')})")
except Exception as e:
    print("[creplay-result] ERROR:", e)
PY
say DONE
