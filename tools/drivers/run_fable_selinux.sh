#!/usr/bin/env bash
# Re-optimize selinux (same target as new-kube-1: CVE-2021-36085 / secilc-fuzzer)
# using the NEW Claude model "Fable 5, 1M context" (claude-fable-5[1m]) as the
# phase-2 optimizer, so its replay speedup can be compared to the previous
# optimization (new-kube-1: 1.4549x). Phase 2 only (optimize + replay).
# Restores the working manifest.json on exit (crash-safe trap).
set -uo pipefail
exec >>/tmp/fable_selinux.log 2>&1
cd /home/sefcom/asu/project/test/benchmark

EXP=fable-selinux
say() { echo "[fable $(date -u +%FT%TZ)] $*"; }
say "==================== START ===================="

# --- backup working manifest + restore on exit ---
MBAK=$(mktemp /tmp/fable_manifest_bak.XXXX.json)
cp manifest.json "$MBAK" 2>/dev/null || echo "[]" > "$MBAK"
restore() { cp "$MBAK" manifest.json 2>/dev/null && say "manifest.json restored"; }
trap restore EXIT
mkdir -p "results/$EXP"

# --- compose manifest: the exact new-kube-1 selinux entry ---
python3 - <<'PY'
import json
entry = {"cve": "CVE-2021-36085", "local_id": 42493454, "project": "selinux",
         "fuzz_target": "secilc-fuzzer", "job_type": "libfuzzer_asan_selinux",
         "engine": "libfuzzer", "sanitizer": "asan", "arch": "x86_64",
         "crash_type": "Heap-use-after-free READ 8", "good": True}
json.dump([entry], open("manifest.json", "w"), indent=2)
json.dump([entry], open("results/fable-selinux/manifest_full.json", "w"), indent=2)
print("[fable-compose] manifest:", entry["project"], entry["cve"])
PY
say "composed manifest (selinux CVE-2021-36085)"

# --- phase 2: optimize with Fable 5 (1M) ---
export OPTIMIZER_BACKEND=claude BENCHMARK_OPTIMIZER=claude
export PHASE2_OPTIMIZER_SKILL=profile-once-fuzz-folds
export PHASE2_OPTIMIZER_TIMEOUT_SECS=14400
export PHASE2_MAX_PARALLEL=1
export BENCHMARK_CLAUDE_MODEL='claude-fable-5[1m]'
# Bound the optimizer's profiling/validation corpus so every docker step stays
# under the agent's 600s tool-timeout (Fable 5 backgrounds + yields on longer
# steps in headless -p mode). Authoritative replay is measured on the FULL
# corpus afterwards, separately.
export FUZZ_SOURCE_FOLDS_MAX_CORPUS_FILES=2000
say "phase 2 START (claude model=$BENCHMARK_CLAUDE_MODEL / profile-once-fuzz-folds)"
python3 -u run_benchmark.py --experiment-id "$EXP" --phase 2 --duration 86400
say "phase 2 exited rc=$?"

# --- report the fresh replay number ---
python3 - <<'PY'
import json, os
p="results/fable-selinux/selinux-CVE-2021-36085/setup_metadata.json"
if os.path.exists(p):
    d=json.load(open(p)); r=d.get("replay",{}); v=d.get("verification",{})
    print("[fable-result] verification:", v)
    print("[fable-result] replay_speedup:", r.get("replay_speedup") or r.get("speedup"))
    print("[fable-result] base/opt median_s:",
          (r.get("baseline") or {}).get("median_time_s"),
          (r.get("optimized") or {}).get("median_time_s"))
    print("[fable-result] corpus files/src:", r.get("corpus_file_count"), r.get("corpus_source"))
else:
    print("[fable-result] NO setup_metadata — phase 2 did not complete")
PY
say "==================== DONE ===================="
