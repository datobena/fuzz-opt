#!/usr/bin/env bash
# Re-optimize selinux (CVE-2021-36085 / secilc-fuzzer) with the CODEX backend
# (codex exec, default model gpt-5.5 @ xhigh) to compare its replay speedup
# against the Fable-5 and new-kube-1 optimizations. Same corpus cap (2000) as the
# Fable run for a fair fold-selection comparison; the authoritative full-corpus
# replay is done separately afterwards. Phase 2 only. Restores manifest on exit.
set -uo pipefail
exec >>/tmp/codex_selinux.log 2>&1
cd /home/sefcom/asu/project/test/benchmark

EXP=codex-selinux
say(){ echo "[codex $(date -u +%FT%TZ)] $*"; }
say "==================== START ===================="
MBAK=$(mktemp /tmp/codex_manifest_bak.XXXX.json)
cp manifest.json "$MBAK" 2>/dev/null || echo "[]" > "$MBAK"
restore(){ cp "$MBAK" manifest.json 2>/dev/null && say "manifest.json restored"; }
trap restore EXIT
mkdir -p "results/$EXP"

python3 - <<'PY'
import json
entry = {"cve":"CVE-2021-36085","local_id":42493454,"project":"selinux",
         "fuzz_target":"secilc-fuzzer","job_type":"libfuzzer_asan_selinux",
         "engine":"libfuzzer","sanitizer":"asan","arch":"x86_64",
         "crash_type":"Heap-use-after-free READ 8","good":True}
json.dump([entry],open("manifest.json","w"),indent=2)
json.dump([entry],open("results/codex-selinux/manifest_full.json","w"),indent=2)
print("[codex-compose]", entry["project"], entry["cve"])
PY
say "composed manifest (selinux CVE-2021-36085)"

export OPTIMIZER_BACKEND=codex BENCHMARK_OPTIMIZER=codex
export PHASE2_OPTIMIZER_SKILL=profile-once-fuzz-folds
export PHASE2_OPTIMIZER_TIMEOUT_SECS=14400
export PHASE2_MAX_PARALLEL=1
export FUZZ_SOURCE_FOLDS_MAX_CORPUS_FILES=2000
# codex default model gpt-5.5 (~/.codex/config.toml); BENCHMARK_CODEX_MODEL unset
say "phase 2 START (codex exec / gpt-5.5 / profile-once-fuzz-folds, cap=2000)"
python3 -u run_benchmark.py --experiment-id "$EXP" --phase 2 --duration 86400
say "phase 2 exited rc=$?"

python3 - <<'PY'
import json,os
p="results/codex-selinux/selinux-CVE-2021-36085/setup_metadata.json"
if os.path.exists(p):
    d=json.load(open(p)); r=d.get("replay",{}); v=d.get("verification",{})
    print("[codex-result] verification:",v)
    print("[codex-result] replay_speedup:",r.get("replay_speedup") or r.get("speedup"))
    print("[codex-result] base/opt median_s:",(r.get("baseline") or {}).get("median_time_s"),(r.get("optimized") or {}).get("median_time_s"))
    print("[codex-result] corpus files/src:",r.get("corpus_file_count"),r.get("corpus_source"))
else:
    print("[codex-result] NO setup_metadata — phase 2 did not complete")
PY
say "==================== DONE ===================="
