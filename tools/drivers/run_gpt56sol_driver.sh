#!/usr/bin/env bash
# Optimize selinux + libavc with the CODEX backend / GPT-5.6-Sol @ max reasoning,
# using the SAME skill mut8h used: the conservative base `profile-once-fuzz-folds`
# (Category-1/2 Behavior-Preservation Contract), up-to-date. Everything else
# matches mut8h's process (mutation-augmented profiling, 5-min cap, skip sizing);
# only the optimizer model/backend differ. Phase-2 ONLY, then pause.
set -u
cd /home/sefcom/asu/project/test/benchmark

EXP=gpt56sol
TS=$(date -u +%Y%m%d_%H%M%SZ)
LOG="gpt56sol_phase2_${TS}.log"
echo "$LOG" > .gpt56sol_logname

# --- back up the 5-project manifest, compose a 2-entry one, restore on exit ---
MBAK=$(mktemp /tmp/gpt56sol_manifest_bak.XXXX.json)
cp manifest.json "$MBAK"
echo "$MBAK" > .gpt56sol_manifest_bak
restore() { cp "$MBAK" manifest.json; echo "[gpt56sol] manifest.json restored" >> "$LOG"; }
trap restore EXIT
python3 - <<'PY'
import json
m = json.load(open("manifest.json"))
sel = [e for e in m if e["project"] in ("libavc", "selinux")]
json.dump(sel, open("manifest.json", "w"), indent=2)
print("[gpt56sol] composed manifest:", [e["project"] for e in sel])
PY

# --- codex backend, GPT-5.6-Sol; reasoning=max comes from ~/.codex/config.toml ---
export OPTIMIZER_BACKEND=codex BENCHMARK_OPTIMIZER=codex
export BENCHMARK_CODEX_MODEL=gpt-5.6-sol
export PHASE2_OPTIMIZER_SKILL=profile-once-fuzz-folds       # SAME skill as mut8h (conservative)
# mutation-augmented profiling, same as mut8h (mandatory, no seed-only fallback)
export PHASE2_MUTATION_ENABLED=1 PHASE2_MUTATION_REQUIRED=1 PHASE2_MUTATION_SKIP_SIZING=1
export PHASE2_OPTIMIZER_TIMEOUT_SECS=18000                  # 5h per target

{
  echo "[gpt56sol $(date -u +%FT%TZ)] phase-2 START"
  echo "  backend=codex model=gpt-5.6-sol reasoning=max(config) skill=$PHASE2_OPTIMIZER_SKILL"
  echo "  targets=selinux,libavc  mutation=on skip_sizing=1"
  python3 -u run_benchmark.py --experiment-id "$EXP" --phase 2 --phase2-max-parallel 2
  rc=$?
  echo "[gpt56sol $(date -u +%FT%TZ)] phase-2 DONE rc=$rc"
  cp manifest.json "manifest_${EXP}.json"    # snapshot for covtime/covdiff tooling
  echo "[gpt56sol $(date -u +%FT%TZ)] PAUSED after phase 2 (no phase 3)"
} >> "$LOG" 2>&1
