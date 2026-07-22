#!/usr/bin/env bash
# Optimize selinux + libavc with CODEX / gpt-5.5 @ max, mutation-augmented, in
# BOTH modes:
#   gpt55base -> profile-once-fuzz-folds            (conservative, Category-1/2)
#   gpt55agg  -> profile-once-fuzz-folds-aggressive (input-dependent; now carries
#                the new per-input-determinism hard line)
# Two experiments run SEQUENTIALLY (they share the oss-fuzz build dirs for the
# same targets, so cannot overlap). Same mutation-augmented process as mut8h.
# Phase-2 only, then pause.
set -u
cd /home/sefcom/asu/project/test/benchmark
TS=$(date -u +%Y%m%d_%H%M%SZ)
LOG="gpt55_phase2_${TS}.log"
echo "$LOG" > .gpt55_logname

# --- back up 5-project manifest, compose 2-entry, restore on exit ---
MBAK=$(mktemp /tmp/gpt55_manifest_bak.XXXX.json)
cp manifest.json "$MBAK"; echo "$MBAK" > .gpt55_manifest_bak
restore() { cp "$MBAK" manifest.json; echo "[gpt55] manifest.json restored" >> "$LOG"; }
trap restore EXIT
python3 - <<'PY'
import json
m = json.load(open("manifest.json"))
sel = [e for e in m if e["project"] in ("libavc", "selinux")]
json.dump(sel, open("manifest.json", "w"), indent=2)
print("[gpt55] composed manifest:", [e["project"] for e in sel])
PY

# --- common env: codex / gpt-5.5 (reasoning=max from ~/.codex/config.toml), mutations on ---
export OPTIMIZER_BACKEND=codex BENCHMARK_OPTIMIZER=codex
export BENCHMARK_CODEX_MODEL=gpt-5.5
export BENCHMARK_CODEX_REASONING=xhigh          # gpt-5.5 rejects config's "max"; xhigh is its top tier
export PHASE2_MUTATION_ENABLED=1 PHASE2_MUTATION_REQUIRED=1 PHASE2_MUTATION_SKIP_SIZING=1
export PHASE2_OPTIMIZER_TIMEOUT_SECS=18000     # 5h per target

run_exp() {
  local exp="$1" skill="$2"
  export PHASE2_OPTIMIZER_SKILL="$skill"
  echo "[gpt55 $(date -u +%FT%TZ)] ==== $exp START (skill=$skill model=gpt-5.5) ====" >> "$LOG"
  python3 -u run_benchmark.py --experiment-id "$exp" --phase 2 --phase2-max-parallel 2 >> "$LOG" 2>&1
  echo "[gpt55 $(date -u +%FT%TZ)] ==== $exp DONE rc=$? ====" >> "$LOG"
  cp manifest.json "manifest_${exp}.json"
}

run_exp gpt55base profile-once-fuzz-folds
run_exp gpt55agg  profile-once-fuzz-folds-aggressive
echo "[gpt55 $(date -u +%FT%TZ)] ALL DONE (phase-2 only; paused)" >> "$LOG"
