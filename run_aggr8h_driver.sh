#!/usr/bin/env bash
# Aggressive / input-dependent phase-2 optimization on the same 5 projects as
# mut-8h (assimp, libavc, libxml2, selinux, wolfssl). ONLY the fold contract
# changes vs mut-8h: the optimizer uses the relaxed skill
# `profile-once-fuzz-folds-aggressive` (input-dependent folds allowed; the sole
# hard behavioral line is the fuzzing-mode gate / lcms anti-pattern). Everything
# else is held constant for a clean A/B:
#   - same optimizer model (claude-fable-5[1m]) and backend (claude)
#   - mutation-augmented profiling stays MANDATORY (no seed-only fallback)
#   - the harness PoC gate stays ON: any optimized binary that stops reproducing
#     the target crash is reverted to baseline (recorded unoptimized).
# Phase-2 ONLY -- then STOP for review before any phase-3 fuzzing.
set -u
cd /home/sefcom/asu/project/test/benchmark

EXP=aggr-8h
TS=$(date -u +%Y%m%d_%H%M%SZ)
LOG="aggr8h_phase2_${TS}.log"
echo "$LOG" > .aggr8h_logname

export BENCHMARK_OPTIMIZER=claude
export OPTIMIZER_BACKEND=claude
export BENCHMARK_CLAUDE_MODEL='claude-fable-5[1m]'
export PHASE2_OPTIMIZER_SKILL=profile-once-fuzz-folds-aggressive
# mutation-augmented profiling is the new normal: mandatory, no seed-only fallback
export PHASE2_MUTATION_ENABLED=1
export PHASE2_MUTATION_REQUIRED=1
# generous per-bash agent timeout for the optimizer (match mut-8h: 90 min)
export BASH_DEFAULT_TIMEOUT_MS=5400000
export BASH_MAX_TIMEOUT_MS=5400000

{
  echo "[aggr-8h $(date -u +%FT%TZ)] phase-2 START"
  echo "  skill=$PHASE2_OPTIMIZER_SKILL model=$BENCHMARK_CLAUDE_MODEL backend=$BENCHMARK_OPTIMIZER"
  echo "  mutation: enabled=$PHASE2_MUTATION_ENABLED required=$PHASE2_MUTATION_REQUIRED"
  python3 -u run_benchmark.py --experiment-id "$EXP" --phase 2 --phase2-max-parallel 3
  rc=$?
  echo "[aggr-8h $(date -u +%FT%TZ)] phase-2 DONE rc=$rc"
  # snapshot the manifest under the per-experiment name the covtime/covdiff tools expect
  cp manifest.json "manifest_${EXP}.json"
  echo "[aggr-8h $(date -u +%FT%TZ)] wrote manifest_${EXP}.json"
  echo "[aggr-8h $(date -u +%FT%TZ)] PAUSED after phase 2 (no phase 3) -- awaiting review"
} >> "$LOG" 2>&1
