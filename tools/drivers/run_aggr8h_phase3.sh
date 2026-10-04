#!/usr/bin/env bash
# Phase-3 fuzzing for the aggr-8h experiment: baseline vs optimized, 10 trials x
# 8h each, on k8s -- same shape as mut-8h so the two are directly comparable.
# The aggressive-contract optimized binaries are already built in phase 2.
set -u
cd /home/sefcom/asu/project/test/benchmark

EXP=aggr-8h
TS=$(date -u +%Y%m%d_%H%M%SZ)
LOG="aggr8h_phase3_${TS}.log"
echo "$LOG" > .aggr8h_p3_logname

export PHASE3_BACKEND=k8s
export PHASE3_K8S_TRIALS=10
export PHASE3_K8S_PARALLELISM=10
DURATION=28800   # 8 hours per trial

{
  echo "[aggr-8h p3 $(date -u +%FT%TZ)] phase-3 START trials=$PHASE3_K8S_TRIALS parallelism=$PHASE3_K8S_PARALLELISM dur=${DURATION}s (8h)"
  python3 -u run_benchmark.py --experiment-id "$EXP" --phase 3 --duration "$DURATION"
  rc=$?
  echo "[aggr-8h p3 $(date -u +%FT%TZ)] phase-3 DONE rc=$rc"
} >> "$LOG" 2>&1
