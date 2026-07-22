#!/usr/bin/env bash
# Coverage-over-time for aggr-8h: pull each trial's corpus from the PVC and
# replay it cumulatively on the BASELINE binary (the only fair yardstick, since
# folding changes the optimized binary's edge map). Both variants live in the
# aggr-8h experiment, so SRC and OPT experiments are the same id.
set -u
cd /home/sefcom/asu/project/test/benchmark
TS=$(date -u +%Y%m%d_%H%M%SZ)
LOG="aggr8h_covtime_${TS}.log"
echo "$LOG" > .aggr8h_covtime_logname

export COVTIME_SRC_EXP=aggr-8h
export COVTIME_OPT_EXP=aggr-8h
export COVTIME_PROJECTS="assimp libavc libxml2 selinux wolfssl"
export COVTIME_PULL_DIR=covdiff_pertrial_aggr8h
export COVTIME_OUT=covtime_aggr8h
export COVTIME_DURATION=28800   # 8h

{
  echo "[aggr-8h covtime $(date -u +%FT%TZ)] PULL per-trial corpora from PVC"
  python3 -u run_covdiff_pertrial.py --pull
  echo "[aggr-8h covtime $(date -u +%FT%TZ)] BUILD cov(t) curves"
  python3 -u run_covtime.py --build --aggregate mean
  echo "[aggr-8h covtime $(date -u +%FT%TZ)] DONE rc=$?"
} >> "$LOG" 2>&1
