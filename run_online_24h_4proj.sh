#!/bin/bash
# Launch the online fuzzing chain on 4 projects IN PARALLEL for 24h, optimizing every
# 1.5h. Each project gets a dedicated 8-core trial block (4 baseline + 4 online) plus a
# distinct profile core, so the trials and per-project replay-timing gates don't collide.
#   cores 0-3   : reserved (system + orchestrator python)
#   cores 4-35  : 4 projects x 8 trial cores
#   cores 36-39 : 4 distinct optimizer profile cores
set -u
cd /home/sefcom/asu/project/test/benchmark

DURATION=${DURATION:-86400}          # 24h
INTERVAL=${INTERVAL:-5400}           # 1.5h min between swaps
OPT_TIMEOUT=${OPT_TIMEOUT:-5400}     # 1.5h optimizer backstop
EXP_PREFIX=${EXP_PREFIX:-online-24h}

# project | trial-core-block | profile-core
ROWS=(
  "libxml2 4-11 36"
  "wolfssl 12-19 37"
  "libavc 20-27 38"
  "selinux 28-35 39"
)

PIDFILE=/tmp/claude-1000/-home-sefcom-asu-project-test-benchmark/dc432318-f227-4d54-b723-f5cec6bf45ca/scratchpad/online_24h_pids.txt
: > "$PIDFILE"

for row in "${ROWS[@]}"; do
  read -r proj cores pcpu <<< "$row"
  exp="${EXP_PREFIX}-${proj}"
  log=".${exp}.log"
  echo "launching $proj  trials=$cores profile_cpu=$pcpu exp=$exp"
  NUM_TRIALS=4 \
  ONLINE_ENABLED=1 PHASE3_BACKEND=local \
  ONLINE_SWAP_INTERVAL_SECS="$INTERVAL" ONLINE_CONVERGENCE_K=3 \
  PHASE2_OPTIMIZER_TIMEOUT_SECS="$OPT_TIMEOUT" \
  PHASE2_MUTATION_DURATION_SECS=600 PHASE2_CORPUS_BUILD_DURATION_SECS=600 \
  FUZZ_SOURCE_FOLDS_MAX_CORPUS_FILES=20000 \
  ONLINE_TRIAL_CORES="$cores" ONLINE_PROFILE_CPU="$pcpu" \
  nohup python3 run_benchmark.py --online --phase 3 --project "$proj" \
    --duration "$DURATION" --experiment-id "$exp" > "$log" 2>&1 &
  pid=$!
  echo "${proj} ${pid} ${exp} ${log}" >> "$PIDFILE"
  echo "  -> PID $pid, log $log"
  sleep 3
done

echo "=== all 4 launched; pids in $PIDFILE ==="
cat "$PIDFILE"
