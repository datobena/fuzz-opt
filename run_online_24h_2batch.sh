#!/bin/bash
# Online optimization, 4 targets as 2 batches of 2, 24h each, 9 trials per arm.
#
# CORE LAYOUT -- this box has 80 logical CPUs but only 40 PHYSICAL cores
# (2 threads/core; the HT sibling of core c is c+40). Two fuzzers on one physical
# core do not each get a core, so everything here stays inside 0-39 and the
# 40-79 half is deliberately left idle. Verify with:
#     cat /sys/devices/system/cpu/cpu0/topology/thread_siblings_list   # -> 0,40
#
#   cores 0-1    system: docker daemon + the two orchestrator processes
#   cores 2, 3   optimizer profile core, one per concurrent project
#   cores 4-21   project A: 9 baseline + 9 online trials, one core each
#   cores 22-39  project B: 9 baseline + 9 online trials, one core each
#   cores 40-79  idle (HT siblings) -- never allocated
#
# The profile core carries ALL optimizer CPU work for its project: the profiling
# prebuild, the rebuild, the replay gate, the PoC check, and every build/smoke/
# replay the sandboxed agent requests through the broker. That is what keeps
# optimization from stealing cycles from the trials it is measured against, and
# it is why the CPU ledger can charge each stage as core-seconds.
#
#   ./run_online_24h_2batch.sh 1     # batch 1: libxml2  + wolfssl
#   ./run_online_24h_2batch.sh 2     # batch 2: libavc   + selinux
#   ./run_online_24h_2batch.sh 3     # batch 3: lcms     + yara
#   ./run_online_24h_2batch.sh 4     # batch 4: c-blosc2 + assimp
set -u
cd "$(dirname "$0")"

BATCH="${1:-}"
case "$BATCH" in
  1) ROWS=("libxml2 4-21 2" "wolfssl 22-39 3") ;;
  2) ROWS=("libavc 4-21 2" "selinux 22-39 3") ;;
  3) ROWS=("lcms 4-21 2" "yara 22-39 3") ;;
  4) ROWS=("c-blosc2 4-21 2" "assimp 22-39 3") ;;
  *) echo "usage: $0 <1|2|3|4>"; exit 2 ;;
esac

DURATION=${DURATION:-86400}          # 24h
INTERVAL=${INTERVAL:-7200}           # minimum fuzzing time between rounds (2h)
OPT_TIMEOUT=${OPT_TIMEOUT:-14400}    # 4h backstop (0 disables it entirely).
                                     # NOT a working deadline -- the agent is not
                                     # told about it, and a round is free to
                                     # overrun INTERVAL: run_optimizer_loop waits
                                     # INTERVAL *between* rounds, so it is a floor,
                                     # not a schedule, and the next round profiles
                                     # whatever mutations the trials accumulated
                                     # meanwhile. This only catches a session that
                                     # is stuck rather than slow; observed working
                                     # sessions run well under an hour.
                                     # Caveat: if it does fire, the round is
                                     # discarded whole -- the diff is saved only
                                     # once the agent returns.
TRIALS=${TRIALS:-9}
# 0 = never stop early. A barren stretch is not evidence the next round is
# barren too: the corpus the optimizer profiles keeps growing, so a foldable
# hotspot can appear on round 7 after six rejects. The old value of 3 ended
# lcms's optimization at round 4 of a 24h campaign, leaving the online arm to
# finish as a second baseline. Set a positive value to restore early stopping.
CONVERGENCE_K=${CONVERGENCE_K:-0}
EXP_PREFIX=${EXP_PREFIX:-online-24h-b${BATCH}}

# Refuse to start if the optimization skill is absent: without it
# run_replay_speedup cannot load replay_timing.py, so the gate rejects every
# round and 24h of compute yields nothing. It fails silently by design, so it is
# checked here instead.
if ! python3 bootstrap_server.py --check 2>&1 | grep -q "ok  . optimizer skill"; then
  echo "ABORT: optimizer skill missing -- run 'python3 bootstrap_server.py --check'" >&2
  exit 3
fi

PIDFILE=".online_b${BATCH}_pids.txt"
: > "$PIDFILE"

for row in "${ROWS[@]}"; do
  read -r proj cores pcpu <<< "$row"
  exp="${EXP_PREFIX}-${proj}"
  log=".${exp}.log"
  echo "launching $proj  trials=${cores} (9+9) profile_cpu=${pcpu} exp=${exp}"

  NUM_TRIALS="$TRIALS" \
  ONLINE_ENABLED=1 PHASE3_BACKEND=local \
  ONLINE_SWAP_INTERVAL_SECS="$INTERVAL" ONLINE_CONVERGENCE_K="$CONVERGENCE_K" \
  PHASE2_OPTIMIZER_TIMEOUT_SECS="$OPT_TIMEOUT" \
  ONLINE_LIVE_MUTATION_CAPTURE=1 \
  ONLINE_MUTATION_MODE=reservoir \
  PHASE2_MUTATION_CAP=20000 \
  PHASE2_CORPUS_BUILD_DURATION_SECS=600 \
  FUZZ_SOURCE_FOLDS_MAX_CORPUS_FILES=20000 \
  ONLINE_TRIAL_CORES="$cores" ONLINE_PROFILE_CPU="$pcpu" \
  nohup python3 run_benchmark.py --online --phase 3 --project "$proj" \
    --duration "$DURATION" --experiment-id "$exp" > "$log" 2>&1 &

  pid=$!
  echo "${proj} ${pid} ${exp} ${log}" >> "$PIDFILE"
  echo "  -> PID $pid, log $log"
  sleep 3
done

echo "=== batch ${BATCH} launched; pids in ${PIDFILE} ==="
cat "$PIDFILE"
echo
echo "watch progress:  tail -f .${EXP_PREFIX}-*.log"
echo "cpu cost so far: python3 cpu_cost_report.py --experiment-id ${EXP_PREFIX}-<project>"
