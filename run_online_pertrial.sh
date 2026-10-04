#!/bin/bash
# Per-trial-optimizer campaign: ONE project per experiment, 10 baseline + 10
# optimized trials, and TEN independent optimizers -- one per optimized trial.
#
# WHAT CHANGED FROM b1..b6, and why it matters for the numbers
#
#   Before: one optimizer edited one shared source tree and hot-swapped ONE
#   binary into all 10 optimized trials. Every optimized trial therefore ran the
#   SAME binary, so between-trial variance in that arm measured AFL's randomness
#   alone -- the optimizer contributed exactly one sample per campaign while the
#   statistics were computed as if there were ten. A Mann-Whitney U over those
#   ten is not a test of the optimizer.
#
#   Now: trial i has its own source tree, its own optimizer, its own binary, and
#   its own profiling corpus. Ten genuinely independent optimizer draws, which is
#   what the per-arm statistics have been assuming all along.
#
#   Also gone: "which trial's corpus do we profile?". Optimizer i profiles trial
#   i's OWN mutations, harvested once and then held FIXED for every round it
#   runs, so a round-to-round speedup change is attributable to the edit rather
#   than to the corpus having moved underneath it.
#
# CORE LAYOUT -- 80 logical CPUs but only 40 PHYSICAL cores (HT sibling of core
# c is c+40). Two fuzzers on one physical core do not each get a core, so
# everything stays inside 0-39 and the 40-79 half is deliberately left idle.
#     cat /sys/devices/system/cpu/cpu0/topology/thread_siblings_list   # -> 0,40
#
#   cores 0-1    system: docker daemon + orchestrator
#   cores 2-11   ten optimizer profile cores, ONE PER OPTIMIZER
#   cores 12-31  twenty trials (10 baseline + 10 optimized), one core each
#   cores 32-39  spare headroom (extraction, rebuild bursts)
#   cores 40-79  idle (HT siblings) -- never allocated
#
# Each optimizer's profile core carries ALL of that optimizer's CPU work:
# profiling prebuild, rebuild, replay gate, PoC check, and every build/smoke/
# replay its sandboxed agent requests through the broker. That is what keeps
# optimization from stealing cycles from the trials it is measured against.
#
#   ./run_online_pertrial.sh libxml2
#   BUILD_OPT_LEVEL=   ./run_online_pertrial.sh libxml2    # -O1 (OSS-Fuzz default)
#   DURATION=1800 INTERVAL=300 EXP_PREFIX=smoke ./run_online_pertrial.sh libxml2
set -u
cd "$(dirname "$0")"

PROJ="${1:-}"
[ -z "$PROJ" ] && { echo "usage: $0 <project>"; exit 2; }

# Pin the optimizer's model. Without this no --model is passed and the CLI
# resolves its own ACCOUNT DEFAULT, which nothing records: the sandbox gives the
# agent its own HOME and runs --rm, so the session transcript that carries the
# model dies with the container. b1..b6 cannot be compared on this axis.
export BENCHMARK_CLAUDE_MODEL=${BENCHMARK_CLAUDE_MODEL:-opus}

# -O level for BOTH arms. "O3" is the point of this run: b1..b6 were built at
# the OSS-Fuzz default (-O1), so this also measures what -O3 alone buys in
# throughput before any optimizer edit. Comparable only to other runs at the
# SAME level -- recorded in campaign_provenance.json for exactly that reason.
export BUILD_OPT_LEVEL=${BUILD_OPT_LEVEL-O3}

DURATION=${DURATION:-86400}          # 24h
INTERVAL=${INTERVAL:-7200}           # minimum fuzzing time between an optimizer's rounds
OPT_TIMEOUT=${OPT_TIMEOUT:-14400}    # 4h backstop per round (0 disables)
TRIALS=${TRIALS:-10}                 # 10 per arm; the fuzzing-evaluation SoK
                                     # (S&P'24) recommends >= 10, and b1..b6 ran 9.
CONVERGENCE_K=${CONVERGENCE_K:-0}    # 0 = never stop early; a barren stretch is
                                     # not evidence the next round is barren too.
TRIAL_CORES=${TRIAL_CORES:-12-31}
OPT_CORES=${OPT_CORES:-2-11}
SETUP_CPU=${SETUP_CPU:-2}            # baseline build + noise floor only
EXP_PREFIX=${EXP_PREFIX:-online-24h-c1}

# Refuse to start if the optimization skill is absent: without it
# run_replay_speedup cannot load replay_timing.py, so the gate rejects every
# round and the whole campaign yields nothing. It fails silently by design.
PREFLIGHT=$(PREFLIGHT_CAMPAIGN_SECS="$DURATION" python3 bootstrap_server.py --check 2>&1)
if ! grep -q "ok  . optimizer skill" <<< "$PREFLIGHT"; then
  echo "ABORT: optimizer skill missing -- run 'python3 bootstrap_server.py --check'" >&2
  exit 3
fi
# The REFRESH token must outlive the whole campaign. When it dies mid-run the
# CLI's startup refresh is rejected, it blanks its own access token, and EVERY
# optimizer round fails from that point while the 20 fuzzing trials keep going
# to the full budget -- producing a complete-looking result set in which the
# optimized arm never received a single optimization. That is not hypothetical:
# the first launch of this campaign lost all ten optimizers to a refresh token
# that expired 2h after start, and the run had to be thrown away.
if grep -q "FAIL . refresh token outlives the campaign" <<< "$PREFLIGHT"; then
  grep "refresh token outlives" <<< "$PREFLIGHT" >&2
  echo "ABORT: re-authenticate first -- run 'claude' on the host, then relaunch." >&2
  exit 4
fi

exp="${EXP_PREFIX}-${PROJ}"
log=".${exp}.log"
echo "launching ${PROJ}: ${TRIALS}+${TRIALS} trials on ${TRIAL_CORES}, "\
"${TRIALS} optimizers on ${OPT_CORES}, -O level '${BUILD_OPT_LEVEL:-default}', exp=${exp}"

NUM_TRIALS="$TRIALS" \
ONLINE_ENABLED=1 PHASE3_BACKEND=local \
ONLINE_PER_TRIAL_OPTIMIZER=1 \
ONLINE_FIXED_MUTATION_CORPUS=1 \
ONLINE_SWAP_INTERVAL_SECS="$INTERVAL" ONLINE_CONVERGENCE_K="$CONVERGENCE_K" \
PHASE2_OPTIMIZER_TIMEOUT_SECS="$OPT_TIMEOUT" \
ONLINE_LIVE_MUTATION_CAPTURE=1 \
ONLINE_MUTATION_MODE=reservoir \
PHASE2_MUTATION_CAP=20000 \
PHASE2_CORPUS_BUILD_DURATION_SECS=600 \
FUZZ_SOURCE_FOLDS_MAX_CORPUS_FILES=20000 \
ONLINE_TRIAL_CORES="$TRIAL_CORES" \
ONLINE_OPTIMIZER_CORES="$OPT_CORES" \
ONLINE_PROFILE_CPU="$SETUP_CPU" \
nohup python3 run_benchmark.py --online --phase 3 --project "$PROJ" \
  --duration "$DURATION" --experiment-id "$exp" > "$log" 2>&1 &

pid=$!
echo "${PROJ} ${pid} ${exp} ${log}" > ".online_pertrial_${PROJ}.pid"
echo "  -> PID $pid, log $log"
echo
echo "watch progress:  tail -f ${log}"
echo "per-optimizer:   ls results/${exp}/${PROJ}-*/optimized/online/trials/"
echo "cpu cost so far: python3 analysis/cpu_cost_report.py --experiment-id ${exp}"
