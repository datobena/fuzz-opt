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
#   i's OWN mutations: each round harvests a fresh reservoir sample of what the
#   trial's current best binary executed since the previous dump or restart
#   (ONLINE_FIXED_MUTATION_CORPUS=0; =1 pins round 1's batch instead).
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
#   0-1,32-39    the agent containers (Claude CLI + whatever it runs: it has gcc),
#                AGENT_CPUS; shared by all ten, never a trial or profile core
#   (setup, before any trial starts: builds use all of 2-39, SETUP_BUILD_CPUS)
#   cores 40-79  idle (HT siblings) -- never allocated
#
# Shared-core mode (default on this branch): trial i, its optimizer agent, and
# all round CPU work share trial i's core. Builds/smoke contend naturally;
# profiling/replay pause the fuzzer and agent. No CPU-cost charging is needed.
# ONLINE_SHARED_TRIAL_CPU=0 restores the dedicated optimizer/agent pools above.
# SETUP_CPU and SETUP_BUILD_CPUS apply before trials start in either mode.
#
#   ./run_online_pertrial.sh libxml2
#   BUILD_OPT_LEVEL=O3 ./run_online_pertrial.sh libxml2    # ARVO override, see below
#   DURATION=1800 INTERVAL=300 EXP_PREFIX=smoke ./run_online_pertrial.sh libxml2
#   EXP_ID=smoke-libxml2-20261019-1430 ./run_online_pertrial.sh libxml2   # exact id
# The experiment id is ${EXP_PREFIX}-<project>-<YYYYMMDD-HHMM> unless EXP_ID is set.
set -u
cd "$(dirname "$0")"

PROJ="${1:-}"
[ -z "$PROJ" ] && { echo "usage: $0 <project>"; exit 2; }

# Pin the optimizer's model to an EXPLICIT id. Without any pin the CLI resolves
# its own ACCOUNT DEFAULT, which nothing records (the sandbox gives the agent its
# own HOME and runs --rm, so the transcript dies with the container). But an
# ALIAS is nearly as bad for a model comparison: `opus` resolved to
# `claude-opus-5` at runtime while provenance recorded the literal string
# "opus" -- so the online-24h-bug-{mruby,php-src,mbedtls} runs actually ran
# claude-opus-5, NOT the claude-opus-4-8 the config comment assumes. Pin a full
# id so what runs is what is recorded and reproducible. Override per run, e.g.
#   BENCHMARK_CLAUDE_MODEL=claude-opus-4-8  ./run_online_pertrial.sh mruby
#   BENCHMARK_CLAUDE_MODEL=claude-opus-5-5  ./run_online_pertrial.sh mruby
export BENCHMARK_CLAUDE_MODEL=${BENCHMARK_CLAUDE_MODEL:-claude-opus-5}
echo "optimizer model: ${BENCHMARK_CLAUDE_MODEL}"

# -O level. Default EMPTY: every target is built the way its own benchmark
# builds it -- an ARVO target with its image's CFLAGS and build.sh exactly as
# ARVO/OSS-Fuzz compiled it (-O1 for these sanitizer builds), a FuzzBench target
# the way FuzzBench does (below). It used to default to O3, which also left the
# agent timing -O1 builds through the broker while -O3 builds were gated and
# deployed (fixed: every ARVO build path now shares one env). Setting it (e.g.
# O3) still overrides ARVO targets, for BOTH arms and every agent build alike;
# runs are comparable only at the same level, and campaign_provenance.json
# records the level that actually ran.
export BUILD_OPT_LEVEL=${BUILD_OPT_LEVEL-}

# FuzzBench targets (manifest "kind": "fuzzbench") are built exactly as
# FuzzBench builds them: -O1 for bug benchmarks, -O3 for coverage ones, set by
# fuzzers/utils.py. BUILD_OPT_LEVEL must not touch them (prework also guards),
# so clear it here; campaign_provenance.json records the real per-type level.
FB_KIND=$(python3 - "$PROJ" <<'PY' 2>/dev/null
import json, sys
import config
try:
    entries = json.load(open(config.MANIFEST_PATH))
except Exception:
    sys.exit(0)
kinds = {e.get("kind") for e in entries if e.get("project") == sys.argv[1]}
print("fuzzbench" if "fuzzbench" in kinds else "")
PY
)
if [ "$FB_KIND" = "fuzzbench" ]; then
  if [ -n "${BUILD_OPT_LEVEL}" ]; then
    echo "fuzzbench target: ignoring BUILD_OPT_LEVEL=${BUILD_OPT_LEVEL} (FuzzBench sets -O1 bug / -O3 coverage)"
  fi
  export BUILD_OPT_LEVEL=
fi

DURATION=${DURATION:-86400}          # 24h
INTERVAL=${INTERVAL:-7200}           # minimum fuzzing time between an optimizer's rounds
OPT_TIMEOUT=${OPT_TIMEOUT:-14400}    # 4h backstop per round (0 disables)
TRIALS=${TRIALS:-10}                 # 10 per arm; the fuzzing-evaluation SoK
                                     # (S&P'24) recommends >= 10, and b1..b6 ran 9.
CONVERGENCE_K=${CONVERGENCE_K:-0}    # 0 = never stop early; a barren stretch is
                                     # not evidence the next round is barren too.
TRIAL_CORES=${TRIAL_CORES:-12-31}
OPT_CORES=${OPT_CORES:-2-11}
SETUP_CPU=${SETUP_CPU:-2}            # setup replays + PoC checks (one core)
SETUP_BUILD_CPUS=${SETUP_BUILD_CPUS:-2-39}  # setup builds: every physical core
                                     # but 0-1; no trial runs during setup
AGENT_CPUS=${AGENT_CPUS:-}           # agent containers; empty = derived from the
                                     # trial/optimizer sets (here 0-1,32-39)
EXP_PREFIX=${EXP_PREFIX:-online-24h-c1}

# Dated, so a relaunch can never reuse an experiment id by accident. A reused id
# silently RESUMED the old campaign: every launch sets AFL_AUTORESUME=1 and
# start_trial never wipes afl_out, so the "new" trials picked up the old queues,
# coverage and run_time mid-run (phase 3 now also refuses that outright).
# EXP_ID=<id> names the experiment exactly, for deliberate reuse -- e.g. retrying
# a launch whose setup failed before any trial started (move its log aside first).
#
# An existing log is refused HERE, before this script touches any file, with or
# without EXP_ID. The `> "$log"` below truncates it, and phase 3's stale-state
# guard only runs after that -- so a reused EXP_ID used to destroy the old
# campaign's log and only then be refused.
exp="${EXP_ID:-${EXP_PREFIX}-${PROJ}-$(date +%Y%m%d-%H%M)}"
log=".${exp}.log"
if [ -e "$log" ]; then
  if [ -n "${EXP_ID:-}" ]; then
    echo "ABORT: ${log} already exists: EXP_ID=${EXP_ID} was launched before; move the log aside to reuse the id" >&2
  else
    echo "ABORT: ${log} already exists (two launches of ${PROJ} in one minute?)" >&2
  fi
  exit 5
fi

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

echo "launching ${PROJ}: ${TRIALS}+${TRIALS} trials on ${TRIAL_CORES}, "\
"${TRIALS} optimizers (shared trial CPU=${ONLINE_SHARED_TRIAL_CPU:-1}), -O level '$( [ "$FB_KIND" = fuzzbench ] && echo 'fuzzbench (-O1 bug / -O3 coverage)' || echo "${BUILD_OPT_LEVEL:-default}")', exp=${exp}"

NUM_TRIALS="$TRIALS" \
ONLINE_ENABLED=1 PHASE3_BACKEND=local \
ONLINE_PER_TRIAL_OPTIMIZER=1 \
ONLINE_SHARED_TRIAL_CPU="${ONLINE_SHARED_TRIAL_CPU:-1}" \
ONLINE_FIXED_MUTATION_CORPUS=0 \
ONLINE_SWAP_INTERVAL_SECS="$INTERVAL" ONLINE_CONVERGENCE_K="$CONVERGENCE_K" \
PHASE2_OPTIMIZER_TIMEOUT_SECS="$OPT_TIMEOUT" \
ONLINE_LIVE_MUTATION_CAPTURE=1 \
ONLINE_MUTATION_MODE=reservoir \
PHASE2_MUTATION_CAP=30000 \
PHASE2_CORPUS_BUILD_DURATION_SECS=600 \
FUZZ_SOURCE_FOLDS_MAX_CORPUS_FILES=30000 \
ONLINE_TRIAL_CORES="$TRIAL_CORES" \
ONLINE_OPTIMIZER_CORES="$OPT_CORES" \
ONLINE_PROFILE_CPU="$SETUP_CPU" \
ONLINE_SETUP_BUILD_CPUS="$SETUP_BUILD_CPUS" \
ONLINE_AGENT_CPUS="$AGENT_CPUS" \
nohup python3 run_benchmark.py --online --phase 3 --project "$PROJ" \
  --duration "$DURATION" --experiment-id "$exp" > "$log" 2>&1 &

pid=$!
# Named by experiment id, not project: two campaigns on one project (a smoke
# beside a 24h run) used to overwrite each other's pid file.
echo "${PROJ} ${pid} ${exp} ${log}" > ".online_pertrial_${exp}.pid"
echo "  -> PID $pid, log $log"
echo
echo "watch progress:  tail -f ${log}"
echo "per-optimizer:   ls results/${exp}/${PROJ}-*/optimized/online/trials/"
echo "cpu cost so far: python3 analysis/cpu_cost_report.py --experiment-id ${exp}"
