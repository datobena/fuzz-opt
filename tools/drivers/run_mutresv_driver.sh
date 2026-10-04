#!/usr/bin/env bash
# Full chain (phase 2 -> 3 -> 4), run LOCALLY, for the 4 projects that had the
# mutation-capture prefix bias (libxml2, wolfssl, libavc, selinux; assimp excluded
# -- it never hit the cap). Re-runs under the FIXED capture: reservoir sampling +
# guaranteed one-pass over the seed queue + run-for-max(duration, time_for_one_queue).
# Conservative fold contract (profile-once-fuzz-folds), same optimizer as mut-8h.
set -u
cd /home/sefcom/asu/project/test/benchmark

EXP=mut-resv
DUR=28800                       # 8h trials, matching mut-8h / aggr-8h
TS=$(date -u +%Y%m%d_%H%M%SZ)
LOG="mutresv_fullchain_${TS}.log"
echo "$LOG" > .mutresv_logname

# --- optimizer + mutation-capture env ---
export BENCHMARK_OPTIMIZER=claude
export OPTIMIZER_BACKEND=claude
export BENCHMARK_CLAUDE_MODEL='claude-fable-5[1m]'
export PHASE2_OPTIMIZER_SKILL=profile-once-fuzz-folds
export PHASE2_MUTATION_ENABLED=1
export PHASE2_MUTATION_REQUIRED=1
# fixed capture: reservoir + guaranteed queue-pass + run-for-max(duration,one-queue)
export PHASE2_MUTATION_CAP=20000
export PHASE2_MUTATION_DURATION_SECS=600
# "wait as much as needed": generous optimizer + per-agent-bash timeouts
export PHASE2_OPTIMIZER_TIMEOUT_SECS=86400      # 24h per project
export PHASE2_AGENT_BASH_TIMEOUT_MS=5400000     # 90 min per agent bash call
export BASH_DEFAULT_TIMEOUT_MS=5400000
export BASH_MAX_TIMEOUT_MS=5400000
# run phase 3 locally (pinned docker), NOT k8s
export PHASE3_BACKEND=local

# --- filter manifest to the 4 projects (exclude assimp); restore on exit ---
cp manifest.json .manifest.mutresv.bak
python3 -c "import json; m=[e for e in json.load(open('manifest.json')) if e['project']!='assimp']; json.dump(m, open('manifest.json','w'), indent=2)"
restore(){ cp .manifest.mutresv.bak manifest.json; }
trap restore EXIT

{
  echo "[mut-resv $(date -u +%FT%TZ)] FULL CHAIN (local) START"
  echo "  projects=$(python3 -c "import json;print(','.join(e['project'] for e in json.load(open('manifest.json'))))")"
  echo "  skill=$PHASE2_OPTIMIZER_SKILL model=$BENCHMARK_CLAUDE_MODEL backend=local dur=${DUR}s"
  echo "  mutation=reservoir+queuepass+ensure-queue-pass  opt_timeout=${PHASE2_OPTIMIZER_TIMEOUT_SECS}s"

  echo "[mut-resv $(date -u +%FT%TZ)] PHASE 2 START"
  python3 -u run_benchmark.py --experiment-id "$EXP" --phase 2 --phase2-max-parallel 3
  p2=$?
  echo "[mut-resv $(date -u +%FT%TZ)] PHASE 2 DONE rc=$p2"
  cp manifest.json "manifest_${EXP}.json" 2>/dev/null || true
  if [ "$p2" -ne 0 ]; then echo "[mut-resv] phase 2 failed -> STOP"; exit "$p2"; fi

  echo "[mut-resv $(date -u +%FT%TZ)] PHASE 3 START (local, ${DUR}s)"
  python3 -u run_benchmark.py --experiment-id "$EXP" --phase 3 --duration "$DUR"
  p3=$?
  echo "[mut-resv $(date -u +%FT%TZ)] PHASE 3 DONE rc=$p3"
  if [ "$p3" -ne 0 ]; then echo "[mut-resv] phase 3 failed -> STOP"; exit "$p3"; fi

  echo "[mut-resv $(date -u +%FT%TZ)] PHASE 4 START"
  python3 -u run_benchmark.py --experiment-id "$EXP" --phase 4
  echo "[mut-resv $(date -u +%FT%TZ)] PHASE 4 DONE rc=$?"
  echo "[mut-resv $(date -u +%FT%TZ)] FULL CHAIN COMPLETE"
} >> "$LOG" 2>&1
