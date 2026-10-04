#!/usr/bin/env bash
# Phase-3/4 driver for the new-kube-1-rerun experiment (Kubernetes).
# Waits for the phase-2 driver to finish (NK1_WAIT_PID), confirms it succeeded,
# then runs phase 3 (10 trials/variant, 48h/trial, 10 parallel) and phase 4.
#
# Colliding phase3 jobs were already deleted up-front (authorized), and no other
# run creates them, so this script does NOT delete any k8s jobs itself.
set -uo pipefail
cd /home/sefcom/asu/project/test/benchmark

export PHASE3_BACKEND=k8s
export PHASE3_K8S_TRIALS=10            # match new-kube-1: 10 trials/variant
export PHASE3_K8S_PARALLELISM=10
EXP=new-kube-1-rerun
DURATION=172800                       # 48h/trial, matching new-kube-1

# --- Wait for phase 2 to finish (if a PID was provided) -----------------------
if [ -n "${NK1_WAIT_PID:-}" ]; then
  echo "[driver-p34] $(date -u +%FT%TZ) waiting for phase-2 pid ${NK1_WAIT_PID} to exit..."
  tail --pid="${NK1_WAIT_PID}" -f /dev/null
fi

# --- Confirm phase 2 finished cleanly (success sentinel) ----------------------
P2LOG="$(cat .nk1_rerun_p2_logname 2>/dev/null || true)"
if ! grep -q "PHASE 2 DONE" "${P2LOG}" 2>/dev/null; then
  echo "[driver-p34] phase 2 did not finish cleanly (no 'PHASE 2 DONE' in '${P2LOG}'); aborting phase 3"
  exit 1
fi

# --- Confirm the pruned manifest has survivors --------------------------------
N=$(python3 -c "import json;print(len(json.load(open('manifest.json'))))")
echo "[driver-p34] $(date -u +%FT%TZ) phase 3 manifest has ${N} entries:"
python3 -c "import json;[print('   -',e['project'],e['cve']) for e in json.load(open('manifest.json'))]"
if [ "${N}" -eq 0 ]; then echo "[driver-p34] empty manifest; aborting"; exit 1; fi

# --- Phase 3: Kubernetes fuzzing trials ---------------------------------------
echo "[driver-p34] $(date -u +%FT%TZ) phase 3 (k8s, trials=10, parallel=10, duration=${DURATION})..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 3 --duration "${DURATION}"
p3=$?
echo "[driver-p34] phase3 exit=${p3}"

# --- Phase 4: analysis (run even if some trials failed, to get a report) -------
echo "[driver-p34] $(date -u +%FT%TZ) phase 4 (analysis)..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 4 --duration "${DURATION}"
p4=$?
echo "[driver-p34] phase4 exit=${p4}"

echo "[driver-p34] $(date -u +%FT%TZ) DONE (phase3=${p3}, phase4=${p4})"
