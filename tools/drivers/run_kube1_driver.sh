#!/usr/bin/env bash
# Driver for the kube-1 experiment: wait for the running phase-2 setup to finish,
# prune the manifest to projects that actually produced an optimized binary,
# clean any colliding k8s jobs, then run phase 3 (Kubernetes) and phase 4.
set -uo pipefail
cd /home/sefcom/asu/project/test/benchmark

export OPTIMIZER_BACKEND=claude
export PHASE3_BACKEND=k8s
export PHASE3_K8S_TRIALS=20
export PHASE3_K8S_PARALLELISM=20
DURATION=21600

echo "[driver] $(date -u +%FT%TZ) start"

# 1. Wait for the in-flight phase-2 process to exit (no sleep; tail --pid blocks).
PHASE2_PID="$(pgrep -f 'run_benchmark.py --experiment-id kube-1 --phase 2' | head -1)"
if [ -n "${PHASE2_PID}" ]; then
  echo "[driver] waiting for phase2 pid ${PHASE2_PID} to finish..."
  tail --pid="${PHASE2_PID}" -f /dev/null
fi
echo "[driver] phase2 finished."

# 2. Prune manifest.json to entries whose optimized binary was actually built.
python3 - <<'PY'
import json, os
import config
exp = "kube-1"
manifest = json.load(open("manifest.json"))
keep = []
for e in manifest:
    key = f"{e['project']}-{e['cve']}"
    binp = os.path.join(config.RESULTS_DIR, exp, key, "optimized", "bin", e.get("fuzz_target", ""))
    if os.path.isfile(binp):
        keep.append(e)
    else:
        print(f"[driver] dropping (no optimized binary): {key}")
json.dump(keep, open("manifest.json", "w"), indent=2)
print("[driver] phase3 manifest:", [e["project"] for e in keep])
if not keep:
    raise SystemExit("[driver] no projects survived phase 2; aborting")
PY
rc=$?
if [ "${rc}" -ne 0 ]; then echo "[driver] abort: nothing to run"; exit 1; fi

# 3. Remove any colliding k8s jobs from prior runs (job names are exp-independent).
for p in selinux gpac unrar; do
  for v in baseline optimized; do
    kubectl delete job "phase3-${p}-${v}" --ignore-not-found 2>/dev/null || true
  done
done

# 4. Phase 3 on Kubernetes.
echo "[driver] $(date -u +%FT%TZ) phase 3 (k8s)..."
python3 -u run_benchmark.py --experiment-id kube-1 --phase 3 --duration "${DURATION}"
p3=$?
echo "[driver] phase3 exit=${p3}"

# 5. Phase 4 analysis (run even if some trials failed, so we get a report).
echo "[driver] $(date -u +%FT%TZ) phase 4 (analysis)..."
python3 -u run_benchmark.py --experiment-id kube-1 --phase 4 --duration "${DURATION}"
p4=$?
echo "[driver] phase4 exit=${p4}"

echo "[driver] $(date -u +%FT%TZ) DONE (phase3=${p3}, phase4=${p4})"
