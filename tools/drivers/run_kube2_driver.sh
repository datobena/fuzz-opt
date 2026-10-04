#!/usr/bin/env bash
# kube-2: run the full chain (phase 2 -> 3 -> 4) on the 25 ARVO candidate CVEs
# our optimizer hasn't been run on. Phase 2 optimizes all; only CVEs whose
# optimization was actually APPLIED proceed to the k8s phase-3 trials.
set -uo pipefail
cd /home/sefcom/asu/project/test/benchmark
export OPTIMIZER_BACKEND=claude PHASE3_BACKEND=k8s PHASE3_K8S_TRIALS=20 PHASE3_K8S_PARALLELISM=20
DURATION=21600
EXP=kube-2

# manifest.json already holds the 25-CVE run set.
FULL="$(cat manifest.json)"

echo "[kube2] $(date -u +%FT%TZ) phase 2 (optimize all 25)"
python3 -u run_benchmark.py --experiment-id "$EXP" --phase 2 --duration "$DURATION"

# Prune to CVEs whose optimization was actually applied (real optimized binary,
# not a baseline fallback) so phase 3 only builds/runs meaningful comparisons.
python3 - <<'PY'
import json, os
import config
exp="kube-2"
keep=[]
for e in json.load(open("manifest.json")):
    key=f"{e['project']}-{e['cve']}"
    mp=os.path.join(config.RESULTS_DIR, exp, key, "setup_metadata.json")
    applied=False; binok=False
    if os.path.exists(mp):
        try:
            d=json.load(open(mp)); applied=bool(d.get("verification",{}).get("optimization_applied"))
        except Exception: pass
    binp=os.path.join(config.RESULTS_DIR, exp, key, "optimized", "bin", e.get("fuzz_target",""))
    binok=os.path.isfile(binp)
    if applied and binok: keep.append(e)
    else: print(f"[kube2] drop (applied={applied} bin={binok}): {key}")
json.dump(keep, open("manifest.json","w"), indent=2)
print(f"[kube2] phase3 set: {[e['project']+'/'+e['cve'] for e in keep]}")
if not keep: raise SystemExit("[kube2] nothing optimized; skipping phase 3")
PY
optimized_any=$?

if [ "$optimized_any" -eq 0 ]; then
  # clean any colliding k8s jobs for these projects
  for p in ffmpeg gdal gpac imagemagick lldpd ndpi opensc openthread pjsip selinux wireshark; do
    for v in baseline optimized; do kubectl delete job "phase3-${p}-${v}" --ignore-not-found 2>/dev/null || true; done
  done
  echo "[kube2] $(date -u +%FT%TZ) phase 3 (k8s)"
  python3 -u run_benchmark.py --experiment-id "$EXP" --phase 3 --duration "$DURATION"
else
  echo "[kube2] no optimizations applied; skipping phase 3"
fi

# Phase 4 on whatever got trials.
echo "[kube2] $(date -u +%FT%TZ) phase 4"
python3 -u run_benchmark.py --experiment-id "$EXP" --phase 4 --duration "$DURATION"

# Restore the full 25-CVE manifest for the record.
printf '%s' "$FULL" > manifest.json
echo "[kube2] $(date -u +%FT%TZ) DONE"
