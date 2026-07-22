#!/usr/bin/env bash
# kube-3: rerun the two category-B (source-extraction) failures from kube-2 now
# that the afl/ engine-dir bug is fixed. ndpi + openthread should now extract
# their real project source and build. Full chain: phase 2 -> prune -> phase 3 -> 4.
set -uo pipefail
cd /home/sefcom/asu/project/test/benchmark
export OPTIMIZER_BACKEND=claude PHASE3_BACKEND=k8s PHASE3_K8S_TRIALS=20 PHASE3_K8S_PARALLELISM=20
DURATION=21600
EXP=kube-3

python3 -c "import json; json.dump([
 {'project':'ndpi','cve':'CVE-2020-15472','local_id':42483697,'fuzz_target':'fuzz_process_packet','crash_type':'Heap-buffer-overflow READ 1'},
 {'project':'openthread','cve':'CVE-2019-20791','local_id':42480412,'fuzz_target':'ncp-uart-received-fuzzer','crash_type':'Stack-buffer-overflow WRITE {*}'}
], open('manifest.json','w'), indent=2)"
echo "[kube3] $(date -u +%FT%TZ) phase 2 (ndpi + openthread, extraction fix)"
python3 -u run_benchmark.py --experiment-id "$EXP" --phase 2 --duration "$DURATION"

python3 - <<'PY'
import json, os
import config
keep=[]
for e in json.load(open("manifest.json")):
    key=f"{e['project']}-{e['cve']}"
    mp=os.path.join(config.RESULTS_DIR, "kube-3", key, "setup_metadata.json")
    applied=False
    if os.path.exists(mp):
        try: applied=bool(json.load(open(mp)).get("verification",{}).get("optimization_applied"))
        except Exception: pass
    binp=os.path.join(config.RESULTS_DIR, "kube-3", key, "optimized", "bin", e.get("fuzz_target",""))
    if applied and os.path.isfile(binp): keep.append(e)
    else: print(f"[kube3] drop (applied={applied}): {key}")
json.dump(keep, open("manifest.json","w"), indent=2)
print(f"[kube3] phase3 set: {[e['project'] for e in keep]}")
if not keep: raise SystemExit("[kube3] nothing optimized; skipping phase 3")
PY
rc=$?

if [ "$rc" -eq 0 ]; then
  for p in ndpi openthread; do for v in baseline optimized; do kubectl delete job "phase3-${p}-${v}" --ignore-not-found 2>/dev/null || true; done; done
  echo "[kube3] $(date -u +%FT%TZ) phase 3 (k8s)"
  python3 -u run_benchmark.py --experiment-id "$EXP" --phase 3 --duration "$DURATION"
  echo "[kube3] $(date -u +%FT%TZ) phase 4"
  python3 -u run_benchmark.py --experiment-id "$EXP" --phase 4 --duration "$DURATION"
else
  echo "[kube3] no optimizations applied; skipping phase 3/4"
fi
echo "[kube3] $(date -u +%FT%TZ) DONE"
