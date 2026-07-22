#!/usr/bin/env bash
# Rerun gpac for kube-1 now that a real seed corpus is cached locally
# (corpus_cache/gpac/fuzz_parse). Phase 2 should now actually optimize (the
# first run went BLOCKED_LOW_CONFIDENCE on a 1-byte fallback corpus). If it
# optimizes, run phase 3 on k8s, then a combined phase 4 (selinux + gpac).
set -uo pipefail
cd /home/sefcom/asu/project/test/benchmark
export OPTIMIZER_BACKEND=claude PHASE3_BACKEND=k8s PHASE3_K8S_TRIALS=20 PHASE3_K8S_PARALLELISM=20
DURATION=21600

GPAC='[{"project":"gpac","cve":"CVE-2022-1441","local_id":42507999,"fuzz_target":"fuzz_parse","crash_type":"Stack-buffer-overflow WRITE 1"}]'
BOTH='[{"project":"selinux","cve":"CVE-2021-36084","local_id":42493388,"fuzz_target":"secilc-fuzzer","crash_type":"Heap-use-after-free READ 8"},{"project":"gpac","cve":"CVE-2022-1441","local_id":42507999,"fuzz_target":"fuzz_parse","crash_type":"Stack-buffer-overflow WRITE 1"}]'

echo "[gpac] $(date -u +%FT%TZ) phase 2 (gpac only, cached corpus)"
python3 -c "import json,sys; open('manifest.json','w').write(sys.argv[1])" "$GPAC"
python3 -u run_benchmark.py --experiment-id kube-1 --phase 2 --duration "$DURATION"

applied=$(python3 - <<'PY'
import json
try:
    d = json.load(open("results/kube-1/gpac-CVE-2022-1441/setup_metadata.json"))
    print("1" if d.get("verification", {}).get("optimization_applied") else "0")
except Exception:
    print("0")
PY
)
echo "[gpac] optimization_applied=${applied}"

if [ "${applied}" = "1" ]; then
  for v in baseline optimized; do kubectl delete job "phase3-gpac-${v}" --ignore-not-found 2>/dev/null || true; done
  echo "[gpac] $(date -u +%FT%TZ) phase 3 (k8s)"
  # phase 3 reads manifest.json; keep gpac-only so it doesn't re-run selinux trials
  python3 -u run_benchmark.py --experiment-id kube-1 --phase 3 --duration "$DURATION"
else
  echo "[gpac] optimizer did not apply changes even with a real corpus; skipping phase 3"
fi

echo "[gpac] $(date -u +%FT%TZ) combined phase 4 (selinux + gpac)"
python3 -c "import json,sys; open('manifest.json','w').write(sys.argv[1])" "$BOTH"
python3 -u run_benchmark.py --experiment-id kube-1 --phase 4 --duration "$DURATION"
echo "[gpac] $(date -u +%FT%TZ) DONE"
