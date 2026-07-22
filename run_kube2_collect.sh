#!/usr/bin/env bash
# Manually collect kube-2 phase-3 results (the blocked driver was stopped):
# pull the already-archived trials from NFS, transform to trial_XX/, compute the
# replay metric on the biggest baseline corpus, run phase 4, then clean up jobs.
set -uo pipefail
cd /home/sefcom/asu/project/test/benchmark
export PHASE3_BACKEND=k8s

python3 - <<'PY'
import json
m=[
 {"project":"ffmpeg","cve":"CVE-2019-17542","local_id":42476801,"fuzz_target":"ffmpeg_AV_CODEC_ID_CFHD_fuzzer","crash_type":"Heap-buffer-overflow WRITE 2"},
 {"project":"gpac","cve":"CVE-2021-40569","local_id":42494317,"fuzz_target":"fuzz_parse","crash_type":"Segv on unknown address"},
 {"project":"selinux","cve":"CVE-2021-36085","local_id":42493454,"fuzz_target":"secilc-fuzzer","crash_type":"Heap-use-after-free READ 8"},
]
json.dump(m, open("manifest.json","w"), indent=2)
print("manifest set to 3 optimized CVEs")
PY

echo "[collect] collecting + transforming + replay..."
python3 - <<'PY'
import json, subprocess, phase3_k8s
manifest=json.load(open("manifest.json"))
collected=phase3_k8s.collect_artifacts(manifest, "kube-2")
print("[collect] collector pod:", collected["pod"])
res=phase3_k8s.transform_all(collected, manifest, "kube-2")
print("[collect] transformed", len(res), "trial dirs")
try:
    phase3_k8s.compute_replay_metrics(collected, manifest, "kube-2")
finally:
    subprocess.run(["kubectl","delete","pod",collected["pod"],"--wait=false"])
PY

echo "[collect] phase 4..."
python3 -u run_benchmark.py --experiment-id kube-2 --phase 4 --duration 21600 2>&1 | tail -8

echo "[collect] cleaning up kube-2 k8s jobs..."
for p in ffmpeg gpac selinux; do
  for v in baseline optimized; do kubectl delete job "phase3-${p}-${v}" --ignore-not-found 2>/dev/null || true; done
done
echo "[collect] DONE"
