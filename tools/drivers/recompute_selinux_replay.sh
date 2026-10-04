#!/usr/bin/env bash
# Recompute the selinux replay-speedup metric for kube-1 now that the
# replay_timing utf-8 bug is fixed. Fetches the biggest baseline corpus
# (corpus-9) from NFS via a throwaway pod, replays it on baseline vs optimized,
# writes setup_metadata.replay, then regenerates the phase-4 report.
set -uo pipefail
cd /home/sefcom/asu/project/test/benchmark

POD=replay-fetch-selinux
ZIP="/artifacts/bena/phase3-kube/kube-1/selinux/baseline/phase3-selinux-baseline/corpora/corpus-9-phase3-selinux-baseline-9-ccz7v.zip"
WORK=/tmp/selinux_replay
rm -rf "$WORK"; mkdir -p "$WORK/corpus"

kubectl run "$POD" --restart=Never --image=busybox:1.36 --overrides='{"spec":{"containers":[{"name":"c","image":"busybox:1.36","command":["sh","-c","sleep 900"],"volumeMounts":[{"name":"a","mountPath":"/artifacts"}]}],"volumes":[{"name":"a","persistentVolumeClaim":{"claimName":"nfs"}}]}}'
kubectl wait --for=condition=Ready "pod/$POD" --timeout=120s
kubectl cp "$POD:$ZIP" "$WORK/corpus.zip"
kubectl delete pod "$POD" --wait=false
(cd "$WORK/corpus" && unzip -qo ../corpus.zip)
echo "[recompute] corpus files: $(find "$WORK/corpus" -type f | wc -l)"

python3 - <<'PY'
import phase3_k8s
from pathlib import Path
key_dir = Path("results/kube-1/selinux-CVE-2021-36084").resolve()
sp = phase3_k8s.record_replay_metric(
    key_dir=key_dir,
    baseline_bin_dir=key_dir / "baseline" / "bin",
    optimized_bin_dir=key_dir / "optimized" / "bin",
    corpus_dir="/tmp/selinux_replay/corpus",
    fuzz_target="secilc-fuzzer",
)
print("[recompute] selinux replay_speedup:", sp)
PY

echo "[recompute] regenerating phase 4 report..."
PHASE3_BACKEND=k8s python3 -u run_benchmark.py --experiment-id kube-1 --phase 4 --duration 21600 2>&1 | tail -6
echo "[recompute] DONE"
