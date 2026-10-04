#!/usr/bin/env bash
# Retry driver for new-kube-1-rerun: re-optimize the 4 projects that stalled in
# the first phase-2 attempt (assimp, libavc, selinux, wolfssl) WITH a corpus-file
# cap, which keeps each optimizer docker step under the agent timeout and avoids
# the headless background-yield quirk that made them produce no fold.
#
# The 2 already-optimized projects (libxml2, PcapPlusPlus) are left as-is. After
# re-optimizing, the full 6-manifest is restored and pruned to whatever actually
# optimized; phase 3 (10 trials/variant, 48h/trial, k8s 10-parallel) and phase 4
# then run on the survivors. No k8s job deletion here (collisions were already
# cleared and nothing recreated them).
set -uo pipefail
cd /home/sefcom/asu/project/test/benchmark

export BENCHMARK_OPTIMIZER=claude
export FUZZ_SOURCE_FOLDS_MAX_CORPUS_FILES=2000   # the mitigation that was missing
export PHASE3_BACKEND=k8s
export PHASE3_K8S_TRIALS=10
export PHASE3_K8S_PARALLELISM=10
EXP=new-kube-1-rerun
DURATION=172800
FULL="manifest_${EXP}.json"                       # snapshot of all 6

echo "[retry] $(date -u +%FT%TZ) start: re-optimize 4 declined with corpus cap=2000"

# Build a manifest of just the 4 declined entries from the 6-snapshot.
python3 - "$FULL" assimp libavc selinux wolfssl <<'PY'
import json, sys
full = json.load(open(sys.argv[1]))
want = set(sys.argv[2:])
sub = [e for e in full if e["project"] in want]
json.dump(sub, open("manifest.json", "w"), indent=2)
print("[retry] phase-2 manifest (4):", [e["project"] for e in sub])
PY

# --- Phase 2 for the 4 (capped corpus). The ">=3 built" gate counts only these
#     4, so its exit code is NOT authoritative here — we judge by per-project
#     metadata after, combined with the 2 already done.
echo "[retry] $(date -u +%FT%TZ) phase 2 (4 declined, capped corpus)..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 2 || true
echo "[retry] phase2-of-4 returned (exit ignored; judging by metadata)"

# --- Restore the full 6-manifest and prune to entries that optimized ----------
cp "$FULL" manifest.json
python3 - "${EXP}" <<'PY'
import json, os, sys
import config
exp = sys.argv[1]
manifest = json.load(open("manifest.json"))
keep = []
for e in manifest:
    key = f"{e['project']}-{e['cve']}"
    meta = os.path.join(config.RESULTS_DIR, exp, key, "setup_metadata.json")
    ok = False; reason = "no setup_metadata.json"
    if os.path.isfile(meta):
        try:
            v = json.load(open(meta)).get("verification", {})
            ok = bool(v.get("optimized"))
            reason = f"baseline={v.get('baseline')} optimized={v.get('optimized')} applied={v.get('optimization_applied')}"
        except Exception as ex:
            reason = f"bad metadata: {ex}"
    if ok:
        keep.append(e)
    else:
        print(f"[retry] dropping (optimized did not verify): {key} ({reason})")
json.dump(keep, open("manifest.json", "w"), indent=2)
print("[retry] phase-3 manifest:", [e["project"] for e in keep])
if not keep:
    raise SystemExit("[retry] no survivors; aborting")
PY
rc=$?
if [ "${rc}" -ne 0 ]; then echo "[retry] no survivors; abort"; exit 1; fi

# --- Phase 3 + 4 --------------------------------------------------------------
echo "[retry] $(date -u +%FT%TZ) phase 3 (k8s, trials=10, parallel=10, duration=${DURATION})..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 3 --duration "${DURATION}"
p3=$?
echo "[retry] phase3 exit=${p3}"
echo "[retry] $(date -u +%FT%TZ) phase 4 (analysis)..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 4 --duration "${DURATION}"
p4=$?
echo "[retry] $(date -u +%FT%TZ) DONE (phase3=${p3}, phase4=${p4})"
