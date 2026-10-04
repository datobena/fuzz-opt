#!/usr/bin/env bash
# Clean re-run of new-kube-1-rerun with the proper fix: the harness pre-builds the
# fixed corpus + baseline profile (full corpus, NO cap), so the single-turn agent
# never has to background a long docker step and yield. All 6 projects, fresh.
set -uo pipefail
cd /home/sefcom/asu/project/test/benchmark

export BENCHMARK_OPTIMIZER=claude
unset FUZZ_SOURCE_FOLDS_MAX_CORPUS_FILES 2>/dev/null || true   # no cap
export PHASE3_BACKEND=k8s
export PHASE3_K8S_TRIALS=10
export PHASE3_K8S_PARALLELISM=10
EXP=new-kube-1-rerun
DURATION=172800
FULL="manifest_${EXP}.json"

echo "[v2] $(date -u +%FT%TZ) start: all 6, harness corpus prebuild, no cap"
cp "$FULL" manifest.json
python3 -c "import json;print('[v2] manifest:',[e['project'] for e in json.load(open('manifest.json'))])"

# --- Phase 2 (all 6). Harness prebuilds corpus+profile per project; the >=3 gate
#     exit code is not authoritative for us — we judge by per-project metadata.
echo "[v2] $(date -u +%FT%TZ) phase 2 (setup + optimize, claude, prebuilt corpus)..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 2 || true
echo "[v2] phase2 returned (judging by metadata)"

# --- Prune to entries whose optimized binary verified -------------------------
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
        print(f"[v2] dropping (optimized did not verify): {key} ({reason})")
json.dump(keep, open("manifest.json", "w"), indent=2)
print("[v2] phase-3 manifest:", [e["project"] for e in keep])
if not keep:
    raise SystemExit("[v2] no survivors; aborting")
PY
rc=$?
if [ "${rc}" -ne 0 ]; then echo "[v2] no survivors; abort"; exit 1; fi

# --- Phase 3 + 4 (cluster already clean; no job deletion needed) --------------
echo "[v2] $(date -u +%FT%TZ) phase 3 (k8s, trials=10, parallel=10, duration=${DURATION})..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 3 --duration "${DURATION}"
p3=$?
echo "[v2] phase3 exit=${p3}"
echo "[v2] $(date -u +%FT%TZ) phase 4 (analysis)..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 4 --duration "${DURATION}"
p4=$?
echo "[v2] $(date -u +%FT%TZ) DONE (phase3=${p3}, phase4=${p4})"
