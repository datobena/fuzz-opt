#!/usr/bin/env bash
# Rerun phase 2 (-> 3 -> 4) for the two round2-8 "problem" targets under the
# CURRENT code: behavior-preservation contract + strict replay gate
# (PHASE2_MIN_REPLAY_SPEEDUP=1.02) + corpus/replay crash-robustness fixes
# (build_corpus per-unit mem caps; replay_timing per-slot retry).
#
#   libjxl-arvo-35172   : round2-8 replay was UNMEASURABLE (djxl_fuzzer -runs=0
#                         SIGSEGV, exit 139) -> speedup blanked to None, kept.
#   sleuthkit-arvo-24893: round2-8 replay 0.999x (bit-exact O(n^2)->O(n) fold not
#                         exercised by the corpus) -> no real speedup, kept.
# Both were kept in round2-8 because the strict replay gate was not yet active.
# This rerun re-optimizes them so the crash is filtered/retried (libjxl) and the
# gate reverts anything <=1.02x (sleuthkit). Phase 3 only runs for a survivor.
set -uo pipefail
cd /home/sefcom/asu/project/test/benchmark

export BENCHMARK_OPTIMIZER=claude
export PHASE3_BACKEND=k8s
export PHASE3_K8S_TRIALS=10
export PHASE3_K8S_PARALLELISM=10
export RATE_LIMIT_MAX_WAITS=72        # ride out a full ~5h session-limit reset
EXP=round2-rerun
DURATION=172800                       # 48h/trial (matches round2-8 for comparability)
FULL="manifest_round2-rerun.json"

echo "[rerun] $(date -u +%FT%TZ) start exp=${EXP} backend=claude trials=10 dur=${DURATION}"
cp "$FULL" manifest.json
python3 -c "import json;print('[rerun] targets:',[e['project'] for e in json.load(open('manifest.json'))])"

# --- Phase 2: baseline build + claude optimize + PoC verify + replay gate ------
echo "[rerun] $(date -u +%FT%TZ) phase 2 ..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 2 || true
echo "[rerun] phase2 returned (judging by metadata)"

# --- Prune to entries whose optimized binary verified AND survived the gate ----
# verification.optimized is False when the strict replay gate reverts a fold, so
# this same check drops gate-reverted (0.999x / unmeasurable) optimizations.
cp "$FULL" manifest.json
python3 - "${EXP}" <<'PY'
import json, os, sys
import config
exp = sys.argv[1]
keep = []
for e in json.load(open("manifest.json")):
    key = f"{e['project']}-{e['cve']}"
    meta = os.path.join(config.RESULTS_DIR, exp, key, "setup_metadata.json")
    ok, reason = False, "no setup_metadata.json"
    if os.path.isfile(meta):
        try:
            d = json.load(open(meta))
            v = d.get("verification", {})
            r = d.get("replay") or {}
            rs = r.get("replay_speedup") if isinstance(r, dict) else None
            fail = (d.get("failure") or {}).get("stage")
            ok = bool(v.get("optimized"))
            reason = (f"baseline={v.get('baseline')} optimized={v.get('optimized')} "
                      f"applied={v.get('optimization_applied')} replay_speedup={rs} "
                      f"reject={fail}")
        except Exception as ex:
            reason = f"bad metadata: {ex}"
    (keep.append(e) if ok else print(f"[rerun] dropping (not kept): {key} ({reason})"))
    if ok:
        print(f"[rerun] keeping: {key} ({reason})")
json.dump(keep, open("manifest.json", "w"), indent=2)
print("[rerun] phase3 manifest:", [e["project"] for e in keep])
if not keep:
    raise SystemExit("[rerun] no optimization survived the gate; nothing to fuzz")
PY
if [ $? -ne 0 ]; then
  echo "[rerun] $(date -u +%FT%TZ) DONE (phase2 only; nothing survived the strict gate)"
  exit 0
fi

# --- Phase 3 (k8s) + Phase 4 (analysis) for any survivor ----------------------
echo "[rerun] $(date -u +%FT%TZ) phase 3 ..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 3 --duration "${DURATION}"
p3=$?; echo "[rerun] phase3 exit=${p3}"
echo "[rerun] $(date -u +%FT%TZ) phase 4 ..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 4 --duration "${DURATION}"
p4=$?
echo "[rerun] $(date -u +%FT%TZ) DONE (phase3=${p3}, phase4=${p4})"
