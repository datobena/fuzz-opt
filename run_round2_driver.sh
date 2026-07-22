#!/usr/bin/env bash
# Full pipeline (phase 2 -> 3 -> 4) on the 8 recommended ARVO targets, under the
# current behavior-preservation contract + all phase-2 fixes (harness corpus
# prebuild, 5h optimizer timeout, session-resume, 90min agent Bash timeout).
#
# 8 targets (screened build_ok + reproduce_ok):
#   freeradius-server, graphicsmagick, hunspell, libjxl, libredwg, radare2,
#   sleuthkit, yara
# (libjxl/radare2 previously found no fold under both backends; libredwg/sleuthkit
#  /yara optimized under codex; graphicsmagick/freeradius/hunspell never tried.
#  We try all 8 fresh under the current claude contract.)
set -uo pipefail
cd /home/sefcom/asu/project/test/benchmark

export BENCHMARK_OPTIMIZER=claude
export PHASE3_BACKEND=k8s
export PHASE3_K8S_TRIALS=10
export PHASE3_K8S_PARALLELISM=10
export RATE_LIMIT_MAX_WAITS=72        # ride out a full ~5h session-limit reset
EXP=round2-8
DURATION=172800                       # 48h/trial
FULL="manifest_${EXP}.json"

echo "[round2] $(date -u +%FT%TZ) start exp=${EXP} backend=claude trials=10 dur=${DURATION}"
cp "$FULL" manifest.json
python3 -c "import json;print('[round2] targets:',[e['project'] for e in json.load(open('manifest.json'))])"

# --- Phase 2: baseline build + claude optimize + PoC verify (8 projects) -------
echo "[round2] $(date -u +%FT%TZ) phase 2 ..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 2 || true
echo "[round2] phase2 returned (judging by metadata)"

# --- Prune to entries whose optimized binary verified -------------------------
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
            v = json.load(open(meta)).get("verification", {})
            ok = bool(v.get("optimized"))
            reason = f"baseline={v.get('baseline')} optimized={v.get('optimized')} applied={v.get('optimization_applied')}"
        except Exception as ex:
            reason = f"bad metadata: {ex}"
    (keep.append(e) if ok else print(f"[round2] dropping (optimized did not verify): {key} ({reason})"))
json.dump(keep, open("manifest.json", "w"), indent=2)
print("[round2] phase3 manifest:", [e["project"] for e in keep])
if not keep:
    raise SystemExit("[round2] no projects optimized; nothing to fuzz")
PY
[ $? -ne 0 ] && { echo "[round2] abort: nothing optimized"; exit 1; }

# --- Phase 3 (k8s, 10 trials x 48h) + Phase 4 (analysis) ----------------------
echo "[round2] $(date -u +%FT%TZ) phase 3 ..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 3 --duration "${DURATION}"
p3=$?; echo "[round2] phase3 exit=${p3}"
echo "[round2] $(date -u +%FT%TZ) phase 4 ..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 4 --duration "${DURATION}"
p4=$?
echo "[round2] $(date -u +%FT%TZ) DONE (phase3=${p3}, phase4=${p4})"
