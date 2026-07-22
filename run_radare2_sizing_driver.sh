#!/usr/bin/env bash
# radare2-only phase-2 (-> conditional 3/4) with the NEW time-budgeted corpus
# sizing + parallel detect_leaks=0 crash-filter. radare2/ia_fuzz previously hit a
# double timeout (4h crash-filter + 5h optimizer) and produced nothing because
# its ~seconds/unit target made one -runs=0 pass take tens of min to hours.
# Expectation: sizing caps the corpus to ~n_min (flag 'too_slow') so the
# prebuild (filter+profile) completes in minutes; the agent then gets a real
# profile and 5h to try folds. This measures whether the fix makes radare2
# tractable (and whether it yields a fold).
set -uo pipefail
cd /home/sefcom/asu/project/test/benchmark

export BENCHMARK_OPTIMIZER=claude
export PHASE3_BACKEND=k8s
export PHASE3_K8S_TRIALS=10
export PHASE3_K8S_PARALLELISM=10
export RATE_LIMIT_MAX_WAITS=72
EXP=radare2-sizing
DURATION=172800
FULL="manifest_radare2.json"

echo "[radare2] $(date -u +%FT%TZ) start exp=${EXP} backend=claude budget=${PHASE2_CORPUS_REPLAY_BUDGET_SECS:-1800}"
cp "$FULL" manifest.json
python3 -c "import json;print('[radare2] target:',[e['project'] for e in json.load(open('manifest.json'))])"

echo "[radare2] $(date -u +%FT%TZ) phase 2 ..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 2 || true
echo "[radare2] phase2 returned (judging by metadata)"

# Surface the sizing decision as soon as phase 2 finishes.
python3 - "${EXP}" <<'PY'
import json, os, sys
import config
key = "radare2-arvo-10222"
base = os.path.join(config.RESULTS_DIR, sys.argv[1], key)
cb = os.path.join(base, "optimized", "source_diff", "profiles", "corpus_build",
                  "corpus_build_metadata.json")
if os.path.isfile(cb):
    sz = (json.load(open(cb)) or {}).get("sizing", {})
    print("[radare2] sizing:", json.dumps(sz))
else:
    print("[radare2] no corpus_build_metadata (prebuild may have used a different path):", cb)
meta = os.path.join(base, "setup_metadata.json")
if os.path.isfile(meta):
    d = json.load(open(meta)); v = d.get("verification", {}); r = d.get("replay") or {}
    print("[radare2] verify:", json.dumps(v),
          "replay_speedup:", (r.get("replay_speedup") if isinstance(r, dict) else None),
          "failure:", (d.get("failure") or {}).get("stage"))
PY

# Prune to a surviving optimization (verification.optimized True == passed the gate).
cp "$FULL" manifest.json
python3 - "${EXP}" <<'PY'
import json, os, sys
import config
keep = []
for e in json.load(open("manifest.json")):
    key = f"{e['project']}-{e['cve']}"
    meta = os.path.join(config.RESULTS_DIR, sys.argv[1], key, "setup_metadata.json")
    ok = False
    if os.path.isfile(meta):
        try: ok = bool(json.load(open(meta)).get("verification", {}).get("optimized"))
        except Exception: ok = False
    (keep.append(e) if ok else print(f"[radare2] not kept: {key}"))
json.dump(keep, open("manifest.json", "w"), indent=2)
if not keep:
    raise SystemExit("[radare2] no optimization survived; phase-2 only")
print("[radare2] phase3 manifest:", [e["project"] for e in keep])
PY
if [ $? -ne 0 ]; then
  echo "[radare2] $(date -u +%FT%TZ) DONE (phase2 only; no fold survived)"
  exit 0
fi

echo "[radare2] $(date -u +%FT%TZ) phase 3 ..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 3 --duration "${DURATION}"; p3=$?
echo "[radare2] $(date -u +%FT%TZ) phase 4 ..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 4 --duration "${DURATION}"; p4=$?
echo "[radare2] $(date -u +%FT%TZ) DONE (phase3=${p3}, phase4=${p4})"
