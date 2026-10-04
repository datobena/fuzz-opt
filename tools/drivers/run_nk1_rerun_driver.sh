#!/usr/bin/env bash
# Phase-2 driver for the new-kube-1-rerun experiment (NO Kubernetes here).
# Re-runs the 6 optimizable projects from new-kube-1 (libxml2, wolfssl, libavc,
# assimp, PcapPlusPlus, selinux) from the beginning with the CLAUDE optimizer
# backend and the updated behavior-preservation fold skills. The 2 that could not
# be optimized in new-kube-1 (c-blosc2, open62541) are already absent from
# manifest.json.
#
# This script does phase 2 (baseline build + claude optimize + PoC verify) and
# prunes the manifest to verified optimizations. Phase 3/4 (Kubernetes) is a
# SEPARATE script (run_nk1_rerun_phase34.sh) because it must first delete
# colliding phase3 jobs left by the prior run — an action that needs explicit
# authorization.
set -uo pipefail
cd /home/sefcom/asu/project/test/benchmark

export BENCHMARK_OPTIMIZER=claude     # phase-2 optimizer = claude (not codex)
EXP=new-kube-1-rerun

echo "[driver-p2] $(date -u +%FT%TZ) start exp=${EXP} backend=claude"
echo "[driver-p2] manifest projects:"
python3 -c "import json;[print('   -',e['project'],e['cve']) for e in json.load(open('manifest.json'))]"

# Snapshot the curated 6-entry manifest before phase-2/prune may rewrite it.
cp manifest.json "manifest_${EXP}.json"

# --- Phase 2: baseline build + claude optimization + PoC verification ---------
echo "[driver-p2] $(date -u +%FT%TZ) phase 2 (setup + optimize, claude)..."
python3 -u run_benchmark.py --experiment-id "${EXP}" --phase 2
p2=$?
echo "[driver-p2] phase2 exit=${p2}"
if [ "${p2}" -ne 0 ]; then echo "[driver-p2] phase2 failed; aborting"; exit 1; fi

# --- Prune manifest to entries whose OPTIMIZED binary actually verified --------
# (verification.optimized == True). With the updated skills + the blocking
# optimized-PoC check, a bug-removing fold is reverted to baseline and reported
# optimized=False; such entries are dropped so no invalid comparison reaches
# phase 3.
python3 - "${EXP}" <<'PY'
import json, os, sys
import config
exp = sys.argv[1]
manifest = json.load(open("manifest.json"))
keep = []
for e in manifest:
    key = f"{e['project']}-{e['cve']}"
    meta = os.path.join(config.RESULTS_DIR, exp, key, "setup_metadata.json")
    ok = False
    reason = "no setup_metadata.json"
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
        print(f"[driver-p2] dropping (optimized did not verify): {key} ({reason})")
json.dump(keep, open("manifest.json", "w"), indent=2)
print("[driver-p2] phase3 manifest:", [e["project"] for e in keep])
if not keep:
    raise SystemExit("[driver-p2] no projects survived phase 2")
PY

echo "[driver-p2] $(date -u +%FT%TZ) PHASE 2 DONE (exit=${p2})."
echo "[driver-p2] Next: authorize k8s job cleanup, then run run_nk1_rerun_phase34.sh"
