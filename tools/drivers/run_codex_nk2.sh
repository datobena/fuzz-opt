#!/usr/bin/env bash
# Optimize ALL new-kube-2 projects with the CODEX backend (codex exec, gpt-5.5).
# new-kube-2 projects (n132/arvo images): radare2, libredwg, libjxl, lcms,
# sleuthkit, yara, PcapPlusPlus. Of these, Claude (nk2) only folded lcms,
# sleuthkit, PcapPlusPlus; this run tests codex on all 7 (incl. the 4 Claude
# dropped). Same corpus cap (2000) as the codex-selinux run for tractability and
# consistency (sleuthkit's full corpus wedges; others are large). Phase 2 only.
# Restores the working manifest.json on exit.
set -uo pipefail
exec >>/tmp/codex_nk2.log 2>&1
cd /home/sefcom/asu/project/test/benchmark

EXP=codex-nk2
say(){ echo "[cnk2 $(date -u +%FT%TZ)] $*"; }
say "==================== START ===================="
MBAK=$(mktemp /tmp/cnk2_manifest_bak.XXXX.json)
cp manifest.json "$MBAK" 2>/dev/null || echo "[]" > "$MBAK"
restore(){ cp "$MBAK" manifest.json 2>/dev/null && say "manifest.json restored"; }
trap restore EXIT
mkdir -p "results/$EXP"

# compose manifest = all 7 new-kube-2 projects (reuse the exact nk2 entries)
python3 - <<'PY'
import json
m=json.load(open("results/new-kube-2/manifest_full.json"))
json.dump(m, open("manifest.json","w"), indent=2)
json.dump(m, open("results/codex-nk2/manifest_full.json","w"), indent=2)
print("[cnk2-compose]", [e["project"] for e in m])
PY
say "composed manifest: $(python3 -c 'import json;print([e["project"] for e in json.load(open("manifest.json"))])')"

export OPTIMIZER_BACKEND=codex BENCHMARK_OPTIMIZER=codex
export PHASE2_OPTIMIZER_SKILL=profile-once-fuzz-folds
export PHASE2_OPTIMIZER_TIMEOUT_SECS=14400
export PHASE2_MAX_PARALLEL=3
export FUZZ_SOURCE_FOLDS_MAX_CORPUS_FILES=2000
# codex default model gpt-5.5 (~/.codex/config.toml); BENCHMARK_CODEX_MODEL unset
say "phase 2 START (codex exec / gpt-5.5 / profile-once-fuzz-folds, cap=2000, parallel=3)"
python3 -u run_benchmark.py --experiment-id "$EXP" --phase 2 --duration 86400
say "phase 2 exited rc=$?"

# summary: which optimized + replay speedup per project
python3 - <<'PY'
import json, os
EXP="codex-nk2"; base=f"results/{EXP}"
m=json.load(open(f"{base}/manifest_full.json"))
rows=[]
for e in m:
    key=f"{e['project']}-{e['cve']}"
    smp=f"{base}/{key}/setup_metadata.json"
    if not os.path.exists(smp):
        rows.append((e["project"],"NO_SETUP",None)); continue
    d=json.load(open(smp)); v=d.get("verification",{}); r=d.get("replay",{})
    applied=bool(v.get("optimization_applied"))
    spd=r.get("replay_speedup") or r.get("speedup")
    rows.append((e["project"], "optimized" if applied else "no-fold", spd))
print("[cnk2-summary] project / status / capped-replay-speedup")
for p,s,spd in rows:
    print(f"   {p:14} {s:10} {spd if spd is not None else ''}")
json.dump(rows, open(f"{base}/codex_nk2_summary.json","w"), indent=2)
PY
say "==================== DONE ===================="
