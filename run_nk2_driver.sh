#!/usr/bin/env bash
# new-kube-2 driver: 4 new n132/arvo targets + re-optimized PcapPlusPlus.
# Full pipeline: compose manifest -> phase 2 (optimize) -> prune to (4 new +
# PcapPlusPlus) -> phase 3 (24h k8s trials) -> phase 4 (report).
# Pure k8s/docker orchestration (the only LLM use is phase-2's own optimizer).
# Restores the working manifest.json on exit (crash-safe trap).
set -uo pipefail
exec >>/tmp/nk2_driver.log 2>&1
cd /home/sefcom/asu/project/test/benchmark

EXP=new-kube-2
say() { echo "[nk2 $(date -u +%FT%TZ)] $*"; }
say "==================== START ===================="

# --- backup working manifest + restore on exit ---
MBAK=$(mktemp /tmp/nk2_manifest_bak.XXXX.json)
cp manifest.json "$MBAK" 2>/dev/null || echo "[]" > "$MBAK"
restore() { cp "$MBAK" manifest.json 2>/dev/null && say "manifest.json restored"; }
trap restore EXIT
mkdir -p "results/$EXP"

# --- 1) compose manifest: NEW working (buffer) + PcapPlusPlus ---
python3 - <<'PY'
import json, os
USED = {"gpac","selinux","unrar","ffmpeg","gdal","imagemagick","lldpd","ndpi",
        "opensc","openthread","pjsip","wireshark","assimp","c-blosc2","libavc",
        "libxml2","open62541","PcapPlusPlus","wolfssl"}
rows = json.load(open("arvo_image_screen_results.json"))
new = {}
for r in rows:
    if r.get("status") == "working" and r["project"] not in USED:
        new.setdefault(r["project"], r)        # best (first) id per project
def entry(project, lid, ft, ct):
    return {"project": project, "cve": f"arvo-{lid}", "local_id": int(lid),
            "image": f"n132/arvo:{lid}-vul", "fuzz_target": ft, "crash_type": ct}
# Buffer of 6 NEW (so 4 survive phase 2), preferring clean observed_crash +
# project diversity; graphicsmagick last (its screen observed_crash="attempting").
PREFER = ["radare2", "libredwg", "libjxl", "lcms", "sleuthkit", "yara",
          "hunspell", "freeradius-server", "graphicsmagick"]
ordered = [new[p] for p in PREFER if p in new] + \
          [new[p] for p in sorted(new) if p not in PREFER]
manifest = [entry(r["project"], r["local_id"], r["fuzz_target"], r.get("crash_type",""))
            for r in ordered[:6]]
# always re-optimize PcapPlusPlus (fixed corpus resolver -> bundled 430)
manifest.append(entry("PcapPlusPlus", 22232, "FuzzTarget", "Heap-buffer-overflow READ 1"))
json.dump(manifest, open("manifest.json", "w"), indent=2)
json.dump(manifest, open("results/new-kube-2/manifest_full.json", "w"), indent=2)
print("[nk2-compose] manifest:", [(e["project"], e["local_id"]) for e in manifest])
PY
say "composed manifest: $(python3 -c 'import json;print([e["project"] for e in json.load(open("manifest.json"))])')"

# --- 2) phase 2: optimize all (drop non-optimizers) ---
export OPTIMIZER_BACKEND=claude BENCHMARK_OPTIMIZER=claude
export PHASE2_OPTIMIZER_SKILL=profile-once-fuzz-folds
export PHASE2_OPTIMIZER_TIMEOUT_SECS=14400
export PHASE2_MAX_PARALLEL=4
say "phase 2 START (claude / profile-once-fuzz-folds)"
python3 -u run_benchmark.py --experiment-id "$EXP" --phase 2 --duration 86400
say "phase 2 exited rc=$?"

# --- 3) prune to entries that optimized: cap 4 NEW + always keep PcapPlusPlus ---
python3 - <<'PY'
import json, os
EXP="new-kube-2"; base=f"results/{EXP}"
manifest=json.load(open(f"{base}/manifest_full.json"))
def ok(e):
    key=f"{e['project']}-{e['cve']}"
    smp=f"{base}/{key}/setup_metadata.json"
    if not os.path.exists(smp): return False
    v=json.load(open(smp)).get("verification",{})
    binp=f"{base}/{key}/optimized/bin/{e['fuzz_target']}"
    return bool(v.get("baseline")) and bool(v.get("optimized")) and os.path.exists(binp)
opt=[e for e in manifest if ok(e)]
new=[e for e in opt if e["project"]!="PcapPlusPlus"][:4]
pcap=[e for e in opt if e["project"]=="PcapPlusPlus"]
kept=new+pcap
json.dump(kept, open("manifest.json","w"), indent=2)
json.dump(kept, open(f"{base}/manifest_phase2.json","w"), indent=2)
print("[nk2-prune] optimized & kept:", [e["project"] for e in kept])
if not kept:
    raise SystemExit("[nk2-prune] FATAL: nothing optimized")
PY
rc=$?
[ "$rc" -ne 0 ] && { say "prune FATAL rc=$rc (nothing optimized) — stopping"; exit 1; }
say "pruned manifest: $(python3 -c 'import json;print([e["project"] for e in json.load(open("manifest.json"))])')"

# --- 4) phase 3: 24h k8s trials ---
export PHASE3_BACKEND=k8s PHASE3_K8S_TRIALS=10 PHASE3_K8S_PARALLELISM=10
say "phase 3 START (24h trials, 10x10)"
python3 -u run_benchmark.py --experiment-id "$EXP" --phase 3 --duration 86400
say "phase 3 exited rc=$?"

# --- 5) phase 4: analysis/report (86400 = TTB window) ---
say "phase 4 START"
python3 -u run_benchmark.py --experiment-id "$EXP" --phase 4 --duration 86400
say "phase 4 exited rc=$?"
say "==================== DONE ===================="
