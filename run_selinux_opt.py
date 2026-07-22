#!/usr/bin/env python3
"""Re-optimize selinux ONLY (phase 2), with NO optimizer wall-clock timeout, into
the existing new-kube-1-rerun experiment.

Calls phase2_setup.setup_cve() directly for the single selinux entry, so it never
reads or writes manifest.json and therefore cannot interfere with the running
4-project phase 3.

Per user instruction: do NOT dump progress on a timeout. The 3h optimizer timeout
is disabled here so the optimization can run as long as it needs; a separate
hourly heartbeat (run_selinux_heartbeat.sh) records progress so we can spot a
genuine hang without killing a slow-but-working run.
"""
import json
import logging
import os
import sys

import config
import phase2_setup

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)

# No optimizer wall-clock timeout — run to natural completion.
config.PHASE2_OPTIMIZER_TIMEOUT_SECS = None

EXP = "new-kube-1-rerun"
manifest = json.load(open("manifest_new-kube-1-rerun.json"))
selinux = next(e for e in manifest if e["project"] == "selinux")

print(f"[selinux-opt] {EXP}: phase-2 for {selinux['project']}/{selinux['cve']} "
      f"(local_id={selinux['local_id']}, target={selinux['fuzz_target']}) "
      f"— NO optimizer timeout", flush=True)

ok = phase2_setup.setup_cve(selinux, EXP)

meta_path = os.path.join(config.RESULTS_DIR, EXP, f"selinux-{selinux['cve']}",
                         "setup_metadata.json")
verdict = "no metadata"
if os.path.exists(meta_path):
    j = json.load(open(meta_path))
    v = j.get("verification", {})
    r = j.get("replay", {}) or {}
    verdict = (f"baseline={v.get('baseline')} optimized={v.get('optimized')} "
               f"applied={v.get('optimization_applied')} "
               f"speedup={r.get('replay_speedup')} "
               f"fail={j.get('failure', {}).get('stage')}")
print(f"[selinux-opt] DONE setup_cve={ok} :: {verdict}", flush=True)
