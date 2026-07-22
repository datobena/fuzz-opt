#!/usr/bin/env python3
"""Run phase-3 fuzzing trials for selinux ONLY (k8s), into the new-kube-1-rerun
experiment, WITHOUT touching manifest.json / trial_results.json / state.json — so
the running 4-project phase 3 is undisturbed.

selinux was optimized in the earlier no-timeout phase-2 run (1.41x replay, bug
preserved). This launches its baseline+optimized trials at the same config as the
rest of the experiment (10 trials/variant, 48h/trial). Job names are
phase3-selinux-{baseline,optimized}-new-kube-1-rerun — they do not collide with
the 4 projects already running.
"""
import json
import logging
import os
import sys

# Must be set before importing config (read at import time).
os.environ.setdefault("PHASE3_BACKEND", "k8s")
os.environ.setdefault("PHASE3_K8S_TRIALS", "10")
os.environ.setdefault("PHASE3_K8S_PARALLELISM", "10")

import config
import phase3_k8s

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)

EXP = "new-kube-1-rerun"
DURATION = 172800  # 48h/trial, matching the rest of the experiment

manifest = json.load(open("manifest_new-kube-1-rerun.json"))
selinux = [e for e in manifest if e["project"] == "selinux"]
assert selinux, "selinux entry not found in manifest snapshot"

# Safety: only run trials if selinux's phase-2 produced a verified optimized build.
meta = os.path.join(config.RESULTS_DIR, EXP, "selinux-CVE-2021-36085",
                    "setup_metadata.json")
v = json.load(open(meta)).get("verification", {})
assert v.get("baseline") and v.get("optimized"), f"selinux not optimized: {v}"

print(f"[selinux-p3] launching k8s trials for selinux "
      f"({config.PHASE3_K8S_TRIALS} trials/variant, {DURATION}s, "
      f"parallelism={config.PHASE3_K8S_PARALLELISM})", flush=True)

results = phase3_k8s.run_all_trials_k8s(selinux, EXP, duration=DURATION)

n = len(results) if results else 0
print(f"[selinux-p3] DONE — collected {n} selinux trial results", flush=True)
