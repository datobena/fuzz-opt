#!/usr/bin/env python3
"""Trust-check a phase-3 experiment's bug-find counts.

Two tiers, both via the canonical classifier in lib/crash_classify:

  (default) CHEAP — classify each trial from crash_times metadata: a find is a
    real sanitizer `crash-*` before the run cutoff, excluding slow-units,
    timeouts, OOMs, and the empty-input boundary artifact. Fast, no docker.

  --reproduce  GOLD — additionally replay each candidate crash artifact on the
    TARGET BINARY and confirm it actually crashes under the sanitizer, and that
    the signature matches the manifest's expected crash_type. This rejects
    fold-induced false-positive crashes and non-reproducible/flaky crashes
    (e.g. libavc's multithreaded decoder). Requires docker + built binaries +
    the crash artifacts present locally under
    results/<exp>/<key>/<variant>/trial_NN/crashes/.

Usage:
  python3 verify_crashes.py --experiment aggr-8h
  python3 verify_crashes.py --experiment aggr-8h --reproduce
"""
import argparse
import collections
import json
import os

import config
import phase3_k8s as p3
from lib import crash_classify as cc


def _manifest(exp):
    path = f"manifest_{exp}.json"
    if not os.path.exists(path):
        path = config.MANIFEST_PATH
    return json.load(open(path))


def _trial_records(exp):
    """Yield (project, variant, trial_name, crash_times, cutoff, trial_dir)."""
    tr_path = os.path.join(config.RESULTS_DIR, exp, "trial_results.json")
    results = json.load(open(tr_path)) if os.path.exists(tr_path) else []
    exp_dir = os.path.join(config.RESULTS_DIR, exp)
    for r in results:
        name = r.get("trial", "")
        parts = name.split("-")
        if len(parts) < 3:
            continue
        project, variant = parts[0], parts[1]
        cutoff = r.get("max_total_time") or config.TRIAL_DURATION_SECS
        yield project, variant, name, r.get("crash_times") or [], cutoff, exp_dir


def _find_trial_dir(exp_dir, project, variant, trial_name):
    """Locate the on-disk trial dir (…/<key>/<variant>/trial_NN) for artifacts."""
    for key in os.listdir(exp_dir):
        if not key.startswith(project + "-"):
            continue
        vdir = os.path.join(exp_dir, key, variant)
        if not os.path.isdir(vdir):
            continue
        # trial_name ends in trial_NN or a k8s pod suffix; match the index
        idx = trial_name.rsplit("trial", 1)[-1].lstrip("_-")
        for d in os.listdir(vdir):
            if d.startswith("trial_") and d.split("_")[-1] == idx.split("-")[0]:
                return os.path.join(vdir, d), key
    return None, None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--experiment", required=True)
    ap.add_argument("--reproduce", action="store_true",
                    help="replay each candidate crash on the target binary (gold standard)")
    ap.add_argument("--timeout", type=int, default=120)
    a = ap.parse_args()

    manifest = _manifest(a.experiment)
    sig = {e["project"]: e.get("crash_type", "") for e in manifest}
    ftgt = {e["project"]: e.get("fuzz_target", "") for e in manifest}

    cheap = collections.defaultdict(lambda: {"found": 0, "total": 0, "ttbs": []})
    gold = collections.defaultdict(lambda: {"matched": 0, "reproduced": 0, "no_repro": 0,
                                            "candidates": 0, "sigs": collections.Counter()})

    for project, variant, name, cts, cutoff, exp_dir in _trial_records(a.experiment):
        k = (project, variant)
        cheap[k]["total"] += 1
        ttb = cc.trial_time_to_bug(cts, cutoff)
        if ttb is not None:
            cheap[k]["found"] += 1
            cheap[k]["ttbs"].append(ttb)

        if a.reproduce and ttb is not None:
            tdir, key = _find_trial_dir(exp_dir, project, variant, name)
            if not tdir:
                continue
            out_dir = os.path.join(exp_dir, key, variant, "bin")
            # verify the earliest real-crash artifact
            cands = sorted((e for e in cts if cc.is_target_bug_find(e, cutoff)),
                           key=lambda e: e["timestamp_s"])
            if not cands:
                continue
            gold[k]["candidates"] += 1
            art = os.path.join(tdir, "crashes", cands[0]["artifact"])
            # expected_signature=None -> returns (crashed_at_all, detected_signature);
            # we bucket the match ourselves so non-repro vs wrong-signature are distinct.
            crashed, detected = cc.verify_crash_reproduces(
                art, out_dir, ftgt.get(project, ""),
                expected_signature=None, timeout=a.timeout)
            if not crashed:
                gold[k]["no_repro"] += 1
                continue
            gold[k]["reproduced"] += 1
            gold[k]["sigs"][cc.normalize_signature(detected) or "?"] += 1
            if cc.normalize_signature(detected) == cc.normalize_signature(sig.get(project, "")):
                gold[k]["matched"] += 1

    print(f"\n=== {a.experiment}: canonical bug-find counts (cheap) ===")
    for project in sorted({p for p, _ in cheap}):
        for variant in ("baseline", "optimized"):
            c = cheap.get((project, variant))
            if not c:
                continue
            import statistics
            mean = f"{statistics.mean(c['ttbs']):.1f}s" if c["ttbs"] else "-"
            line = f"  {project:9s} {variant:10s} crash-typed {c['found']}/{c['total']}  meanTTB={mean}"
            if a.reproduce:
                g = gold[(project, variant)]
                sigs = ", ".join(f"{s}×{n}" for s, n in g["sigs"].most_common())
                # "found a bug" = a real crash that reproduces, ANY signature.
                # matched (the specific manifest CVE) is informational only.
                line += (f"   | FOUND-BUG(reproduced) {g['reproduced']}/{g['candidates']}"
                         f", non-repro {g['no_repro']}  bugs:[{sigs}]"
                         f"  (of which manifest-CVE sig: {g['matched']})")
            print(line)
    if a.reproduce:
        print("\n  target signatures:", {e['project']: e.get('crash_type') for e in manifest})
    print()


if __name__ == "__main__":
    main()
