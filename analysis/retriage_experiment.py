#!/usr/bin/env python3
"""Re-classify and gold-standard triage a finished AFL experiment.

Two independent problems this repairs, both libFuzzer-era assumptions that
survived the AFL migration and made the two arms incomparable:

  1. crash_type. phase3_runner.monitor_trial (BASELINE) hardcodes "crash" for
     every artifact, while phase3_online (OPTIMIZED) ran them through
     classify_crash(), whose prefix tests are libFuzzer's -- so every AFL
     `id:...,sig:NN,...` artifact came back "unknown". crash_classify drops
     anything not typed "crash", so the optimized arm scored found_bug=False on
     all 9 trials of b3r2 while holding 126 sanitizer aborts. classify_crash is
     fixed now; this rewrites the stored metadata that was already recorded.

  2. Cheap classification is not proof. crash_classify's own docstring says the
     metadata tier cannot distinguish the target bug from a fold-induced
     false-positive crash, and the optimized binary here reports 669 edges
     against baseline's 827 -- the folds changed it materially. So every
     artifact is REPLAYED against the manifest's expected signature.

Writes triage_<variant>_<trial>.json per trial and a triage_summary.json per
experiment. Nothing is overwritten in place without --write-metadata.

    python3 retriage_experiment.py --experiment online-24h-b3r2-yara --project yara
    python3 retriage_experiment.py --experiment online-24h-b3r2-yara --project yara \
        --reproduce --write-metadata
"""
import argparse
import json
import logging
import os
import sys


# The pipeline modules (config, phase*, lib/, sandbox/) live at the repo root,
# one level up; Python only puts THIS script's directory on sys.path.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import config
import phase3_runner
from lib import afl_triage, crash_classify

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("retriage")


def reclassify(crash_times):
    """Re-run classify_crash over stored crash_times. Returns (new_list, n_changed)."""
    out, changed = [], 0
    for c in crash_times or []:
        new = dict(c)
        was = c.get("crash_type")
        now = phase3_runner.classify_crash(c.get("artifact", ""))
        if now != was:
            changed += 1
        new["crash_type"] = now
        out.append(new)
    return out, changed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--experiment", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--reproduce", action="store_true",
                    help="replay every artifact (gold standard; needs docker)")
    ap.add_argument("--write-metadata", action="store_true",
                    help="persist corrected crash_type/found_bug into metadata.json")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--expected-signature", default=None,
                    help="LAST RESORT. Overrides the manifest's crash_type when no "
                         "PoC repro.log exists to compare stacks against. Prefer the "
                         "reference stack, which is used automatically when the PoC's "
                         "repro.log is present: choosing a label by hand after seeing "
                         "which one makes the numbers work is fitting the measurement "
                         "rule to the result.")
    args = ap.parse_args()

    exp_dir = os.path.join(config.RESULTS_DIR, args.experiment)
    manifest = {e["project"]: e for e in json.load(open(config.MANIFEST_PATH))}
    entry = manifest.get(args.project)
    if not entry:
        logger.error("no manifest entry for %s", args.project)
        return 1
    key = f"{args.project}-{entry['cve']}"
    # ARVO's own reproducer output for this target. When present, crash identity
    # comes from the stack, and the manifest label stops mattering.
    repro = os.path.join(config.RESULTS_DIR, args.experiment, key, "poc", "repro.log")
    reference = ""
    if os.path.exists(repro):
        reference = open(repro, errors="replace").read()
    expected = args.expected_signature or entry.get("crash_type", "")
    fuzz_target = entry.get("fuzz_target", "")
    image = f"bench-aflpp/{key}"
    logger.info("target %s | fuzz_target=%s | identity: %s",
                key, fuzz_target,
                f"reference stack from {repro}" if reference
                else f"sanitizer label {expected!r} (NO repro.log -- weaker)")

    summary = {"experiment": args.experiment, "target": key,
               "expected_signature": expected, "arms": {}}

    for variant in ("baseline", "optimized"):
        vdir = os.path.join(exp_dir, key, variant)
        if not os.path.isdir(vdir):
            continue
        out_dir = os.path.join(vdir, "bin")
        arm = {"trials": 0, "cheap_found": 0, "artifacts": 0, "reclassified": 0,
               "gold_found": 0, "verdicts": {}, "ttb_cheap": [], "ttb_gold": [],
               "per_trial": {}}

        for tname in sorted(d for d in os.listdir(vdir) if d.startswith("trial_")):
            tdir = os.path.join(vdir, tname)
            mpath = os.path.join(tdir, "metadata.json")
            if not os.path.exists(mpath):
                continue
            meta = json.load(open(mpath))
            cutoff = meta.get("duration_seconds") or config.TRIAL_DURATION_SECS
            cts, changed = reclassify(meta.get("crash_times")
                                      or _load_ct(tdir))
            arm["trials"] += 1
            arm["artifacts"] += len(cts)
            arm["reclassified"] += changed

            ttb = crash_classify.trial_time_to_bug(cts, cutoff)
            if ttb is not None:
                arm["cheap_found"] += 1
                arm["ttb_cheap"].append(ttb)

            rec = {"artifacts": len(cts), "reclassified": changed,
                   "cheap_found": ttb is not None, "cheap_ttb_s": ttb}

            if args.reproduce and cts:
                crashes_dir = os.path.join(tdir, "afl_out", "default", "crashes")
                triaged = afl_triage.triage_trial(
                    crashes_dir, image=image, out_dir=out_dir,
                    fuzz_target=fuzz_target, expected_signature=expected,
                    timeout=args.timeout, reference=reference)
                for t in triaged:
                    arm["verdicts"][t["verdict"]] = arm["verdicts"].get(t["verdict"], 0) + 1
                gttb = afl_triage.target_bug_ttb(triaged)
                if gttb is not None:
                    arm["gold_found"] += 1
                    arm["ttb_gold"].append(gttb)
                rec.update(gold_found=gttb is not None, gold_ttb_s=gttb,
                           verdicts=afl_triage.summarize_triage(triaged))
                with open(os.path.join(tdir, "triage.json"), "w") as f:
                    json.dump(triaged, f, indent=2)
                logger.info("%s/%s: %d artifacts -> %s", variant, tname,
                            len(triaged), rec["verdicts"])

            if args.write_metadata:
                meta["crash_times"] = cts
                meta["found_bug"] = ttb is not None
                meta["time_to_bug_s"] = ttb
                meta["num_crashes"] = len(cts)
                meta.setdefault("retriage", {})["crash_type_reclassified"] = changed
                with open(mpath, "w") as f:
                    json.dump(meta, f, indent=2)
                with open(os.path.join(tdir, "crash_times.json"), "w") as f:
                    json.dump(cts, f, indent=2)

            arm["per_trial"][tname] = rec

        summary["arms"][variant] = arm

    spath = os.path.join(exp_dir, "triage_summary.json")
    with open(spath, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n===== {key} — expected: {expected} =====")
    for variant, arm in summary["arms"].items():
        print(f"  {variant}:")
        print(f"    trials                {arm['trials']}")
        print(f"    artifacts             {arm['artifacts']}")
        print(f"    crash_type corrected  {arm['reclassified']}")
        print(f"    cheap  found_bug      {arm['cheap_found']}/{arm['trials']}")
        if args.reproduce:
            print(f"    GOLD   found_bug      {arm['gold_found']}/{arm['trials']}")
            print(f"    verdicts              {arm['verdicts']}")
    print(f"\nwrote {spath}")
    return 0


def _load_ct(tdir):
    p = os.path.join(tdir, "crash_times.json")
    return json.load(open(p)) if os.path.exists(p) else []


if __name__ == "__main__":
    sys.exit(main())
