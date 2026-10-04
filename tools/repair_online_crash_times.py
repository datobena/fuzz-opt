#!/usr/bin/env python3
"""Rebuild online-arm crash_times.json / metadata.json from the AFL artifacts.

Why this exists
---------------
The online monitor used to scan ``<trial>/crashes`` -- the libFuzzer-era artifact
directory, which stays empty forever under AFL -- for libFuzzer filenames
("crash-", "oom-", "timeout-"). AFL writes
``<trial>/afl_out/default/crashes/id:000000,sig:06,...,time:MS`` instead, so the
online arm recorded ZERO crashes while the baseline arm (which reads the AFL
location) recorded them correctly. A campaign affected by this reports the
baseline finding the bug and the optimized arm never finding it -- a clean,
plausible, exactly-inverted result.

The artifacts themselves were always correct, so any affected campaign is
repairable after the fact. AFL's ``time:`` field is campaign-cumulative even
across relaunches (AFL_AUTORESUME restores the previous run_time), so the
timestamps need no per-session adjustment -- confirmed on a live campaign where a
trial relaunched at 07:46 reported run_time 25976s at 11:56 against the
never-relaunched baseline's 26096s.

Safe to run on an unaffected campaign: it only rewrites a trial whose recorded
crash count disagrees with the artifacts on disk, and it never touches the
baseline arm's files unless asked.

    python3 repair_online_crash_times.py --experiment-id online-24h-b1-wolfssl
    python3 repair_online_crash_times.py --experiment-id ... --apply
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


# The pipeline modules (config, phase*, lib/, sandbox/) live at the repo root,
# one level up; Python only puts THIS script's directory on sys.path.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))


import config
from lib import afl, crash_classify


def _trial_dirs(exp_dir: Path, variant: str):
    for d in sorted((exp_dir / variant).glob("trial_*")):
        if d.is_dir():
            yield d


def repair_trial(trial_dir: Path, duration: int | None, apply: bool,
                 force: bool = False) -> dict | None:
    """Return a summary of what is (or would be) rewritten, else None."""
    crashes_dir = trial_dir / "afl_out" / "default" / "crashes"
    artifacts = afl.collect_crashes(crashes_dir)

    ct_path = trial_dir / "crash_times.json"
    try:
        recorded = json.loads(ct_path.read_text())
    except (OSError, json.JSONDecodeError):
        recorded = []

    # Count agreement is not enough. The online monitor classifies a crash by
    # replaying it against optimized/bin -- which is HOT-SWAPPED during the run,
    # and after the last round holds a binary no trial ever executed. A genuine
    # find then classifies as "unknown" and is dropped from time-to-bug. Observed:
    # a crash at 21.25h reproduced against the iter_05 and iter_06 binaries that
    # were actually live, but not against the final one.
    #
    # Every artifact AFL writes under crashes/ is a real crash by construction --
    # AFL only saves inputs that made the target die -- so a recorded entry typed
    # anything other than "crash" is a classification artifact, not evidence.
    mistyped = any(c.get("crash_type") != "crash" for c in recorded)
    if len(recorded) == len(artifacts) and not (mistyped or force):
        return None                       # already consistent; leave it alone

    rebuilt = [{
        "timestamp_s": a["timestamp_s"],
        "artifact": a["artifact"],
        # Every AFL artifact under crashes/ is a real sanitizer crash; the
        # boundary cases crash_classify screens for (empty-input, end-of-run) are
        # libFuzzer artefacts and cannot appear here.
        "crash_type": "crash",
    } for a in artifacts]

    summary = {
        "trial": trial_dir.name,
        "recorded": len(recorded),
        "on_disk": len(rebuilt),
        "time_to_bug_s": crash_classify.trial_time_to_bug(rebuilt, duration),
    }
    if not apply:
        return summary

    ct_path.write_text(json.dumps(rebuilt, indent=2))
    meta_path = trial_dir / "metadata.json"
    try:
        meta = json.loads(meta_path.read_text())
    except (OSError, json.JSONDecodeError):
        meta = {}
    meta["num_crashes"] = len(rebuilt)
    meta["found_bug"] = crash_classify.trial_found_bug(rebuilt, duration)
    meta["time_to_bug_s"] = crash_classify.trial_time_to_bug(rebuilt, duration)
    meta["crash_times_repaired_from_artifacts"] = True
    meta_path.write_text(json.dumps(meta, indent=2))
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--variant", default="optimized",
                    help="arm to repair (default: optimized -- the affected one)")
    ap.add_argument("--duration", type=int, default=None,
                    help="trial budget in seconds; crashes at/after it are boundary "
                         "artifacts (default: read from metadata)")
    ap.add_argument("--force", action="store_true",
                    help="rewrite every trial from artifacts, not only mismatches")
    ap.add_argument("--apply", action="store_true",
                    help="write the files (default: report only)")
    args = ap.parse_args()

    root = Path(config.RESULTS_DIR) / args.experiment_id
    if not root.is_dir():
        print(f"no such experiment: {root}", file=sys.stderr)
        return 1

    total = 0
    for exp_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        rows = []
        for trial_dir in _trial_dirs(exp_dir, args.variant):
            duration = args.duration
            if duration is None:
                try:
                    duration = json.loads(
                        (trial_dir / "metadata.json").read_text()
                    ).get("duration_seconds")
                except (OSError, json.JSONDecodeError):
                    duration = None
            r = repair_trial(trial_dir, duration, args.apply, args.force)
            if r:
                rows.append(r)
        if not rows:
            continue
        print(f"\n=== {exp_dir.name} / {args.variant} ===")
        for r in rows:
            ttb = r["time_to_bug_s"]
            print(f"  {r['trial']}: recorded={r['recorded']} on_disk={r['on_disk']} "
                  f"time_to_bug={'-' if ttb is None else f'{ttb:.1f}s'}")
        total += len(rows)

    if total == 0:
        print("nothing to repair: recorded crash counts match the artifacts")
    else:
        print(f"\n{total} trial(s) {'repaired' if args.apply else 'would be repaired'}"
              f"{'' if args.apply else ' -- re-run with --apply'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
