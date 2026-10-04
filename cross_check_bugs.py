#!/usr/bin/env python3
"""Bidirectional crash cross-check: did the optimizer ADD or REMOVE a bug?

Every crash artifact is replayed on BOTH arms' binaries:

  optimized artifact -> baseline binary   does not crash  => INTRODUCED by a fold
  baseline  artifact -> optimized binary  does not crash  => REMOVED (masked) by a fold

Two things make a naive version of this wrong, and both are handled here.

**Flaky crashes.** libavc is a threaded decoder; many of its artifacts do not
reproduce even on the binary that produced them. Calling those "removed" would
invent a result out of scheduler noise. So every artifact is first replayed
against its OWN arm's binary (``--tries`` attempts, crash if ANY attempt
crashes). Artifacts that fail that control are reported separately and excluded
from the introduced/removed counts -- they are evidence of nothing.

**Benign signature shifts.** A fold that changes allocation layout can make ASan
trip a different check first at the same frame: ``use-after-poison`` where the
baseline reports ``heap-use-after-free``. That is one bug, not two, so kinds are
normalised before comparison. What matters for this audit is whether the program
still dies at the same place, not which sanitizer check won the race.

The optimized side uses the binary that was LIVE when the crash fired (from
swap_timeline.json), not the final one -- after the last round that is a binary
no trial ever executed.

    python3 cross_check_bugs.py --experiment-id online-24h-b2-selinux --jobs 36
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import config
import verify_crash_signatures as V
from lib import afl
from prework.prework_build import prework_image_for

# A fold that shifts allocation layout changes which ASan check fires first at
# the same frame. Same bug -- compare the frame, not the check that won.
_KIND_ALIAS = {
    "use-after-poison": "heap-use-after-free",
    "container-overflow": "heap-buffer-overflow",
}


def normalize(sig: str | None) -> str | None:
    if not sig:
        return None
    kind, _, frame = sig.partition(":")
    return f"{_KIND_ALIAS.get(kind, kind)}:{frame}" if frame else _KIND_ALIAS.get(kind, kind)


def crashes(image, bin_dir, target, artifact, cpu, tries):
    """(signature or None) -- retried, because a threaded target is flaky."""
    for _ in range(tries):
        sig = normalize(V.signature(V.replay(image, bin_dir, target, artifact, cpu)))
        if sig:
            return sig
    return None


def last_live_binary(online_dir: Path, baseline_bin: Path) -> tuple[Path, str]:
    """The final binary trials ACTUALLY ran (last swap), not the last built."""
    try:
        tl = json.loads((online_dir / "swap_timeline.json").read_text())
    except (OSError, json.JSONDecodeError):
        return baseline_bin, "iter_00"
    # `per_trial` is empty for a round that finished after the trials ended --
    # its binary was built and archived but no trial ever executed it. Comparing
    # against that would audit a binary the experiment never ran.
    swapped = [e for e in tl if e.get("per_trial")]
    if not swapped:
        return baseline_bin, "iter_00"
    it = int(max(swapped, key=lambda e: e.get("ts", 0)).get("iter", 0))
    d = online_dir / f"iter_{it:02d}" / "bin"
    return (d, f"iter_{it:02d}") if d.is_dir() else (baseline_bin, "iter_00")


def one(task):
    (arm, trial, art_path, image, target, own_bin, other_bin, cpu, tries) = task
    own = crashes(image, Path(own_bin), target, Path(art_path), cpu, tries)
    other = None
    if own:                                  # only meaningful if the control held
        other = crashes(image, Path(other_bin), target, Path(art_path), cpu, tries)
    return arm, trial, Path(art_path).name, own, other


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--jobs", type=int, default=32)
    ap.add_argument("--tries", type=int, default=3,
                    help="replay attempts before calling an artifact non-crashing")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    manifest = {e["project"]: e for e in json.loads(Path(config.MANIFEST_PATH).read_text())}
    root = Path(config.RESULTS_DIR) / args.experiment_id
    out_all = {}

    for exp in sorted(p for p in root.iterdir() if p.is_dir()):
        entry = V.resolve_entry(exp.name, manifest)
        if entry is None:
            print(f"  {exp.name}: no manifest entry; skipped", file=sys.stderr)
            continue
        image, target = prework_image_for(entry), entry["fuzz_target"]
        base_bin = exp / "baseline" / "bin"
        online = exp / "optimized" / "online"
        final_opt, final_label = last_live_binary(online, base_bin)

        tasks = []
        for arm in ("baseline", "optimized"):
            for trial in sorted((exp / arm).glob("trial_*")):
                try:
                    meta = json.loads((trial / "metadata.json").read_text())
                except (OSError, json.JSONDecodeError):
                    meta = {}
                for a in afl.collect_crashes(trial / "afl_out" / "default" / "crashes"):
                    p = next(iter((trial / "afl_out" / "default")
                                  .glob(f"crashes*/{a['artifact']}")), None)
                    if p is None:
                        continue
                    if arm == "optimized":
                        own, _ = V.live_binary(
                            V.trial_online_dir(online, trial.name),
                            meta.get("start_time", 0),
                            a["timestamp_s"], base_bin)
                        other = base_bin
                    else:
                        own, other = base_bin, final_opt
                    cpu = 4 + (len(tasks) % max(args.jobs, 1))
                    tasks.append((arm, trial.name, str(p), image, target,
                                  str(own), str(other), cpu, args.tries))

        print(f"\n=== {exp.name} ===  {len(tasks)} artifacts, "
              f"optimized side compared against {final_label}")
        rows, done = [], 0
        with ProcessPoolExecutor(max_workers=args.jobs) as ex:
            futs = [ex.submit(one, t) for t in tasks]
            for f in as_completed(futs):
                rows.append(f.result())
                done += 1
                if done % 25 == 0 or done == len(tasks):
                    print(f"    [{done}/{len(tasks)}]")

        stats = collections.Counter()
        introduced, removed, shifted = [], [], []
        for arm, trial, name, own, other in rows:
            if not own:
                stats[f"{arm}:non-reproducible (excluded)"] += 1
                continue
            stats[f"{arm}:reproducible"] += 1
            if other is None:
                (introduced if arm == "optimized" else removed).append((trial, name, own))
                stats[f"{arm}:" + ("INTRODUCED" if arm == "optimized" else "REMOVED")] += 1
            else:
                stats[f"{arm}:present in both arms"] += 1
                if other != own:
                    shifted.append((arm, trial, name, own, other))

        for k in sorted(stats):
            print(f"    {k:44} {stats[k]:4}")
        for label, items in (("INTRODUCED by optimizer (crash only on folded binary)", introduced),
                             ("REMOVED by optimizer (baseline crash gone on folded binary)", removed)):
            print(f"\n    {label}: {len(items)}")
            for trial, name, sig in items[:12]:
                print(f"      {trial} {name[:26]:26} {sig}")
            if len(items) > 12:
                print(f"      ... and {len(items)-12} more")
        if shifted:
            print(f"\n    signature differs across arms (same artifact crashes both): {len(shifted)}")
            for arm, trial, name, a, b in shifted[:8]:
                print(f"      {arm:9} {trial} {a}  ->  {b}")
        out_all[exp.name] = {
            "counts": dict(stats),
            "introduced": [{"trial": t, "artifact": n, "signature": s} for t, n, s in introduced],
            "removed": [{"trial": t, "artifact": n, "signature": s} for t, n, s in removed],
            "final_optimized_binary": final_label,
        }

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(out_all, indent=2))
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
