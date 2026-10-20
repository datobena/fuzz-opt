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

**Assert crashes.** An assert() abort has no sanitizer kind; it is identified
by its assert site (``assert:<file>:<line>``, lib/crash_classify.assert_site).
Without that it read as "did not crash", and php's 17 assert artifacts all
landed in "non-reproducible".

Which optimized binaries. An optimized artifact is replayed on the binary that
was LIVE when it fired (from swap_timeline.json). A baseline artifact is
replayed on EVERY binary some optimized trial deployed: under the per-trial
optimizer each trial runs its own chain of binaries, so there is no single
"optimized binary", and a fold in any one of them could hide the bug. To bound
the cost, at most ``--per-bug`` baseline artifacts per baseline signature are
checked (earliest first); the number skipped is printed.

    python3 cross_check_bugs.py --experiment-id online-24h-b2-selinux --jobs 36
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path


# The pipeline modules (config, phase*, lib/, sandbox/) live at the repo root,
# one level up; Python only puts THIS script's directory on sys.path.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))


import config
import verify_crash_signatures as V
from lib import afl
from lib.crash_classify import assert_crash_site
from lib.provenance import experiment_image

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
        out = V.replay(image, bin_dir, target, artifact, cpu)
        site = assert_crash_site(out)
        sig = normalize(V.signature(out) or (f"assert:{site}" if site else None))
        if sig:
            return sig
    return None


def confirm_gap(image, target, artifact, hit_bin, miss_bin, cpu, tries, rounds=None,
                with_sig=False):
    """Re-test a "crashes on hit_bin, not on miss_bin" result before reporting it.

    A flaky artifact (threaded or timing-dependent target) can hit once and then
    miss three times on the other binary by chance; with ~26-57 deployed
    binaries per campaign, that chance turns into a false INTRODUCED/REMOVED
    almost surely. So the two binaries are replayed interleaved, ``rounds``
    times each. Returns:
      "gap"   hit_bin crashed again and miss_bin never did -- a real difference
      "both"  miss_bin crashed too -- no difference
      "flaky" hit_bin never crashed again -- evidence of nothing
    With ``with_sig`` returns (verdict, miss_bin's signature when "both").
    """
    rounds = rounds or max(5, 2 * tries)
    hit = 0
    for _ in range(rounds):
        sig = crashes(image, miss_bin, target, artifact, cpu, 1)
        if sig:
            return ("both", sig) if with_sig else "both"
        hit += bool(crashes(image, hit_bin, target, artifact, cpu, 1))
    v = "gap" if hit else "flaky"
    return (v, None) if with_sig else v


def line_moved_only(a: str, b: str, window: int = 50) -> bool:
    """Same assert/ubsan site with its line moved by an edit to the file.

    Within ``window`` lines only: two different asserts in one file
    (zend_compile.c:9852 vs :1200) are different bugs, not a moved line.
    """
    ma, mb = (re.fullmatch(r"((?:assert|ubsan):.*):(\d+)", x or "") for x in (a, b))
    return bool(ma and mb and ma.group(1) == mb.group(1)
                and abs(int(ma.group(2)) - int(mb.group(2))) <= window)


def warn_if_asserts_invisible() -> None:
    """Assert crashes are recognised by the ASan ABRT report that handle_abort=2
    makes them print (crash_classify.assert_crash_site). An env override of the
    replay UBSAN_OPTIONS without it silently turns every assert into a
    non-reproducer."""
    if "handle_abort=2" not in (getattr(config, "REPLAY_UBSAN_OPTIONS", "") or ""):
        print("WARNING: replay UBSAN_OPTIONS lack handle_abort=2; assert crashes "
              "will read as non-reproducible", file=sys.stderr)


def deployed_binaries(online_dir: Path) -> list[tuple[Path, str]]:
    """Every optimized binary some trial actually ran, as (bin dir, label).

    Per-trial layout: trials/trial_NN/swap_timeline.json lists EVERY trial's
    swaps (each row carries trial_id), so only NN's rows count, and the binary is
    trials/trial_NN/iter_KK/bin. Legacy layout: online/swap_timeline.json, where
    a row with an empty ``per_trial`` is a round that finished after the trials
    ended -- built, never run. iter_00 is the baseline build and is left out.
    """
    tdir = online_dir / "trials"
    dirs = sorted(tdir.glob("trial_*")) if tdir.is_dir() else []
    out = []
    for d in dirs or [online_dir]:
        try:
            tl = json.loads((d / "swap_timeline.json").read_text())
        except (OSError, json.JSONDecodeError):
            continue
        m = re.fullmatch(r"trial_(\d+)", d.name)
        if m:
            tid = int(m.group(1))
            iters = {int(e["iter"]) for e in tl
                     if "iter" in e and e.get("trial_id", tid) == tid}
        else:
            iters = {int(e["iter"]) for e in tl if "iter" in e and e.get("per_trial")}
        for it in sorted(iters):
            b = d / f"iter_{it:02d}" / "bin"
            if it > 0 and b.is_dir() and any(b.iterdir()):
                out.append((b, f"{d.name}/iter_{it:02d}" if m else f"iter_{it:02d}"))
    return out


def one(task):
    (key, image, target, bin_dir, art_path, cpu, tries) = task
    return key, crashes(image, Path(bin_dir), target, Path(art_path), cpu, tries)


def one_gap(task):
    (key, image, target, hit_bin, miss_bin, art_path, cpu, tries) = task
    return key, confirm_gap(image, target, Path(art_path), Path(hit_bin),
                            Path(miss_bin), cpu, tries)


def run_all(tasks, jobs, fn=one):
    """{key: fn's result}, with progress."""
    res, done = {}, 0
    with ProcessPoolExecutor(max_workers=jobs) as ex:
        for f in as_completed([ex.submit(fn, t) for t in tasks]):
            k, sig = f.result()
            res[k] = sig
            done += 1
            if done % 50 == 0 or done == len(tasks):
                print(f"    [{done}/{len(tasks)}]")
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--jobs", type=int, default=32)
    ap.add_argument("--tries", type=int, default=3,
                    help="replay attempts before calling an artifact non-crashing")
    ap.add_argument("--per-bug", type=int, default=3,
                    help="baseline artifacts per baseline signature replayed on every "
                         "deployed optimized binary (0 = all)")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()
    warn_if_asserts_invisible()

    manifest = {e["project"]: e for e in json.loads(Path(config.MANIFEST_PATH).read_text())}
    root = Path(config.RESULTS_DIR) / args.experiment_id
    out_all = {}

    for exp in sorted(p for p in root.iterdir() if p.is_dir()):
        entry = V.resolve_entry(exp.name, manifest)
        if entry is None:
            print(f"  {exp.name}: no manifest entry; skipped", file=sys.stderr)
            continue
        image, target = experiment_image(exp, entry), entry["fuzz_target"]
        base_bin = exp / "baseline" / "bin"
        online = exp / "optimized" / "online"
        deployed = deployed_binaries(online)

        # Pass 1: every artifact on the binary that produced it (the control).
        arts, tasks = {}, []
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
                    own = (V.live_binary(V.trial_online_dir(online, trial.name),
                                         meta.get("start_time", 0),
                                         a["timestamp_s"], base_bin)[0]
                           if arm == "optimized" else base_bin)
                    key = (arm, trial.name, p.name)
                    arts[key] = (str(p), a["timestamp_s"], str(own))
                    cpu = 4 + (len(tasks) % max(args.jobs, 1))
                    tasks.append((key, image, target, str(own), str(p), cpu, args.tries))

        print(f"\n=== {exp.name} ===  {len(tasks)} artifacts, "
              f"{len(deployed)} deployed optimized binaries")
        own_sig = run_all(tasks, args.jobs)

        # Pass 2: optimized -> baseline; baseline -> every deployed binary.
        by_sig = collections.defaultdict(list)
        for key, sig in own_sig.items():
            if sig and key[0] == "baseline":
                by_sig[sig].append(key)
        checked, skipped = [], 0
        for sig, keys in by_sig.items():
            keys.sort(key=lambda k: arts[k][1])
            n = len(keys) if args.per_bug <= 0 else args.per_bug
            checked += keys[:n]
            skipped += len(keys[n:])
        no_deployed = 0
        if not deployed:
            print("    no deployed optimized binaries: baseline -> optimized not checked")
            no_deployed, checked, skipped = len(checked) + skipped, [], 0
        same_as_base = {}
        tasks = []
        for key, sig in own_sig.items():
            if sig and key[0] == "optimized":
                # Found before the trial's first swap: its own binary IS the
                # baseline, and pass 1 already answered the question.
                if Path(arts[key][2]).resolve() == base_bin.resolve():
                    same_as_base[(key, "baseline")] = sig
                else:
                    tasks.append(((key, "baseline"), str(base_bin)))
        for key in checked:
            tasks += [((key, label), str(b)) for b, label in deployed]
        tasks = [(k, image, target, b, arts[k[0]][0], 4 + (i % max(args.jobs, 1)), args.tries)
                 for i, (k, b) in enumerate(tasks)]
        other_sig = run_all(tasks, args.jobs) if tasks else {}
        other_sig.update(same_as_base)

        # Pass 3: re-test every apparent gap before it is reported.
        bins = {lab: b for b, lab in deployed}
        gaps = []
        for (key, lab), o in other_sig.items():
            if o is None and own_sig.get(key):
                hit, miss = ((arts[key][2], base_bin) if key[0] == "optimized"
                             else (base_bin, bins[lab]))
                gaps.append(((key, lab), image, target, str(hit), str(miss),
                             arts[key][0], 4 + (len(gaps) % max(args.jobs, 1)), args.tries))
        verdict = run_all(gaps, args.jobs, one_gap) if gaps else {}
        for k, v in verdict.items():
            if v == "both":
                other_sig[k] = own_sig[k[0]]      # crashes there after all
            elif v == "flaky":
                other_sig[k] = "flaky"

        stats = collections.Counter()
        introduced, removed, shifted = [], [], []
        for key, sig in sorted(own_sig.items()):
            arm, trial, name = key
            if not sig:
                stats[f"{arm}:non-reproducible (excluded)"] += 1
                continue
            stats[f"{arm}:reproducible"] += 1
            if arm == "optimized":
                other = other_sig.get((key, "baseline"))
                if other == "flaky":
                    stats["optimized:flaky on re-test (excluded)"] += 1
                    continue
                if other is None:
                    introduced.append((trial, name, sig))
                    stats["optimized:INTRODUCED"] += 1
                else:
                    stats["optimized:present on baseline"] += 1
                    if other != sig:
                        shifted.append((arm, trial, name, sig, other, "baseline"))
            elif key in checked:
                gone = [lab for _, lab in deployed if other_sig.get((key, lab)) is None]
                unconfirmed = any(other_sig.get((key, lab)) == "flaky" for _, lab in deployed)
                for _, lab in deployed:
                    o = other_sig.get((key, lab))
                    if o not in (None, "flaky") and o != sig:
                        shifted.append((arm, trial, name, sig, o, lab))
                if gone:
                    removed.append((trial, name, sig, gone))
                    stats["baseline:REMOVED on >=1 deployed binary"] += 1
                elif unconfirmed:
                    stats["baseline:flaky on re-test vs >=1 binary (excluded)"] += 1
                else:
                    stats["baseline:present on every deployed binary"] += 1
        stats["baseline:not replayed on optimized (per-bug cap)"] = skipped
        if no_deployed:
            stats["baseline:not replayed on optimized (no deployed binary)"] = no_deployed
        # A line move alone (an edit to the same file) is expected; list only
        # changes of kind or frame, and count the rest.
        moved = [x for x in shifted if line_moved_only(x[3], x[4])]
        shifted = [x for x in shifted if not line_moved_only(x[3], x[4])]
        stats["signature: line moved only (same bug)"] = len(moved)

        for k in sorted(stats):
            print(f"    {k:50} {stats[k]:4}")
        print(f"\n    INTRODUCED by optimizer (crash only on folded binary): {len(introduced)}")
        for trial, name, sig in introduced[:12]:
            print(f"      {trial} {name[:26]:26} {sig}")
        if len(introduced) > 12:
            print(f"      ... and {len(introduced)-12} more")
        print(f"\n    REMOVED by optimizer (baseline crash gone on a deployed binary): {len(removed)}")
        for trial, name, sig, gone in removed[:12]:
            print(f"      {trial} {name[:26]:26} {sig}  gone on {len(gone)}/{len(deployed)}: "
                  + ", ".join(gone[:4]) + (" ..." if len(gone) > 4 else ""))
        if len(removed) > 12:
            print(f"      ... and {len(removed)-12} more")
        if shifted:
            print(f"\n    signature differs across binaries (same artifact crashes both): {len(shifted)}")
            for arm, trial, name, a, b, lab in shifted[:8]:
                print(f"      {arm:9} {trial} {a}  ->  {b}  ({lab})")
        out_all[exp.name] = {
            "counts": dict(stats),
            "introduced": [{"trial": t, "artifact": n, "signature": s} for t, n, s in introduced],
            "removed": [{"trial": t, "artifact": n, "signature": s, "gone_on": g}
                        for t, n, s, g in removed],
            "shifted": [{"arm": a, "trial": t, "artifact": n, "own": x, "other": y, "binary": lab}
                        for a, t, n, x, y, lab in shifted],
            "deployed_binaries": [lab for _, lab in deployed],
        }

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(out_all, indent=2))
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
