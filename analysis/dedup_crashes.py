#!/usr/bin/env python3
"""Collapse crash ARTIFACTS into distinct BUGS.

Why the raw counts are wrong
----------------------------
AFL de-duplicates crashes against an in-memory bitmap that is NOT restored on
resume, and the online arm resumes after every hot swap (``crashes/`` is
archived to ``crashes.<ts>`` each time). So a bug found in round 1 is re-saved as
"new" in rounds 2, 3, ... purely because the fuzzer was restarted. The online arm
therefore accumulates artifacts roughly in proportion to how many times it was
swapped, which is an artifact of the experiment design, not a property of the
target. Comparing raw counts across arms measures the number of restarts.

Identity used here
------------------
A crash is identified by its sanitizer report, not by the input that produced it:

  ``(error kind, top N non-runtime frames)``

The top frames are sanitizer interceptors (``__asan_memcpy`` and friends),
identical for every overflow, so they are dropped. Kinds are normalised --
a fold that shifts allocation layout can make ASan trip ``use-after-poison``
where the baseline reports ``heap-use-after-free`` at the same frame; that is one
bug reported by two checks, not two bugs.

Two granularities are reported because neither is universally right: 1 frame
merges different call paths into the same bug (can under-count), 3 frames splits
one bug reached two ways (can over-count). The truth is bracketed by them.

Content-hash de-duplication is reported alongside as a lower bound on the
restart effect: identical bytes re-saved after a relaunch are unambiguously the
same finding.

    python3 analysis/dedup_crashes.py --experiment-id online-24h-b2-selinux --jobs 34
"""
from __future__ import annotations

import argparse
import collections
import hashlib
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
from cross_check_bugs import _KIND_ALIAS
from lib import afl
from prework.prework_build import prework_image_for

_ASAN = re.compile(r"ERROR: AddressSanitizer: ([a-z-]+)")
_FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in ([A-Za-z_][A-Za-z0-9_:]*)")
_RUNTIME = ("__asan", "__sanitizer", "__interceptor", "__lsan", "operator new",
            "malloc", "free", "realloc", "calloc")

# Frames the OPTIMIZER inserted. The fold contract requires every inserted
# function to be named fold_* (the AFL_LLVM_DENYLIST depends on it), so a fold_
# frame is by construction not original target code -- it is the optimizer's own
# helper that the surrounding code was moved into. Keying bug identity on it
# makes the SAME defect look different between arms: yara's optimized arm scored
# a third "bug" at fold_skip_wide_chars that is the wide_string_fits_in_pe
# overread relocated into a helper, inflating the optimized arm by one.
# Attribute to the nearest real frame instead. Whether a fold INTRODUCED a bug is
# a separate question, answered by cross_check_bugs replaying on the other arm's
# binary -- not by the stack.
_OPTIMIZER_INSERTED = ("fold_",)


_ASSERT = re.compile(r"assert(?:ion)?[^\n]*?failure[^\n]*?in\s+(\S+?)\((\d+)\)", re.I)
_ASSERT2 = re.compile(r"Assertion\s+`[^\']*\'\s+failed\.", re.I)


def abort_identity(out: str):
    """(kind, [site]) for a crash that aborts WITHOUT a sanitizer report.

    An assertion failure is a real, reachable abort -- AFL records it as sig:06
    and it reproduces on the upstream build -- but it is not a memory-safety
    violation, and it only exists in builds that leave asserts enabled. Returning
    None here (the old behaviour) made these look like "did not reproduce", so
    they were invisible rather than excluded on purpose. Classify them so the
    caller can report them separately and deliberately.
    """
    m = _ASSERT.search(out)
    if m:
        return "assert", [f"{Path(m.group(1)).name}:{m.group(2)}"]
    if _ASSERT2.search(out):
        return "assert", ["<libc-assert>"]
    return None, []


def report_identity(out: str, depth: int = 3):
    """(kind, [top non-runtime frames]) from a sanitizer report."""
    m = _ASAN.search(out)
    if not m:
        return None, []
    kind = _KIND_ALIAS.get(m.group(1), m.group(1))
    frames = [f for f in _FRAME.findall(out)
              if not f.startswith(_RUNTIME) and not f.startswith(_OPTIMIZER_INSERTED)]
    return kind, frames[:depth]


def one(task):
    (arm, trial, path, ts, image, target, bin_dir, cpu, tries) = task
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]
    last = ""
    for _ in range(tries):
        out = V.replay(image, Path(bin_dir), target, Path(path), cpu)
        last = out or last
        kind, frames = report_identity(out)
        if kind:
            return arm, trial, Path(path).name, ts, digest, kind, frames
    # No sanitizer report: distinguish a non-memory-safety abort (assert) from a
    # genuine non-reproducer, rather than lumping both into "did not reproduce".
    kind, frames = abort_identity(last)
    return arm, trial, Path(path).name, ts, digest, kind, frames


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--jobs", type=int, default=32)
    ap.add_argument("--tries", type=int, default=3)
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    manifest = {e["project"]: e for e in json.loads(Path(config.MANIFEST_PATH).read_text())}
    root = Path(config.RESULTS_DIR) / args.experiment_id
    out_all = {}

    for exp in sorted(p for p in root.iterdir() if p.is_dir()):
        entry = V.resolve_entry(exp.name, manifest)
        if entry is None:
            continue
        image, target = prework_image_for(entry), entry["fuzz_target"]
        base_bin = exp / "baseline" / "bin"
        online = exp / "optimized" / "online"

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
                    b = (V.live_binary(V.trial_online_dir(online, trial.name),
                                       meta.get("start_time", 0),
                                       a["timestamp_s"], base_bin)[0]
                         if arm == "optimized" else base_bin)
                    cpu = 4 + (len(tasks) % max(args.jobs, 1))
                    tasks.append((arm, trial.name, str(p), a["timestamp_s"],
                                  image, target, str(b), cpu, args.tries))

        print(f"\n=== {exp.name} ===  {len(tasks)} artifacts")
        rows = []
        with ProcessPoolExecutor(max_workers=args.jobs) as ex:
            for f in as_completed([ex.submit(one, t) for t in tasks]):
                rows.append(f.result())

        summary = {}
        for arm in ("baseline", "optimized"):
            rs = [r for r in rows if r[0] == arm]
            reproduced = [r for r in rs if r[5]]
            # Assertion aborts are REAL and reproduce upstream, but they are not
            # memory-safety violations and exist only while asserts are compiled
            # in. Keep them out of the bug count and report them on their own
            # line, rather than silently discarding them as non-reproducers.
            asserts = [r for r in reproduced if r[5] == "assert"]
            live = [r for r in reproduced if r[5] != "assert"]
            assert_sites = collections.Counter(
                (r[6][0] if r[6] else "?") for r in asserts)
            assert_trials = len({r[1] for r in asserts})
            by1 = collections.defaultdict(list)
            by3 = collections.defaultdict(list)
            for _, trial, name, ts, digest, kind, frames in live:
                by1[(kind, tuple(frames[:1]))].append((ts, trial))
                by3[(kind, tuple(frames[:3]))].append((ts, trial))
            digests = {r[4] for r in live}
            summary[arm] = {
                "artifacts_raw": len(rs),
                "poc_crash": len(live),
                "assert_aborts": len(asserts),
                "assert_trials": assert_trials,
                "assert_sites": dict(assert_sites),
                "non_reproducing": len(rs) - len(reproduced),
                "unique_by_content": len(digests),
                "unique_bugs_1frame": len(by1),
                "unique_bugs_3frame": len(by3),
                "bugs": sorted(
                    ({"signature": f"{k}:{'<-'.join(fr) or '?'}",
                      "artifacts": len(v),
                      "trials": len({t for _, t in v}),
                      "first_seen_s": min(ts for ts, _ in v),
                      # per-trial FIRST detection, so a bug's spread across
                      # replicates is visible rather than collapsed to a count.
                      "per_trial_first_s": {
                          t: min(ts for ts, tt in v if tt == t)
                          for t in sorted({t for _, t in v})}}
                     for (k, fr), v in by1.items()),
                    key=lambda d: -d["artifacts"]),
                "bugs_3frame": sorted(
                    ({"signature": f"{k}:{'<-'.join(fr) or '?'}",
                      "artifacts": len(v),
                      "trials": len({t for _, t in v}),
                      "first_seen_s": min(ts for ts, _ in v),
                      "per_trial_first_s": {
                          t: min(ts for ts, tt in v if tt == t)
                          for t in sorted({t for _, t in v})}}
                     for (k, fr), v in by3.items()),
                    key=lambda d: -d["artifacts"]),
            }
            s = summary[arm]
            print(f"  {arm:9} raw {s['artifacts_raw']:5} -> sanitizer {s['poc_crash']:5}"
                  f" -> unique inputs {s['unique_by_content']:5}"
                  f" -> DISTINCT BUGS {s['unique_bugs_1frame']:2} (1-frame)"
                  f" / {s['unique_bugs_3frame']:2} (3-frame)")
            if s["assert_aborts"]:
                sites = ", ".join(f"{k} x{v}" for k, v in
                                  sorted(s["assert_sites"].items(), key=lambda x: -x[1])[:3])
                print(f"  {'':9} + {s['assert_aborts']:5} assertion aborts in "
                      f"{s['assert_trials']}/9 trials (NOT counted as bugs): {sites}")
            if s["non_reproducing"]:
                print(f"  {'':9} + {s['non_reproducing']:5} did not reproduce")

        allbugs = sorted({b["signature"] for a in summary for b in summary[a]["bugs"]})
        print(f"\n  {'distinct bug (kind:top frame)':50} {'baseline':>18} {'optimized':>18}")
        print(f"  {'':50} {'trials  first':>18} {'trials  first':>18}")
        for sig in allbugs:
            cell = []
            for arm in ("baseline", "optimized"):
                b = next((x for x in summary[arm]["bugs"] if x["signature"] == sig), None)
                cell.append(f"{b['trials']}/9  {b['first_seen_s']/3600:5.1f}h" if b else "   -        -")
            print(f"  {sig[:50]:50} {cell[0]:>18} {cell[1]:>18}")
        out_all[exp.name] = summary

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(out_all, indent=2))
        print(f"\nwrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
