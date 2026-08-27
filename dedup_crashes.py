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

    python3 dedup_crashes.py --experiment-id online-24h-b2-selinux --jobs 34
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

sys.path.insert(0, str(Path(__file__).resolve().parent))

import config
import verify_crash_signatures as V
from cross_check_bugs import _KIND_ALIAS
from lib import afl
from prework.prework_build import prework_image_for

_ASAN = re.compile(r"ERROR: AddressSanitizer: ([a-z-]+)")
_FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in ([A-Za-z_][A-Za-z0-9_:]*)")
_RUNTIME = ("__asan", "__sanitizer", "__interceptor", "__lsan", "operator new",
            "malloc", "free", "realloc", "calloc")


def report_identity(out: str, depth: int = 3):
    """(kind, [top non-runtime frames]) from a sanitizer report."""
    m = _ASAN.search(out)
    if not m:
        return None, []
    kind = _KIND_ALIAS.get(m.group(1), m.group(1))
    frames = [f for f in _FRAME.findall(out) if not f.startswith(_RUNTIME)]
    return kind, frames[:depth]


def one(task):
    (arm, trial, path, ts, image, target, bin_dir, cpu, tries) = task
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]
    for _ in range(tries):
        out = V.replay(image, Path(bin_dir), target, Path(path), cpu)
        kind, frames = report_identity(out)
        if kind:
            return arm, trial, Path(path).name, ts, digest, kind, frames
    return arm, trial, Path(path).name, ts, digest, None, []


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
                    b = (V.live_binary(online, meta.get("start_time", 0),
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
            live = [r for r in rs if r[5]]                 # poc_crash
            by1 = collections.defaultdict(list)
            by3 = collections.defaultdict(list)
            for _, trial, name, ts, digest, kind, frames in live:
                by1[(kind, tuple(frames[:1]))].append((ts, trial))
                by3[(kind, tuple(frames[:3]))].append((ts, trial))
            digests = {r[4] for r in live}
            summary[arm] = {
                "artifacts_raw": len(rs),
                "poc_crash": len(live),
                "unique_by_content": len(digests),
                "unique_bugs_1frame": len(by1),
                "unique_bugs_3frame": len(by3),
                "bugs": sorted(
                    ({"signature": f"{k}:{'<-'.join(fr) or '?'}",
                      "artifacts": len(v),
                      "trials": len({t for _, t in v}),
                      "first_seen_s": min(ts for ts, _ in v)}
                     for (k, fr), v in by1.items()),
                    key=lambda d: -d["artifacts"]),
            }
            s = summary[arm]
            print(f"  {arm:9} raw {s['artifacts_raw']:4} -> poc_crash {s['poc_crash']:4}"
                  f" -> unique inputs {s['unique_by_content']:4}"
                  f" -> DISTINCT BUGS {s['unique_bugs_1frame']:2} (1-frame)"
                  f" / {s['unique_bugs_3frame']:2} (3-frame)")

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
