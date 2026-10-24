#!/usr/bin/env python3
"""Coverage growth per trial, both arms measured on the SAME binary.

Why the common instrument matters
---------------------------------
The two arms execute different binaries: the online arm's has folded code, and
its inserted ``fold_*`` helpers are deliberately excluded from instrumentation.
So AFL's own ``edges_found`` counts edges of two different programs and cannot
be compared across arms. Replaying BOTH arms' accumulated corpora on the
baseline build asks the comparable question instead: what behaviour of the
original program did this corpus reach?

Method: one ``afl-showmap`` pass per trial writes a per-input edge map through
the forkserver; the maps are then unioned in the order the inputs were
discovered (AFL's ``time:`` field, which is campaign-cumulative across the online
arm's relaunches). Output is one CSV per trial: time_s, inputs, cumulative_edges.

    python3 analysis/coverage_growth.py --experiment-id online-24h-b1-wolfssl --jobs 18
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path


# The pipeline modules (config, phase*, lib/, sandbox/) live at the repo root,
# one level up; Python only puts THIS script's directory on sys.path.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))


import config
from lib.provenance import experiment_image

_TIME = re.compile(r"time:(\d+)")


def discovery_ms(name: str) -> int | None:
    """Discovery time of a queue entry, in AFL's milliseconds.

    A relaunched online-arm AFL re-imports the previous queue as seeds, and
    names each imported entry ``id:N,time:0,execs:0,orig:<its original name>``.
    The FIRST ``time:`` is then the import (always 0) and the real discovery
    time sits inside ``orig:``. Taking the first match collapsed whole corpora
    onto t=0 -- mbedtls r2 put 969 of 997 inputs there, and the coverage panel
    drew the optimized arm as a flat line at its final edge count from hour 0.
    Take the LAST match: non-imported names carry exactly one, and nested
    re-imports keep the oldest-named original innermost.
    """
    ms = _TIME.findall(name)
    return int(ms[-1]) if ms else None


def showmap_maps(image: str, baseline_bin: Path, fuzz_target: str,
                 queue: Path, out: Path, cpu: int, timeout: int = 3600) -> bool:
    """One forkserver pass over the whole queue -> one edge map per input."""
    cmd = [
        "docker", "run", "--rm", "--privileged", "--cpuset-cpus", str(cpu),
        # Capped like every other analysis container in the repo (cf.
        # profile_stability_search.py): -m none lets the target allocate without
        # limit, and --jobs of these run at once, so a single runaway input must
        # die in its own cgroup instead of taking the host down.
        "--memory", "4g", "--memory-swap", "4g",
        # As the invoking user: showmap writes one map per input, and root-owned
        # output cannot be read or cleaned up afterwards by a non-root caller.
        "--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp",
        "-e", "AFL_NO_AFFINITY=1", "-e", "AFL_SKIP_CPUFREQ=1",
        "-e", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1",
        "-e", "ASAN_OPTIONS=detect_leaks=0",
        "-v", f"{baseline_bin.absolute()}:/out:ro",
        "-v", f"{queue.absolute()}:/queue:ro",
        # Mount the PARENT: afl-showmap CREATES its -o directory and aborts with
        # "cannot create output directory ... File exists" if it is already
        # there -- which bind-mounting the directory itself guarantees. The
        # failure is silent (it still exits 0), yielding zero maps and a flat
        # coverage curve that looks like a target which covers nothing.
        "-v", f"{out.parent.absolute()}:/w",
        "--entrypoint", "/bin/bash", image, "-lc",
        f"rmdir /w/{out.name} 2>/dev/null; "
        # Large-map targets (FuzzBench bloaty/curl/php/...): afl-showmap aborts
        # unless AFL_MAP_SIZE is set; take it from the target itself.
        f"m=$(AFL_DUMP_MAP_SIZE=1 /out/{fuzz_target} 2>/dev/null); "
        f'case "$m" in ""|*[!0-9]*) ;; *) export AFL_MAP_SIZE=$m;; esac; '
        f"/out/afl-showmap -i /queue -o /w/{out.name} -t 5000+ -m none -- "
        f"/out/{fuzz_target} >/dev/null 2>&1; ls /w/{out.name} | wc -l",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    return r.returncode == 0 or (out.is_dir() and any(out.iterdir()))


def growth_from_maps(maps: Path) -> list[tuple[float, int, int]]:
    """Union edge sets in discovery order -> (time_s, n_inputs, cum_edges)."""
    entries = []
    for f in maps.iterdir():
        if not f.is_file():
            continue
        ms = discovery_ms(f.name)
        if ms is None:
            continue
        entries.append((ms / 1000.0, f))
    entries.sort(key=lambda e: e[0])

    seen: set[int] = set()
    rows = []
    for i, (t, f) in enumerate(entries, 1):
        try:
            for line in f.read_text(errors="replace").splitlines():
                edge = line.split(":", 1)[0]
                if edge.isdigit():
                    seen.add(int(edge))
        except OSError:
            continue
        rows.append((t, i, len(seen)))
    return rows


def resolve_entry(exp_dir_name: str, manifest: dict) -> dict | None:
    """Manifest entry for a results directory.

    The directory is named ``<project>-<cve>``, and the CVE half may itself
    contain hyphens ("selinux-CVE-2021-36085"). Splitting on hyphen count
    therefore yields "selinux-CVE" and silently matches nothing -- the target is
    skipped and the run reports success having done no work. Match the project
    prefix against the manifest instead of inferring it from the name.
    """
    for name, entry in manifest.items():
        if exp_dir_name == name or exp_dir_name.startswith(name + "-"):
            return entry
    return None


def one_trial(args) -> tuple[str, str, int, str]:
    exp_dir, arm, trial, image, fuzz_target, cpu, outdir = args
    queue = Path(trial) / "afl_out" / "default" / "queue"
    baseline_bin = Path(exp_dir) / "baseline" / "bin"
    name = f"{arm}_{Path(trial).name}"
    if not queue.is_dir() or not any(queue.iterdir()):
        return (arm, Path(trial).name, 0, "empty queue")
    tmp = Path(tempfile.mkdtemp(prefix="cov-"))
    try:
        maps = tmp / "maps"
        if not showmap_maps(image, baseline_bin, fuzz_target, queue, maps, cpu):
            return (arm, Path(trial).name, 0, "showmap failed")
        rows = growth_from_maps(maps)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    out = Path(outdir) / f"{name}.csv"
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["time_s", "inputs", "cumulative_edges"])
        w.writerows(rows)
    return (arm, Path(trial).name, rows[-1][2] if rows else 0, str(out))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--jobs", type=int, default=16)
    ap.add_argument("--outdir", default="coverage_growth")
    args = ap.parse_args()

    manifest = {e["project"]: e for e in json.loads(Path(config.MANIFEST_PATH).read_text())}
    root = Path(config.RESULTS_DIR) / args.experiment_id
    tasks = []
    for exp_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        entry = resolve_entry(exp_dir.name, manifest)
        if entry is None:
            continue
        # The image the campaign ran with: the bench-aflpp baseline binaries
        # link that image's libc++.so.1 and would not load elsewhere.
        image, target = experiment_image(exp_dir, entry), entry["fuzz_target"]
        # Namespaced by EXPERIMENT, not just by CVE. Two campaigns on the same
        # target (c1 cold builds vs c2 incremental) both resolve to the same CVE
        # directory, so the second silently overwrote the first's CSVs -- and
        # then the plot built from them overwrote the first's figure too. The
        # raw AFL queues are untouched so this is recoverable by re-replaying,
        # but that is 25 minutes per campaign to recover something that never
        # needed to be lost.
        outdir = Path(args.outdir) / args.experiment_id / exp_dir.name
        outdir.mkdir(parents=True, exist_ok=True)
        for arm in ("baseline", "optimized"):
            for i, trial in enumerate(sorted((exp_dir / arm).glob("trial_*"))):
                # Spread across the trial cores; the fuzzing is over, they are free.
                cpu = 4 + (len(tasks) % max(args.jobs, 1))
                tasks.append((str(exp_dir), arm, str(trial), image, target, cpu, str(outdir)))

    print(f"  {len(tasks)} trials to replay on the baseline binary")
    done = 0
    with ProcessPoolExecutor(max_workers=args.jobs) as ex:
        futs = [ex.submit(one_trial, t) for t in tasks]
        for f in as_completed(futs):
            arm, trial, edges, note = f.result()
            done += 1
            print(f"  [{done}/{len(tasks)}] {arm:9} {trial}: {edges} edges  "
                  f"{'' if note.endswith('.csv') else note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
