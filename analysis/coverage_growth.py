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
the forkserver, replaying the inputs in the order they were discovered (AFL's
``time:`` field, which is campaign-cumulative across the online arm's
relaunches); the maps are then unioned in that same order. Output is one CSV per
trial: time_s, inputs, cumulative_edges.

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
import traceback
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


def replay_key(name: str) -> tuple[int, bytes, bytes]:
    """Discovery order, with a tie-break that is the same in both arms.

    Replay order is not neutral: the harnesses are persistent, so one process
    runs every input, and one-time-per-process code (openssl x509: ~140 edges
    on the first real input) is credited to whichever input runs FIRST. Plain
    ``id:`` order put a late find first in every hot-swapped trial: a resumed
    AFL++ re-imports the old queue newest-first and renumbers it, so id:000000
    became e.g. ``orig:id:002620,...,time:61052610`` and took the one-time edges
    to t=17h. Sorting by discovery time puts the seeds (time 0) first.

    Seeds all share time 0, so they tie-break on their ORIGINAL file name: the
    text after ``,orig:``, which AFL++ (pivot_inputs) copies from the seed's
    file name and never nests -- a re-import keeps only what follows the first
    ``,orig:``. A fresh AFL++ imports seeds in alphasort order of exactly that
    name, so this reproduces the baseline arm's seed ids, while a resumed arm's
    seed ids run reversed after each swap. Byte order matches alphasort in the
    image's C/POSIX locale. Entries without ``orig:`` compare by their own name;
    the full name settles anything left.
    """
    _, sep, orig = name.partition(",orig:")
    return (discovery_ms(name) or 0, os.fsencode(orig if sep else name),
            os.fsencode(name))


def replay_order(queue: Path) -> list[str]:
    """Every regular file in the queue, in the order afl-showmap runs them.

    Entries with a ``time:`` come first, by ``replay_key``. Any without one
    (e.g. an AFL++ sync import ``id:N,sync:X,src:N``) go last, by name: ``-i``
    replayed them too, and ``growth_from_maps`` leaves them out of the curve as
    it always did, so running them last keeps them from touching it.
    """
    names = [e.name for e in os.scandir(queue) if e.is_file(follow_symlinks=False)]
    timed = sorted((n for n in names if discovery_ms(n) is not None), key=replay_key)
    untimed = sorted((n for n in names if discovery_ms(n) is None), key=os.fsencode)
    return timed + untimed


# The image's AFL++ is built ALWAYS_COLORED, and a crash/timeout notice ends in
# a colour reset with no newline, so the next line reads "\x1b[0mProcessing ...".
_ANSI = re.compile(rb"\x1b\[[0-9;]*m")
_PROCESSING = re.compile(rb"^Processing /queue/(.*)$", re.M)
_PROCESSED = re.compile(rb"^\[\+\] Processed (\d+) input files\.$", re.M)


def parse_replay_log(log: bytes) -> tuple[list[str], int | None]:
    """afl-showmap's stdout -> (inputs it started, in order; its final
    "Processed N input files." count, or None if it never got there)."""
    text = _ANSI.sub(b"", log)
    done = _PROCESSED.findall(text)
    return ([os.fsdecode(n) for n in _PROCESSING.findall(text)],
            int(done[-1]) if done else None)


def showmap_maps(image: str, baseline_bin: Path, fuzz_target: str,
                 queue: Path, order: list[str], out: Path, cpu: int,
                 timeout: int = 3600) -> bool:
    """One forkserver pass over the queue IN ``order`` -> one edge map per input.

    ``-i`` would replay in alphasort (= ``id:``) order, so the inputs go in as
    an ``-I`` file list instead; each map is still written under the input's
    own file name. AFL_PRINT_FILENAMES makes afl-showmap log every input just
    before running it. The replay only counts if that log is exactly ``order``
    (minus empty files, which afl-showmap skips), afl-showmap reached its final
    "Processed N" line with that same N, and every one of those inputs has a
    map: wrong order, a dropped input or an aborted pass (even on the last
    input) all fail here instead of yielding a plausible-looking curve.
    """
    filelist = out.parent / "replay_order.txt"
    filelist.write_bytes(b"".join(b"/queue/" + os.fsencode(n) + b"\n" for n in order))
    log = out.parent / "replay.log"
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
        "-e", "ASAN_OPTIONS=detect_leaks=0", "-e", "AFL_PRINT_FILENAMES=1",
        "-v", f"{baseline_bin.absolute()}:/out:ro",
        "-v", f"{queue.absolute()}:/queue:ro",
        # Mount the PARENT and let afl-showmap create -o itself. Older builds
        # were seen to abort ("cannot create output directory ... File
        # exists", still exit 0, zero maps) when -o already existed, which
        # bind-mounting the directory itself guarantees; 4.21a's -i/-I mode
        # reuses an existing one, and the log checks below catch either way.
        "-v", f"{out.parent.absolute()}:/w",
        "--entrypoint", "/bin/bash", image, "-lc",
        f"rmdir /w/{out.name} 2>/dev/null; "
        # Large-map targets (FuzzBench bloaty/curl/php/...): afl-showmap aborts
        # unless AFL_MAP_SIZE is set; take it from the target itself.
        f"m=$(AFL_DUMP_MAP_SIZE=1 /out/{fuzz_target} 2>/dev/null); "
        f'case "$m" in ""|*[!0-9]*) ;; *) export AFL_MAP_SIZE=$m;; esac; '
        # Only afl-showmap's own messages reach stdout (the target's go to
        # /dev/null unless AFL_DEBUG_CHILD), i.e. the "Processing" log.
        f"/out/afl-showmap -I /w/{filelist.name} -o /w/{out.name} -t 5000+ -m none -- "
        f"/out/{fuzz_target} >/w/{log.name} 2>/dev/null",
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False
    try:
        ran, processed = parse_replay_log(log.read_bytes())
    except OSError:
        return False
    expected = [n for n in order if (queue / n).stat().st_size]
    return (ran == expected and processed == len(expected)
            and all((out / n).is_file() for n in expected))


def growth_from_maps(maps: Path, order: list[str]
                     ) -> tuple[list[tuple[float, int, int]], list[str]]:
    """Union edge sets in replay order -> ((time_s, n_inputs, cum_edges), unreadable).

    One row per queue entry with a ``time:``; entries without one are skipped,
    as before. An input without a readable map (an empty input, which
    afl-showmap skips, or a map that cannot be read) adds no edges but is still
    counted; unreadable maps are returned so the caller can report them.
    """
    seen: set[int] = set()
    rows, unreadable = [], []
    for name in order:
        ms = discovery_ms(name)
        if ms is None:
            continue
        f = maps / name
        if f.is_file():
            try:
                for line in f.read_text(errors="replace").splitlines():
                    edge = line.split(":", 1)[0]
                    if edge.isdigit():
                        seen.add(int(edge))
            except OSError:
                unreadable.append(name)
        rows.append((ms / 1000.0, len(rows) + 1, len(seen)))
    return rows, unreadable


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


def one_trial(args) -> tuple[str, str, int, bool, str]:
    """Replay one trial and (re)write its CSV.

    On success the trial's previous CSV is replaced atomically. It is removed
    only when THIS replay fails (a failed result or an exception), so the plot
    cannot mix a stale curve in with this run's. An interruption (Ctrl-C, a
    killed worker, a host reset) removes nothing: KeyboardInterrupt is not an
    Exception, and a killed process runs no handler, so every trial keeps its
    last good CSV.
    """
    out = Path(args[6]) / f"{args[1]}_{Path(args[2]).name}.csv"
    try:
        result = _replay_trial(*args, out=out)
    except Exception:
        out.unlink(missing_ok=True)
        out.with_suffix(".csv.part").unlink(missing_ok=True)
        raise
    if not result[3]:
        out.unlink(missing_ok=True)
    return result


def _replay_trial(exp_dir, arm, trial, image, fuzz_target, cpu, outdir, *,
                  out: Path) -> tuple[str, str, int, bool, str]:
    queue = Path(trial) / "afl_out" / "default" / "queue"
    baseline_bin = Path(exp_dir) / "baseline" / "bin"
    order = replay_order(queue) if queue.is_dir() else []
    if not order:
        return (arm, Path(trial).name, 0, False, "empty queue")
    tmp = Path(tempfile.mkdtemp(prefix="cov-"))
    try:
        maps = tmp / "maps"
        if not showmap_maps(image, baseline_bin, fuzz_target, queue, order, maps, cpu):
            return (arm, Path(trial).name, 0, False,
                    "showmap failed (incomplete or out-of-order replay)")
        rows, unreadable = growth_from_maps(maps, order)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    part = out.with_suffix(".csv.part")
    with open(part, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["time_s", "inputs", "cumulative_edges"])
        w.writerows(rows)
    os.replace(part, out)
    note = (f"{len(unreadable)} unreadable map(s), counted with no edges"
            if unreadable else "")
    return (arm, Path(trial).name, rows[-1][2] if rows else 0, True, note)


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
    done, failed = 0, []
    with ProcessPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(one_trial, t): t for t in tasks}
        for f in as_completed(futs):
            try:
                arm, trial, edges, ok, note = f.result()
            except Exception as e:  # noqa: BLE001 - report it with the rest
                t = futs[f]
                arm, trial, edges, ok, note = t[1], Path(t[2]).name, 0, False, f"error: {e!r}"
                # A worker's exception carries its remote traceback as __cause__.
                traceback.print_exception(e)
            done += 1
            if not ok:
                t = futs[f]
                csv_left = (Path(t[6]) / f"{arm}_{trial}.csv").exists()
                failed.append(f"{Path(t[0]).name} {arm} {trial}: {note}"
                              f"{'  (previous CSV left in place)' if csv_left else ''}")
            print(f"  [{done}/{len(tasks)}] {arm:9} {trial}: {edges} edges  {note}")
    if failed:
        print(f"  {len(failed)} of {len(tasks)} trials FAILED:")
        for line in sorted(failed):
            print(f"    {line}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
