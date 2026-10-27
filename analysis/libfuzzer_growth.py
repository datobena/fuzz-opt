"""Historical libFuzzer input adapter for plot_coverage_growth.py.

Replay retained inputs in discovery (mtime) order on ONE baseline binary.
Pre-seed libFuzzer's merge control file with that order: its COV records list
newly reached baseline edges, so one pass builds the entire cumulative curve.
No corpus timestamps, contents or original experiment files are modified.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import matplotlib.pyplot as plt
import numpy as np

ARMS = {"baseline": ("#4C72B0", "Baseline"),
        "optimized": ("#DD8452", "Static-optimized")}
STATUS = re.compile(r"^#(\d+)\s+.*?exec/s:\s*(\d+)")


def throughput(trial):
    """Cumulative-average rate, with approximate times from libFuzzer's clock.

    exec/s = executions / integer elapsed seconds, rounded down. Use the
    midpoint of the resulting time interval, preserving log order. Metadata
    provides the exact final duration and execution count; never label this
    cumulative-average rate as instantaneous throughput.
    """
    md = json.loads((trial / "metadata.json").read_text())
    duration = float(md["duration_s"])
    xs, ys = [], []
    for line in (trial / "fuzzer.log").read_text(errors="replace").splitlines():
        m = STATUS.match(line)
        if not m:
            continue
        count, rate = map(int, m.groups())
        if rate <= 0:
            continue
        t = count / (rate + 0.5)
        if t >= duration:
            continue
        if xs and t <= xs[-1]:
            continue
        xs.append(t); ys.append(rate)
    total = md.get("final_stats", {}).get("total_execs")
    if total and duration > 0:
        xs.append(duration); ys.append(total / duration)
    if not xs:
        raise ValueError(f"No throughput samples: {trial}")
    return np.asarray(xs), np.asarray(ys)


def parse_control(control, times):
    """Union COV IDs; reject incomplete or crash-skipped merge replays."""
    n = int(control[0])
    if n != len(times) or int(control[1]) != 0:
        raise ValueError("Merge control header does not match the corpus")
    finished, discoveries = set(), {}
    for line in control[2 + n:]:
        p = line.split()
        if len(p) < 2:
            continue
        if p[0] == "FT":
            finished.add(int(p[1]))
        elif p[0] == "COV":
            discoveries[int(p[1])] = {int(x) for x in p[2:]}
    if finished != set(range(n)):
        raise ValueError(f"Incomplete baseline replay: {len(finished)}/{n} inputs")
    seen, rows = set(), [(0.0, 0, 0)]
    for i, t in enumerate(times):
        seen.update(discoveries.get(i, ()))
        rows.append((t, i + 1, len(seen)))
    return rows


def replay_trial(trial, binary, image, destination, binary_sha):
    md = json.loads((trial / "metadata.json").read_text())
    start, duration = float(md["start_time"]), float(md["duration_s"])
    corpus = trial / "corpus"
    units = sorted(((p.stat().st_mtime, p.name, p.stat().st_size)
                    for p in corpus.iterdir() if p.is_file()))
    if not units:
        raise ValueError(f"Empty corpus: {corpus}")
    # Absolute epoch times in metadata must agree with the retained files.
    # A copied/extracted corpus with reset timestamps cannot recover discovery.
    if units[0][0] > start + duration + 5:
        raise ValueError(f"Corpus mtimes postdate trial: {corpus}")
    times = [min(duration, max(0.0, ts - start)) for ts, _, _ in units]
    fingerprint = hashlib.sha256(json.dumps(
        ["ordered-merge-v1", binary_sha, image, start, duration, units]
    ).encode()).hexdigest()
    stamp = destination.with_suffix(".json")
    if destination.is_file() and stamp.is_file():
        if json.loads(stamp.read_text()).get("fingerprint") == fingerprint:
            print(f"  cached {trial.parent.name}/{trial.name}", flush=True)
            return destination
    with tempfile.TemporaryDirectory(prefix="libfuzzer-growth-") as tmp:
        work = Path(tmp)
        (work / "out").mkdir()
        control = work / "control"
        control.write_text(f"{len(units)}\n0\n" + "".join(
            f"/corpus/{name}\n" for _, name, _ in units))
        command = ["docker", "run", "--rm", "--network", "none",
                   "--memory", "2g", "--cpus", "1",
                   "--user", f"{os.getuid()}:{os.getgid()}",
                   "-e", "ASAN_OPTIONS=detect_leaks=0",
                   "-v", f"{binary.parent.resolve()}:/out:ro",
                   "-v", f"{corpus.resolve()}:/corpus:ro",
                   "-v", f"{work}:/work",
                   "--entrypoint", f"/out/{binary.name}", image,
                   "-merge=1", "-merge_control_file=/work/control",
                   "-seed=1337", "-detect_leaks=0", "-rss_limit_mb=1500",
                   "-timeout=10", "/work/out", "/corpus"]
        result = subprocess.run(command, capture_output=True, text=True,
                                errors="replace", timeout=900)
        log = result.stdout + result.stderr
        destination.with_suffix(".log").write_text(log)
        if result.returncode:
            raise RuntimeError(f"Replay failed for {trial}: {log[-2000:]}")
        rows = parse_control(control.read_text().splitlines(), times)
        # A merge can recover from a crashing input and still return success.
        # parse_control requires every input's FT record, rejecting that case.
    with destination.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["time_s", "inputs", "cumulative_edges"])
        writer.writerows(rows)
    stamp.write_text(json.dumps({"fingerprint": fingerprint,
                                "baseline_sha256": binary_sha,
                                "trial": str(trial.resolve()),
                                "method": "baseline ordered libFuzzer merge replay",
                                "inputs": len(units), "final_edges": rows[-1][2]}, indent=2))
    print(f"  replayed {trial.parent.name}/{trial.name}: "
          f"{len(units)} inputs, {rows[-1][2]} baseline edges", flush=True)
    return destination


def plot_experiment(args, grid, band):
    root = Path(args.results_dir) / args.experiment_id
    targets = [p for p in sorted(root.iterdir()) if (p / "setup_metadata.json").is_file()
               and (not args.target or p.name == args.target)]
    if not targets or args.jobs < 1:
        raise ValueError("No matching targets, or --jobs is less than one")
    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    for target in targets:
        setup = json.loads((target / "setup_metadata.json").read_text())
        binary = target / "baseline" / "bin" / setup["entry"]["fuzz_target"]
        binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
        covdir = Path(args.covdir) / args.experiment_id / target.name
        covdir.mkdir(parents=True, exist_ok=True)
        trials = {arm: sorted((target / arm).glob("trial_*/metadata.json")) for arm in ARMS}
        cov, exe = {a: [] for a in ARMS}, {a: [] for a in ARMS}
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            pending = {}
            for arm in ARMS:
                for md in trials[arm]:
                    trial = md.parent
                    exe[arm].append(throughput(trial))
                    path = covdir / f"{arm}_{trial.name}.csv"
                    pending[pool.submit(replay_trial, trial, binary, args.runner_image,
                                        path, binary_sha)] = arm
            for future in as_completed(pending):
                arm = pending[future]
                with future.result().open() as f:
                    rows = list(csv.DictReader(f))
                cov[arm].append((np.array([float(r["time_s"]) for r in rows]),
                                 np.array([int(r["cumulative_edges"]) for r in rows])))
        # Use this repository's shared mean / t-based 95% CI implementation.
        fig, axes = plt.subplots(2, 1, figsize=(13, 9.2), sharex=True)
        for ax, data, title, ylabel in [
            (axes[0], cov, "Coverage growth — replayed on the common baseline binary",
             "Cumulative baseline edges"),
            (axes[1], exe, "Throughput — cumulative average reported by libFuzzer",
             "Executions / second")]:
            for arm, (color, label) in ARMS.items():
                if not data[arm]:
                    continue
                mean, lo, hi, n = band(data[arm], hold_right=(data is cov))
                ax.plot(grid / 3600, mean, color=color, label=f"{label} (n={n})")
                ax.fill_between(grid / 3600, lo, hi, color=color, alpha=.25)
            ax.set_title(title, fontsize=11); ax.set_ylabel(ylabel)
            ax.set_ylim(bottom=0); ax.set_xlim(0, grid[-1] / 3600)
            ax.grid(alpha=.3); ax.legend(loc="best")
        axes[1].set_xlabel("Elapsed time (hours)")
        fig.suptitle(f"{args.experiment_id} · {target.name}\nMean ± 95% confidence interval across available trials")
        fig.text(.5, .015,
                 "Coverage time: retained corpus mtimes relative to recorded trial start. "
                 "Throughput time: estimated from executions / integer exec/s.\n"
                 "Static A/B run: optimized binary fixed throughout; optimizer CPU cost not recorded.",
                 ha="center", fontsize=9)
        fig.tight_layout(rect=(0, .065, 1, .94))
        stem = outdir / f"{args.experiment_id}_{target.name}_coverage_execs"
        for suffix in (".png", ".pdf"):
            fig.savefig(stem.with_suffix(suffix), dpi=150, bbox_inches="tight")
        plt.close(fig)
        print(f"  wrote {stem}.png and .pdf", flush=True)
    return 0
