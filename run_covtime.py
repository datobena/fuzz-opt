#!/usr/bin/env python3
"""Coverage-OVER-TIME on a common BASELINE binary (offline replay).

For each nk1 project, reconstruct edge-coverage-vs-time for BOTH the
baseline-generated and the optimized-generated corpus, measured on the SAME
baseline binary. This extends the final-corpus per-trial covdiff
(run_covdiff_pertrial.py) with a time axis so we can see *when* coverage is
reached, not just the endpoint -- and whether harness optimization narrows the
reachable surface over the run.

How the time axis is recovered
------------------------------
libFuzzer writes each newly-discovered corpus unit into /corpus at the moment it
finds it, so the unit's file mtime IS its discovery time. That mtime survives
inside the archived corpus zip's central directory. We read it via
`zipfile.ZipInfo.date_time` -- NOT from extracted files, whose on-disk mtimes are
the *extraction* time (`zipfile.extractall` does not restore mtimes).

Per trial we anchor t0 = latest_unit_mtime - duration_seconds (duration from the
run's metadata; fallback 172800 = 48h). Each unit's relative time is
clamp(mtime - t0, 0, duration). Seed inputs carry stale pre-run mtimes (< t0) and
correctly clamp to t=0. We then bucket units by discovery time and CUMULATIVELY
replay them on the baseline binary with libFuzzer -runs=0 (reusing
run_covdiff_pertrial._cov), so coverage is monotonic non-decreasing by
construction.

Why offline, not a live in-pod snapshot
---------------------------------------
A running optimized trial reports coverage on the OPTIMIZED binary (a different
edge map from folded/stubbed code) -- the wrong yardstick. Replaying archived
corpora on the BASELINE binary is the only way to put both variants on a common
scale. (config.COVERAGE_SNAPSHOT_INTERVAL was scaffolded for such a live
snapshot; this offline builder is what actually satisfies the baseline-binary
requirement.)

Outputs (per project)
---------------------
  results/new-kube-1-rerun/<key>/<variant>/trial_<id>/coverage_over_time.json
      [{"time_s": float, "edges": int}, ...]   (schema phase4_analysis reads)
  covtime/<project>.png    (median line + 25/75 IQR band, baseline vs optimized)

Usage
-----
  python3 run_covtime.py --build [--projects wolfssl selinux] \
                         [--variants baseline optimized] [--interval 1800]
"""
import argparse
import datetime
import json
import os
import re
import shutil
import zipfile
from pathlib import Path

import config
import phase3_k8s as p3
from lib import stats_util
from run_covdiff_pertrial import _cov, manifest, SRC_EXP, OUT as PERTRIAL_OUT

IN = PERTRIAL_OUT                       # covdiff_pertrial/ (already-pulled zips)
OUT = Path(os.environ.get("COVTIME_OUT", "covtime"))   # PNGs land here; scratch under OUT/_work
DEFAULT_DURATION = int(os.environ.get("COVTIME_DURATION", "172800"))  # fallback when metadata absent
INTERVAL = int(getattr(config, "COVERAGE_SNAPSHOT_INTERVAL", 1800))


def _zip_unit_times(zip_path: Path) -> dict:
    """name -> discovery datetime, from the zip central directory (NOT extract)."""
    with zipfile.ZipFile(zip_path) as zf:
        return {i.filename: datetime.datetime(*i.date_time)
                for i in zf.infolist() if not i.is_dir()}


def _resolve_duration(key: str) -> int:
    """duration_seconds from any baseline trial metadata of the source experiment."""
    base = Path(config.RESULTS_DIR) / SRC_EXP / key / "baseline"
    for mp in sorted(base.glob("trial_*/metadata.json")):
        try:
            d = json.load(open(mp))
            if d.get("duration_seconds"):
                return int(d["duration_seconds"])
        except (json.JSONDecodeError, OSError):
            continue
    return DEFAULT_DURATION


def _dedupe_by_trial(zips: list) -> list:
    """One zip per trial_id (the most complete, by unit count). Returns [(id, zip)]."""
    best = {}
    for z in zips:
        m = re.match(r"corpus-(\d+)-", z.name)
        if not m:
            continue
        tid = int(m.group(1))
        n = len(_zip_unit_times(z))
        if tid not in best or n > best[tid][1]:
            if tid in best:
                print(f"    dup trial {tid}: keeping larger corpus "
                      f"({max(n, best[tid][1])} units)")
            best[tid] = (z, n)
    return sorted((tid, zt[0]) for tid, zt in best.items())


def _build_curve(zip_path: Path, bin_dir: Path, target: str,
                 duration: int, interval: int, work: Path) -> list:
    """Cumulative time-ordered replay of one trial corpus on the baseline binary.

    Returns [{"time_s": float, "edges": int}, ...] over buckets 0..duration.
    """
    times = _zip_unit_times(zip_path)
    if not times:
        return None

    latest = max(times.values())
    # Seed units are copied in with stale pre-run mtimes; the run is `duration`
    # long and ends at <= latest, so anything older than (latest - duration) is a
    # seed. Anchor t0 at the earliest freshly-discovered unit = the run start.
    # Using (latest - duration) directly would be wrong when the fuzzer saturates
    # early (last discovery << run end): it would shove all the real accumulation
    # to the END of the window. Coverage discovery is front-loaded, so the
    # earliest fresh unit is the run start; seeds (older than window_start) clamp
    # to t=0 and later carry forward flat once discovery stops.
    window_start = latest - datetime.timedelta(seconds=duration)
    fresh_mtimes = [dt for dt in times.values() if dt > window_start]
    t0 = min(fresh_mtimes) if fresh_mtimes else window_start
    rel = {name: min(max((dt - t0).total_seconds(), 0.0), float(duration))
           for name, dt in times.items()}

    span_h = (latest - t0).total_seconds() / 3600.0
    if span_h < duration / 3600.0 - 1:
        print(f"    {zip_path.name}: discovery saturated at {span_h:.1f}h "
              f"(of {duration / 3600.0:.0f}h) -> flat thereafter")

    # Extract bytes once; time already captured above.
    all_dir = work / "all"
    all_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(all_dir)

    order = sorted(rel.items(), key=lambda kv: kv[1])   # by discovery time
    buckets = list(range(0, duration + 1, interval))
    if buckets[-1] != duration:
        buckets.append(duration)

    cumdir = work / "cum"
    cumdir.mkdir(parents=True, exist_ok=True)
    curve, idx, last_cov = [], 0, None
    for b in buckets:
        newly = 0
        while idx < len(order) and order[idx][1] <= b:
            name = order[idx][0]
            src = all_dir / name
            if src.is_file():
                dst = cumdir / os.path.basename(name)
                try:
                    os.link(src, dst)          # hardlink: no copy, real file for docker
                    newly += 1
                except FileExistsError:
                    pass
            idx += 1
        force_final = (b == duration)
        if newly == 0 and last_cov is not None and not force_final:
            curve.append({"time_s": float(b), "edges": last_cov})
            continue
        n_in_cum = sum(1 for _ in cumdir.iterdir())
        if n_in_cum == 0:
            cov = 0
        else:
            cov = _cov(bin_dir, cumdir, target).get("cov")
            if cov is None:                    # replay failed; carry forward
                cov = last_cov if last_cov is not None else 0
        # Coverage of a growing corpus is monotonic by definition; clamp to the
        # running max to remove the ~+-1 edge run-to-run noise in libFuzzer's
        # cov: measurement (ASLR / pointer-dependent branches).
        if last_cov is not None:
            cov = max(cov, last_cov)
        last_cov = cov
        curve.append({"time_s": float(b), "edges": cov})
    return curve


def _emit_results_tree(key: str, variant: str, trial_id: int, curve: list) -> bool:
    """Write coverage_over_time.json into the existing trial dir (best-effort)."""
    d = Path(config.RESULTS_DIR) / SRC_EXP / key / variant / f"trial_{trial_id:02d}"
    if not d.is_dir():
        return False
    json.dump(curve, open(d / "coverage_over_time.json", "w"), indent=2)
    return True


def _plot(p: str, curves: dict, aggregate: str):
    png = OUT / f"{p}.png"
    stats_util.plot_coverage_over_time(
        curves["optimized"], curves["baseline"],
        title=f"Coverage over time (baseline binary): {p}",
        output_path=str(png), aggregate=aggregate)
    return png


def _curves_from_results(key: str, variant: str) -> list:
    """Reconstruct per-trial curves from the emitted results-tree JSONs."""
    out = []
    base = Path(config.RESULTS_DIR) / SRC_EXP / key / variant
    for f in sorted(base.glob("trial_*/coverage_over_time.json")):
        try:
            out.append([(e["time_s"], e["edges"]) for e in json.load(open(f))])
        except (OSError, json.JSONDecodeError):
            continue
    return out


def replot(projects: set, variants: list, aggregate: str):
    """Re-render plots from saved curves (covtime/<p>.curves.json, else the
    results-tree JSONs) WITHOUT re-replaying. Fast; use to change mean/median."""
    OUT.mkdir(exist_ok=True)
    for e in manifest():
        p = e["project"]
        if projects and p not in projects:
            continue
        key = p3.cve_key(p, e["cve"])
        cj = OUT / f"{p}.curves.json"
        curves = {"baseline": [], "optimized": []}
        if cj.is_file():
            d = json.load(open(cj))
            for v in variants:
                curves[v] = [[(t, ed) for t, ed in tr] for tr in d.get(v, [])]
            src = "curves.json"
        else:
            for v in variants:
                curves[v] = _curves_from_results(key, v)
            src = "results-tree json"
        if curves["baseline"] or curves["optimized"]:
            _plot(p, curves, aggregate)
            print(f"  replotted {p} ({aggregate}) from {src}: "
                  f"base n={len(curves['baseline'])}, opt n={len(curves['optimized'])}")


def build(projects: set, variants: list, interval: int, aggregate: str = "mean"):
    OUT.mkdir(exist_ok=True)
    for e in manifest():
        p = e["project"]
        if projects and p not in projects:
            continue
        cve, target = e["cve"], e.get("fuzz_target", "")
        key = p3.cve_key(p, cve)
        bin_dir = Path(config.RESULTS_DIR) / SRC_EXP / key / "baseline" / "bin"
        if not (bin_dir / target).is_file():
            print(f"SKIP {p}: baseline binary missing ({bin_dir / target})")
            continue
        duration = _resolve_duration(key)
        print(f"\n=== {p} ({key}) target={target} duration={duration}s "
              f"interval={interval}s ===")

        curves = {"baseline": [], "optimized": []}
        for variant in variants:
            vdir = IN / p / variant
            zips = _dedupe_by_trial(sorted(vdir.glob("corpus-*.zip"))) if vdir.is_dir() else []
            if not zips:
                print(f"  {variant}: no corpus zips in {vdir}")
                continue
            for trial_id, zpath in zips:
                work = OUT / "_work" / p / variant / f"trial_{trial_id:02d}"
                if work.exists():
                    shutil.rmtree(work)
                work.mkdir(parents=True)
                try:
                    curve = _build_curve(zpath, bin_dir, target, duration, interval, work)
                finally:
                    shutil.rmtree(work, ignore_errors=True)
                if not curve:
                    print(f"  {variant} trial {trial_id:02d}: empty corpus, skipped")
                    continue
                wrote = _emit_results_tree(key, variant, trial_id, curve)
                curves[variant].append([(c["time_s"], c["edges"]) for c in curve])
                print(f"  {variant} trial {trial_id:02d}: "
                      f"edges {curve[0]['edges']} -> {curve[-1]['edges']} "
                      f"over {len(curve)} buckets"
                      f"{'  (json written)' if wrote else ''}")

        if curves["baseline"] or curves["optimized"]:
            json.dump(curves, open(OUT / f"{p}.curves.json", "w"))
            _plot(p, curves, aggregate)
            print(f"  wrote {OUT / f'{p}.png'}")

    shutil.rmtree(OUT / "_work", ignore_errors=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build", action="store_true",
                    help="build curves (replay) + plots")
    ap.add_argument("--replot", action="store_true",
                    help="re-render plots from saved curves, no replay")
    ap.add_argument("--projects", nargs="*", default=None,
                    help="subset of projects (default: all in manifest)")
    ap.add_argument("--variants", nargs="*", default=["baseline", "optimized"],
                    choices=["baseline", "optimized"])
    ap.add_argument("--interval", type=int, default=INTERVAL,
                    help=f"bucket width in seconds (default {INTERVAL})")
    ap.add_argument("--aggregate", choices=["mean", "median"], default="mean",
                    help="cross-trial aggregation for the band (default mean+95%% CI)")
    a = ap.parse_args()
    if not (a.build or a.replot):
        ap.error("pass --build and/or --replot")
    projs = set(a.projects) if a.projects else None
    if a.build:
        build(projs, a.variants, a.interval, a.aggregate)
    if a.replot:
        replot(projs, a.variants, a.aggregate)
