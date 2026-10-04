#!/usr/bin/env python3
"""Coverage growth and throughput on a WALL-CLOCK axis, with the dead time shown.

Two corrections that matter for an honest comparison:

1. Common instrument. The arms execute different binaries, so AFL's own
   edges_found counts edges of two different programs. coverage_growth.py
   replays BOTH arms' corpora on the BASELINE build; this plots that.

2. Wall-clock, not run_time. AFL's clock (plot_data relative_time, and the
   queue/crash `time:` fields) is run_time -- it does not advance while the
   process is stopped. The online arm is stopped at every hot swap, so plotting
   against AFL's clock silently DELETES that downtime and makes the arm look as
   though it fuzzed for the full wall-clock window. Each trial's samples are
   therefore shifted by the downtime accumulated before them, the stopped
   intervals are drawn explicitly (exec/s = 0, coverage flat), and the
   optimizer's own CPU cost is overlaid.

    python3 plot_coverage_growth.py --experiment-id online-24h-b1-wolfssl
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config

ARMS = {"baseline": ("#4C72B0", "Baseline"), "optimized": ("#DD8452", "Online-optimized")}
HOURS = 24.0
# 30 s bins. Must be SHORTER than the shortest stopped interval (~100 s for a
# hot swap), or a bin straddles the gap edge, averages inserted zeros with
# real throughput, and the stop never reaches zero on the plot.
GRID = np.arange(0, HOURS * 3600 + 30, 30, dtype=float)


def per_trial_charge_windows(exp_dir: Path, swaps_by_trial: dict) -> dict:
    """{trial: [(run_time, charge_s)]} -- each trial charged its OWN optimizer.

    Under per-trial optimizers, trial i runs its own optimizer against its own
    source tree and never benefits from the other nine. Charging it the campaign
    total (per-replicate) bills it for CPU spent on binaries it never executed;
    dividing the total by ten (the average) hides that the optimizers did
    measurably different amounts of work. Both answer the wrong question. The
    right one is: if this were a real single campaign, how long would ITS
    optimizer have taken?

    Measured directly. Each optimizer is pinned to one core, so its CPU is the
    wall time its sessions ran, and a session directory
    (trials/trial_NN/iter_MM/sandbox) belongs to exactly one trial -- unlike the
    ledger rows, 86% of which the broker writes without a trial_id and which
    time-window matching cannot separate (ten sessions overlap; 89% ambiguous).

    Session wall is scaled by ledger_cpu / session_wall to strip agent
    model-wait: blocked on the API the core is free, so it is not CPU. On c1
    that factor is 0.834 -- 95.0h of session wall against 79.2h of charged CPU.
    """
    root = exp_dir / "optimized" / "online" / "trials"
    if not root.is_dir():
        return {}
    sessions: dict[int, list] = {}
    for d in sorted(root.glob("trial_*/iter_*/sandbox")):
        m = re.search(r"trial_(\d+)/iter_(\d+)", str(d))
        if not m:
            continue
        times = [f.stat().st_mtime for f in d.rglob("*") if f.is_file()]
        if times:
            sessions.setdefault(int(m.group(1)), []).append(
                (min(times), max(times) - min(times)))
    if not sessions:
        return {}

    wall_total = sum(d for v in sessions.values() for _, d in v)
    try:
        cost = json.loads(
            (exp_dir / "optimized" / "online" / "cpu_cost.json").read_text())
        cpu_total = float(cost.get("total_core_s") or 0.0)
    except (OSError, json.JSONDecodeError, TypeError):
        cpu_total = 0.0
    k = (cpu_total / wall_total) if (cpu_total and wall_total) else 1.0

    starts = sorted(json.loads(m.read_text()).get("start_time", 0)
                    for m in (exp_dir / "optimized").glob("trial_*/metadata.json"))
    if not starts:
        return {}
    t0 = starts[0]

    out: dict[int, list] = {}
    for t, rounds in sessions.items():
        acc = 0.0
        prior_down = swaps_by_trial.get(t, [])
        for begin, dur in sorted(rounds):
            wall = begin - t0
            down = sum(d for rt, d in prior_down if rt <= wall)
            out.setdefault(t, []).append((max(wall - down - acc, 0.0), dur * k))
            acc += dur * k
    return out


def cpu_charge_windows(exp_dir: Path, project: str, swaps):
    """Optimizer CPU, charged to the online arm as lost fuzzing time.

    The profiling, rebuilds and replays run on a separate core, so they do not
    stop the trials -- but that core could have been fuzzing. Charging
    ``core_seconds / trial_cores`` per round puts both arms on an equal CPU
    budget: the online arm's curve is shifted right by the fuzzing time its
    optimizer consumed, so a coverage advantage has to be paid for before it
    counts. Agent model-wait is NOT charged (it is GPU/API latency, not CPU).

    Returned in run_time coordinates so it composes with the swap downtime.
    """
    try:
        cost = json.loads((exp_dir / "optimized" / "online" / "cpu_cost.json").read_text())
    except (OSError, json.JSONDecodeError):
        return []
    starts = sorted(
        json.loads(m.read_text()).get("start_time", 0)
        for m in (exp_dir / "optimized").glob("trial_*/metadata.json"))
    if not starts:
        return []
    t0 = starts[0]
    out = []
    for r in cost.get("rounds", []):
        charge = float(r.get("fuzz_seconds_equivalent") or 0.0)
        end = r.get("t_end")
        if charge <= 0 or not end:
            continue
        wall = end - t0
        prior = sum(d for rt, d in swaps if rt <= wall)   # downtime already elapsed
        out.append((max(wall - prior, 0.0), charge))
    return out


def swap_windows(experiment_id: str, trial_id: int | None = None):
    """Hot-swap stops for ONE trial (or, legacy, for the whole online arm).

    Two log formats, because the design changed underneath this script:

      shared-binary (b1..b6)  "online round N: HOT-SWAP into K running online
                              trials" -- ONE stop applies to every online trial,
                              so a single global window list is correct.
      per-trial     (c1+)     "trial_07 round N: HOT-SWAP (swap generation G)"
                              -- each trial stops on its OWN schedule, so the
                              windows must be read per trial and applied only to
                              that trial's samples. Averaging them onto a common
                              timeline would place a gap where no trial actually
                              stopped and shift every trial by downtime it did
                              not experience.

    A log that parses to ZERO swaps is treated as an error, not as "no
    downtime". The old parser matched only the shared-binary string, so against
    a per-trial log it silently returned [] and the online arm was plotted
    UNCHARGED -- exactly the flattering curve the file-missing guard below was
    written to prevent.
    """
    log = Path(f".{experiment_id}.log")
    if not log.is_file():
        raise SystemExit(
            f"missing run log {log} -- it is the only record of hot-swap "
            f"downtime; without it the online arm would be plotted uncharged")
    stamp = lambda l: dt.datetime.strptime(l[:19], "%Y-%m-%d %H:%M:%S")
    text = log.read_text(errors="replace").splitlines()

    per_trial = any(re.search(r"trial_\d+ round \d+: HOT-SWAP", l) for l in text)
    start = None
    pend: dict[str, dt.datetime] = {}
    downtime: dict[str, float] = {}
    out: dict[str, list] = {}
    for line in text:
        if "Started trial" in line and start is None:
            start = stamp(line)
            continue
        if start is None:
            continue
        if per_trial:
            m = re.search(r"trial_(\d+) round \d+: HOT-SWAP", line)
            if m:
                pend[m.group(1)] = stamp(line)
                continue
            m = re.search(r"trial_(\d+) round \d+: swap complete", line)
            key = m.group(1) if m else None
        else:
            if "HOT-SWAP into" in line:
                pend["*"] = stamp(line)
                continue
            key = "*" if "swap complete" in line else None
        if key is None or key not in pend:
            continue
        began = pend.pop(key)
        dur = (stamp(line) - began).total_seconds()
        acc = downtime.get(key, 0.0)
        wall = (began - start).total_seconds()
        out.setdefault(key, []).append((wall - acc, dur))
        downtime[key] = acc + dur

    total = sum(len(v) for v in out.values())
    if total == 0:
        raise SystemExit(
            f"{log} parsed to ZERO hot swaps. Refusing to plot: the online arm "
            f"would be drawn as if it never stopped. Check the log format "
            f"(expected 'HOT-SWAP into' or 'trial_NN round N: HOT-SWAP').")

    if not per_trial:
        return out["*"]
    if trial_id is None:
        # Legacy callers want one list; hand back the union so the charged-CPU
        # bookkeeping still composes, but per-trial callers pass trial_id.
        return sorted(w for v in out.values() for w in v)
    return out.get(f"{trial_id:02d}", [])


def swap_windows_by_trial(experiment_id: str) -> dict:
    """{trial_id: [(run_time, duration), ...]} -- empty dict for legacy logs."""
    log = Path(f".{experiment_id}.log")
    if not log.is_file():
        return {}
    text = log.read_text(errors="replace")
    if not re.search(r"trial_\d+ round \d+: HOT-SWAP", text):
        return {}
    ids = sorted({int(m) for m in re.findall(r"trial_(\d+) round \d+: HOT-SWAP", text)})
    return {i: swap_windows(experiment_id, i) for i in ids}


def to_wall(t, windows):
    """run_time -> wall-clock elapsed, adding the downtime accrued before t."""
    t = np.asarray(t, dtype=float)
    shift = np.zeros_like(t)
    for rt, dur in windows:
        shift += np.where(t >= rt, dur, 0.0)
    return t + shift


def with_gaps(xs, ys, windows, hold):
    """Insert the stopped intervals: value ``hold`` (0 for rate, flat for total)."""
    xs, ys = list(xs), list(ys)
    pts = sorted(zip(to_wall(xs, windows), ys))
    out_x, out_y = [], []
    walls = []
    acc = 0.0
    for rt, dur in windows:
        w = to_wall([rt], windows[:0])[0] + acc
        walls.append((w, w + dur)); acc += dur
    i = 0
    for x, y in pts:
        while i < len(walls) and walls[i][1] <= x:
            a, b = walls[i]
            last = out_y[-1] if out_y else y
            if hold == "zero":
                # Sample the stop DENSELY. Two endpoint zeros leave every bin in
                # the interior empty, and an empty bin is NaN -- a hole in the
                # aggregate line, not the zero the stop actually was. Spacing
                # must be below the bin width so no interior bin stays empty.
                step = min(GRID[1] - GRID[0], max(b - a, 1e-6)) / 2.0
                zs = list(np.arange(a, b, step)) + [b]
                out_x += zs
                out_y += [0.0] * len(zs)
            else:
                out_x += [a, b]
                out_y += [last, last]
            i += 1
        out_x.append(x); out_y.append(y)
    return np.array(out_x), np.array(out_y)


def band(series, gridded=False, hold_right=False):
    """Per-time-point mean across trials with a t-based 95% confidence interval.

    Trials are interpolated onto a common grid first; ``left/right=nan`` keeps a
    trial from contributing outside its own observed span, so the interval widens
    honestly where fewer trials are still reporting rather than extrapolating.

    ``hold_right`` carries each trial's LAST value forward to the end of the grid
    instead of going NaN. Required for the cumulative-coverage panel, where a
    series' last x is the last DISCOVERY, not the end of the trial: coverage is
    monotonic, so "found nothing after t" must plot as a flat line, not as a
    missing one. Without it a target that saturates early renders as almost
    nothing -- lcms stops discovering at t=0.015s and produced a coverage panel
    with 1 finite point out of 2881, an empty axis that reads as "no data" when
    the truth is "no NEW data". Never set it for a RATE panel, where the absence
    of samples is genuinely unknown rather than unchanged.
    """
    def _row(xs, ys):
        row = np.interp(GRID, xs, ys, left=np.nan,
                        right=(ys[-1] if hold_right and len(ys) else np.nan))
        return row

    m = (np.vstack(series) if gridded else
         np.vstack([_row(xs, ys) for xs, ys in series]))
    mean = np.nanmean(m, axis=0)
    n = np.sum(~np.isnan(m), axis=0)
    with np.errstate(invalid="ignore"):
        sd = np.nanstd(m, axis=0, ddof=1)
    half = np.zeros_like(mean); ok = n > 1
    half[ok] = sd[ok] / np.sqrt(n[ok]) * stats.t.ppf(0.975, n[ok] - 1)
    return mean, mean - half, mean + half, m.shape[0]


def bin_rate(xs, ys):
    """Mean rate within each grid interval, per trial.

    A RATE must be averaged over an interval, not sampled at a point: exec/s is
    logged every second and swings by an order of magnitude between adjacent
    samples, so interpolating at the grid spacing picks an arbitrary sample and
    produces noise that then appears to need smoothing. Rolling-smoothing that
    result is worse than useless here -- the window spans many grid points and
    blurs away the stopped intervals this figure exists to show. Binning gives
    the same legibility honestly: a bin lying inside a gap averages to zero.
    """
    idx = np.digitize(xs, GRID) - 1
    out = np.full(GRID.shape, np.nan)
    ok = (idx >= 0) & (idx < GRID.size)
    if not ok.any():
        return out
    sums = np.bincount(idx[ok], weights=np.asarray(ys)[ok], minlength=GRID.size)
    cnts = np.bincount(idx[ok], minlength=GRID.size)
    nz = cnts > 0
    out[nz] = sums[nz] / cnts[nz]
    return out


def gap_mask(walls):
    """True for grid bins lying inside a stopped/charged window."""
    m = np.zeros(GRID.shape, dtype=bool)
    for a, b in walls:
        m |= (GRID + (GRID[1] - GRID[0]) > a) & (GRID < b)
    return m


def smooth(y, mask, win):
    """Rolling mean applied SEGMENT-WISE, never across a stopped interval.

    Smoothing straight through a gap is what made the earlier figures wrong: the
    window spans the stop, drags neighbouring throughput into it, and the arm
    never appears to halt. Each run of fuzzing bins between two stops is instead
    smoothed on its own, and gap bins are pinned to exactly zero.
    """
    if win < 2:
        return y
    out = np.array(y, dtype=float)
    out[mask] = 0.0
    edges = np.flatnonzero(np.diff(np.r_[True, mask, True].astype(np.int8)))
    for lo, hi in zip(edges[::2], edges[1::2]):
        seg = out[lo:hi]
        good = ~np.isnan(seg)
        if good.sum() < 2:
            continue
        w = min(win, max(good.sum() // 2, 2))
        filled = np.where(good, seg, np.nanmean(seg[good]))
        pad = w // 2
        padded = np.r_[np.full(pad, filled[0]), filled, np.full(pad, filled[-1])]
        sm = np.convolve(padded, np.ones(w) / w, mode="same")[pad:pad + seg.size]
        sm[~good] = np.nan
        out[lo:hi] = sm
    return out


def _windows_for(windows, arm, trial_id):
    """Windows that apply to ONE trial's samples.

    The baseline arm never stops, so it always gets []. For the online arm,
    a dict means per-trial optimizers (look up this trial); a list is the
    legacy shared-binary case where one stop applied to every trial.
    """
    if arm != "optimized":
        return []
    if isinstance(windows, dict):
        return windows.get(trial_id, [])
    return windows


def _trial_id(path) -> int:
    m = re.search(r"trial_(\d+)", str(path))
    return int(m.group(1)) if m else -1


def load_coverage(d: Path, windows):
    out = {}
    for arm in ARMS:
        series = []
        for f in sorted(d.glob(f"{arm}_trial_*.csv")):
            xs, ys = [], []
            with open(f) as fh:
                for row in csv.DictReader(fh):
                    xs.append(float(row["time_s"])); ys.append(int(row["cumulative_edges"]))
            if xs:
                w = _windows_for(windows, arm, _trial_id(f))
                series.append(with_gaps(xs, ys, w, hold="flat"))
        if series:
            out[arm] = series
    return out


def load_execs(exp_dir: Path, windows):
    out = {}
    for arm in ARMS:
        series = []
        for pd in sorted(exp_dir.glob(f"{arm}/trial_*/afl_out/default/plot_data")):
            xs, ys = [], []
            for line in Path(pd).read_text(errors="replace").splitlines():
                if line.startswith("#"):
                    continue
                p = [c.strip() for c in line.split(",")]
                if len(p) < 11:
                    continue
                try:
                    xs.append(float(p[0])); ys.append(float(p[10]))
                except ValueError:
                    continue
            if xs:
                w = _windows_for(windows, arm, _trial_id(pd))
                series.append(with_gaps(xs, ys, w, hold="zero"))
        if series:
            out[arm] = series
    return out


def _charge_caption(exp_dir: Path) -> str:
    """How the plotted optimizer cost was converted to fuzzing time.

    per-replicate charges each trial the FULL optimizer cost (each online trial
    is a replicate of a campaign that would run its own optimizer); as-run
    divides by the arm, which is what this machine actually spent.
    """
    for f in [exp_dir / "optimized" / "online" / "cpu_cost.json"]:
        if not f.exists():
            continue
        try:
            d = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        model = d.get("charge_model")
        tc = d.get("trial_cores") or 9
        if model == "per-trial-optimizer":
            # Measured, not divided: this trial's own session wall time scaled
            # by the ledger's CPU/wall ratio. Saying "total / N" would describe
            # an average the windows do not use -- the trials differ by ~12%.
            return "as THIS trial's own optimizer CPU (measured), per-trial-optimizer"
        if model == "per-replicate":
            return "in full to every replicate (per-replicate)"
        if model == "as-run":
            return f"as core-seconds / {tc} trials (as-run)"
        return f"as core-seconds / {tc} trials (legacy file, model unrecorded)"
    return "(charge model unknown)"


def cpu_cost(exp_dir: Path):
    """Cumulative optimizer CPU, expressed as fuzzing-time equivalent."""
    f = exp_dir / "optimized" / "online" / "cpu_cost.json"
    try:
        d = json.loads(f.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    rounds = [r for r in d.get("rounds", []) if r.get("t_end")]
    if not rounds:
        return None
    t0 = min(r["t_start"] for r in rounds if r.get("t_start"))
    xs = [(r["t_end"] - t0) for r in rounds]
    ys = list(np.cumsum([r.get("fuzz_seconds_equivalent", 0.0) for r in rounds]))
    return np.array(xs), np.array(ys)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--covdir", default="coverage_growth")
    ap.add_argument("--outdir", default="plots")
    ap.add_argument("--no-charge-cpu", dest="charge_cpu", action="store_false",
                    help="show only the stopped-for-swap gaps, without charging "
                         "the optimizer's CPU as lost fuzzing time")
    ap.add_argument("--smooth", type=int, default=9,
                    help="throughput smoothing window in 30 s bins (default 9 = "
                         "4.5 min); applied within fuzzing segments only, never "
                         "across a stopped interval. 0 disables.")
    args = ap.parse_args()

    root = Path(config.RESULTS_DIR) / args.experiment_id
    project = args.experiment_id.rsplit("-", 1)[-1]
    outdir = Path(args.outdir); outdir.mkdir(parents=True, exist_ok=True)
    by_trial = swap_windows_by_trial(args.experiment_id)
    swaps = swap_windows(args.experiment_id)          # union, for CPU bookkeeping

    for exp_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        # Optimizer CPU, charged to the online arm. Unlike a swap stop this is
        # campaign-wide (the optimizer's core could have been fuzzing at that
        # instant for ANY trial), so it stays on one shared timeline.
        charge = (cpu_charge_windows(exp_dir, project, swaps)
                  if args.charge_cpu else [])

        # Per-trial design: each trial's own stops shift only its own samples.
        # The shared CPU charge is added to every online trial on top of that.
        if by_trial:
            # Each trial charged ITS OWN optimizer, not a share of the campaign.
            pt = per_trial_charge_windows(exp_dir, by_trial) if args.charge_cpu else {}
            if pt:
                windows = {t: sorted(w + pt.get(t, []))
                           for t, w in by_trial.items()}
                # Bands: the per-trial charges land at different instants, so
                # shade the MEDIAN trial's windows as the representative case
                # and say so in the caption. Shading all ten would overlap into
                # a solid block that implies every trial paid at every moment.
                med = sorted(pt, key=lambda t: sum(d for _, d in pt[t]))[len(pt)//2]
                charge = pt[med]
            else:
                windows = {t: sorted(w + charge) for t, w in by_trial.items()}
            # Bands: draw the CHARGE only. A per-trial stop is ~16s against a
            # 24h axis -- under half a pixel -- and ten trials stop at ten
            # different instants, so there is no common interval to shade. The
            # old single-timeline bands would have implied a synchronised stop
            # that never happened.
            band_windows = sorted(charge)
        else:
            windows = sorted(swaps + charge)
            band_windows = windows
        walls, acc = [], 0.0
        for rt, dur in band_windows:
            walls.append((rt + acc, rt + acc + dur)); acc += dur

        # Match coverage_growth.py's experiment-namespaced layout, falling back
        # to the flat CVE-only path so campaigns replayed before the rename
        # still plot.
        covdir = Path(args.covdir) / args.experiment_id / exp_dir.name
        if not covdir.is_dir():
            covdir = Path(args.covdir) / exp_dir.name
        cov = load_coverage(covdir, windows)
        exe = load_execs(exp_dir, windows)
        if not cov and not exe:
            continue

        gmask = gap_mask(walls)
        # Stacked, sharing the wall-clock axis: coverage and throughput are read
        # against the same instants (a swap gap, a round landing), and that
        # correspondence is what a side-by-side layout makes the reader do in
        # their head.
        fig, axes = plt.subplots(2, 1, figsize=(13, 9.2), sharex=True)
        for ax, data, ylab, title in (
            (axes[0], cov, "Cumulative edges (replayed on baseline binary)",
             "Coverage growth — common instrument\nmean ± 95% CI across trials"),
            (axes[1], exe, "Executions / second",
             "Throughput as actually run\nmean ± 95% CI across trials"),
        ):
            for a, b in walls:
                ax.axvspan(a / 3600, b / 3600, color="#999999", alpha=0.35, lw=0)
            for arm, (colour, label) in ARMS.items():
                if arm not in data:
                    continue
                if data is exe:
                    mean, lo, hi, n = band([bin_rate(xs, ys) for xs, ys in data[arm]],
                                           gridded=True)
                    # Mask per ARM. gmask marks the ONLINE arm's stopped/charged
                    # windows, and smooth() pins masked bins to exactly zero --
                    # so sharing one mask blanked the BASELINE's throughput for
                    # the duration of a cost it never paid (893 min of assimp's
                    # 1440, i.e. most of the run read as "baseline not fuzzing").
                    # load_execs already withholds the windows from the
                    # baseline's data; this withholds them from its rendering.
                    amask = (gmask if arm == "optimized"
                             else np.zeros_like(gmask, dtype=bool))
                    mean, lo, hi = (smooth(mean, amask, args.smooth),
                                    smooth(lo, amask, args.smooth),
                                    smooth(hi, amask, args.smooth))
                else:
                    # Cumulative coverage: hold the last value to the grid end.
                    mean, lo, hi, n = band(data[arm], hold_right=True)
                ax.plot(GRID / 3600, mean, color=colour, label=f"{label} (n={n})")
                ax.fill_between(GRID / 3600, lo, hi, color=colour, alpha=0.25)
            # Only the lower panel is labelled: the axis is shared, so repeating
            # it above just crowds the gap between the two plots.
            if ax is axes[-1]:
                ax.set_xlabel("Wall-clock time (hours)")
            ax.set_ylabel(ylab)
            ax.set_title(title, fontsize=10); ax.grid(alpha=0.3); ax.set_xlim(0, HOURS)
            # exec/s cannot be negative; the CI's normal approximation can dip
            # below zero at high variance, so crop the view rather than the data.
            if data is exe:
                ax.set_ylim(bottom=0)
        axes[0].legend(loc="lower right"); axes[1].legend(loc="upper right")

        cc = cpu_cost(exp_dir)
        if cc is not None:
            ax2 = axes[1].twinx()
            ax2.step(cc[0] / 3600, cc[1] / 60, where="post", color="#55A868",
                     linestyle="--", linewidth=1.6,
                     label="optimizer CPU (fuzzing-time equivalent)")
            ax2.set_ylabel("Cumulative optimizer cost (minutes of fuzzing)", color="#55A868")
            ax2.tick_params(axis="y", labelcolor="#55A868")
            ax2.legend(loc="lower right", fontsize=8)

        # Per-trial mode: report the MEDIAN trial, because there is no single
        # campaign-wide figure any more -- each trial stopped on its own
        # schedule and paid its own optimizer. A total would describe a run
        # nobody performed.
        if isinstance(windows, dict):
            per_swap = {t: sum(d for _, d in by_trial.get(t, [])) for t in windows}
            per_all = {t: sum(d for _, d in w) for t, w in windows.items()}
            mt = sorted(per_all, key=lambda t: per_all[t])[len(per_all)//2]
            swap_s, cpu_s = per_swap[mt], per_all[mt] - per_swap[mt]
            n_swaps = len(by_trial.get(mt, []))
            who = f" (median trial_{mt:02d} of {len(windows)})"
        else:
            swap_s = sum(d for _, d in swaps)
            cpu_s = sum(d for _, d in windows) - swap_s
            n_swaps = len(swaps)
            who = ""
        fig.suptitle(
            f"{exp_dir.name}{who} — online arm charged for its own cost: "
            f"{swap_s/60:.1f} min stopped for {n_swaps} hot swaps"
            # Read the charge model from the ledger rather than hardcoding a
            # divisor: cpu_cost.json records which model produced
            # fuzz_seconds_equivalent, and a stale "÷ 9 trials" caption on a
            # per-replicate number is a lie about the very quantity plotted.
            + (f" + {cpu_s/60:.1f} min optimizer CPU (profile / rebuild / replay), "
               f"charged {_charge_caption(exp_dir)}" if args.charge_cpu else "")
            + ".  Grey bands = online arm not fuzzing.", fontsize=9)
        fig.tight_layout()
        # Same reason as the CSV path: name by experiment so a second campaign
        # on one target cannot overwrite the first's figure.
        path = outdir / f"{args.experiment_id}_{exp_dir.name}_coverage_execs.png"
        fig.savefig(path, dpi=150, bbox_inches="tight"); plt.close(fig)
        print(f"  wrote {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
