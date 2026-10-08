#!/usr/bin/env python3
"""Per-source-file coverage heatmap, baseline arm vs optimized arm.

WHY THIS IS MEASURED ON ONE BINARY. The two arms run different programs: the
optimizer inserts, deletes and moves lines, and with per-trial optimizers it
does so differently in each of the ten optimized trials. So `vm.c:812` is a
different line in all eleven trees, and the campaign's own edge counts
(`coverage_growth.py`) are NOT comparable across arms -- they count edges of
different programs. What IS comparable is what each arm's accumulated AFL queue
executes when replayed through ONE coverage build of the pristine baseline
source, which is what `line_exec_counts.py` produces into .linecov/<target>/
and what this reads. The question answered is therefore

    "which parts of the ORIGINAL program did each arm's corpus reach?"

and a cell may be compared with any other cell in the figure.

THE DENOMINATOR IS THE UNION, NOT THE PER-TRIAL REPORT. All twenty replays run
the same binary, so the instrumented line set is physically identical; but
llvm-cov's export omits some zero-coverage regions, and the per-trial reports
here disagree by up to 0.9% (26,637 vs 26,885 lines on mruby). Taking each
trial's own line count as its denominator would make a trial look better purely
for having a smaller report. So every file's denominator is the union of that
file's lines across all twenty trials, and a line missing from a trial's report
counts as not covered -- which is what its absence means.

Two panels, each with ONE scale:
  left   coverage % per (file, trial), sequential -- the reading surface
  right  median(optimized) - median(baseline) in percentage points, diverging
         -- where the arms actually diverge, which is invisible at left when
         both arms sit at 90%+

Usage:
  python3 analysis/coverage_heatmap.py --experiment online-24h-bug-mruby
  python3 analysis/coverage_heatmap.py --experiment online-24h-bug-mruby --sort delta
  python3 analysis/coverage_heatmap.py --experiment online-24h-bug-mruby --top 50
"""
from __future__ import annotations

import argparse
import json
import os
import statistics as st
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LinearSegmentedColormap, TwoSlopeNorm

# The pipeline modules (config, phase*, lib/, sandbox/) live at the repo root,
# one level up; Python only puts THIS script's directory on sys.path.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import config

CACHE = Path(os.environ.get("LINE_COV_CACHE", "/home/sefcom/fuzz-opt/.linecov"))

# Sequential ramp: ONE hue, light -> dark, so magnitude reads as depth of ink
# rather than as a change of category. A rainbow would imply the 40%-60% step
# and the 80%-100% step mean different kinds of thing; they do not.
SEQ = LinearSegmentedColormap.from_list(
    "cov", ["#F7FAFC", "#D6E4F0", "#A8C6E3", "#6E9DCB", "#3F74AB", "#1F4B82", "#122E52"])
# Diverging ramp for the delta panel: two hues with a NEUTRAL GRAY midpoint, so
# "no difference" reads as absence of colour and cannot be confused with a pole.
DIV = LinearSegmentedColormap.from_list(
    "delta", ["#8C3B2E", "#C08476", "#E8E6E3", "#7FA8C9", "#1F4B82"])

INK, MUTED, FAINT = "#1A1D21", "#5B6470", "#C8CDD4"


def target_dir(experiment: str) -> str:
    """The campaign's project directory, which keys the .linecov cache."""
    base = Path(config.RESULTS_DIR) / experiment
    if not base.is_dir():
        raise SystemExit(f"no such experiment: {base}")
    skip = {"state.json", "trial_results.json", "introspector", "report",
            "line_counts", "campaign_provenance.json"}
    cands = [p.name for p in base.iterdir() if p.name not in skip and p.is_dir()]
    if not cands:
        raise SystemExit(f"no project dir under {base}")
    return sorted(cands)[0]


def load(experiment: str) -> tuple[list[str], dict[str, dict[str, dict[str, int]]]]:
    """-> (trial names in arm order, {trial: {file: {line: count}}})."""
    tgt = target_dir(experiment)
    counts = CACHE / tgt / "counts"
    if not counts.is_dir():
        raise SystemExit(
            f"no line-coverage cache for {experiment} (looked in {counts}).\n"
            f"Generate it first:  python3 analysis/line_exec_counts.py "
            f"--experiment {experiment}\n"
            f"That needs a SANITIZER=coverage build plus a replay of all 20 "
            f"queues, so do not run it while a campaign is fuzzing.")
    data, names = {}, []
    for arm in ("baseline", "optimized"):
        for p in sorted(counts.glob(f"{arm}_trial_*.json")):
            names.append(p.stem)
            data[p.stem] = json.load(open(p))
    if not names:
        raise SystemExit(f"{counts} holds no *_trial_*.json")
    return names, data


def build_matrix(names, data, top, sort):
    """Coverage fraction per (file, trial) against a union denominator."""
    # Union of every file's lines across all trials -- the real instrumented
    # surface of the one shared binary. See the module docstring.
    denom: dict[str, set] = {}
    for d in data.values():
        for f, lines in d.items():
            denom.setdefault(f, set()).update(lines)

    files = sorted(denom, key=lambda f: -len(denom[f]))
    shown, rest = files[:top], files[top:]

    # Basenames are NOT unique: mruby ships src/string.c and
    # mrbgems/mruby-string-ext/src/string.c, and they came out -1.0pp and
    # -17.8pp, so labelling both "string.c" puts two unrelated findings under
    # one name. Use the shortest trailing path that is unique among the rows.
    def label_for(path: str) -> str:
        parts = Path(path).parts
        for k in range(1, len(parts) + 1):
            cand = "/".join(parts[-k:])
            if sum(1 for o in shown
                   if "/".join(Path(o).parts[-k:]) == cand) == 1:
                return cand
        return path

    def frac(d, f):
        tot = len(denom[f])
        hit = sum(1 for ln, n in d.get(f, {}).items() if n > 0)
        return 100.0 * hit / tot if tot else float("nan")

    rows = [[frac(data[t], f) for t in names] for f in shown]
    labels = [label_for(f) for f in shown]
    if rest:
        # Fold the tail into one row rather than dropping it, so the figure
        # still accounts for the whole program.
        tot = sum(len(denom[f]) for f in rest)
        agg = []
        for t in names:
            hit = sum(1 for f in rest for ln, n in data[t].get(f, {}).items() if n > 0)
            agg.append(100.0 * hit / tot if tot else float("nan"))
        rows.append(agg)
        labels.append(f"+{len(rest)} smaller files")
        shown = shown + ["__rest__"]

    M = np.array(rows, dtype=float)
    nb = sum(1 for t in names if t.startswith("baseline"))
    delta = np.array([np.median(r[nb:]) - np.median(r[:nb]) for r in M])

    if sort == "delta":
        order = np.argsort(-np.abs(delta))
        M, delta = M[order], delta[order]
        labels = [labels[i] for i in order]
        denom_n = [len(denom[shown[i]]) if shown[i] != "__rest__"
                   else sum(len(denom[f]) for f in rest) for i in order]
    else:
        denom_n = [len(denom[f]) if f != "__rest__"
                   else sum(len(denom[g]) for g in rest) for f in shown]
    return M, delta, labels, denom_n, nb


def plot(experiment, M, delta, labels, denom_n, names, nb, out):
    nrow, ncol = M.shape
    fig = plt.figure(figsize=(max(11.0, 0.46 * ncol + 7.2), max(5.0, 0.248 * nrow + 2.5)))
    gs = fig.add_gridspec(1, 2, width_ratios=[ncol, 3.1], wspace=0.035)
    ax, axd = fig.add_subplot(gs[0]), fig.add_subplot(gs[1])

    im = ax.imshow(M, aspect="auto", cmap=SEQ, vmin=0, vmax=100,
                   interpolation="nearest")
    ax.set_yticks(range(nrow))
    ax.set_yticklabels([f"{l}  ({n:,})" for l, n in zip(labels, denom_n)],
                       fontsize=7.4, color=INK)
    ax.set_xticks(range(ncol))
    ax.set_xticklabels([t.split("_")[-1] for t in names], fontsize=7.2, color=MUTED)
    # The arm boundary is the one structural fact in the x axis, so it gets a
    # real line; the per-cell grid does not, because it carries no information.
    ax.axvline(nb - 0.5, color="#FFFFFF", lw=2.4)
    ax.axvline(nb - 0.5, color=INK, lw=0.9)
    for x, lab in ((nb / 2 - 0.5, f"baseline  (n={nb})"),
                   (nb + (ncol - nb) / 2 - 0.5, f"optimized  (n={ncol - nb})")):
        ax.text(x, -1.15, lab, ha="center", va="bottom", fontsize=9.2, color=INK)
    ax.set_xlabel("trial", fontsize=8.6, color=MUTED, labelpad=5)
    for s in ax.spines.values():
        s.set_color(FAINT)
    ax.tick_params(length=0)

    dn = TwoSlopeNorm(vmin=min(-0.01, float(np.nanmin(delta))), vcenter=0.0,
                      vmax=max(0.01, float(np.nanmax(delta))))
    axd.imshow(delta.reshape(-1, 1), aspect="auto", cmap=DIV, norm=dn,
               interpolation="nearest")
    axd.set_xticks([]); axd.set_yticks([])
    # Direct labels: the delta strip is 1 column wide, so every value fits and
    # none of it has to be read off a colour.
    for i, v in enumerate(delta):
        axd.text(0, i, f"{v:+.1f}", ha="center", va="center", fontsize=6.9,
                 color="#FFFFFF" if abs(v) > 0.62 * max(abs(dn.vmin), abs(dn.vmax))
                 else INK)
    axd.set_xlabel("Δ median\n(pp, opt−base)", fontsize=8.0, color=MUTED, labelpad=5)
    for s in axd.spines.values():
        s.set_color(FAINT)

    cb = fig.colorbar(im, ax=[ax, axd], location="bottom", fraction=0.031,
                      pad=0.10 if nrow > 20 else 0.16, aspect=48)
    cb.set_label("lines executed at least once, % of that file's instrumented lines",
                 fontsize=8.4, color=MUTED)
    cb.ax.tick_params(labelsize=7.6, color=FAINT, labelcolor=MUTED)
    cb.outline.set_color(FAINT)

    med_b = np.median(M[:, :nb]); med_o = np.median(M[:, nb:])
    fig.suptitle(
        f"{experiment} — source-line coverage of the ORIGINAL program, by arm\n"
        f"both arms' AFL queues replayed through one coverage build of the "
        f"pristine baseline; median cell {med_b:.1f}% → {med_o:.1f}%",
        fontsize=10.4, color=INK, y=0.995)
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--experiment", required=True)
    ap.add_argument("--top", type=int, default=34,
                    help="source files to show individually; the rest fold into "
                         "one row so the figure still covers the whole program")
    ap.add_argument("--sort", choices=("size", "delta"), default="size",
                    help="size: biggest files first, stable across experiments. "
                         "delta: largest arm difference first.")
    ap.add_argument("--outdir", default="plots")
    args = ap.parse_args()

    names, data = load(args.experiment)
    M, delta, labels, denom_n, nb = build_matrix(names, data, args.top, args.sort)

    out = Path(args.outdir) / f"{args.experiment}_coverage_heatmap.png"
    out.parent.mkdir(parents=True, exist_ok=True)
    plot(args.experiment, M, delta, labels, denom_n, names, nb, out)

    # Table view: identity must never be colour-alone, and these numbers are
    # what any follow-up statistic should be computed from.
    csv = Path(args.outdir) / f"{args.experiment}_coverage_heatmap.csv"
    with open(csv, "w") as f:
        f.write("source_file,instrumented_lines," + ",".join(names)
                + ",median_baseline,median_optimized,delta_pp\n")
        for lab, n, row, d in zip(labels, denom_n, M, delta):
            f.write(f'"{lab}",{n},' + ",".join(f"{v:.3f}" for v in row)
                    + f",{np.median(row[:nb]):.3f},{np.median(row[nb:]):.3f},{d:+.3f}\n")

    print(f"wrote {out}")
    print(f"wrote {csv}")
    print(f"  {M.shape[0]} rows x {M.shape[1]} trials "
          f"({nb} baseline / {M.shape[1] - nb} optimized)")
    print(f"  median cell: baseline {np.median(M[:, :nb]):.2f}%  "
          f"optimized {np.median(M[:, nb:]):.2f}%")
    big = sorted(zip(labels, delta), key=lambda kv: -abs(kv[1]))[:5]
    print("  largest arm deltas (pp): "
          + ", ".join(f"{l} {d:+.1f}" for l, d in big))
    return 0


if __name__ == "__main__":
    sys.exit(main())
