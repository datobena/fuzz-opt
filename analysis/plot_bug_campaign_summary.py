#!/usr/bin/env python3
"""Six-panel summary + statistics of one FuzzBench bug campaign (per-trial optimizers).

    python3 analysis/plot_bug_campaign_summary.py --experiment-id online-24h-r2-bloaty

Inputs (run these first):
  - AFL per-trial plot_data / fuzzer_stats        -> executions over time, AFL edges
  - coverage_growth/<exp>/<target>/*.csv          -> analysis/coverage_growth.py
                                                     (both arms replayed on the BASELINE binary)
  - results/<exp>/dedup_crashes.json              -> analysis/dedup_crashes.py --json-out
  - cpu ledger                                    -> analysis/cpu_cost_report.py
  - optimized/online/trials/*/iter_*/round_provenance.json

Writes plots/<exp>_summary.png and results/<exp>/summary_stats.json.

Cost-adjusted throughput = raw exec ratio x T / (T + optimizer core-hours per trial):
the optimizer's CPU, spent on one more fuzzing core, would have bought that much
more baseline fuzzing.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from scipy.stats import mannwhitneyu  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
BASE_C, OPT_C = "#3b76c0", "#d1603d"
ARMS = ("baseline", "optimized")


def a12(x, y) -> float:
    """Vargha-Delaney A12: P(X > Y) + 0.5 P(X = Y)."""
    gt = sum((a > b) + 0.5 * (a == b) for a in x for b in y)
    return gt / (len(x) * len(y))


# Every A12 this script reports means the same thing, on every metric.
A12_CONVENTION = ("P(random optimized trial is better than random baseline trial) "
                  "+ 0.5 P(tie); > 0.5 = optimized better. Better = more for execs "
                  "and edges, smaller (found earlier) for target_ttb.")


def mwu(x, y, lower_is_better: bool = False) -> dict:
    """Two-sided Mann-Whitney U p of optimized x vs baseline y, and A12 per A12_CONVENTION.

    A12 is P(x > y) for bigger-is-better metrics and P(x < y) when lower_is_better
    (time to bug), so > 0.5 always favours the optimized arm.
    """
    if len(x) < 2 or len(y) < 2 or len(set(x) | set(y)) < 2:
        return {"p": None, "a12": None}
    return {"p": float(mannwhitneyu(x, y, alternative="two-sided").pvalue),
            "a12": round(a12(y, x) if lower_is_better else a12(x, y), 3)}


def stats_file(path: Path) -> dict:
    out = {}
    for line in path.read_text().splitlines():
        k, sep, v = line.partition(":")
        if sep:
            out[k.strip()] = v.strip()
    return out


def exec_series(trial: Path, grid: np.ndarray) -> np.ndarray | None:
    t, e = [], []
    for line in (trial / "afl_out" / "default" / "plot_data").read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        f = [x.strip() for x in line.split(",")]
        t.append(float(f[0]))
        e.append(float(f[11]))
    if len(t) < 2:
        return None
    # A resume restarts from the last stats write, so a few samples step back.
    return np.interp(grid, t, np.maximum.accumulate(e), left=0)


def cov_series(csv: Path, grid: np.ndarray) -> tuple[np.ndarray, int]:
    t, g = [], []
    for line in csv.read_text().splitlines()[1:]:
        a, _, c = line.split(",")
        t.append(float(a))
        g.append(int(c))
    return np.interp(grid, t, g, left=g[0]), g[-1]


def rounds(tdir: Path) -> list[dict]:
    out = []
    for prov in sorted(tdir.glob("optimized/online/trials/trial_*/iter_*/round_provenance.json")):
        d = json.loads(prov.read_text())
        out.append({"trial": prov.parent.parent.name, "iter": d.get("iter"),
                    "outcome": d.get("outcome"), "speedup": d.get("speedup")})
    return out


def optimizer_core_s(exp_id: str) -> float:
    r = subprocess.run([sys.executable, str(REPO / "analysis" / "cpu_cost_report.py"),
                        "--experiment-id", exp_id, "--json"],
                       capture_output=True, text=True, cwd=REPO)
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return float("nan")
    rows = data.values() if isinstance(data, dict) else data
    for row in rows:
        if isinstance(row, dict):
            for k in ("total_core_s", "total_core_seconds", "core_s"):
                if k in row:
                    return float(row[k])
    return float("nan")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--hours", type=float, default=24.0)
    ap.add_argument("--outdir", default="plots")
    ap.add_argument("--target-bug", nargs="+", metavar="SUBSTR",
                    help="treat every dedup signature containing one of these strings as "
                         "ONE target bug (a trial finds it at its first hit of any form), "
                         "e.g. php's zend_ast.c:697 null access and its zend_compile.c:9852 "
                         "assert; default: the signature found by the most trials")
    a = ap.parse_args()

    exp = REPO / "results" / a.experiment_id
    tdir = next(p for p in exp.iterdir() if p.is_dir())
    grid = np.linspace(0, a.hours * 3600, 600)
    gh = grid / 3600

    execs, final_execs, afl_edges, cov, cov_final = {}, {}, {}, {}, {}
    for arm in ARMS:
        trials = sorted((tdir / arm).glob("trial_*"))
        series = [exec_series(t, grid) for t in trials]
        execs[arm] = np.array([s for s in series if s is not None])
        fs = [stats_file(t / "afl_out" / "default" / "fuzzer_stats") for t in trials]
        final_execs[arm] = [float(s["execs_done"]) for s in fs]
        afl_edges[arm] = [int(s["edges_found"]) for s in fs]
        csvs = sorted((REPO / "coverage_growth" / a.experiment_id / tdir.name)
                      .glob(f"{arm}_trial_*.csv"))
        pairs = [cov_series(c, grid) for c in csvs]
        cov[arm] = np.array([p[0] for p in pairs])
        cov_final[arm] = [p[1] for p in pairs]

    dedup = json.loads((exp / "dedup_crashes.json").read_text())[tdir.name]
    n = {arm: dedup[arm].get("n_trials", len(final_execs[arm])) for arm in ARMS}
    bugs = {}
    for arm in ARMS:
        for b in dedup[arm]["bugs"]:
            bugs.setdefault(b["signature"], {})[arm] = {
                k: v / 3600 for k, v in b["per_trial_first_s"].items()}
    # The target bug: the one found by the most trials overall.
    target = max(bugs, key=lambda s: sum(len(bugs[s].get(arm, {})) for arm in ARMS))
    if a.target_bug:
        forms = [sig for sig in bugs if any(x in sig for x in a.target_bug)]
        if not forms:
            raise SystemExit(f"--target-bug {a.target_bug}: no dedup signature matches "
                             "(asserts are only in dedup_crashes.json with --count-asserts)")
        target = " | ".join(forms)
        merged = {arm: {} for arm in ARMS}
        for sig in forms:
            for arm, per in bugs[sig].items():
                for t, h in per.items():
                    merged[arm][t] = min(h, merged[arm].get(t, h))
        bugs[target] = merged

    core_s = optimizer_core_s(a.experiment_id)
    per_trial_h = core_s / 3600 / n["optimized"]
    raw = float(np.median(final_execs["optimized"]) / np.median(final_execs["baseline"]))
    cost_adj = raw * a.hours / (a.hours + per_trial_h)
    rr = rounds(tdir)
    kept = [r for r in rr if r["outcome"] == "kept"]

    ttb = {arm: sorted(bugs[target].get(arm, {}).values()) for arm in ARMS}
    stats = {
        "experiment": a.experiment_id, "target": tdir.name, "trials": n,
        "a12_convention": A12_CONVENTION,
        "execs_median": {arm: float(np.median(final_execs[arm])) for arm in ARMS},
        "execs": mwu(final_execs["optimized"], final_execs["baseline"]),
        "raw_exec_ratio": round(raw, 3),
        "optimizer_core_h_total": round(core_s / 3600, 1),
        "optimizer_core_h_per_trial": round(per_trial_h, 2),
        "cost_adjusted": round(cost_adj, 3),
        "afl_edges_median": {arm: float(np.median(afl_edges[arm])) for arm in ARMS},
        "afl_edges": mwu(afl_edges["optimized"], afl_edges["baseline"]),
        "common_edges_median": {arm: float(np.median(cov_final[arm])) for arm in ARMS},
        "common_edges": mwu(cov_final["optimized"], cov_final["baseline"]),
        "common_edges_per_trial": cov_final,
        "afl_edges_per_trial": afl_edges,
        "execs_per_trial": final_execs,
        "target_bug": target,
        "target_ttb_h": ttb,
        "target_ttb_median_h": {arm: (float(np.median(ttb[arm])) if ttb[arm] else None)
                                for arm in ARMS},
        "target_ttb": mwu(ttb["optimized"], ttb["baseline"], lower_is_better=True),
        "bugs": {s: {arm: {"trials": len(v.get(arm, {})),
                           "first_h": (round(min(v[arm].values()), 2) if v.get(arm) else None)}
                     for arm in ARMS} for s, v in bugs.items()},
        "non_reproducing": {arm: dedup[arm]["non_reproducing"] for arm in ARMS},
        "rounds_attempted": len(rr), "rounds_kept": len(kept),
        "rounds_by_outcome": {o: sum(r["outcome"] == o for r in rr)
                              for o in sorted({str(r["outcome"]) for r in rr})},
        "kept_speedup_median": (float(np.median([r["speedup"] for r in kept]))
                                if kept else None),
    }
    (exp / "summary_stats.json").write_text(json.dumps(stats, indent=2) + "\n")

    fig, ax = plt.subplots(2, 3, figsize=(19, 10))
    fig.suptitle(f"{tdir.name} — {a.experiment_id}: {n['baseline']}+{n['optimized']} trials, "
                 f"{a.hours:g} h, per-trial optimizers", fontsize=13, fontweight="bold")

    def band(axis, arrs, scale=1.0):
        for arm, c in zip(ARMS, (BASE_C, OPT_C)):
            arr = arrs[arm] / scale
            axis.plot(gh, np.median(arr, 0), color=c, lw=2, label=f"{arm} (median)")
            axis.fill_between(gh, np.percentile(arr, 25, 0), np.percentile(arr, 75, 0),
                              color=c, alpha=0.2)
        axis.set_xlim(0, a.hours)
        axis.grid(alpha=0.3)
        axis.legend(loc="lower right")

    p = ax[0][0]
    band(p, execs, 1e6)
    p.set(title=f"Cumulative executions — raw {raw:.2f}x "
                f"(p={stats['execs']['p']:.3f}, A12={stats['execs']['a12']})",
          xlabel="campaign time (h)", ylabel="executions (millions), median + IQR")

    p = ax[0][1]
    band(p, cov)
    ce = stats["common_edges_median"]
    p.set(title=f"Coverage on the baseline binary — {ce['optimized']:.0f} vs {ce['baseline']:.0f} "
                f"(p={stats['common_edges']['p']:.3f}, A12={stats['common_edges']['a12']})",
          xlabel="campaign time (h)", ylabel="edges (both arms replayed on baseline)")
    lo = min(np.percentile(cov[arm], 25, 0)[len(gh) // 10] for arm in ARMS)
    p.set_ylim(bottom=lo)

    p = ax[0][2]
    for arm, c in zip(ARMS, (BASE_C, OPT_C)):
        ts = ttb[arm]
        xs = [0] + ts + [a.hours]
        ys = [0] + [(i + 1) / n[arm] for i in range(len(ts))] + [len(ts) / n[arm]]
        p.step(xs, ys, where="post", color=c, lw=2,
               label=f"{arm}: {len(ts)}/{n[arm]}, median "
                     f"{stats['target_ttb_median_h'][arm] or float('nan'):.2f} h")
    p.set(title=f"Time to target bug (p={stats['target_ttb']['p']:.2f}, "
                f"A12={stats['target_ttb']['a12']}; >0.5 = optimized earlier)",
          xlabel="campaign time (h)", ylabel="fraction of trials that found it",
          xlim=(0, a.hours), ylim=(0, 1.05))
    first_swap = None
    tl = glob.glob(str(tdir / "optimized/online/trials/trial_*/swap_timeline.json"))
    if tl:
        rows = json.loads(Path(tl[0]).read_text())
        starts = [json.loads((t / "metadata.json").read_text())["start_time"]
                  for t in sorted((tdir / "optimized").glob("trial_*"))]
        if rows and starts:
            first_swap = (min(r["ts"] for r in rows) - min(starts)) / 3600
            p.axvline(first_swap, color="gray", ls="--", lw=1)
            p.text(first_swap, 0.03, " first optimized\n binary swapped in", fontsize=8,
                   color="gray")
    p.text(0.98, 0.5, target.split(":", 1)[-1][-48:], transform=p.transAxes, ha="right",
           fontsize=8, color="dimgray")
    p.legend(loc="lower right")
    p.grid(alpha=0.3)

    p = ax[1][0]
    for i, (arm, c) in enumerate(zip(ARMS, (BASE_C, OPT_C))):
        for j, (vals, lab) in enumerate(((final_execs[arm], "execs"),)):
            ys = np.array(vals) / 1e6
            x = i + (np.random.default_rng(i).random(len(ys)) - 0.5) * 0.2
            p.scatter(x, ys, color=c, edgecolor="k", lw=0.4, s=50, zorder=3)
            p.hlines(np.median(ys), i - 0.25, i + 0.25, color=c, lw=3)
    p.set(title="Final executions per trial", xticks=[0, 1], ylabel="executions (millions)")
    p.set_xticklabels(ARMS)
    p.grid(alpha=0.3, axis="y")

    p = ax[1][1]
    for i, (arm, c) in enumerate(zip(ARMS, (BASE_C, OPT_C))):
        for k, (vals, mk) in enumerate(((cov_final[arm], "o"), (afl_edges[arm], "^"))):
            x = i + (k - 0.5) * 0.35 + (np.random.default_rng(10 * i + k).random(len(vals))
                                       - 0.5) * 0.12
            p.scatter(x, vals, color=c, marker=mk, edgecolor="k", lw=0.4, s=45, zorder=3,
                      label=("baseline-binary replay" if k == 0 else "AFL's own edges_found")
                      if i == 0 else None)
    p.set(title="Final edges per trial", xticks=[0, 1], ylabel="edges")
    p.set_xticklabels(ARMS)
    p.legend(loc="lower center", fontsize=8)
    p.grid(alpha=0.3, axis="y")

    p = ax[1][2]
    vals = (raw, cost_adj)
    bars = p.bar(["raw\n(median execs)", f"cost-adjusted\n(+{per_trial_h:.1f} core-h/trial)"],
                 vals, color=[OPT_C, "#9e9e9e"], edgecolor="k")
    p.axhline(1.0, ls="--", color="k", lw=1)
    for r, v in zip(bars, vals):
        p.text(r.get_x() + r.get_width() / 2, v + 0.04, f"{v:.2f}x", ha="center",
               fontweight="bold", bbox=dict(fc="white", ec="none", pad=1))
    p.set(title=f"Throughput vs baseline — {len(kept)}/{len(rr)} rounds kept, median gate "
                f"{stats['kept_speedup_median'] or float('nan'):.3f}x",
          ylabel="x baseline", ylim=(0, max(vals) * 1.25))
    p.grid(alpha=0.3, axis="y")

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    os.makedirs(a.outdir, exist_ok=True)
    out = Path(a.outdir) / f"{a.experiment_id}_summary.png"
    plt.savefig(out, dpi=120)
    print("wrote", out, "and", exp / "summary_stats.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
