#!/usr/bin/env python3
"""Coverage-increase-over-time for the CPU-pinned local run, using ctime.

Each file libFuzzer keeps in the corpus is an input it retained because it added
new coverage/features, so cumulative corpus size over time is a direct
coverage-increase curve. Timestamps come from each file's ctime (== mtime here,
since libFuzzer writes units once), relative to the trial's earliest file.
Aggregated as mean across trials per variant; a crashed trial holds its final
count flat afterwards. One plot per target (baseline vs aggr8h vs mut8h).
"""
import glob, json, os, statistics
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = "local_pinned"
TARGETS = ["selinux", "libavc"]
VARIANTS = ["baseline", "aggr8h", "mut8h"]
COLORS = {"baseline": "#1f77b4", "aggr8h": "#d62728", "mut8h": "#2ca02c"}
DUR = 28800
STEP = 300                                   # 5-min grid
GRID = list(range(0, DUR + STEP, STEP))


def trial_curve(corpus_dir):
    """Return sorted list of file ctimes relative to the earliest file (t0)."""
    fs = [f for f in glob.glob(corpus_dir + "/*") if os.path.isfile(f)]
    if not fs:
        return None
    cts = sorted(os.stat(f).st_ctime for f in fs)
    t0 = cts[0]
    return [c - t0 for c in cts]


def cumulative_on_grid(rel_ctimes):
    """Cumulative unit count at each grid time (step function)."""
    out, i, n = [], 0, len(rel_ctimes)
    for t in GRID:
        while i < n and rel_ctimes[i] <= t:
            i += 1
        out.append(i)
    return out


def main():
    results = json.load(open(f"{ROOT}/results.json"))
    done = {(r["target"], r["variant"], r["trial"]) for r in results}

    for target in TARGETS:
        plt.figure(figsize=(9, 5.5))
        summary = []
        for v in VARIANTS:
            curves = []
            for tr in range(10):
                if (target, v, tr) not in done:
                    continue
                rel = trial_curve(f"{ROOT}/{target}/{v}/trial_{tr:02d}/corpus")
                if rel:
                    curves.append(cumulative_on_grid(rel))
            if not curves:
                continue
            mean = [statistics.mean(c[i] for c in curves) for i in range(len(GRID))]
            lo = [min(c[i] for c in curves) for i in range(len(GRID))]
            hi = [max(c[i] for c in curves) for i in range(len(GRID))]
            xs = [t / 3600 for t in GRID]
            plt.plot(xs, mean, color=COLORS[v], label=f"{v} (n={len(curves)}, final≈{mean[-1]:.0f})")
            plt.fill_between(xs, lo, hi, color=COLORS[v], alpha=0.12)
            summary.append((v, len(curves), mean[-1]))
        plt.xlabel("time since trial start (h, from corpus ctime)")
        plt.ylabel("cumulative corpus units (new-coverage inputs)")
        plt.title(f"{target}: coverage increase over time (CPU-pinned local run)\n"
                  f"mean across trials; band = min–max")
        plt.legend(); plt.grid(alpha=0.3); plt.tight_layout()
        out = f"{ROOT}/covtime_{target}.png"
        plt.savefig(out, dpi=110); plt.close()
        print(f"wrote {out}  " + " | ".join(f"{v}:{n}tr final~{f:.0f}" for v, n, f in summary))


if __name__ == "__main__":
    main()
