#!/usr/bin/env python3
"""Four-panel summary of the online-24h-bug-libxml2 campaign.

Sources (all authoritative, no coverage-build replay needed):
  - AFL per-trial plot_data  -> cumulative execs & edges over time (spans full 24h)
  - crash_times.json         -> restart-safe, campaign-relative time-to-first-crash
"""
import glob, json, statistics
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

B = "results/online-24h-bug-libxml2/libxml2-fuzzbench-900025"
GRID = np.linspace(0, 24*3600, 400)
BASE_C, OPT_C = "#3b76c0", "#d1603d"

def series(arm, exec_col=11, edge_col=12):
    """interp total_execs and edges_found onto GRID for each trial."""
    execs, edges = [], []
    for pd in sorted(glob.glob(f"{B}/{arm}/trial_*/afl_out/default/plot_data")):
        t, e, g = [], [], []
        for ln in open(pd):
            if ln.startswith("#") or not ln.strip():
                continue
            f = ln.split(",")
            try:
                t.append(float(f[0])); e.append(float(f[exec_col])); g.append(float(f[edge_col]))
            except (ValueError, IndexError):
                continue
        if len(t) < 2:
            continue
        execs.append(np.interp(GRID, t, e, left=0))
        edges.append(np.interp(GRID, t, g, left=g[0]))
    return np.array(execs), np.array(edges)

def ttb(arm):
    out = []
    for ct in sorted(glob.glob(f"{B}/{arm}/trial_*/crash_times.json")):
        ts = [x.get("timestamp_s") for x in json.load(open(ct))
              if isinstance(x, dict) and isinstance(x.get("timestamp_s"), (int, float))]
        if ts:
            out.append(min(ts)/3600)
    return out

be, bg = series("baseline")
oe, og = series("optimized")
bt, ot = ttb("baseline"), ttb("optimized")
gh = GRID/3600

fig, ax = plt.subplots(2, 2, figsize=(13, 9))
fig.suptitle("libxml2 (FuzzBench bug, 10+10 trials, 24h, Opus 5) — ASan build, per-trial optimizers",
             fontsize=13, fontweight="bold")

# Panel A: cumulative execs over time
a = ax[0][0]
for arr, c, lab in ((be, BASE_C, "baseline"), (oe, OPT_C, "optimized")):
    m = arr.mean(0)/1e6
    a.plot(gh, m, color=c, lw=2, label=lab)
    a.fill_between(gh, arr.min(0)/1e6, arr.max(0)/1e6, color=c, alpha=0.15)
a.set(title="Cumulative executions  (realized throughput 1.21x)",
      xlabel="campaign time (h)", ylabel="total execs (millions)", xlim=(0, 24))
a.legend(loc="upper left"); a.grid(alpha=0.3)
a.annotate(f"{oe.mean(0)[-1]/1e6:.0f}M vs {be.mean(0)[-1]/1e6:.0f}M\n= 1.21x",
           (0.97, 0.05), xycoords="axes fraction", ha="right", fontsize=9,
           bbox=dict(boxstyle="round", fc="#fff3e0", ec=OPT_C))

# Panel B: edges found over time (coverage proxy)
b = ax[0][1]
for arr, c, lab in ((bg, BASE_C, "baseline"), (og, OPT_C, "optimized")):
    m = arr.mean(0)
    b.plot(gh, m, color=c, lw=2, label=lab)
    b.fill_between(gh, arr.min(0), arr.max(0), color=c, alpha=0.15)
b.set(title="Edges found  (coverage — tied)",
      xlabel="campaign time (h)", ylabel="AFL edges_found", xlim=(0, 24))
b.legend(loc="center right"); b.grid(alpha=0.3)
b.annotate(f"{og.mean(0)[-1]:.0f} vs {bg.mean(0)[-1]:.0f} edges\n(0.99x, tied)",
           (0.04, 0.92), xycoords="axes fraction", ha="left", va="top", fontsize=9,
           bbox=dict(boxstyle="round", fc="#eef3fb", ec=BASE_C))

# Panel C: time-to-first-crash (the headline for a reachable bug)
c = ax[1][0]
rng = np.random.default_rng(0)
for i, (data, col, lab) in enumerate(((bt, BASE_C, "baseline"), (ot, OPT_C, "optimized"))):
    y = i + 1 + (rng.random(len(data))-0.5)*0.22
    c.scatter(data, y, color=col, s=55, alpha=0.8, edgecolor="k", linewidth=0.4, zorder=3)
    med = statistics.median(data)
    c.plot([med, med], [i+0.7, i+1.3], color=col, lw=3, zorder=4)
    c.text(med, i+1.38, f"median {med:.2f}h", color=col, ha="center", fontsize=9)
c.set(title="Time to first crash  (both 10/10 — no significant gain)",
      xlabel="hours to first crash", yticks=[1, 2], xlim=(0, 7), ylim=(0.5, 2.7))
c.set_yticklabels(["baseline", "optimized"]); c.grid(alpha=0.3, axis="x")
c.annotate("Mann-Whitney p=0.55, A12=0.58 (n.s.)", (0.5, 0.04),
           xycoords="axes fraction", ha="center", fontsize=9,
           bbox=dict(boxstyle="round", fc="#f3f3f3", ec="gray"))

# Panel D: realized vs cost-adjusted throughput
d = ax[1][1]
bars = d.bar(["realized\n(raw 24h)", "cost-adjusted\n(+5.56h/trial opt)"],
             [1.213, 0.984], color=[OPT_C, "#9e9e9e"], edgecolor="k")
d.axhline(1.0, ls="--", color="k", lw=1)
d.text(1.5, 1.01, "break-even", fontsize=8, ha="right")
for rect, v in zip(bars, (1.213, 0.984)):
    d.text(rect.get_x()+rect.get_width()/2, v+0.01, f"{v:.2f}x", ha="center", fontweight="bold")
d.set(title="Throughput speedup vs baseline", ylabel="x baseline", ylim=(0, 1.4))
d.grid(alpha=0.3, axis="y")
d.annotate("39 kept folds (mean 1.054x), compounding;\noptimizer cost erases the raw gain",
           (0.5, 0.06), xycoords="axes fraction", ha="center", fontsize=8.5,
           bbox=dict(boxstyle="round", fc="#f3f3f3", ec="gray"))

plt.tight_layout(rect=[0, 0, 1, 0.97])
out = "plots/online-24h-bug-libxml2_summary.png"
plt.savefig(out, dpi=130)
print("wrote", out)
