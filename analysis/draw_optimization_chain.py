#!/usr/bin/env python3
"""Render the fuzz-throughput source-optimization chain (phase 2) as a PNG."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

fig, ax = plt.subplots(figsize=(12.5, 16.5))
ax.set_xlim(0, 100)
ax.set_ylim(0, 152)
ax.axis("off")

# palette
C = dict(ctx="#cfd8dc", src="#bbdefb", corpus="#90caf9", prof="#ffe0b2",
         hot="#ffcc80", fold="#c8e6c9", build="#a5d6a7", gate="#ffcdd2",
         dec="#ef9a9a", out="#b2dfdb", loop="#7e57c2")


def box(xc, yc, w, h, text, fc, ec="#37474f", tc="#102027", fs=10, bold=False,
        style="round,pad=0.3,rounding_size=8"):
    ax.add_patch(FancyBboxPatch((xc - w / 2, yc - h / 2), w, h,
                 boxstyle=style, fc=fc, ec=ec, lw=1.8, zorder=2))
    ax.text(xc, yc, text, ha="center", va="center", fontsize=fs, zorder=3,
            color=tc, fontweight="bold" if bold else "normal", linespacing=1.35)


def arrow(x1, y1, x2, y2, color="#37474f", lw=2.2, ls="-", rad=0.0, label=None,
          lx=None, ly=None, lcolor=None, fs=9):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2),
                 connectionstyle=f"arc3,rad={rad}", arrowstyle="-|>",
                 mutation_scale=20, lw=lw, color=color, ls=ls, zorder=1))
    if label:
        ax.text(lx, ly, label, ha="center", va="center", fontsize=fs,
                color=lcolor or color, fontstyle="italic", zorder=4,
                bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="none", alpha=0.85))


CX = 37          # main column center
W = 56           # main box width

ax.text(CX, 150, "Fuzz-Throughput Source Optimizer — the chain (Phase 2)",
        ha="center", fontsize=15, fontweight="bold", color="#102027")

# context: upstream
box(CX, 143, W, 7, "PHASE 1 · select target  —  ARVO reproducible CVE\n(64-bit · libFuzzer · ASAN · real fuzz target)", C["ctx"], fs=9.5)

# main chain
box(CX, 130, W, 9,
    "①  EXTRACT SOURCE  +  build baseline\nbuild_arvo_with_source_intercept  →  /out binary  +  project src tree",
    C["src"], bold=False, fs=9.5)
box(CX, 116, W, 10,
    "②  COLLECT / GENERATE CORPUS   (build_corpus.py)\nGCS download  ▸  local cache  ▸  fuzz-to-build\n+ sanitize (drop crashing/hanging seeds)  →  FROZEN corpus",
    C["corpus"], fs=9.5)
box(CX, 101, W, 10,
    "③  PROFILE on the corpus\nreal_fuzzer_profile.py (live)  /  replay_fuzzer_profile.py\n→  perf flat.txt (self-time)  +  callgraph.txt",
    C["prof"], fs=9.5)
box(CX, 86, W, 11,
    "④  FIND HOTSPOT  →  fold candidate   (fold-step)\nself-time > 1% (fn)  /  > 5% (subsystem)\nexclude harness · driver · kernel · syslib · instrumentation",
    C["hot"], fs=9.5)
box(CX, 71, W, 11,
    "⑤  APPLY FOLD  —  edit LIBRARY source only  (Claude / Codex)\nelide teardown · LUT · object pool · syscall / diagnostic elision\ninserted helpers annotated no_sanitize(\"coverage\")",
    C["fold"], fs=9.5)
box(CX, 57, W, 9,
    "⑥  GUARD  +  REBUILD  +  smoke\nverify_source_only_changes.py   ·   phase2_build_check.py",
    C["build"], fs=9.5)
box(CX, 42, W, 11,
    "⑦  ACCEPTANCE GATE — deterministic replay   (replay_timing.py)\nSAME frozen corpus on baseline vs optimized\n-runs=0 · no mutation · pinned CPU · median of K  →  replay_speedup",
    C["gate"], fs=9.5)
box(CX, 29, W, 7, "faster than previous best?", C["dec"], bold=True, fs=10.5)
box(CX, 17, W, 8,
    "✓ OPTIMIZED binary  +  replay_speedup\n(written to setup_metadata.json)",
    C["out"], bold=True, fs=10)

# context: downstream
box(CX, 6, W, 7,
    "PHASE 3 · N fuzzing trials (k8s) → time-to-bug    │    PHASE 4 · stats + report",
    C["ctx"], fs=9.5)

# straight down arrows
ys = [(139.5, 134.5), (125.5, 121), (111, 106), (96, 91.5),
      (80.5, 76.5), (65.5, 61.5), (52.5, 47.5), (36.5, 32.5)]
for y1, y2 in ys:
    arrow(CX, y1, CX, y2)
# gate -> decision and decision -> keep(output)
arrow(CX, 25.5, CX, 21, label="KEEP", lx=CX - 9, ly=23.3, lcolor="#2e7d32", fs=10)
arrow(CX, 13, CX, 9.6)

# REVERT branch (left): decision back to fold/hotspot
arrow(CX - W / 2, 29, 6, 29, color="#c62828", rad=0)
arrow(6, 29, 6, 86, color="#c62828", rad=0)
arrow(6, 86, CX - W / 2, 86, color="#c62828",
      label="REVERT fold\n→ try next candidate", lx=6, ly=58, lcolor="#c62828", fs=9)

# LOOP-BACK on the right: kept fold -> continue
rx = CX + W / 2
# profile-once: next hotspot (back to ④)
arrow(rx, 29, 86, 29, color=C["loop"], rad=0)
arrow(86, 29, 86, 86, color=C["loop"], rad=0)
arrow(86, 86, rx, 86, color=C["loop"],
      label="PROFILE-ONCE\nkeep + next hotspot\n(no re-profile)", lx=88.5, ly=52, lcolor=C["loop"], fs=8.7)
# evolving: deepen corpus + re-profile (back to ③ via ②)
arrow(rx, 31, 96, 31, color="#5e35b1", rad=0, ls="--")
arrow(96, 31, 96, 116, color="#5e35b1", rad=0, ls="--")
arrow(96, 116, rx, 116, color="#5e35b1", ls="--",
      label="EVOLVING\ndeepen corpus\n+ re-profile\noptimized build", lx=92, ly=130, lcolor="#5e35b1", fs=8.7)

# legend
leg = [("source / build", C["src"]), ("corpus", C["corpus"]),
       ("profile / hotspot", C["prof"]), ("fold + rebuild", C["fold"]),
       ("replay gate", C["gate"]), ("output", C["out"]), ("context", C["ctx"])]
for i, (lab, col) in enumerate(leg):
    yx = 1.5
    xx = 2 + i * 14
    ax.add_patch(FancyBboxPatch((xx, yx), 2.2, 1.6, boxstyle="round,pad=0.1",
                 fc=col, ec="#37474f", lw=1))
    ax.text(xx + 3, yx + 0.8, lab, fontsize=7.6, va="center")

plt.tight_layout()
out = "/home/sefcom/asu/project/test/benchmark/optimization_chain.png"
plt.savefig(out, dpi=145, bbox_inches="tight", facecolor="white")
print("wrote", out)
