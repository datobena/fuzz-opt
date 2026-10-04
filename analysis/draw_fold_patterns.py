#!/usr/bin/env python3
"""Render 'redundant-work patterns in fuzzing → the fold that fixes each' as PNG."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

fig, ax = plt.subplots(figsize=(15.5, 13.5))
ax.set_xlim(0, 100)
ax.set_ylim(0, 100)
ax.axis("off")

PROB = "#ffd2cc"   # problem (red-ish)
SOL = "#c8e6c9"    # solution (green)
ROOT = "#fff3cd"   # root insight (amber)
GATE = "#d1c4e9"   # guardrail (purple)
TAGS = ["#bbdefb", "#b3e5fc", "#b2dfdb", "#ffe0b2", "#f8bbd0", "#d7ccc8"]


def box(xc, yc, w, h, text, fc, ec="#455a64", tc="#102027", fs=10, bold=False, align="center"):
    ax.add_patch(FancyBboxPatch((xc - w / 2, yc - h / 2), w, h,
                 boxstyle="round,pad=0.25,rounding_size=6", fc=fc, ec=ec, lw=1.6, zorder=2))
    ax.text(xc, yc, text, ha=align, va="center", fontsize=fs, zorder=3, color=tc,
            fontweight="bold" if bold else "normal", linespacing=1.3)


def arrow(x1, y1, x2, y2, color="#37474f", lw=2.4):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>",
                 mutation_scale=18, lw=lw, color=color, zorder=1))


ax.text(50, 98.3, "Why fuzzing is slow:  the same work, re-done every iteration  —  and the fold that removes it",
        ha="center", fontsize=15, fontweight="bold", color="#102027")

# root insight
box(50, 92, 96, 6.5,
    "A fuzzer runs the target millions of times, mutating only the INPUT.\n"
    "Each run re-does the work the input never changes — that repeated, deterministic work dominates the profile, not the bug-finding.",
    ROOT, fs=10.5)

# column headers
box(11, 84.5, 19, 3.4, "PATTERN  (repeated work)", "#eceff1", fs=9.5, bold=True)
box(37, 84.5, 32, 3.4, "PROBLEM — done identically every iteration", PROB, fs=9.5, bold=True)
box(78, 84.5, 38, 3.4, "→  FOLD  (what the optimizer does)", SOL, fs=9.5, bold=True)

rows = [
    ("①  Immutable\nsetup-state\n(do-once)",
     "Re-parses the same configs, test certs/keys, lookup\ntables and canonical paths every run — none depend\non the fuzz input.",
     "Parse / build once at init; reuse the parsed object\nas static immutable state."),
    ("②  Fixed keys\n& params\n(do-once)",
     "Regenerates the same keypair / KEX params / test\ncredentials per input — when crypto isn't the target.",
     "Generate once at startup; clone or reuse per\niteration (bounded pool if the caller mutates it)."),
    ("③  Random /\ntime / syscalls\n(do-once)",
     "Re-calls rand·getrandom, time·clock_gettime,\ngetpid·getuid·getenv each run — values irrelevant\nto the path under test.",
     "Cache one fixed value at init; deterministic seed;\nmemory-backed answer for repeated queries."),
    ("④  Deterministic\nhelpers\n(memoize)",
     "A hot, pure helper recomputes the same output for\nthe same normalized inputs, over and over.",
     "Finite-domain lookup table, or a small memo cache\nkeyed by the normalized input bytes."),
    ("⑤  Object build\n/ decode\n(do-once)",
     "Re-allocates and re-decodes the same immutable\nbytes / rebuilds the same large structs, then frees\nthem — every single run.",
     "Resettable object pool; decode once; reuse buffers\nwith an explicit reset instead of rebuild."),
    ("⑥  Sync &\nbookkeeping\n(elide)",
     "Locks, fsync durability, logging/tracing/metrics and\nfake network setup sit on the hot path — pointless\nfor in-process, single-threaded fuzzing.",
     "Fuzz-only fast path: lock-free under one thread;\nstrip redundant I/O and diagnostic formatting."),
]

y = 78
dy = 11.0
for i, (tag, prob, sol) in enumerate(rows):
    box(11, y, 19, dy - 1.4, tag, TAGS[i], fs=9.3, bold=True)
    box(37, y, 32, dy - 1.4, prob, PROB, fs=8.9)
    box(78, y, 38, dy - 1.4, sol, SOL, fs=8.9)
    arrow(53.2, y, 58.8, y)
    y -= dy

# guardrail footer
box(50, y + 1.0, 96, 6.2,
    "GUARDRAIL — a fold ships only if it  (1) preserves behavior bit-exactly  (same result for every reachable input)  AND\n"
    "(2) measurably lowers deterministic-replay time on the frozen corpus.   Otherwise it is reverted.   (Removing a real bug-check ≠ a fold.)",
    GATE, fs=9.6)

plt.tight_layout()
out = "/home/sefcom/asu/project/test/benchmark/fuzzing_redundant_work_patterns.png"
plt.savefig(out, dpi=145, bbox_inches="tight", facecolor="white")
print("wrote", out)
