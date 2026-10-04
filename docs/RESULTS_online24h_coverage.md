# Online source-fold optimization — coverage and cost (4 targets, 24 h, 9+9 trials)

**Runs:** `online-24h-b1-{libxml2,wolfssl}` (2026-08-03→04), `online-24h-b2-{libavc,selinux}` (2026-08-05→06)
**Design:** per target, 9 baseline trials vs 9 online-optimized trials, each pinned to its own
physical core (cores 4–39; the 40–79 HT siblings are left idle). AFL++ 5.02c, 24 h per trial.
The online arm is profiled by an LLM agent every ≥2 h; accepted folds are rebuilt and
hot-swapped into the running trials.

---

## 1. How coverage is measured

The two arms execute *different binaries*, so AFL's own `edges_found` is not comparable across
them — the online binary contains folded code and inserted helpers with their own edges.

Instead, **both arms' accumulated queues are replayed on the baseline binary**
(`coverage_growth.py`, one `afl-showmap` pass per trial), and edge sets are unioned in discovery
order. This asks the only comparable question: *what behaviour of the original program did this
corpus reach?* All coverage numbers below are from that common instrument.

## 2. How the optimizer's cost is charged

The online arm does not get its optimization for free. Two costs are charged to it, and only to
it — the baseline never stops and runs no optimizer:

| Charge | What it is |
|---|---|
| **Hot-swap downtime** | trials are stopped while the rebuilt binary is installed (~100 s each) |
| **Optimizer CPU** | profiling, rebuilds, replay gate, broker build/smoke/replay, on a separate core |

Optimizer CPU is converted to lost fuzzing time as `core_seconds ÷ 9 trials`, on the assumption
that the optimizer's core would otherwise have run a tenth trial at equal efficiency. Each charge
is inserted into the timeline as a gap at the point the round ran: throughput is pinned to zero,
coverage held flat, and everything after shifts right by the accumulated amount.

**Agent model-wait is NOT charged** — it is API latency, not CPU that could have been fuzzing.

## 3. Results

Final cumulative edges at t = 24 h, median across 9 trials, replayed on the baseline binary.

| Target | Baseline | Optimized | Uncharged | **Charged** | Total charge | Folds kept |
|---|---:|---:|---:|---:|---:|---:|
| selinux (CVE-2021-36085) | 5860 | 6200 | +5.90 % | **+5.80 %** | 42.9 min | 7 |
| libxml2 (arvo-1972) | 3281 | 3378 | +2.99 % | **+2.96 %** | 61.5 min | 5 |
| wolfssl (arvo-26567) | 1195 | 1212 | +1.42 % | **+1.42 %** | 60.8 min | 7 |
| libavc (arvo-16505) | 6235 | 6251 | +0.27 % | **+0.26 %** | 36.0 min | 3 |

Charging barely moves the result: by the time the charges accumulate, both arms are deep in the
flat region of the coverage curve, so a right-shift of ~4 % of the budget costs almost nothing in
final coverage.

### Cost breakdown

| Target | Swaps | Swap downtime | Optimizer CPU | Charged per trial | Share of 24 h |
|---|---:|---:|---:|---:|---:|
| libxml2 | 5 | 8.3 min | 28 744 core-s | 53.2 min | 4.3 % |
| wolfssl | 7 | 9.8 min | 27 580 core-s | 51.1 min | 4.2 % |
| selinux | 7 | 9.9 min | 17 808 core-s | 33.0 min | 3.0 % |
| libavc | 3 | 4.9 min | 16 767 core-s | 31.0 min | 2.5 % |

For selinux, `broker_replay` (the agent timing its own candidates) is ~60 % of the optimizer CPU;
profiling, rebuild and the final gate together are under a third.

### Per-round replay speedups

| Target | Round-by-round | Outcome |
|---|---|---|
| selinux | 1.82, 1.70, 1.16, 1.27, 1.27, 1.10, *1.01 rej*, 1.12 | large first win, then decaying |
| libxml2 | 1.21, 1.37, 1.30, 1.05, 1.03, *1.01 rej* | steady, then exhausted |
| wolfssl | 1.07, 1.13, 1.07, 1.34, 1.02, 1.04, 1.47 | erratic, kept finding wins |
| libavc | 1.03, 1.02, 1.02, *empty*, *empty*, *0.997 rej* | converged after 3 small folds |

`rej` = rejected by the replay gate for no speedup. libavc's two empty rounds were the agent
reporting **list-exhausted**: it wrote and measured candidate folds, reverted them for failing the
timing gate on confirmation, and refused the remaining hot spots on contract grounds (thread
spin-waits alter interleaving in a racy decoder; buffer pooling would retain input-derived state
and suppress ASan's use-after-free detection).

## 4. Reading the results

The benefit tracks **how much contract-compliant headroom the target actually has**, not the
optimizer's effort. selinux handed the agent sparse hash-table walks worth 1.8× on the first round
(an occupancy bitmap so iteration skips empty buckets, turning full-table walks from O(nslot) into
O(occupied)). libavc's remaining cost was memory management and thread waits, both correctly
refused — so it converged early and produced no coverage effect.

**libavc's +0.26 % is noise, not a small win.** Two of its nine baseline trials sit ~500 edges
below the other seven, so between-trial spread dwarfs the arm difference. selinux is the only
target where the arms cleanly separate (baseline 5806–5973, optimized 6132–6264, no overlap).

## 5. Known limitations

1. **Inserted helpers are instrumented.** The skill requires every inserted function to be named
   `fold_*` so AFL's denylist (`fun:fold_*`) excludes it from coverage instrumentation. In several
   rounds the agent instead used `__attribute__((no_sanitize("coverage")))`, which is upstream
   SanitizerCoverage's mechanism and has **no effect** under AFL++'s LLVM-PCGUARD fork. Those
   helpers add edges to the optimized binary, diluting AFL's feedback with edges that have nothing
   to do with the target. This **biases against the optimized arm**, so the numbers above are
   conservative. Affected: wolfssl iter_03/04/06, libavc iter_02, selinux iter_02/03.
2. **The CPU charge assumes** the optimizer's core would otherwise have run a tenth trial at the
   same efficiency.
3. **Charges land as one lump per round**, where the real CPU was spread across that round's ~1.5 h.
   The total is exact; the fine structure of the shift is approximate.
4. **A round can outlive the campaign.** selinux's round 8 finished 36 min after its trials ended
   and swapped into zero trials — its cost is charged past the 24 h boundary, where it is clipped.

## 6. Reproducing

```bash
python3 analysis/coverage_growth.py      --experiment-id online-24h-b2-selinux --jobs 18
python3 analysis/plot_coverage_growth.py --experiment-id online-24h-b2-selinux --outdir plots
python3 analysis/cpu_cost_report.py      --experiment-id online-24h-b2-selinux
```

`plot_coverage_growth.py` reads hot-swap downtime from `.<experiment-id>.log` and **refuses to run
if that log is absent** — without it the online arm would be plotted uncharged and would look
better than it is. Pass `--no-charge-cpu` to see swap downtime only.

Bug-finding results are in [`RESULTS_online24h_bugs.md`](RESULTS_online24h_bugs.md).
