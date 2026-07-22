# local-pinned — CPU-Pinned Local Fuzzing: baseline vs mut8h vs aggr8h

**Goal:** remove the k8s node/load noise that made cross-run time-to-bug (TTB) comparisons
unreliable, by running phase-3 **locally with each trial pinned to a dedicated physical core**, and
directly compare the **same baseline binary** against the two optimized variants (mut8h's
conservative fold and aggr8h's aggressive fold) on the same hardware.

**Setup.** Targets **selinux** (CVE-2021-36085) and **libavc** (arvo-16505). Three binaries each —
`baseline`, `aggr8h`-optimized, `mut8h`-optimized (the mut-8h and aggr-8h baselines are
byte-identical, so there is one shared baseline). **10 trials × 8h** per (target,variant) = **60
trials**. Every trial pinned to a **distinct physical core** (logical CPUs 0–19; HT siblings 20–39
left idle → zero sibling contention), same seed corpus, same per-trial seed (`1337 + trial·1000`),
same libFuzzer flags as the k8s runs. Scored with the canonical classifier `lib/crash_classify`
(real `crash-*` before the 28800 s cutoff, excluding slow-units / timeouts / OOMs / empty-input
boundary artifact). "Found a bug" is **signature-agnostic** — any real reproducible crash counts.

---

## TL;DR

- **Pinning removed the hardware noise, but the variance stayed huge.** Even on dedicated identical
  cores with the same binary, selinux TTB has a **±1–3 h standard deviation on a ~2 h mean**. The
  dominant noise source is the fuzzer's own trajectory variance across seeds, **not** the cluster —
  so at n=10 it swamps any optimization signal.
- **Optimization gave no reliable improvement, and coverage is flat.** On the common baseline
  binary all three variants reach **0.99–1.01×** coverage on both targets. selinux detection went
  *down* with optimization (baseline 10/10 → mut8h 8/10 → aggr8h 7/10), within the noise.
- **The aggressive fold's throughput advantage is fake over a long run.** aggr8h starts ~1.6×
  baseline exec/s but decays **below** baseline by ~30 min (its retained string-pool bloating —
  confirmed by monotonic RSS growth). mut8h's conservative fold sustains ~1.2–1.3×, but that extra
  throughput buys nothing (same coverage, same-or-worse detection).

---

## 1. Bug detection & time-to-bug (real crashes, signature-agnostic)

| target | variant | found/10 | mean TTB | median TTB | sd |
|---|---|---|---:|---:|---:|
| **selinux** | baseline | **10/10** | 2.10h | 2.49h | ±1.17h |
| selinux | aggr8h | 7/10 | 2.68h | 0.97h | ±2.81h |
| selinux | mut8h | 8/10 | 2.39h | 1.32h | ±2.10h |
| **libavc** | baseline | 1/10 | 7.27h | 7.27h | — |
| libavc | aggr8h | 3/10 | 4.16h | 5.03h | ±2.54h |
| libavc | mut8h | 1/10 | 7.93h | 7.93h | — |

- **selinux:** optimization did not help — both optimized variants found the bug **fewer** times
  than baseline (10 → 8/7). The huge sd (±1–3 h) means none of these differences are significant at
  n=10; the "faster" optimized means are also survivorship-biased (slow trials that fail to find the
  bug drop out of the average).
- **libavc:** all three sit near the floor (1–3 / 10). libavc's decoder is **multithreaded**, so its
  crashes are largely non-deterministic — most crash-typed artifacts don't even reproduce on replay
  (see §4). Treat libavc's TTB numbers as unreliable.

---

## 2. Coverage on the **baseline binary** (common yardstick)

Each variant's *accumulated corpus* replayed on the single baseline binary (`-runs=0`), so all three
are scored on the same edge map (folding changes the optimized binaries' own instrumentation, which
is why their in-run `cov:` counts are not comparable).

| target | variant | n | baseline edges | vs baseline |
|---|---|---:|---:|---:|
| **selinux** | baseline | 10 | 5044 | 1.000× |
| selinux | aggr8h | 10 | 4995 | **0.990×** |
| selinux | mut8h | 10 | 5079 | **1.007×** |
| **libavc** | baseline | 10 | 4789 | 1.000× |
| libavc | aggr8h | 10 | 4718 | **0.985×** |
| libavc | mut8h | 9 | 4746 | **0.991×** |

**Coverage is identical within noise (0.99–1.01×).** The optimized binaries execute more but their
inputs cover the same fraction of the baseline program. Optimization moved throughput, not
exploration.

---

## 3. Throughput over time — the aggressive fold decays below baseline

Instantaneous exec/s, measured **within each time window** and averaged only over trials still
fuzzing in that window (no censoring confound):

| window | baseline | aggr8h | mut8h |
|---|---:|---:|---:|
| 0–5m | 478/s | **745/s** | 642/s |
| 25–35m | 430/s | **337/s** | 509/s |
| 55–65m | 375/s | **263/s** | 458/s |
| 3.8–4h | — (all crashed) | 159/s | 268/s |

aggr8h starts fastest (745/s, ~1.6× baseline) then **collapses to 159/s, crossing below baseline by
~30 min.** mut8h stays above baseline the whole run. RSS confirms the mechanism (full-8h trials):

| trial | 5m | 30m | 1h | 2h | 4h |
|---|---:|---:|---:|---:|---:|
| aggr8h | 632 | 676 | 699 | 707 | **741 ↑** |
| mut8h | 614 | 669 | 669 | 682 | 682 (flat) |
| baseline | 447 | 469 | 469 | 482 | 482 (flat) |

aggr8h's memory climbs monotonically (retained pool accumulating input-derived strings); baseline
and mut8h are flat.

---

## 4. Reproducibility (data-quality flag)

Replaying each "find" on the binary (`verify_crashes.py --reproduce`):
- **selinux** crashes all reproduce — they're real bugs (mostly off-target SEGVs in
  `__cil_resolve_name_with_parents`, which still count as bugs under the signature-agnostic rule).
- **libavc** crashes mostly **do not reproduce** (multithreaded decoder → non-deterministic), so its
  detection counts are the least trustworthy — true rate closer to 0–1/10.

---

## 5. Root cause of the aggr8h regression

The aggr8h selinux fold made `cil_strpool_destroy()` a no-op until the interned string pool exceeds
2²⁰ entries — so the pool **persists and accumulates input-derived strings across fuzz iterations**
instead of being torn down each time. On the phase-2 fixed-corpus replay this looked like a 1.82×
speedup, but in a live campaign it (a) bloats memory and slows every iteration (the decay above),
and (b) breaks **per-input determinism** — the target's behavior on one input now depends on
previous inputs, which corrupts coverage feedback and crash reproducibility even when the per-input
result is unchanged. mut8h avoids all of this by freeing the *contents* every iteration and keeping
only the empty fixed-size table.

> A new hard rule (**no cross-iteration input-derived state / per-input determinism**) was added to
> both fold skills' contracts as a result of this finding.

---

## 6. Conclusion

On identical, CPU-pinned hardware, throughput optimization of selinux/libavc — conservative
(mut8h) or aggressive (aggr8h) — **does not make coverage-guided fuzzing find bugs faster or reach
more coverage.** The apparent effects are within the fuzzer's intrinsic run-to-run variance, which
at n=10 is far larger than any optimization signal. The aggressive fold is actively counterproductive
over a long run (throughput decays below baseline, and it makes the target stateful). The
replay-speedup metric that drove phase-2 (aggr8h 1.82×, mut8h 1.26×) does not predict — and here
inverts against — live fuzzing outcomes.

---

## Artifacts

- Per-trial results: `local_pinned/results.json` (+ `local_pinned/<target>/<variant>/trial_NN/{result.json,fuzz.log,corpus/,crashes/}`)
- Coverage on baseline binary: `local_pinned/covbaseline_final.json`
- Coverage-increase plots (ctime): `local_pinned/covtime_{selinux,libavc}.png`
- Driver + analysis: `run_local_pinned.py`, `plot_local_cov.py`, `covbaseline_final.py`, `verify_crashes.py`
- Driver log: `local_pinned_20260710_033316Z.log`
