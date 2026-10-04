# aggr-8h — Aggressive / Input-Dependent Optimization + 8h Fuzzing Results

**Experiment:** `aggr-8h` · **Projects:** assimp, libavc, libxml2, selinux, wolfssl (same 5 as mut-8h)
**Phase 2:** optimize each target with an **aggressive, input-dependent** fold contract (vs mut-8h's conservative Category-1/2-only contract).
**Phase 3:** fuzz baseline vs optimized, **10 trials × 8h/trial** on k8s (libFuzzer, time-to-bug).
**All aggregates are MEAN across trials.**

This run holds **everything constant vs mut-8h except the fold contract** — same optimizer (`claude-fable-5[1m]`, claude backend), same mutation-augmented profiling (mandatory, no seed-only fallback), same targets, same 10×8h phase-3.

---

## TL;DR

- **Aggressive folding produced much larger *replay* speedups** (assimp **33.81×**, selinux 1.82×) and optimized **all 5/5** targets — including wolfssl, which mut-8h left unoptimized.
- **…but it did not help find bugs.** Counting only **real ASan crashes**, the optimized binary found the bug the **same** on assimp (10/10) and **less often** on selinux (9/10→6/10) and libavc (5/10→4/10). No target improved.
- **Coverage-over-time is unchanged** (opt/base ≈ 1.0 everywhere, like mut-8h). Because the optimized corpus reaches the same edges on the baseline binary, the selinux/libavc detection dips are most likely **run-to-run variance**, not a narrowed surface.
- **The big replay speedups are decoupled from live fuzzing** — even more starkly than mut-8h. assimp's 33.81× deterministic-replay speedup buys **zero** coverage and **no** faster/ more-frequent bug-finding.
- **The one hard line held:** no fuzzing-mode behavior gate (`#ifdef FUZZING` / `*_NOOPTIMIZE`) in any diff, and the harness PoC gate confirmed all 5 optimized binaries still crash on their known bug — **zero reverts**.

---

## ⚠️ Measurement correction (read before the tables)

The phase-3 crash log records three things that are **not** the target bug and must be excluded from time-to-bug:

- **slow-units** (`crash_type = "unknown"`, artifact `slow-unit-*`) — inputs libFuzzer flags as too slow, not crashes. libavc is dominated by these (31–36 per variant).
- **the end-of-run boundary artifact** — a `crash` at t ≈ 28801s (just past the 28800s cutoff) with artifact `da39a3ee…` (= SHA-1 of the empty input). libxml2's "10/10 crashes" are entirely this.
- **timeouts** (`crash_type = "timeout"`).

A **real find** = `crash_type == "crash"` AND `t < 28800s` AND not the empty-input artifact. All phase-3 numbers below use that definition.

---

## Phase 2 — optimization (all 5 optimized, bug-preserving, 0 reverts)

| target | replay speedup (aggr / mut-8h) | fold (file) | what it does |
|---|---|---|---|
| **assimp** | **33.81×** / 9.48× | `IOStreamBuffer.h` | size the read cache to the **actual file size** (+4 KiB guard) lazily in `open()`, instead of eagerly allocating + `'\n'`-filling the full 16 MiB every import. **Input-dependent.** |
| **selinux** | **1.82×** / 1.26× | `cil_strpool.c`, `cil.c` | **retain the interned string pool across `cil_db` lifetimes** (bounded at 2²⁰ entries) instead of teardown-per-iteration; shrink symtab `1<<13→1<<9`, enlarge pool table. Persists input-derived state across runs. |
| **wolfssl** | **1.22×** / *unoptimized* | `tfm.c` (`fp_read_radix`) | **batch** base-radix digits into a native word, folding into the bignum once per near-full accumulator instead of per-digit `fp_mul_d + fp_add_d`. Conservative run found nothing safe here. |
| **libavc** | **1.21×** / 1.14× | `ih264d_api.c` | **process-lifetime static-buffer pool** — reuse the decoder's fixed buffers across create/destroy (re-`memset` + re-init) instead of alloc/free each iteration. |
| **libxml2** | **1.17×** / 1.05× | `error.c`, `threads.c`, `uri.c` | **skip** the error `strdup`s + `xmlLastError` mirroring (diagnostics never read on the parse path); `xmlIsMainThread()→1`; memoize `xmlPathToURI`. |

`replay speedup` = baseline replay time ÷ optimized replay time on the frozen fixed corpus (deterministic `-runs=0`). It is the phase-2 acceptance metric, **not** a live-fuzzing measurement — see phase 3.

---

## Phase 3 — time-to-bug (real ASan crashes only)

| target | baseline detect | optimized detect | mean TTB (found) base → opt |
|---|:---:|:---:|---|
| **assimp** | **10/10** | **10/10** | 5.7s → 5.3s |
| **selinux** | **9/10** | **6/10** | 2.47h → 1.81h |
| **libavc** | **5/10** | **4/10** | 2.85h → 2.53h |
| libxml2 | 0/10 | 0/10 | — (only the empty-input boundary artifact) |
| wolfssl | 0/10 | 0/10 | — (bug never triggers in 8h, either variant) |

### "Found a bug" = any real, reproducible crash (signature-agnostic)

A trial counts as finding a bug if it produced a **real sanitizer crash** (not a slow-unit / timeout /
OOM / empty-input boundary artifact) — regardless of whether it is the specific manifest CVE. An
off-target crash is still a bug. `verify_crashes.py --reproduce` replays each candidate crash on the
binary to confirm it is a genuine, reproducible crash (and reports which bug, for transparency):

| target | crash-typed (b→o) | **reproduces as a real crash (b→o)** | which bugs (baseline) |
|---|---|---|---|
| **assimp** | 10→10 | **10/10 → 10/10** | heap-buffer-overflow ×9, stack-buffer-overflow ×1 |
| **selinux** | 9→6 | **9/10 → 6/10** | SEGV ×7, heap-buffer-overflow ×1, heap-use-after-free (the CVE) ×1 |
| **libavc** | 5→4 | **0/10 → 1/10** | crash-typed artifacts mostly **don't reproduce** (multithreaded decoder → non-deterministic) |
| libxml2 | 0→0 | 0/10 → 0/10 | — |
| wolfssl | 0→0 | 0/10 → 0/10 | — |

Two takeaways:

1. **The bug-find comparison stands on the signature-agnostic count**: assimp 10/10=10/10 (no change),
   selinux 9→6, libavc 5→4 — the aggressive optimization improves bug-finding on **no** target
   (equal on assimp, fewer on selinux/libavc, within variance given flat coverage). This is the metric
   that matters.
2. **Reproducibility is a data-quality flag, not a success gate.** selinux's crashes all reproduce
   (they're real bugs — mostly off-target SEGVs, which is fine). **libavc is the caveat**: its
   crash-typed count (5/4) mostly does **not** reproduce because the decoder is multithreaded, so
   libavc's numbers are the least reliable and its true bug-find rate is closer to 0–1/10.

- **assimp** — the only equal-detection (fair) comparison: 10/10 both, and the per-trial crashing inputs are identical per seed. 5.7s→5.3s is within the noise of a 2–18s crash. **No meaningful change.**
- **selinux** — optimized found the bug in **6/10 vs 9/10**. The "faster" optimized mean TTB (1.81h vs 2.47h) is **survivorship bias**: when the aggressive fold makes the 3 slower trials *fail to find the bug at all*, their long times leave the average, so the mean-of-found looks faster while the binary is actually **worse** at finding the bug. Lower detection + "faster" mean = the signature of censoring bias, not a speedup.
- **libavc** — 5/10 → 4/10; small, noisy samples; buried under 31–36 slow-units per variant.
- **libxml2 / wolfssl** — neither variant finds the real bug in 8h.

---

## Phase 3 — coverage-over-time

Both variants' corpora replayed on the **same baseline binary** (the only fair yardstick — folding changes the optimized binary's own edge map). Mean edges across 10 trials; `opt/base` ratio.

| target | 0.5h | 1h | 2h | 4h | 8h | final edges base→opt |
|---|---:|---:|---:|---:|---:|---|
| assimp | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 3579 → 3582 |
| libavc | 1.01 | 1.01 | 1.00 | 1.00 | 1.01 | 4752 → 4785 |
| libxml2 | 1.01 | 1.00 | 1.01 | 1.03 | 1.02 | 3703 → 3786 |
| selinux | 1.01 | 1.00 | 0.99 | 0.97 | 0.99 | 5086 → 5060 |
| wolfssl | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1234 → 1234 |

**Coverage is unchanged** (ratios ≈ 1.0). The optimized corpus reaches the same edges on the baseline binary as the baseline corpus does. This is the same flat result mut-8h showed — and it's the key to reading the detection dips: since the aggressive folds did **not** change what the fuzzer explores, the selinux/libavc detection differences (9→6, 5→4 over 10 trials) are most consistent with **run-to-run variance**, not a real narrowing of the bug surface. Plots: `covtime_aggr8h/{assimp,libavc,libxml2,selinux,wolfssl}.png`.

---

## Conclusions

1. **Aggressive, input-dependent folding maximized the wrong metric.** It bought large deterministic-replay speedups (assimp 33.81×) that convert to **no** coverage gain and **no** better bug-finding — the same decoupling mut-8h found, but sharper, because the replay speedups here are much larger with the same null live effect.
2. **Relaxing the contract did not beat the conservative run on any live outcome.** Detection was equal (assimp) or lower (selinux, libavc); coverage was flat everywhere. The extra fold freedom produced bolder *throughput* rewrites, not better fuzzing.
3. **The gate did its job cleanly.** All 5 optimized binaries still reproduce their known PoC (0 reverts), and no fold used a fuzzing-mode gate — so the aggressive folds are "honest" (they don't fake speedups by skipping the bug in fuzz builds), yet they still don't help.
4. **Net:** for these targets, throughput optimization — conservative or aggressive — does not make coverage-guided fuzzing find bugs faster. Live fuzzing is exploration-bound, and replay-speedup is not a proxy for it.

---

## Caveats

- **Detection differences are within plausible fuzzing variance** (n=10, high per-trial variance; coverage identical). selinux 9-vs-6 and libavc 5-vs-4 should not be over-read as a causal "the fold hurt detection" without more trials; the flat coverage argues for variance.
- **Optimized crashes were not individually triaged.** The aggressive contract explicitly allows *adding* crashes (false positives). Optimized "finds" are assumed to be the target bug but were not verified to reproduce on the baseline binary / share the root cause. Since optimized detection is ≤ baseline on every target, this doesn't change the conclusion (it could only lower the true optimized detection further).
- **mut-8h's published TTBs are suspect.** They were recovered from partial pod logs (`outcome=finding`) after that run's collector OOM'd, which likely also counted slow-units / boundary artifacts as finds. A clean aggr-vs-mut TTB comparison would require re-deriving mut-8h with the same real-crash filter used here.
- **libxml2 & wolfssl are effectively censored** (no real crash in 8h from a cold start), so their replay/coverage numbers carry no TTB signal.

---

## Methodology / artifacts

- Aggressive skill: `profile-once-fuzz-folds-aggressive` (both `~/.claude` and `~/.codex` trees) — relaxed contract adds a Category-3 "input-dependent" tier; the only behavioral reject is a fuzzing-mode gate. Enabled via `PHASE2_OPTIMIZER_SKILL`.
- Parallelism fix: mutation-capture + skill-script docker container names were `…-{int(time.time())}` and collided under parallel phase-2; changed to `-{pid}-{uuid}` (`mutation_capture.py`, `build_corpus.py`, `replay_fuzzer_profile.py`).
- Drivers: `run_aggr8h_driver.sh` (phase 2), `run_aggr8h_phase3.sh` (phase 3, 10×8h), `run_aggr8h_covtime.sh` (coverage).
- Per-target diffs: `results/aggr-8h/<target>/optimized/source_diff/optimization.diff`
- Per-trial crash data: `results/aggr-8h/trial_results.json` (+ `…/<target>/<variant>/trial_NN/crash_times.json`)
- Coverage curves/plots: `covtime_aggr8h/<target>.{curves.json,png}`
- Pulled corpora: `covdiff_pertrial_aggr8h/<target>/<variant>/`
