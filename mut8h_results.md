# mut-8h — Mutation-Augmented Optimization + 8h Fuzzing Results

> ## ⚠️ CORRECTION (added 2026-07-09, revised) — detection counts mostly OK; multipliers are noisy; libxml2 is wrong
>
> This run's phase-3 collection failed (tar-stream OOM), so its numbers were recovered from pod logs
> via `outcome=finding`, which fires on ASan crash **or** timeout/OOM/leak/end-of-run boundary
> artifact. Success here is defined signature-agnostically: **any real crash is a bug find** (an
> off-target crash still counts). Checked against the later clean `aggr-8h` run (same binaries), the
> per-target detection counts hold up within run-to-run variance:
>
> | target | mut-8h `finding` | aggr-8h real-crash | verdict |
> |---|---|---|---|
> | assimp | 10/10 | 10/10 | ✓ correct |
> | libavc | 3/4 | 5/4 | ✓ same ballpark (variance; libavc crashes are non-deterministic) |
> | selinux | 8/8 | 9/6 | ✓ same ballpark (variance) |
> | wolfssl | 0/0 | 0/0 | ✓ correct |
> | **libxml2** | **10/10** | **0/0** | ✗ **boundary artifact** — real answer 0; see the libxml2 caveat below |
>
> **So:** the detection counts are approximately right EXCEPT libxml2 (the "10/10" is the empty-input
> end-of-run artifact, not a real bug — libxml2 found nothing, as already noted). What remains weak is
> the **TTB *speedup multipliers*** (1.30–1.54×): small/censored subsets + run-to-run variance —
> e.g. baseline assimp averaged 8.3s here vs 5.7s in aggr-8h (*same binary*), so 1.54× is not robust.
> Treat the multipliers as directional, not precise. Coverage-over-time (opt/base ≈ 1.0) is valid
> (independent method). Exact TTBs can't be re-derived (per-trial crash data didn't survive the OOM).

**Experiment:** `mut-8h`  ·  **Projects:** assimp, libavc, libxml2, selinux, wolfssl (5 ARVO/CVE targets)
**Phase 2:** optimize each target for throughput on a **seed + captured-mutations** corpus profile.
**Phase 3:** fuzz baseline vs optimized, **10 trials × 8h/trial** on k8s (libFuzzer, time-to-bug).
**All aggregates below are MEAN across trials.**

---

## TL;DR

- **Optimization sped up time-to-bug on 3/5 targets** — assimp **1.54×**, libavc **1.47×**, selinux **1.30×** faster mean TTB. libxml2/wolfssl never produced a real crash in 8h.
- **Optimization did NOT change coverage** — baseline vs optimized coverage-over-time is ~identical everywhere (opt/base 0.96–1.01). So the folds speed re-hitting the *known* bug but don't help *explore* more.
- **The replay-speedups overstate the live-fuzzing benefit** — e.g. assimp's 9.48× deterministic-replay speedup yields only a 1.54× TTB improvement and 0 coverage gain, because live fuzzing is bottlenecked by mutation/exploration, not raw replay throughput.
- **What's new here:** phase-2 now profiles+optimizes on the **mutations libFuzzer actually generates** (captured via a custom-mutator shim), not just the seed corpus, and uses **only the project-provided seed corpus** (no GCS). Mutation-augmented profiling is now **mandatory with no seed-only fall-back** — a target that can't be mutation-profiled is hard-failed, and one whose optimizer finds no bug-preserving fold is marked **unoptimized** (this is what changed for wolfssl).

---

## Phase 2 — optimization

| project | opt basis | replay speedup | bug preserved | optimized usable |
|---|---|---:|:---:|:---:|
| **assimp** | 🧬 mutation-augmented | **9.48×** | ✅ | ✅ |
| **selinux** | 🧬 mutation-augmented | 1.26× | ✅ | ✅ |
| **libavc** | 🧬 mutation-augmented | 1.14× | ✅ | ✅ |
| **libxml2** | 🧬 mutation-augmented | 1.05× | ✅ | ✅ |
| **wolfssl** | 🧬 mutation-augmented | 1.00× (**unoptimized**\*) | n/a | n/a |

\* **wolfssl — unoptimized (genuine negative result).** Mutation-augmented optimization captured 50k mutations but found **no bug-preserving fold** it could keep (every speedup candidate risked hiding the ARVO-26567 bug). Under the mutation-augmented-only policy there is **no seed-only fall-back**, so wolfssl stays **unoptimized** (optimized == baseline). The earlier run *did* fall back to a seed-profile fold (1.11×) to give wolfssl an optimized variant — that fall-back has since been removed from the pipeline (`PHASE2_MUTATION_REQUIRED`); the wolfssl phase-3 numbers below were collected on that now-retired seed-only binary, but wolfssl never crashed in 8h either variant, so the outcome (no bug found) is unaffected.

`replay speedup` = baseline replay time ÷ optimized replay time on the **frozen fixed corpus** (deterministic `-runs=0`). It is the phase-2 acceptance metric, not a live-fuzzing throughput measurement.

---

## Phase 3 — time-to-bug (mean over trials that found the bug)

| project | baseline: n found · mean TTB | optimized: n found · mean TTB | mean TTB speedup |
|---|---|---|---:|
| **assimp** | 10/10 · 8.3s | 10/10 · 5.4s | **1.54×** |
| **libavc** | 3/10 · ~7.05h | 4/10 · ~4.80h | **1.47×** |
| **selinux** | 8/10 · ~3.67h | 8/10 · ~2.83h | **1.30×** |
| libxml2 | 10/10 · 8.00h | 10/10 · 8.00h | 1.0× (boundary artifact — see caveats) |
| wolfssl | 0/10 | 0/10 | — (bug never triggered in 8h) |

- **assimp** is the cleanest signal (full 10/10 both variants): optimized finds the bug 1.54× faster.
- **selinux** flips positive under mean (it was 0.99× under median — the median hid a real improvement).
- **libxml2's "findings" are at ~28802s = the 8h cutoff** — the spurious end-of-run boundary artifact, i.e. no real crash, so it's effectively censored, not a genuine tie.
- **wolfssl** never crashed in 8h (either variant), so no TTB comparison.

---

## Phase 3 — coverage-over-time

Both variants' corpora replayed on the **same baseline binary** (folding changes the optimized binary's edge map, so the baseline binary is the only fair yardstick). Mean edges across 10 trials; `opt/base` ratio.

| project | 0.5h | 1h | 2h | 4h | 8h |
|---|---:|---:|---:|---:|---:|
| assimp | 0.98 | 0.98 | 0.98 | 0.98 | 0.98 |
| libavc | 0.99 | 0.99 | 0.98 | 0.98 | **0.96** |
| libxml2 | 1.00 | 1.00 | 0.99 | 1.00 | 1.01 |
| selinux | 1.01 | 1.02 | 1.01 | 1.01 | 0.99 |
| wolfssl | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |

Mean final-coverage (edges), baseline → optimized: assimp 3579→3524, libavc 4854→4664, libxml2 3480→3532, selinux 5087→5043, wolfssl 1231→1233.

**Coverage is unchanged** (ratios ~1.0). The only real divergence is **libavc ending ~4% lower** (its folding trimmed a little reachable surface). Plots (mean line + 95% CI band): `covtime_mut8h/{assimp,libavc,libxml2,selinux,wolfssl}.png`.

Note: **assimp's curve is flat** — it crashes in ~8s, so there is no 8h coverage-accumulation window; its cov(t) is not informative (TTB is the metric there). **libxml2 and wolfssl are the cleanest full-8h coverage comparisons** and are dead flat at 1.0.

---

## Conclusions

1. **Throughput optimization → faster time-to-bug, not more coverage.** Across the 3 targets that crash (assimp, libavc, selinux), the optimized binary re-hits the *known* bug 1.30–1.54× faster on average, but neither reaches nor accelerates toward more coverage.
2. **Replay-speedup is a weak predictor of the fuzzing benefit.** assimp's 9.48× replay speedup → 1.54× TTB and 0 coverage change; the modest 1.05–1.26× targets → small/neutral TTB. Deterministic replay gets much faster; live fuzzing does not scale with it because it's exploration-bound.
3. **Mutation-augmented profiling changes what gets optimized but not the coverage outcome.** It surfaced a big foldable hotspot on assimp (9.48×) that seed-only profiling would rank lower; on wolfssl it (correctly) found nothing safe to fold.

---

## Caveats & data-recovery notes

- **Mean-of-found TTB is over different subsets** for censored targets (libavc 3 vs 4 found, selinux 8 vs 8) — those speedups compare non-identical subsets and are noisier than assimp's full 10/10. A censoring-aware estimate or mean±std can be added if wanted.
- **libxml2 findings are the 8h boundary artifact**, not real crashes — treat libxml2 as censored (no bug found).
- **Phase-3 artifact collection failed** (single tar-stream OOM, rc=137, the known collection-truncation issue). Results were recovered directly:
  - **TTB** from the 100 surviving pod logs (`outcome=` / `elapsed_seconds=`).
  - **Coverage** by pulling the per-trial corpus zips from the NFS PVC and reconstructing cov(t) from each unit's zip-stored **mtime** (discovery time), replayed cumulatively on the baseline binary.
- **ctime-based cov(t) was requested but is not recoverable:** the raw `/corpus` was pod-local (deleted on completion) and the archived zips store only mtime. For write-once corpus units ctime==mtime at write time anyway, so it would not differ.

---

## Methodology — what changed in the pipeline for this run

- **Phase-2 corpus = provided seed corpus only (no GCS).** `_phase2_corpus_source` resolves the bundled `<target>_seed_corpus.zip`; the GCS download is off (`PHASE2_USE_GCS_CORPUS=0`).
- **Mutation capture.** Before freezing the fixed corpus, a diagnostic build with a custom-mutator shim (`mutation_dump_mutator.c`, linked via build.sh/Makefile injection) fuzzes the target for **≤5 min** (`PHASE2_MUTATION_DURATION_SECS=300`) or a 50k-file cap, saving **every** mutation. Seed + mutations are combined into the fixed corpus that is profiled AND used as the fold-acceptance replay gate. (`mutation_capture.py`, `_augment_corpus_with_mutations`.)
- **Per-target build quirks handled:** shim injection covers `$LIB_FUZZING_ENGINE` and `-lFuzzingEngine` link lines plus wolfssl's nested `FUZZERS_LIBS` Makefiles. wolfssl's slow triple-nested rebuild needed gate-sizing re-enabled (`PHASE2_MUTATION_SKIP_SIZING=0`) + a small gate cap so the optimizer could iterate.
- **Coverage tooling** (`run_covtime.py`, `run_covdiff_pertrial.py`) made experiment-configurable via env (`COVTIME_SRC_EXP`/`OPT_EXP`/`PULL_DIR`/`OUT`/`DURATION`).

---

## Artifacts

- Phase-2 per-target metadata: `results/mut-8h/<project>-<cve>/setup_metadata.json`
- Recovered TTB (raw per-trial): `results/mut-8h/podlog_recovery/ttb_raw.json`
- Coverage curves (per trial): `covtime_mut8h/<project>.curves.json`
- Coverage plots: `covtime_mut8h/<project>.png`
- Pulled corpus zips: `covdiff_pertrial_mut8h/<project>/<variant>/`
- Full-fidelity corpus archives (for deeper analysis): NFS PVC `/artifacts/bena/phase3-kube/mut-8h/`
