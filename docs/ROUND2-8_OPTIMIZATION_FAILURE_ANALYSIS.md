# round2-8 — Per-Project Optimization Failure Analysis

**Experiment:** `results/round2-8/` &nbsp;•&nbsp; **Optimizer:** `claude` (profile-once-fuzz-folds)
&nbsp;•&nbsp; **Phase-2 dates:** 2026-06-28 → 06-29 &nbsp;•&nbsp; **Contract:** Behavior-Preservation
(Category-1/2 folds only) &nbsp;•&nbsp; **Note:** the strict replay-speedup gate
(`PHASE2_MIN_REPLAY_SPEEDUP`) and the corpus/replay crash-robustness fixes were **not yet active**
during this run.

## TL;DR

Of 8 ARVO targets, **only 1 (yara)** produced a kept fold with a real deterministic-replay speedup —
and even it was **not statistically significant** in phase-4 (10 trials). The other 7 fall into four
distinct failure modes:

| # | Project | Target | Applied? | Replay | Phase-4 TTB (base→opt median) | Failure mode |
|---|---------|--------|:---:|:---:|:---:|---|
| 1 | **yara**-arvo-3848 | pe_fuzzer | ✅ kept | **1.35×** | 1.07 h → 0.65 h · **1.65×** (p=0.35, n.s.) | *(success, not significant)* |
| 2 | **sleuthkit**-arvo-24893 | sleuthkit_fls_ext_fuzzer | ✅ built | **+10.8%** (profiling) / **0.999×** (phase-4) | 0.38 h → 0.41 h · 0.93× (n.s.) | Real profiled hotspot; wins only on the profiling corpus |
| 3 | **libjxl**-arvo-35172 | djxl_fuzzer | ✅ built | **unmeasurable** (SIGSEGV) | 16.26 h → 17.43 h · 0.93× (n.s.) | Replay **crashed** (exit 139) + net-negative |
| 4 | **radare2**-arvo-10222 | ia_fuzz | ❌ none | — | — | **Double timeout** (corpus filter 4h + agent 5h) |
| 5 | **freeradius**-arvo-38283 | (freeradius) | ❌ reverted | — | — | Fold didn't beat baseline → reverted |
| 6 | **graphicsmagick**-arvo-8280 | coder_PTIF_fuzzer | ❌ reverted | — | — | Hot paths are input-dependent TIFF decode |
| 7 | **hunspell**-arvo-51102 | (hunspell) | ❌ reverted | — | — | Object rebuilt per-iteration; only fold ~2% slower |
| 8 | **libredwg**-arvo-31419 | llvmfuzz | ❌ reverted | — | — | Honest 1.00× — no fold beat baseline |

Phase-4 (10 trials) confirms **0/3 fuzzed projects reached significance**, and 2 of the 3
(libjxl, sleuthkit) were **net-negative** on time-to-bug (0.93×).

### Phase-4 time-to-bug — absolute numbers (the values behind the ratios)

10 trials/variant (sleuthkit optimized: n=8), 48 h cap. **Median is the headline** metric; the mean
is shown only for context and is inflated by 48 h-censored trials that never crashed.

| Project | Base median | Opt median | Median × | Base mean | Opt mean | Mean × | Bugs (b/o) | p (1-sided) | A12 |
|---------|-----------:|-----------:|:-------:|----------:|---------:|:------:|:----------:|:-----------:|:---:|
| **yara**-arvo-3848 | 1.07 h | 0.65 h | **1.65×** | 7.98 h | 5.57 h | 1.43× | 9/9 | 0.35 | 0.56 |
| **sleuthkit**-arvo-24893 | 0.38 h | 0.41 h | 0.93× | 11.05 h | 14.32 h | 0.77× | 8/6 | 0.48 | 0.51 |
| **libjxl**-arvo-35172 | 16.26 h | 17.43 h | 0.93× | 23.05 h | 27.06 h | 0.85× | 9/7 | 0.59 | 0.48 |

**Spread — why nothing is significant** (min/max and per-trial std of the same 10-trial samples):

| Project | Base min–max | Base std | Opt min–max | Opt std |
|---------|-------------|---------:|-------------|--------:|
| yara | 0.08–48.00 h | 15.90 h | 0.03–48.00 h | 14.93 h |
| sleuthkit | 0.14–48.00 h | 19.68 h | 0.08–48.00 h | 21.61 h |
| libjxl | 11.88–48.00 h | 13.04 h | 7.98–48.00 h | 18.12 h |

**How significant is this, really:**
- The absolute median shifts are tiny next to the spread. yara's headline "1.65×" is a **~25-minute**
  median saving (1.07 h → 0.65 h); sleuthkit's regression is **~2 minutes** (0.38 h → 0.41 h); libjxl's
  is **~70 minutes** (16.26 h → 17.43 h).
- Every project has ≥1 trial that never crashed (max = 48.00 h) and a per-trial std of **13–22 h**. One
  or two censored trials swamp any sub-hour median difference, so at n=10 the Mann-Whitney test clears
  **none** of them (all p ≥ 0.35) and every A12 is "negligible" (0.48–0.56 ≈ a coin flip).
- So even yara — the only genuine per-exec win (2.16× live exec/s, 1.35× deterministic replay) — does
  **not** convert into a defensible time-to-bug result: the bug is already found in ~1 h from the seed
  corpus, leaving too little wall-clock for a throughput gain to surface above the variance.

#### Every trial, sorted by time-to-bug (h) — `*` = 48.00 h cap (bug never found)

These are the individual trial times behind every median/mean/std above, reconstructed from each trial's
`crash_times.json` with the same target-crash-type filter the report uses (a `crash_type: "crash"` counts;
slow-units/timeouts do **not** — those trials are censored at the 48 h cap). They reproduce the report's
medians and means exactly.

**yara-arvo-3848** — bug found: baseline 9/10, optimized 9/10

| variant | per-trial TTB (h), sorted |
|---------|---------------------------|
| baseline  | 0.08 · 0.17 · 0.20 · 0.67 · 0.92 · 1.22 · 1.48 · 2.64 · **24.39** · **48.00\*** |
| optimized | 0.03 · 0.04 · 0.22 · 0.26 · 0.36 · 0.94 · 1.44 · 1.69 · 2.71 · **48.00\*** |

*Read:* optimized is faster across the fast bulk (7/10 trials < 1 h vs 5/10 baseline) and drops
baseline's lone 24 h straggler — a real, consistent nudge. But each variant still has **one** trial that
never crashes, and that single 48 h point dominates the mean and keeps p at 0.35. The signal is real but
thin.

**sleuthkit-arvo-24893** — bug found: baseline 8/10, optimized 6/8

| variant | per-trial TTB (h), sorted |
|---------|---------------------------|
| baseline  | 0.14 · 0.18 · 0.20 · 0.20 · 0.28 · 0.48 · **4.05** · **9.00** · **48.00\*** · **48.00\*** |
| optimized | 0.08 · 0.14 · 0.19 · 0.27 · 0.55 · **17.31** · **48.00\*** · **48.00\*** |

*Read:* the bug is normally found in **minutes** (6/10 baseline and 5/8 optimized trials under 0.5 h), so
the two variants are indistinguishable on the fast bulk. The entire "0.93×" comes down to which handful of
trials happened to stall (4–17 h) or hit the 48 h wall — pure sampling noise at this n.

**libjxl-arvo-35172** — bug found: baseline 9/10, optimized 7/10

| variant | per-trial TTB (h), sorted |
|---------|---------------------------|
| baseline  | 11.88 · 14.16 · 14.59 · 15.37 · 15.58 · 16.93 · 24.16 · 24.92 · 44.86 · **48.00\*** |
| optimized | **7.98** · **10.38** · **11.29** · 14.70 · 17.07 · 17.80 · 47.34 · **48.00\*** · **48.00\*** · **48.00\*** |

*Read:* this is the clearest case of a misleading ratio. Optimized's **fastest three** trials (7.98,
10.38, 11.29 h) each **beat baseline's fastest** (11.88 h) — per-crash the optimized binary is *not*
slower. The apparent 0.93× "regression" is **entirely** that optimized happened to leave **3** trials
uncrashed vs baseline's **1**. Flip one or two of those coin-tosses and the sign reverses — which is
exactly what "not statistically significant" is telling you.

---

## Failure mode A — Optimizer / corpus-filter timeout

### radare2-arvo-10222 (`ia_fuzz`, Heap-buffer-overflow)
**No optimization was ever produced — the target is too slow/large to process within the time caps.**
It hit **two** timeouts back-to-back:

1. **Harness corpus crash-filter timed out at 14 400 s (4 h).** The prebuild filters each corpus unit
   with `timeout 10 /out/ia_fuzz "$f"`; with a large corpus and a slow `ia_fuzz` binary this loop
   never finished and was killed (`rc=1`). Log:
   > `Phase-2 prebuild corpus failed (rc=1); agent will build it … timed out after 14400 seconds`
2. **Agent optimizer then timed out at 18 000 s (5 h).** With no prebuilt corpus, the agent had to
   grow/profile it itself; it spent the entire 5 h budget iterating hotspots (its `profiles/grow/`
   corpus survives as evidence) and was killed before converging on any contract-compliant fold. Log:
   > `claude optimization for radare2/ia_fuzz timed out` → `Optimization not applied/built for radare2`

**Result:** empty `optimized/` (no `optimization.diff`), fell back to baseline, dropped before phase-3.
**Root cause:** `ia_fuzz` (radare2 binary-analysis harness) is extremely heavy per-execution, so both
the per-unit crash-filter and the profile/iterate loop blow their wall-clock budgets. Not a
correctness failure — a throughput/scale failure of the pipeline itself.

---

## Failure mode B — Correct, profile-guided fold that wins on the profiling corpus but not in the fuzzing regime

The fold **was** chosen the right way (profile → hotspot → optimize) and **does** speed up the corpus
it was profiled on. It "fails" only because the *headline* metric and the *real fuzzing* run use a
**different, much smaller corpus** that never exercises the hotspot. This is a corpus-representativeness
problem, not a target-selection problem.

### sleuthkit-arvo-24893 (`sleuthkit_fls_ext_fuzzer`, Heap-buffer-overflow READ)

**It was profiled first — and the target was a genuine hotspot.** The phase-2 `profile_once` perf
profile (`optimized/source_diff/profiles/profile_once/flat.txt`) ranks `tsk_fs_dir_add` at **3.80%
self-time — the hottest *application* function** after `ext2fs_dent_parse_block` (22.78%) and the ASan
coverage hooks; its O(n²) `meta_addr` comparisons also feed `__sanitizer_cov_trace_cmp8` (**12.09%**).
So this was not a blind pick from reading the source: it is exactly what the profiler flagged.

**Profiling corpus:** **2486 files** — the project's public GCS corpus (3529 merged, minus 1043
crashers removed by the filter). Real ext2/3/4 images with real directory trees, so the O(n) per-add /
O(n²) per-directory duplicate-name scan actually accumulates.

**What was applied** (`tsk/fs/fs_dir.c`, +210 lines; `tsk_fs.h` +2): a **Category-2** acceleration of
that scan in `tsk_fs_dir_add()` — an exact open-addressing **membership hash-set** of the `meta_addr`
values currently in `names[]`. When the new `meta_addr` is absent the scan is provably empty and is
skipped; when present the original scan runs unchanged; on any allocation failure it falls back to the
full scan. Result is **bit-identical `names[]`** for every input.

**On the corpus it was profiled on, it worked:** the agent's self-measured deterministic replay was
**1.108× (≈ +10.8%)** on the 2486-file fixed corpus, and the phase-2 keep-gate measures on that **same
"fixed" corpus** — so the fold was kept legitimately.

**Where the ≤1× numbers come from — a different corpus:**
- The **0.999×** I first reported is **not** the keep-gate number. Phase-4's `record_replay_metric`
  (`phase3_k8s.py:266`) **re-measures replay on the "biggest baseline" k8s corpus and overwrites**
  `setup_metadata["replay"]` (note `corpus_source: "k8s_biggest_baseline"`). For sleuthkit that corpus
  is only **76 files** of small mutated inputs — tiny directories, so the O(n²) term never dominates and
  the hash-set is pure overhead → 83.97 s → 84.05 s.
- Phase-4 **real fuzzing**: TTB **0.93×** (median **0.38 h → 0.41 h**; ~2 min slower), exec/s 1.07×,
  p=0.48 (negligible). sleuthkit reproduces the
  bug in ~0.4 h from small inputs, so the fuzzing regime never builds directories big enough for the
  optimization to matter.

**Verdict:** correct optimization, correctly profile-selected, real +10.8% on its profiling corpus —
but **irrelevant to the metric that matters** because real fuzzing of this target never enters the
large-directory regime. On the `round2-rerun` the phase-2 gate (fixed corpus) will most likely **keep**
it (~1.1× > 1.02×), *not* revert it — my earlier "the 1.02× gate reverts sleuthkit" was wrong; that was
based on the phase-4 0.999× number, which does not gate.

### libjxl-arvo-35172 (`djxl_fuzzer`, Heap-buffer-overflow WRITE)
**What was applied** (`lib/jxl/color_management.cc`, +89 lines): a **Category-2** memoization of
`MaybeCreateProfile()`, which rebuilds a byte-identical ICC profile (header writes, 3×3 matrix
inversions, curve tags, MD5 over the whole blob) on every decoded image. The fold caches the result in
a bounded (`≤1024`) `std::map` keyed on the full color-encoding identity (color space, white point incl.
custom chromaticity, primaries, transfer function, rendering intent) and returns a copy — bit-identical
to recomputation, mutex-guarded, cache-size-bounded so a fuzzer feeding endless distinct chromaticities
can't grow it unboundedly.

**Why it failed:**
- **Replay was UNMEASURABLE.** A corpus input hard-crashes the `-runs=0` replay of `djxl_fuzzer`
  (**exit 139 / SIGSEGV**), aborting the timing run and blanking the speedup to `None`. Log (twice):
  > `Replay speedup measurement failed: replay run 1 failed (exit 139)`
  > `k8s replay metric failed for …/libjxl-arvo-35172: replay run 2 failed (exit 139)`
- **Phase-4 was net-negative:** TTB **0.93×** (median **16.26 h → 17.43 h**; ~70 min slower), exec/s
  **0.93×**, p=0.59 (negligible) — the map/mutex/key-building cost exceeds the recompute savings on this
  corpus (few repeated encodings).

**Verdict:** kept in round2-8 only because replay was unmeasurable *and* the strict gate wasn't active.
This is the exact case the crash-robustness fixes target (per-unit corpus mem-caps + per-slot replay
retry) — on rerun the crashing unit is filtered/retried so the ≤1.0× reality becomes visible and the
gate reverts it.

---

## Failure mode C — Agent explored, all candidate folds reverted

The agent profiled, tried one or more folds, and **reverted every one** because it either didn't beat
baseline on the deterministic gate or the remaining hot paths were input-dependent (contract-forbidden).
Final `optimization.diff` is **empty**; harness logs `No changes made by profile-once-fuzz-folds`.

### freeradius-server-arvo-38283
Only one fold attempted — a **behavior-preserving Category-1 memoization** — reverted purely because it
**did not beat baseline** on the deterministic replay gate. Agent's own summary:
> "the only fold attempted was a behavior-preserving Category-1 memoization that I reverted purely
> because it didn't beat baseline on the deterministic gate."

### graphicsmagick-arvo-8280 (`coder_PTIF_fuzzer` — pyramid-TIFF decoder)
The agent addressed "the dominant editable cluster" and reported keeping one fold and reverting one,
but **nothing survived into the applied optimization** (empty diff; `optimized=False, applied=False` →
dropped by the phase-3 prune). The remaining hotspots are **input-dependent TIFF parse/decode paths**,
which the contract forbids folding:
> "remaining hotspots are input-dependent TIFF parse/decode paths that can't be folded within the
> Behavior-Preservation Contract."

### hunspell-arvo-51102
The `Hunspell` object is **reconstructed per fuzzer iteration**, so per-iteration setup work is not
cacheable across inputs. The only input-invariant candidate (`utf_tbl` caching) measured **~2% slower**
on the frozen corpus and was reverted. Cumulative **1.00×**:
> "`Hunspell` is reconstructed per iteration, leaving only the input-invariant `utf_tbl`, whose caching
> measured ~2% slower on the frozen corpus and was correctly reverted."

### libredwg-arvo-31419 (`llvmfuzz`)
An **honest negative result**: best attempt `8.803 s` with **no fold kept**, cumulative **1.00×**. The
agent explicitly distinguished this from a low-confidence abstention — build/smoke gates passed, so it's
a genuine 1.00×, not `BLOCKED_LOW_CONFIDENCE`.

---

## The one success (for contrast)

### yara-arvo-3848 (`pe_fuzzer`, Heap-buffer-overflow READ) — KEPT, replay 1.35×
**What was applied** (`libyara/object.c`, +20/-1): replaced the libc `strcmp` in
`yr_object_lookup_field()`'s member-search loop with an **inline byte-wise compare**. Both operands are
**input-independent constant identifiers** (module structure declarations and fixed rule bytecode /
format-string literals — neither derives from the fuzzer's mutable bytes), so the result is bit-identical
every iteration — a clean **Category-1** fold. The win comes from removing the ASan/libFuzzer `strcmp`
interceptor and `AddValueForMemcmp` value-profile work (the dominant profile cost), while preserving the
function's own coverage instrumentation.

**Measured:** replay **1.3454×** (22.09 s → 16.42 s over 3693 inputs). Phase-4 (10 trials): TTB
**1.65×** (median **1.07 h → 0.65 h**; ~25 min faster), exec/s **2.16×** — but **p=0.35, A12=0.555
(negligible)**: a real per-exec speedup that did not translate into a statistically-significant
time-to-bug improvement at n=10 (per-trial std ≈ 15 h from 48 h-censored non-crashing trials).

---

## Cross-cutting lessons

- **Three different corpora can disagree.** A fold is (a) *profiled & kept* on the phase-2 **"fixed"
  corpus** (public GCS corpus minus crashers — sleuthkit: 2486 files), (b) *headline-reported* on the
  phase-4 **"k8s biggest baseline" corpus** (what a fuzzing run accumulated — sleuthkit: 76 files, which
  **overwrites** the replay field in `setup_metadata`), and (c) *ultimately judged* by phase-4 **real
  fuzzing** time-to-bug. sleuthkit is +10.8% on (a), 0.999× on (b), 0.93× on (c). The keep-gate uses
  (a), so it correctly kept a real profiled speedup; the "failure" is that (a) isn't representative of
  (c) for a target that crashes fast from small inputs.
- **Profile-guided selection worked; corpus representativeness is the open problem.** sleuthkit's
  `tsk_fs_dir_add` was a legitimate 3.80% profiler hotspot — the pipeline picked the right function. The
  gap is that the corpus which makes it hot (real filesystem images) is not the corpus real fuzzing of
  this bug explores. Improving *which corpus the keep-gate replays on* (or judging directly on TTB) would
  close this — not changing how targets are selected.
- **libjxl was genuinely net-negative.** Its ICC-memo overhead exceeded the savings even before the
  replay SIGSEGV: phase-4 exec/s and TTB were both 0.93×. Here the strict **1.02× gate + crash-robustness
  fixes** are exactly right — the phase-2 replay (also on the fixed corpus) crashed to `None`, which now
  reverts it instead of silently keeping it.
- **Most real hot time is off-limits.** For parser/decoder targets (graphicsmagick TIFF, and the
  bodies of freeradius/hunspell/libredwg), the expensive work is **input-dependent** parse/validate/
  decode — which the contract forbids folding. That leaves little legally foldable surface, so honest
  1.00× is the common outcome.
- **Heavy targets exhaust the budget.** radare2's `ia_fuzz` blew both the 4 h corpus-filter cap and the
  5 h optimizer cap. Scale/throughput of the harness — not fold correctness — is the limiter there.
- **Measurement fragility mattered.** libjxl's replay-SIGSEGV silently blanked its result and let a
  net-negative fold through; the crash-robustness fixes (corpus mem-caps + replay retry) plus the strict
  gate close that hole. See the `round2-rerun` of libjxl + sleuthkit.
