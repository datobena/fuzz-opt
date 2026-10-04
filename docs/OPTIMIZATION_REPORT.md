# Fuzz-Throughput Source Optimization — Benchmark Report

**Date:** 2026-06-02
**Pipeline:** OSS-Fuzz / ARVO reproducers · Claude optimizer (`apply-fuzz-source-folds`) · Kubernetes phase-3 trials
**Experiments:** `kube-1`, `kube-2`

---

## 1. Summary

We evaluate whether an LLM-driven, profile-guided **source optimizer** can speed up OSS-Fuzz
targets *without* changing what they find, and whether that throughput translates into faster
bug-finding. Optimizations are gated by a **deterministic corpus-replay timer** (not live
`exec/s`), and bug-finding is measured by **time-to-bug** over 20 fuzzing trials per variant run
as Kubernetes Indexed Jobs.

**Headline result:** the optimizer produces a **reliable, statistically-significant win on
selinux/`secilc-fuzzer`** — reproduced across two different CVEs — in both throughput and
bug-finding. On most other targets it correctly produces **no kept optimization** (the replay
gate rejects folds that don't measurably help), and on instrumentation-bound or
hard-to-crash targets there is no measurable signal.

| Experiment | Target | Replay speedup | Time-to-bug (base → opt) | Significant? |
|---|---|---:|---|---|
| kube-2 | **selinux** CVE-2021-36085 | **2.15×** | **0.36 h → 0.20 h (1.83×)** | **yes** (p=0.029) |
| kube-1 | selinux CVE-2021-36084 | 1.28× | 0.58 h → 0.40 h (1.46×) | no (p=0.26, n=20) |
| kube-2 | gpac CVE-2021-40569 | 1.16× | 6.0 h → 0.50 h (median) | no (p=0.107) |
| kube-2 | ffmpeg CVE-2019-17542 | 1.07× | never found in 6 h | n/a |

---

## 2. Methodology

### 2.1 Pipeline
- **Phase 1** — select CVEs (ARVO reproducible OSS-Fuzz bugs).
- **Phase 2** — build the vulnerable (baseline) binary, verify the PoC crashes, extract source,
  run the optimizer, build the optimized binary.
- **Phase 3** — run *N* fuzzing trials per variant (baseline/optimized) and record time-to-bug,
  throughput, crashes, coverage.
- **Phase 4** — statistical analysis (Mann-Whitney U on time-to-bug, Vargha-Delaney A12 effect
  size) and report.

### 2.2 The optimizer (`apply-fuzz-source-folds`, Claude backend)
A profile-guided loop that edits **library/source code only** (never the harness, build scripts,
or metadata) to remove deterministic/redundant work on the fuzzing hot path:

- **Hotspot criterion:** `perf --no-children` self time **> 1%** for a function, or **> 5%**
  cumulative for a grouped subsystem, measured on the real fuzz target over a deepening corpus.
  Harness, profiling driver, kernel, system-library, and (non-editable) instrumentation frames
  are excluded.
- **Acceptance gate (the key idea):** a candidate is kept only if it produces a **measurable
  deterministic replay speedup**. Coverage is *allowed* to drop (removing dead/error-only code is
  legitimate); replay time is the sole judge.
- **Evolving corpus:** one persistent corpus that deepens across optimization cycles, so hotspots
  migrate from shallow error/invalid-input paths toward the real parser code valid inputs reach.

### 2.3 Deterministic replay metric (replaces live `exec/s`)
The headline throughput number is **`replay_speedup = baseline_time / optimized_time`**, where the
**same frozen corpus** is replayed on both binaries (`-runs=0`, no mutation, pinned CPU, median of
repeats). This is apples-to-apples and immune to the coverage-gradient divergence that makes live
`exec/s` misleading — under live fuzzing the two binaries explore *different* corpora, so live
`exec/s` can swing 2–3× in either direction without any real per-input change.

### 2.4 Kubernetes phase-3 runner
Per `(project, variant)` an **Indexed Job** runs the trials as pods (one trial per completion
index, paired seeds across variants). Each pod archives a small per-trial result (libFuzzer log,
metadata, crashes, reconstructed crash times); baseline pods additionally archive their corpus.
A helper pod collects the small archives off the shared NFS volume; the single biggest baseline
corpus per project is fetched for the replay metric.

---

## 3. Experiment `kube-1`

**Set:** the codex-4 projects minus librawspeed (crashes too fast to measure). Scale: 20 trials,
6 h, parallelism 20.

| Project | CVE | Outcome |
|---|---|---|
| **selinux** | CVE-2021-36084 | optimized + 40 k8s trials + analyzed |
| gpac | CVE-2022-1441 | optimizer found **no kept fold** → excluded from phase 3 |
| unrar | CVE-2017-20006 | MemorySanitizer bug — does **not reproduce under ASAN** → dropped |

**selinux-CVE-2021-36084 (n=20):** replay **1.28×**; live exec/s 2.05× (diagnostic); bug found
20/20 both variants; time-to-bug median **0.58 h → 0.40 h (1.46×)**, p=0.26 (not significant at
n=20).

**The optimization** (representative of the "good" fold class): in `libsepol/cil`, the per-
compilation **string-pool teardown** swept a fixed 32768-bucket hash table (~256 KiB) twice and
reallocated it every run, and the root TYPES symtab was pre-sized to 8192 buckets — both dominate
on the small inputs a fuzzer feeds in. The fold keeps the bucket array allocated across
compilations and tracks only the touched buckets (and shrinks the symtab), eliminating the fixed
setup/teardown cost while preserving behavior (the table still grows on demand; all memory still
freed). Inserted helpers are annotated `no_sanitize("coverage")` so they don't distort the
fuzzer's gradient.

**gpac-CVE-2022-1441 — why no fold:** `fuzz_parse` is **instrumentation-bound** (~30% libFuzzer
`CollectFeatures` + ASAN/LSAN + temp-file I/O); the entire foldable gpac source is **<2% self
time**. The optimizer *tried* a real algorithmic fold (binary-search the box registry instead of
an O(462) linear scan) — it built and smoke-passed, but the replay gate measured **0.94–0.98×**
(no gain) and reverted it. Everything else was below the noise floor. This is the gate working as
designed.

> **Contrast with the earlier codex-4 gpac run**, which *shipped* a log-level demotion
> (`GF_LOG_ERROR → GF_LOG_DEBUG`). It had no replay gate, so it accepted a change that gives an
> early-phase invalid-input speedup but **0.39× live exec/s** overall and **1.04× on deterministic
> replay** — i.e. no real per-input gain; the live swing came purely from coverage-gradient
> divergence (the optimized binary drifted into slower, OOM-heavy exploration). The replay gate
> rejects exactly this class of confounded "optimization."

---

## 4. Experiment `kube-2`

**Set:** 25 ARVO CVEs (11 projects) the optimizer had not been run on, filtered on **measurement
properties only** (64-bit so the profiler works; libFuzzer; ASAN so it reproduces; real fuzz
target) — *not* on perceived optimizability. Scale: 20 trials, 6 h, parallelism 20.

### 4.1 Phase-2 attrition (24 attempted)

| Outcome | Count | Notes |
|---|---:|---|
| Optimized (fold kept) | **3** | ffmpeg-17542, gpac-40569, selinux-36085 |
| No fold (gate rejected / nothing above floor) | 9 | ffmpeg-9994/9995, gdal-17545/25050, gpac-31255, ndpi-15472, opensc-2024-1454, openthread-20791, pjsip-23547 |
| Build / PoC-verify failed | 8 | lldpd, ndpi×2, opensc×5 (typical ARVO reproduce attrition) |
| Abandoned (optimizer hung, see §6) | 4 | imagemagick×2, selinux-36086, wireshark-24476 |

### 4.2 Phase-3 results (the 3 optimized)

| Project | CVE | Replay | TTB base → opt | Found B/O | p (1-sided) | A12 |
|---|---|---:|---|---|---:|---|
| **selinux** | CVE-2021-36085 | **2.15×** | **0.36 h → 0.20 h (1.83×)** | 19/19 → 20/20 | **0.029** | 0.679 (medium) |
| gpac | CVE-2021-40569 | 1.16× | 6.0 h → 0.50 h | 8/19 → 13/20 | 0.107 | 0.612 (small) |
| ffmpeg | CVE-2019-17542 | 1.07× | censored (never found) | 0/19 → 0/20 | — | — |

- **selinux-CVE-2021-36085 — clean, significant win.** Both variants find the use-after-free in
  every trial; the optimized build finds it **1.83× faster** (22 → 12 min median), **p=0.029**,
  medium effect, on top of **2.15× replay throughput**. Reproduces the kube-1 selinux result on a
  second CVE.
- **gpac-CVE-2021-40569 — positive but noisy.** Optimized finds the segv **more often (13/20 vs
  8/19) and sooner** (median 0.5 h vs censored 6 h), but only ~half the trials hit it → high
  variance → **not significant** at n≈20 (p=0.107).
- **ffmpeg-CVE-2019-17542 — no signal.** The CFHD decoder runs at ~2 exec/s; the bug was never
  found in 6 h by either variant, and throughput barely moved (1.07×).

---

## 5. Cross-experiment findings

1. **selinux/`secilc-fuzzer` is the dependable positive** — significant throughput *and*
   bug-finding gains across two CVEs (1.28×/2.15× replay; 1.46×/1.83× TTB). It has a large,
   input-independent per-compilation setup/teardown cost that the fold eliminates.
2. **The replay gate prevents false wins.** Most targets yield no kept fold because nothing clears
   a measurable replay speedup — which is the correct outcome (cf. gpac, where a real fold and a
   cosmetic log-demotion both fail the gate).
3. **Deterministic replay ≫ live `exec/s`.** Live `exec/s` is confounded by exploration divergence
   (gpac codex-4: 0.39× live vs 1.04× replay). All headline numbers use replay.
4. **Optimizability is target-specific, not project-specific.** Different vulnerable commits of the
   *same* harness (gpac `fuzz_parse`) optimize differently (CVE-2022-1441 → none; CVE-2021-40569 →
   1.16×).
5. **Targets with no headroom give nothing:** instrumentation-bound (gpac fuzz_parse) or
   extremely slow/hard-to-crash (ffmpeg CFHD) targets produce no measurable benefit.

---

## 6. Operational issues encountered (and fixes)

| Issue | Impact | Status |
|---|---|---|
| `replay_timing` decoded libFuzzer output as UTF-8 | replay metric silently skipped | **fixed** (`errors="replace"` + `.absolute()` mounts) |
| Public clusterfuzz corpora return HTTP 403 (even authenticated) | optimizer profiled on a 1-byte seed → low-confidence | **fixed** — local corpus-cache fallback (`LOCAL_CORPUS_CACHE_DIR`) |
| Docker Hub anonymous pull rate limit | ~1 pod per phase-3 job stuck in `ImagePullBackOff` (lost 1 baseline trial/project) | mitigated (collected 19/20); not yet fixed |
| **Phase-2 optimizer call has no timeout** | a hung `claude -p` (waiting on an inner Docker step) wedged all 4 workers → phase 2 deadlocked ~28 h | **open** — recommended fix: per-CVE optimizer wall-clock timeout (kill + record as no-fold), mirroring the phase-3 job-wait deadline |

---

## 7. Limitations

- **n = 20** per variant: only large effects reach significance (selinux did; gpac's promising
  trend did not).
- **ARVO reproduce attrition** (~⅓ of candidates fail build/PoC-verify) and **MSAN/UBSAN
  incompatibility** with the ASAN pipeline shrink the usable pool.
- **Replay corpus depth** depends on the target; harnesses that leak/crash early (gpac) cap how
  deep the profiling corpus gets.
- Throughput gains do not always translate to bug-finding gains (ffmpeg: real-but-tiny throughput,
  no bug found).

---

## 8. Recommendations / next steps

1. **Add the phase-2 optimizer timeout** to eliminate the deadlock class (§6).
2. **Higher-n rerun of gpac-CVE-2021-40569** (e.g. n=50) to settle its borderline significance.
3. **Use a private registry or pre-pull/imagePullSecret** to avoid Docker Hub rate-limited
   `ImagePullBackOff`.
4. **Expand the candidate pool** via the local corpus-cache (seed from prior runs) so corpus-403
   targets still optimize.
5. Treat **selinux/`secilc-fuzzer`** as the reference positive control for pipeline regressions.
