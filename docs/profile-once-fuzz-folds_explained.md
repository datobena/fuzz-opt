# The `profile-once-fuzz-folds` skill — what it contains and what it does

This is the optimization **skill** that Codex (and Claude) runs in phase 2 of the benchmark — the thing that actually produced the selinux speedups. It lives at `~/.codex/skills/profile-once-fuzz-folds/` (byte-identical copy in `~/.claude/skills/`). This document explains what's inside it and how it works.

---

## 1. What a "skill" is here

A skill is a self-contained package that teaches an agent a repeatable procedure. It's just files on disk:

- a **`SKILL.md`** — the instructions/contract the agent reads and follows,
- **`references/`** — deeper knowledge docs the agent consults while working,
- **`scripts/`** — ready-made helper tools the agent runs instead of improvising,
- **`agents/openai.yaml`** — codex-specific wiring so Codex exposes it as a callable skill.

When the benchmark invokes `codex exec "Use $profile-once-fuzz-folds ..."`, Codex loads this folder and executes the procedure in `SKILL.md`.

---

## 2. What it's for (one sentence)

**Make an OSS-Fuzz target's project source run faster — higher fuzzing throughput (more executions/second) — by applying source-level rewrites ("folds"), without changing what the code computes.**

Why throughput matters: a fuzzer finds bugs roughly in proportion to how many inputs it can try per second. Speed up the code under test and the same fuzzing campaign explores more, finds bugs sooner. The skill's motto, stated explicitly: **"Speed is the only judge; coverage may drop."**

A quick glossary (the only terms you need):

| term | meaning |
|---|---|
| **fuzz target / harness** | the small entry function the fuzzer drives; the code *it* calls is what we optimize |
| **corpus** | a collection of input files the fuzzer feeds to the target |
| **profile** (`perf`) | a measurement of which functions burn the most CPU time ("hotspots") |
| **replay** | running a binary over a *fixed* set of inputs once, no mutation (`-runs=0`) — used to time it |
| **fold** | a source rewrite that "folds away" redundant work (a cache, a fast path, a bulk operation…) |

---

## 3. The core idea — "profile once, on a fixed corpus"

Most profile-guided optimizers re-profile repeatedly as they change the code. This skill deliberately does **not**. Its whole design is:

1. **Build one fixed corpus** and freeze it.
2. **Profile the baseline exactly once** by recording it *replaying* that frozen corpus → a single ranked list of hot functions.
3. **Walk that list**, applying one fold at a time, and **keep a fold only if replaying the same frozen corpus gets measurably faster** than the best time so far.

The payoff of freezing everything: **what you profile is exactly what you measure.** The hotspot list and the keep/reject decision use the *same* inputs, so they always agree, and every measurement is deterministic and reproducible. (This is why I could re-measure the speedups later and get matching numbers.)

---

## 4. The workflow it follows (from `SKILL.md`)

1. **Validate** — confirm the source dir, harness, `docker`/`python3`, `perf`; resolve the baseline binary (already built by the wrapper — it never rebuilds the baseline).
2. **Protect work** — snapshot files before each change so a failed fold can be reverted cleanly.
3. **Build the fixed corpus once** (`build_corpus.py`) — filter out crashing/hanging seeds, optionally fuzz the baseline for a window to grow it, then freeze an immutable snapshot. *(In our selinux runs this is where the corpus cap took effect; grow-duration was 0, so it just crash-filtered and froze.)*
4. **Profile the baseline once** (`replay_fuzzer_profile.py`) — `perf`-record the baseline replaying the frozen corpus → `flat.txt` (hot functions), `callgraph.txt`, `metadata.json`.
5. **Rank the hotspots** (using `references/profile_guided_analysis.md`) and enrich with heuristic candidates.
6. **Anchor the baseline time** (`replay_timing.py`) — record `baseline_median`; this is the number every fold must beat.
7. **Iterate hotspots** — for each candidate: apply the fold → verify only source files changed → rebuild + smoke-test → **time it; keep only if faster than the previous best, else revert.** Never re-profile.
8. **Stop** when the hotspot list is exhausted (or a safety cap), and report the cumulative speedup.

If it can't get a real build/profile loop working, or the corpus comes out empty, it prints `BLOCKED_LOW_CONFIDENCE` instead of pretending it succeeded.

---

## 5. What's in each file

### `SKILL.md` (224 lines) — the contract
The step-by-step procedure above, plus required/optional inputs (env vars like `FUZZ_SOURCE_FOLDS_CORPUS_DIR`, `..._FIXED_CORPUS_DIR`, `..._REPLAY_REPEATS`), defaults, guardrails, completion criteria, and the exact report format.

### `references/` — the decision knowledge (the "brain")

| file | what it provides |
|---|---|
| **`fuzz_fold_heuristics.md`** (232 ln) | the catalog of *which* rewrites are allowed, how to classify them, and when to refuse — see §6 |
| **`profile_guided_analysis.md`** (354 ln) | how to turn raw `perf` output into a ranked, evidence-backed hotspot working set |
| **`fallback_profiling.md`** (60 ln) | what to do if `perf` is unavailable: try `samply` → `callgrind` → static scan, and downgrade the confidence label |

### `scripts/` — the tools (so the agent doesn't reinvent them)

| script | what it does |
|---|---|
| **`build_corpus.py`** | grow + freeze the one fixed corpus: crash-filter seeds, fuzz the baseline read-write for the window, snapshot a flat immutable copy |
| **`replay_fuzzer_profile.py`** | `perf`-record the baseline **replaying** the fixed corpus (`-runs=0`, looped to a sample floor) → flat/callgraph/metadata |
| **`replay_timing.py`** | the acceptance measurement: time a binary replaying the fixed corpus, N repeats, report median + `baseline/optimized` speedup |
| **`real_fuzzer_profile.py`** | alternative profiler that records an *active* fuzzing window (used by the sibling "fuzz-while-profiling" skill; not the replay path) |
| **`phase2_build_check.py`** | rebuild the modified source tree in Docker and smoke-run it — the validation gate when the wrapper doesn't supply its own |
| **`verify_source_only_changes.py`** | assert the pass only touched source/header files (nothing else slipped in) |

### `agents/openai.yaml` — codex wiring
The codex-specific manifest: display name "Profile Once Fuzz Folds", a short description, and a `default_prompt` that tells the agent to build the corpus once, profile once, iterate hotspots with the replay-timing gate, never re-profile, and report the cumulative speedup. This is the only file that differs between the codex and claude copies of the skill.

---

## 6. What rewrites it looks for, and what it refuses

`fuzz_fold_heuristics.md` defines **six candidate classes** of fold:

1. **Immutable setup-state reuse** — cache one-time initialization instead of redoing it each run.
2. **Fixed key/parameter reuse** — precompute values that never change across inputs.
3. **Fixed randomness/time/syscall folding** — replace nondeterministic or irrelevant calls with constants when the result doesn't affect the target.
4. **Deterministic helper memoization** — cache the result of pure, repeatedly-called helpers.
5. **Object reuse / pooling / one-time decode** — reuse buffers/objects instead of re-allocating.
6. **Synchronization / bookkeeping elision** — drop locking or housekeeping that's pointless under single-threaded fuzzing.

*(The selinux folds map onto these: the `ebitmap` word-wise rewrite and `hashtab`/`symhash` fast paths are class-4/5 "do the same work cheaper"; the empty-table skips and fuzzing-only table cap are class-6 bookkeeping elision.)*

Each candidate gets a **risk label**: `Safe`, `Safe*`, or `Aggressive` (the skill defaults to *aggressive* — it'll accept fuzz-only behavior drift for speed, but never obvious undefined behavior, hangs, or instability).

**Hard refusal rules / guardrails:**
- Edit **only** source/header files (`.c .cc .cpp .cxx .h .hh .hpp .hxx`). Never the harness, shared fuzz support code, `build.sh`, Dockerfiles, corpora, or project metadata.
- Read the harness first and mark it out of scope — don't optimize away the very thing being fuzzed, or delete input-dependent parsing/validation that drives coverage.
- **Coverage-suppression rule:** every *new* function the skill inserts gets `__attribute__((no_sanitize("coverage")))`. The fuzzer steers itself using a coverage map; if the optimizer's own helper functions were instrumented, they'd hijack that signal. Functions whose bodies are edited in place keep their instrumentation.

---

## 7. How this connects to what we ran

When you asked to optimize selinux, the benchmark ran `codex exec "Use $profile-once-fuzz-folds ..."`. Codex (gpt-5.5) executed exactly the workflow above: built the fixed corpus, profiled `secilc-fuzzer` once, ranked hotspots (the `ebitmap`/`hashtab`/`symtab` machinery surfaced), applied folds one at a time, and kept each only when `replay_timing.py` confirmed a faster median — landing at **2.15×**. Fable 5 and the original new-kube-1 run used this same skill; the only thing that differed was the model driving it.

---

*Source: `~/.codex/skills/profile-once-fuzz-folds/` — `SKILL.md`, `references/{fuzz_fold_heuristics,profile_guided_analysis,fallback_profiling}.md`, `scripts/{build_corpus,replay_fuzzer_profile,replay_timing,real_fuzzer_profile,phase2_build_check,verify_source_only_changes}.py`, `agents/openai.yaml`.*
