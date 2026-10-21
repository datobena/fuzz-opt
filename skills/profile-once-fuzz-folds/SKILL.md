---
name: profile-once-fuzz-folds
description: Use when optimizing fuzz-target-reachable project source for throughput with a single up-front profile and a fixed corpus instead of repeated re-profiling. Build the corpus once, profile the baseline once on a deterministic replay of that fixed corpus, then iterate the ranked hotspots keeping only folds that beat the previous best replay time. The highest-value folds are algorithmic and data-structure rewrites tuned to the tiny inputs fuzzing actually feeds. For OSS-Fuzz throughput work where edits stay source-only and harnesses, shared fuzz support code, build scripts, Dockerfiles, and project metadata are off-limits, including wrapper-provided extracted historical trees validated through external build and smoke commands.
---

# Profile Once, Fuzz Folds

## What this skill does

Make an OSS-Fuzz target's project source execute faster — more executions per second — without
changing what the code computes on any input.

The method is deliberately one-shot:

1. Grow a corpus once by fuzzing the baseline binary for a fixed window, then **freeze** it.
2. Profile the baseline **once**, by `perf`-recording it *replaying* that frozen corpus.
3. Walk that single ranked hotspot list. For each candidate, apply a source fold, rebuild, and keep
   it only if a deterministic replay of the same frozen corpus is measurably faster than the best
   time so far. Otherwise revert.

Everything is measured on the same frozen input set, so **what you profiled is exactly what you
measure**: the hotspot list and the keep/revert gate can never disagree, and every number is
reproducible.

**Never re-profile.** There is no refresh window, no evolving corpus, and no post-refresh clean pass
in this skill.

## Two things decide every fold

1. **The Behavior-Preservation Contract** (below) decides whether a fold is *allowed*. It is
   non-negotiable and overrides every other instruction here, including any caller asking for
   "aggressive mode".
2. **Replay time on the frozen corpus** decides whether an allowed fold is *kept*. Speed is the only
   judge among contract-compliant folds. The gate does not look at coverage, and coverage may drop
   when — and only when — the removed work is Category-1 fuzz-invariant.

The gate cannot rescue a fold that fails the contract, and the contract cannot rescue a fold that
does not get faster.

## Behavior-Preservation Contract (non-negotiable)

The fuzzer's job is to find real bugs. The asymmetry is absolute:

- Adding crashes (including false positives) is acceptable — they get triaged later.
- **Making the fuzzed binary crash *less* than the original is never acceptable. No speedup buys it
  back.**

Apply a fold only if the per-candidate provenance self-audit in
`references/fuzz_fold_heuristics.md` places it in one of three categories:

- **Category 1 — fuzz-invariant work.** The data it touches does not derive from the fuzzer's
  mutable input bytes (fixed keys/RNG, `time`/`getpid`/`getenv`, constant config or tables, a fixed
  fd, one-time setup state). Safe to precompute, cache, reuse, or stub.
- **Category 2 — bit-exact pure memoization.** Input-derived but pure, returning the bit-identical
  result for every *reachable* input, preserving the original's allocation, error, and failure
  semantics.
- **Category 3 — behavior-preserving algorithmic reimplementation.** The input-derived work is still
  done, but by a faster algorithm or data structure that produces **bit-identical observable
  behavior**. This is usually where the largest speedups live — see "Where the wins actually are"
  below — and it carries the strictest proof obligation: byte-identical output, the same
  tie-break/ordering choice, and the same crash/timeout/OOM/hang behavior on *all* inputs, including
  large and adversarial ones.

Anything that fits none of the three is out of scope. Not "Aggressive", not "document the risk and
proceed" — **reject it**, regardless of measured speedup.

**Never introduce or rely on a fuzzing-mode behavior gate.** A change gated on
`FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`, `FUZZING_BUILD_MODE`, `LIB_FUZZING_ENGINE`, or any
fuzz-only macro/flag that changes control flow, sets a behavior-changing flag (e.g. a `*_NOOPTIMIZE`
flag), or disables an optimization or validation phase is an automatic reject. The fuzzed binary
must traverse the same input-dependent code as production. The timing gate ignores coverage, so it
will **not** catch a bug-removing fold for you — the provenance audit is the only guard. The worked
failure is in `references/fuzz_fold_heuristics.md`.

**Per-input determinism — no cross-iteration input-derived state.** A fold must never make behavior
on one input depend on a *previous* input. Input-*independent* one-time state (constant tables,
parsed config, a fixed RNG seed — Category 1) may persist. Anything derived from the fuzzer's bytes
must be freed or reset before the next iteration, **even if it is memory-bounded**: keep at most a
fixed-size *container*, reset its *contents*. Carrying fuzzer bytes across iterations corrupts
coverage feedback, makes crashes non-reproducible in isolation, and injects history-dependent
throughput decay even when the per-input result looks identical.

### "Aggressive mode" means ambitious, never unsafe

A caller (including the benchmark wrapper) may ask for aggressive mode. That raises **ambition**, not
risk tolerance: hunt bigger Category-3 subsystem rewrites, take on multi-file folds, prefer the
change with the larger expected win. It never relaxes the contract, and it never authorizes behavior
drift on a path that processes fuzzer-derived data. `Aggressive` as a *risk label* is reserved for
changes that can only *add* crashes while provably never suppressing one.

## Where the wins actually are: the fuzzing regime ≠ the production regime

Read this before ranking candidates. It is the single biggest source of missed speedup.

Production code is tuned for the input distribution production sees: large documents, deep trees,
big tables, long-lived processes. **A coverage-guided fuzzer's distribution is the opposite, by
construction:**

- libFuzzer caps generated inputs at `-max_len` (default 4096, or the longest seed when a corpus is
  supplied); AFL++ trims every queue entry; `-merge=1`, `afl-cmin`, and `afl-tmin` all actively
  drive the corpus toward the *smallest* input that keeps the same coverage.
- So on nearly every execution, N — elements parsed, nodes in a graph, symbols in a table, entries
  in a map — is **tens to a few hundred**, and the same small work is repeated millions of times.

The consequence: **asymptotics stop being the right cost model; constants dominate.** For production
an O(log N) structure with a heavy constant is the right call. Under fuzzing the same structure —
a 64 KB zeroed bucket array, a hashed seed, three allocations, and a pointer chase per lookup — can
lose by an order of magnitude to an O(N) linear scan over twelve contiguous entries that fits in one
cache line. The crossover where the "better" algorithm wins may sit at N in the thousands, which a
minimizing fuzzer reaches approximately never.

So **hunt Category-3 folds first, not last**. Categories 1 and 2 remove *some* work; a
regime-appropriate algorithm or data structure removes cost from *every single execution*, including
exactly the tiny inputs the fuzzer spends all of its time on. The highest-yield shapes:

- **Per-iteration fixed overhead that scales with capacity, not with input size** — zeroing,
  `calloc`, or tearing down a structure provisioned for production scale when eight entries were
  used. Replace with grow-on-demand from a small initial capacity, or track the used entries and
  reset only those (generation counter, dirty list). Same contents, cost now O(used).
- **Heavyweight containers at trivial N** — balanced tree, hash map, or skip list holding a handful
  of items where a flat array with a linear scan (or open addressing) returns the identical answer.
- **Allocator traffic** — a per-call heap allocation of a small scratch buffer replaced by an inline
  fixed-size buffer that spills to the heap above a threshold, with identical bytes handed back.
- **Multi-allocation layouts** collapsed into one, when the bytes observed downstream are identical.

`malloc`/`free`/`memset`/`calloc` and init/teardown symbols sitting high in `flat.txt` are the
signature of this class. See `references/fuzz_fold_heuristics.md` Part 2 and Part 3 §1.

### The one guard you must keep

The fuzzer *does* generate large and adversarial inputs, and slow units, timeouts, and OOMs are real
findings it is rewarded for reporting. A blanket swap that turns O(log N) into O(N²) can convert a
large input from "fine" into a timeout — an observable behavior change, and a contract violation.

This is cheap to handle, so it is never a reason to skip the fold:

- **Prefer the adaptive form.** Keep the original algorithm above a size threshold and take the
  fast small-N path below it. That is exactly what production sort routines do (insertion sort under
  a threshold, quicksort above), and it costs one comparison.
- **A blanket swap is fine when N is provably bounded** — by the engine's `-max_len`, by a
  harness-side size cap, or by a structural limit in the format. State the bound and the resulting
  worst case in the audit (e.g. "at `max_len=4096` the scan is ≤ 4096 iterations of two
  instructions — microseconds against a 25 s timeout").
- **Never trade bounded memory for unbounded memory.** An OOM is an observable behavior change too.

## Direct Execution Contract

If the user asks to optimize OSS-Fuzz project source for fuzzing throughput with a single up-front
profile, or names this skill:

1. Start executing after validating inputs and environment.
2. Restrict repo-tracked edits to source and header files only: `.c`, `.cc`, `.cpp`, `.cxx`, `.h`,
   `.hh`, `.hpp`, `.hxx`.
3. Read the harness first and mark harness-owned code out of scope. Treat the harness file plus
   shared fuzz-only support code and wrappers (for example `fuzz-common.c`, `fuzz-wrapfd.c`, or
   similar files under `fuzz/`) as harness code.
4. Do not edit harness code, `build.sh`, Dockerfiles, metadata, corpora, or project config unless
   the user explicitly expands scope.
5. Apply only Category-1, Category-2, and Category-3 folds, per the Behavior-Preservation Contract.
   Never introduce obvious UB, non-termination, deadlock, or invalid lifetimes.
6. Build the fixed corpus once, profile the baseline once on a replay of it, then iterate the ranked
   hotspots from that single profile.
7. Rebuild and smoke-run after every accepted pass, and keep a fold only if it beats the previous
   best replay time.
8. **Never re-profile.** Stop when the ranked hotspot list is exhausted or the safety cap is hit,
   then report the cumulative speedup.

## Required Inputs

Required arguments:

- `source_dir`
- `harness_path`

Required environment unless wrapper-provided validation commands fully replace the helper path:

- `OSS_FUZZ_PROJECT`
- `OSS_FUZZ_DIR`

If either required variable is unset, infer and export it before stopping:

1. Infer `OSS_FUZZ_DIR` by walking upward from `source_dir` until a directory contains both
   `projects/` and `infra/helper.py`.
2. Infer `OSS_FUZZ_PROJECT` from `source_dir` relative to `OSS_FUZZ_DIR`:
   - if `source_dir` is under `OSS_FUZZ_DIR/local/<name>` or `OSS_FUZZ_DIR/projects/<name>`, use
     `<name>`
   - otherwise use `basename(source_dir)` only when `OSS_FUZZ_DIR/projects/<basename(source_dir)>`
     exists
3. Export inferred values into the command environment before running helper scripts or Docker.
4. If either inference fails or is ambiguous, stop and report the exact missing variables plus the
   attempted inferred values.

Optional environment:

- `FUZZ_TARGET`
- `FUZZ_SOURCE_FOLDS_MODE`
- `FUZZ_SOURCE_FOLDS_CORPUS_DIR` — merged seed corpus (input to the grow window)
- `FUZZ_SOURCE_FOLDS_OUT_DIR` — `/out` of the build under test (the optimized build)
- `FUZZ_SOURCE_FOLDS_BASELINE_OUT_DIR` — `/out` of the baseline build; used to grow the corpus, take
  the one profile, and anchor the baseline replay time
- `FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR` — where the grown-and-frozen fixed corpus snapshot is
  written/read
- `FUZZ_SOURCE_FOLDS_PREBUILT_CORPUS` — when `1`, the wrapper already grew+froze the fixed corpus
  and profiled the baseline; skip steps 3 and 4 and read those artifacts instead of running
  `build_corpus.py` / `replay_fuzzer_profile.py`
- `FUZZ_SOURCE_FOLDS_CORPUS_BUILD_DURATION` — seconds to fuzz the baseline to grow the corpus
  (default `3600`)
- `FUZZ_SOURCE_FOLDS_REPLAY_PROFILE_SECONDS` — minimum perf-sample wall-clock for the replay profile
  loop (default `120`)
- `FUZZ_SOURCE_FOLDS_REPLAY_REPEATS` — replay repeats for the timing gate (default `3`)
- `FUZZ_SOURCE_FOLDS_CORPUS_REPLAY_BUDGET` — time budget for corpus sizing (default `1800`); passed
  to `build_corpus.py --replay-budget-secs`. The corpus is capped to the largest N whose full
  replay-gate measurement fits this budget, so a slow target stays tractable; `0` keeps the full
  corpus
- `FUZZ_SOURCE_FOLDS_MAX_CORPUS_FILES` — absolute cap on corpus files, applied *after* time-sizing
  (min of the two)
- `FUZZ_SOURCE_FOLDS_PROFILE_CPU`
- `FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR`
- `FUZZ_SOURCE_FOLDS_BUILD_TIMEOUT`, `FUZZ_SOURCE_FOLDS_SMOKE_RUNS`, `FUZZ_SOURCE_FOLDS_SMOKE_SEED`,
  `FUZZ_SOURCE_FOLDS_RUN_TIMEOUT`
- `FUZZ_SOURCE_FOLDS_VALIDATION_MODE`, `FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND`,
  `FUZZ_SOURCE_FOLDS_BUILD_COMMAND`, `FUZZ_SOURCE_FOLDS_SMOKE_COMMAND`, `FUZZ_SOURCE_FOLDS_WORK_DIR`

Accepted but ignored — this skill profiles once on a fixed corpus, so it never deepens a corpus or
refreshes a profile:

- `FUZZ_SOURCE_FOLDS_EVOLVING_CORPUS_DIR`
- `FUZZ_SOURCE_FOLDS_REFRESH_PROFILE_DURATION`
- `FUZZ_SOURCE_FOLDS_BASELINE_PROFILE_DURATION` / `FUZZ_SOURCE_FOLDS_PROFILE_DURATION`

Defaults:

- mode: contract-compliant — Categories 1, 2, and 3 only. `FUZZ_SOURCE_FOLDS_MODE=aggressive` (or a caller asking for aggressive mode) raises ambition,
  never risk tolerance; see "Aggressive mode means ambitious, never unsafe" above
- corpus build duration: `3600`
- replay profile minimum sample seconds: `120`
- replay repeats: `3`
- corpus replay budget: `1800` (`0` = keep the full corpus); probe sample: `100`; sizing margin:
  `0.7`; N floor: `200`
- stop rule: ranked hotspot list exhausted, or the safety cap (max cycles / wall-clock) is hit

If `source_dir` or `harness_path` is missing, ask once. If wrapper-provided validation commands are
absent and the helper-path environment is still missing after inference, stop and report the exact
missing variables.

## Bundled Resources

Read these before the first cycle:

- `references/fuzz_fold_heuristics.md` — the contract in full, the provenance audit, candidate
  classes, rewrite patterns, coverage suppression, refusal rules
- `references/profile_guided_analysis.md` — how to rank the single profile into a working set
- `references/fallback_profiling.md` — what to do when `perf` is unavailable

Reuse these bundled helper scripts rather than recreating their logic (paths are relative to this
skill directory):

- `scripts/build_corpus.py --out-dir <baseline-out> --corpus-dir <merged-corpus> --evolving-corpus-dir <grow-workdir> --snapshot-dir <fixed-corpus> --artifact-dir <artifacts> --fuzz-target <target> --duration <seconds> --cpu <cpu> [--replay-budget-secs <s>] [--filter-ncpu <n>] [--probe-sample <k>] [--replay-repeats <n>] [--sizing-margin <f>] [--n-min <n>] [--max-corpus-files <n>]`
- `scripts/replay_fuzzer_profile.py --out-dir <baseline-out> --corpus-dir <fixed-corpus> --artifact-dir <profile-dir> --fuzz-target <target> --min-sample-seconds <seconds> --cpu <cpu>`
- `scripts/replay_timing.py --out-dir <optimized-out> --baseline-out-dir <baseline-out> --corpus-dir <fixed-corpus> --fuzz-target <target> --repeats <n> [--cpu <cpu>] [--min-partial-units <k>]`
  - Prefers a clean full-corpus replay. If a *deterministic* corpus crasher (one the per-unit filter
    cannot catch — it only crashes deep in the batch, not in isolation) aborts every pass, it
    salvages a **partial** measurement: the replay *rate* (`executed_units / time`) over the prefix
    both binaries reach. Because the crash is deterministic, both binaries stop at the same unit, so
    the rate ratio stays apples-to-apples. The result then carries `replay_partial: true`; treat such
    a speedup as weaker evidence and demand a wider margin. `--min-partial-units` (default `0`) sets
    the floor below which a truncated run is too startup-dominated to trust.
- `scripts/verify_source_only_changes.py <backup_root>`

When wrapper-provided validation commands are absent, also reuse:

- `scripts/phase2_build_check.py <source_dir> [--run-fuzzer <target>]`

## Workflow

### 1. Validate prerequisites

1. Confirm `source_dir` exists and `harness_path` resolves from it.
2. Infer and export `OSS_FUZZ_DIR` / `OSS_FUZZ_PROJECT` if unset (see Required Inputs); stop if
   ambiguous.
3. Derive `fuzz_target` from `FUZZ_TARGET` if set, otherwise from the harness filename stem.
4. Treat missing `docker` or `python3` as blockers.
5. Resolve the **baseline binary** as `FUZZ_SOURCE_FOLDS_BASELINE_OUT_DIR` if set, otherwise
   `FUZZ_SOURCE_FOLDS_OUT_DIR`. The baseline binary is already built by the wrapper — never rebuild
   it for the baseline.
6. If `FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND` is set, treat it as the authoritative wrapper-provided
   sequential validation gate and do not require `phase2_build_check.py`.
7. If only `FUZZ_SOURCE_FOLDS_BUILD_COMMAND` and `FUZZ_SOURCE_FOLDS_SMOKE_COMMAND` are set, they are
   still sequential gates: never run them in parallel, because the smoke command depends on build
   artifacts from the build command.
8. Prefer `perf`; if it is unavailable or blocked, follow `references/fallback_profiling.md`.

### 2. Protect existing work

If `source_dir/.git` exists:

1. Do not rewrite commits or revert unrelated user edits.
2. Before each cycle, create a cycle-local backup root under
   `/tmp/profile-once-fuzz-folds/<timestamp>/`.
3. Before editing any file in that cycle, save its pre-cycle contents into the backup root.
4. Use those backups to revert only that cycle's edits when validation or the timing gate fails.

If `source_dir/.git` does not exist:

1. Initialize a throwaway local git repo in `source_dir`.
2. Commit a baseline snapshot with a local throwaway identity.
3. Restore only the current cycle's changes from that local repo when needed.

### 3. Build the fixed corpus (once)

**Prebuilt fast path:** if `FUZZ_SOURCE_FOLDS_PREBUILT_CORPUS` is set, the wrapper has already grown
and frozen the fixed corpus into `FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR` (and profiled the baseline —
see step 4). **Do not run `scripts/build_corpus.py`.** Confirm the snapshot dir is non-empty and
proceed; if it is empty, output `BLOCKED_LOW_CONFIDENCE` and stop. (The wrapper does this heavy step
itself because a large-corpus crash-filter/replay exceeds the agent's per-tool timeout.)

Otherwise, build it yourself:

1. Run `scripts/build_corpus.py` with the **baseline binary**, the merged seed corpus
   (`FUZZ_SOURCE_FOLDS_CORPUS_DIR`), a grow working directory, and
   `--snapshot-dir "$FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR"`. Use `--duration` from
   `FUZZ_SOURCE_FOLDS_CORPUS_BUILD_DURATION` (default `3600`) and `--cpu` from
   `FUZZ_SOURCE_FOLDS_PROFILE_CPU`. Also pass
   `--replay-budget-secs "$FUZZ_SOURCE_FOLDS_CORPUS_REPLAY_BUDGET"` (default `1800`); if
   `FUZZ_SOURCE_FOLDS_MAX_CORPUS_FILES` is set, pass it as `--max-corpus-files`.
2. **Time-budget sizing happens before the crash filter.** The script probes per-unit replay time on
   a small random sample of the merged corpus, then caps the corpus to the largest N whose full
   replay-gate measurement (`2·repeats` passes) fits `--replay-budget-secs`. A slow target thus gets
   a small representative corpus that completes the filter/profile/gate within budget; a fast target
   keeps its full corpus. The chosen N and the measured per-unit time land in
   `corpus_build_metadata.json → sizing` (flag `full`/`capped`/`too_slow`/`no_estimate`).
3. It then seeds the grow corpus from the sized merged seeds (crashing/hanging inputs filtered out,
   in parallel, `detect_leaks=0`, matching the replay), fuzzes the baseline read-write for the
   duration, re-caps to N after growing, then freezes a flat immutable snapshot of the **grown**
   corpus into `FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR`.
4. **That snapshot is the fixed corpus for every later step.** If it is empty, output
   `BLOCKED_LOW_CONFIDENCE` and stop.

### 4. Profile the baseline once (on replay)

**Prebuilt fast path:** if `FUZZ_SOURCE_FOLDS_PREBUILT_CORPUS` is set, the wrapper has already
profiled the baseline into `<FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR>/profile_once/` (`children.txt`
— inclusive time, the primary ranking input — plus `flat.txt`, `callgraph.txt`, `metadata.json`).
**Do not run `scripts/replay_fuzzer_profile.py`.** Read those
artifacts as the single profile, persist a `current_profile.json` pointing at them, and go to step 5.
If they are missing or empty, output `BLOCKED_LOW_CONFIDENCE` and stop.

Otherwise, profile it yourself:

1. Run `scripts/replay_fuzzer_profile.py` with the **baseline binary** and
   `--corpus-dir "$FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR"`, writing into
   `<FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR>/profile_once/`. Use `--min-sample-seconds` from
   `FUZZ_SOURCE_FOLDS_REPLAY_PROFILE_SECONDS` (default `120`) and `--cpu` from
   `FUZZ_SOURCE_FOLDS_PROFILE_CPU`.
2. This perf-records the baseline replaying the fixed corpus read-only, looped to the sample floor,
   and emits `children.txt` (inclusive), `flat.txt`, `callgraph.txt`, and `metadata.json`. The script picks the replay form from
   the binary rather than assuming one: `afl-showmap -C` through the forkserver for an AFL build,
   libFuzzer's `-runs=0` otherwise. Do not hand-run either form — a libFuzzer invocation against an
   AFL binary exits before executing anything and yields a profile of process startup with no target
   symbols in it.
3. Persist the profile and write a small `current_profile.json` recording the artifact dir plus the
   top hotspot files and symbols. **This is the only profile.**
4. If the profiler produces no completed report, output `BLOCKED_LOW_CONFIDENCE` and stop.

### 5. Build the ranked hotspot working set (once)

1. Follow `references/profile_guided_analysis.md` to rank hotspots by **inclusive time** from
   `children.txt` (self-time `flat.txt` is the tiebreaker; `callgraph.txt` for caller chains). This
   credits each target function with the allocator/libc/kernel cost it drives, so allocation-heavy
   source — not the uneditable `__asan`/libc leaves — rises to the top of the list.
2. Enrich the ranked list with heuristic candidates from `references/fuzz_fold_heuristics.md`, even
   when the cost is split across helpers or only weakly visible in the profiler.
3. Skip candidates that require harness edits, changes to shared harness support code, or
   non-source-file changes unless the user explicitly expands scope.
4. Record each candidate with: exact source location, hotspot evidence or heuristic trigger,
   provenance audit and assigned Category, rewrite pattern, expected impact, coverage risk, and risk
   label (`Safe`, `Safe*`, `Aggressive`).

### 6. Anchor the baseline replay time (once)

1. Run `scripts/replay_timing.py` on the fixed corpus for the **baseline binary** to record
   `baseline_median`. Use `--repeats` from `FUZZ_SOURCE_FOLDS_REPLAY_REPEATS` (default `3`) and
   `--cpu` from `FUZZ_SOURCE_FOLDS_PROFILE_CPU`.
2. Set `previous_best = baseline_median`. This is the value the first cycle must beat.

### 7. Iterate the hotspots (one cycle per hotspot or tightly-related group)

For each ranked candidate, in order:

1. Apply the source fold(s). Every function you **insert** must be named with the `fold_` prefix and
   carry both coverage-suppression attributes on its definition; existing functions whose body you
   edit keep their instrumentation. See Part 5 of
   `references/fuzz_fold_heuristics.md` for the exact pattern and why the prefix matters.
2. Run `verify_source_only_changes.py` on the cycle's backup root; if it fails, revert the offending
   edits and rerun verification.
3. Validate build and smoke run through the selected gate: `FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND` if
   set; otherwise `FUZZ_SOURCE_FOLDS_BUILD_COMMAND` then, only after it succeeds,
   `FUZZ_SOURCE_FOLDS_SMOKE_COMMAND`; otherwise
   `phase2_build_check.py <source_dir> --run-fuzzer <fuzz_target>`. If build or smoke fails, repair
   or revert this cycle's edits and continue to the next hotspot.
4. **Acceptance gate (vs previous best).** First confirm the fold passed the provenance audit and is
   Category 1, 2, or 3 — the timing gate runs only on contract-compliant folds and cannot rescue one
   that fails the audit. Then run `replay_timing.py` on the fixed corpus for the optimized `/out`
   (`FUZZ_SOURCE_FOLDS_OUT_DIR`). Keep the fold only if `optimized_median` is measurably below
   `previous_best` — past run-to-run noise, roughly 1–2% or the observed jitter, whichever is larger.
   On keep, set `previous_best = optimized_median`. On no improvement, revert this cycle and leave
   `previous_best` unchanged. Do not gate on coverage — but a coverage drop on an input-dependent
   path means the fold was not contract-compliant, so revert it and record why.
5. **Never re-profile.** Continue to the next ranked hotspot from the same profile.

### 8. Stop

Stop when the ranked hotspot list is exhausted, or when a conservative safety cap is hit (max cycles
≈ list length plus small slack, or a wall-clock budget).

## Candidate Guardrails

Full rewrite patterns and refusal rules are in `references/fuzz_fold_heuristics.md`. The
non-negotiable ones:

1. Do not edit harness-owned code, including shared fuzz-only support code or wrappers such as
   `fuzz-common.c`, unless the user explicitly expands scope.
2. Do not remove or freeze the primitive the harness is directly fuzzing.
3. Do not remove, disable, skip, gate, or short-circuit input-dependent parsing, validation,
   optimization passes, or state transitions — whether by deletion, early return, a flag, or an
   `#ifdef`. If fuzzer input can drive the path, its behavior stays unchanged.
4. Never introduce or rely on a fuzzing-mode behavior gate (Forbidden #1 in the heuristics
   reference). Automatic reject.
5. Do not replace synchronization, timing, randomness, or syscalls blindly; only when the result is
   Category-1 fuzz-invariant and the rewrite does not destabilize execution.
6. Prefer a regime-appropriate rewrite, cache, pool, precompute, or memory-backed fast path over
   semantic deletion. A Category-3 reimplementation may change the internal *method*; it may not
   change observable behavior.
7. A Category-3 swap that regresses the worst case on large inputs needs a size threshold with the
   original algorithm retained above it, unless N is provably bounded and you state the bound.
8. Never retain input-derived state across fuzz iterations, even bounded.
9. Suppress coverage instrumentation on every function this skill **inserts**, and name it `fold_*`.
   The coverage map is the fuzzer's gradient signal; new helpers, wrappers, init/cleanup routines,
   fast paths, memoization shims, and pool managers that did not exist in the original source must
   not divert mutation pressure toward themselves. This matters more here than in a coverage-gated
   skill: the acceptance gate ignores coverage entirely, so an un-suppressed inserted function would
   silently distort the gradient without the gate ever noticing.

## Completion Criteria

Finish only when all are true:

1. the ranked hotspot list is exhausted or the safety cap was reached
2. source-only verification succeeds on the accumulated final tree
3. the selected final build succeeds
4. the requested harness smoke run succeeds through the selected validation gate
5. every skipped, narrowed, or reverted candidate is documented with the reason

## Reporting

Report:

1. **corpus build** — duration used, seed-corpus file count in vs fixed-corpus file count out, the
   time-budget sizing result (measured per-unit replay time, chosen N, flag
   `full`/`capped`/`too_slow`/`no_estimate`), and whether `perf` or a fallback profiler was used
2. **the single profile** — hotspot count and top hotspot files/symbols
3. **headline cumulative speedup** — `baseline_median`, `final_optimized_median`, and
   `cumulative_speedup = baseline_median / final_optimized_median` as a multiplier and a percent
4. **per-cycle table** — hotspot, kept or reverted, `previous_best → this_median`, and the delta
5. **changed files** — with each applied candidate's Category (1/2/3) and risk label (`Safe`,
   `Safe*`, `Aggressive`)
6. **skipped, narrowed, or reverted candidates** and why
7. source-only verification status, and `inserted_funcs_annotated: N/N`
8. final build status, and whether it used wrapper-provided commands or the OSS-Fuzz helper path
9. final harness smoke-run status
10. whether the stop condition was list-exhausted or cap-reached

If the corpus build produced an empty corpus, or the replay profiler produced no usable report,
output `BLOCKED_LOW_CONFIDENCE` instead of claiming success.
