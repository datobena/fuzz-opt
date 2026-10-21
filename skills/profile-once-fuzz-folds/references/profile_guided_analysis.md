# Hotspot Ranking and Candidate Analysis

How to turn the **one** baseline profile into a ranked working set of fold candidates for
`profile-once-fuzz-folds`.

This is analysis only: it produces candidates, it does not apply them. Do not call `claude`, `codex`,
or any external skill runner from here — do the analysis yourself.

**Cadence reminder.** This skill profiles exactly once, on the frozen corpus, using the baseline
binary. There is no evolving corpus, no refresh window, and no re-profile after a fold lands. Rank
once from that single profile, then work the list.

## Inputs

- `source_dir` — local project source checkout to edit
- `harness_path` — harness file, relative to `source_dir` or absolute
- `OSS_FUZZ_PROJECT`, `OSS_FUZZ_DIR`
- the profile artifacts written by `scripts/replay_fuzzer_profile.py` (or staged by the wrapper) in
  `<FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR>/profile_once/`: `flat.txt`, `callgraph.txt`,
  `metadata.json`
- `FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR` — the frozen corpus that profile was taken on
- `FUZZ_SOURCE_FOLDS_OUT_DIR`, `FUZZ_SOURCE_FOLDS_BASELINE_OUT_DIR`, `FUZZ_SOURCE_FOLDS_PROFILE_CPU`

## Core rules

**The Behavior-Preservation Contract overrides everything here.** Read it at the top of
`fuzz_fold_heuristics.md` before ranking anything. A candidate is recommendable only if the
provenance self-audit places it in Category 1 (fuzz-invariant), Category 2 (bit-exact pure
memoization), or Category 3 (behavior-preserving algorithmic reimplementation). Anything that
disables, skips, gates, or approximates a path processing fuzzer-derived data is Forbidden and must
never be reported as a fold — above all, never recommend a change gated on `FUZZING_BUILD_MODE_*` /
`LIB_FUZZING_ENGINE` or any fuzz-only macro that alters an input-dependent path. Adding crashes is
fine; removing one never is.

1. Recommend changes in library and project source only. Never optimize the harness itself or shared
   fuzz-only support code.
2. Never recommend non-source-file edits (`build.sh`, Dockerfiles, metadata, corpora).
3. Rank from the **inclusive time** of the single baseline profile — the `children.txt` report
   (`perf report --children`, its **Children** column), which credits each function with the cost of
   everything it calls. This is what attributes the cost of an allocation (the `__asan` allocator +
   libc + kernel page-fault traffic it triggers) back to the **target source function that drives
   it**, instead of leaving it stranded on uneditable `__asan`/libc leaf rows that no fold can touch.
   Use **self time** (`flat.txt`, `--no-children`) as the tiebreaker and to pinpoint the editable
   work inside a hot caller. If `children.txt` is empty or absent (the call graph failed to record),
   fall back to self-time ranking and say so in the report.
4. Rank by expected reduction in **replay time on the frozen corpus**, not raw CPU percentage alone.
   That is the exact quantity the acceptance gate measures.
5. **Weight algorithmic and data-structure candidates (Category 3) highest.** Under the fuzzing
   regime, constants beat asymptotics — see "The fuzzing cost model" in `fuzz_fold_heuristics.md`
   Part 2. Per-execution fixed overhead (init, teardown, zeroing, allocator traffic) is normally the
   biggest single lever, because the corpus units are tiny and that overhead is paid on every one.
6. Coverage may drop **only** when the removed work is Category-1 fuzz-invariant (for example
   error-only logging on input-independent state). A coverage drop on a path that processes
   fuzzer-derived data means the fold changed input-dependent behavior — illegal, not a win, no matter
   how much replay time it saves.
7. When cost is split across a helper stack, recommend one subsystem-level change rather than several
   tiny local folds.
8. Never recommend a fold that carries input-derived state across fuzz iterations, even a bounded
   cache, pool, or table. The target must stay a function of the current input alone.
9. End the analysis with exactly one status line: `FOLDS_FOUND: N` (use `FOLDS_FOUND: 0` when nothing
   survives the audit).

## Phase 1 — Understand the target

1. Read the harness: its one-time setup, its per-input flow (`LLVMFuzzerTestOneInput` or equivalent),
   and what it hands to the library. Everything in that file, and in shared fuzz-only support code, is
   out of scope for edits — but you must know it to trace provenance.
2. Read `projects/$OSS_FUZZ_PROJECT/build.sh` and `Dockerfile` **for context only** — which flags,
   sanitizer, and engine the build uses, and whether coverage instrumentation is globally disabled.
   Never edit them.
3. Note the engine (libFuzzer vs AFL++) and any input-size bound (`-max_len`, a harness-side size
   cap, a structural limit in the format). That bound is what lets a Category-3 fold justify a blanket
   swap instead of an adaptive threshold.
4. Sample the frozen corpus: file count, median and maximum unit size. A fold that only pays off above
   1 KB is worthless when the median unit is 40 bytes — and that same fact is what makes small-N
   algorithmic folds pay.

## Phase 2 — Read the profile

The profile artifacts already exist; do not re-record them. `children.txt` is `perf report
--children` (an inclusive **Children** column and a **Self** column) — the PRIMARY ranking input.
`flat.txt` is `perf report --stdio --no-children` (self time only) — the tiebreaker. `callgraph.txt`
is the callee-annotated view (useful for reading a caller chain); `metadata.json` records how the
sample was taken. If `children.txt` is empty (no LBR/FP call graph recorded), rank on `flat.txt` and
note the degraded confidence in the report.

Read `metadata.json` first and confirm the profile is real: it must show target symbols and a
completed sample window. A profile whose top frames are only process startup, dynamic-loader, or
`main` means the replay form did not execute the target — report `BLOCKED_LOW_CONFIDENCE` rather than
ranking noise.

**Why inclusive, not self.** A target function that allocates is cheap in *self* time — the cost
lands downstream on `__asan::Allocator::Allocate`, libc, and kernel page-fault handling, all of which
you cannot edit. Self-time ranking therefore buries the exact functions worth folding and surfaces
uneditable allocator leaves. Inclusive time credits that whole chain to the *source* function that
started it, so the allocation-heavy parser routine rises to where it belongs. Reducing the
allocations it drives (fewer/cheaper allocations, buffer reuse, stack allocation, hoisting out of a
loop) harvests the target + `__asan` + libc + kernel cost together.

Signals worth extra weight (read them in `children.txt` by inclusive %, then confirm the editable
site with `flat.txt` + the caller chain):

- a target-source function with **high inclusive but low self** time → it drives expensive
  descendants; the usual descendant is allocation (`malloc`/`free`/`calloc`/`operator new` →
  `__asan` allocator → page faults). Fold the allocation at this source site; never the allocator.
- `memset` / `calloc` / init / reset / teardown / destroy / clear high anywhere → capacity-
  proportional per-iteration cost (heuristics Part 2, shape a and c); find its target caller
- generic container internals (hash, tree, map, `rehash`, `bucket`) ranking above the project's own
  parsing code → a container provisioned for a regime the fuzzer never reaches
- a broad tail with no single dominant self frame → inclusive ranking already rolls it into the
  owning subsystem; fold at that subsystem level

## Phase 3 — Build the working set

Work from `children.txt`, ranking by **inclusive (Children) %**. Build two lists:

1. target-source functions with more than `2%` inclusive time
2. grouped subsystems or caller chains whose combined inclusive time exceeds `5%`

A function with low self but high inclusive time is a PRIMARY candidate, not a skip — it is cheap
itself but drives expensive descendants. Do not, however, just grab the outermost target frame
(`LLVMFuzzerTestOneInput`, a top-level parse entry) because its inclusive % is near-total: descend
its caller chain to the specific source site where the expensive work (usually allocation) is
actually driven, and fold there.

For each item capture: function or subsystem name, **inclusive % and self %**, source module or DSO,
and a representative caller chain.

Exclude as EDIT TARGETS (never fold these directly — but see the reattribution note below):

- functions defined in the harness file or in shared fuzz-only support code
- kernel, dynamic-loader, and system-library frames you cannot edit from project source
- sanitizer and coverage-runtime frames — build-level, not source-level, and out of scope.
  Match both the C spellings (`__asan_*`, `__sanitizer_cov_*`) **and the C++-namespaced ones**
  (`__asan::*`, `__sanitizer::*`, `__lsan::*`, `__ubsan::*`), which is where the bulk of the
  *self*-time cost sits: on a real PcapPlusPlus profile the top two self-time rows were
  `__asan::Allocator::Allocate` (12.3%) and `__sanitizer::StackDepotBase<...>::Put` (6.1%),
  ranking *above* the first project function (`pcpp::BgpLayer::parseBgpLayer`, 4.8%). These
  frames live inside the target's own DSO, so the DSO-share check will not remove them — only
  this filter will. An agent handed them unfiltered will try to fold code it does not own.

**Reattribution (the point of inclusive ranking).** Excluding a leaf as an edit target does NOT mean
discarding its cost. In `children.txt` that cost is already counted inside the inclusive % of the
target-source function that called it. So when an `__asan`/libc/kernel leaf is hot, walk its caller
chain (in `children.txt` / `callgraph.txt`) up to the nearest **target-source** ancestor and credit
the cost there — that ancestor becomes the candidate. The fold reduces the work the ancestor drives
(fewer/cheaper allocations, reuse, stack allocation). **Contract reminder:** reducing genuine,
redundant allocations is a behavior-preserving Category 1/3 fold; pooling, interning, or replacing
the allocator to *dodge* ASan is Forbidden — every real allocation the target still makes must keep
its sanitizer coverage.

Still report the sanitizer self-time share you set aside. It is a large, unfoldable constant in every
profile (ASan ~7–30% depending on allocation and call density), and knowing it is the difference
between "the target spends 5% in parsing" and "5% in parsing and 22% in ASan".

## Phase 4 — Deep analysis

Read the code before classifying it. For each remaining item, minimum required analysis:

1. read the full function body, or the relevant grouped helper stack
2. trace at least two levels of callers
3. inspect the key callees
4. answer:
   - what does this code actually do?
   - are its inputs deterministic for the same fuzz input?
   - are those inputs invariant across iterations?
   - does the specific result matter for bug-finding or code-path exploration?
   - **is the cost proportional to the input, or to a fixed capacity chosen for production scale?**
   - **at the N this corpus actually produces, is a simpler structure or algorithm faster?**
   - can the work be cached, precomputed, pooled, memoized, reimplemented, or served from memory?
   - is the cost split across adjacent helpers that should be folded together?

Then run the **provenance self-audit** from `fuzz_fold_heuristics.md` on every item: enumerate the
inputs, trace each back toward the harness `data`/`size`, and assign Category 1, Category 2,
Category 3, or REJECT. Only Categories 1–3 are recommendable.

The most common high-value options, each only when it passes the audit:

- regime-appropriate algorithm or data structure returning byte-identical output — Category 3;
  adaptive below a size threshold unless N is provably bounded
- capacity-proportional init/teardown made proportional to use (generation counter, dirty list,
  grow-on-demand) — Category 3
- inline / single-allocation layout replacing per-call heap traffic — Category 3
- one-time precompute plus reuse — Category 1 (the precomputed value must be input-invariant)
- static immutable object reuse — Category 1
- object pools or free lists — Category 1, with contents reset to identical state each iteration
- memoized helpers — Category 1 when the key is input-invariant, else Category 2 (bit-exact, total)
- finite input-to-output lookup tables — Category 2 only when exact and total over the reachable
  domain; an assumed-complete domain is Forbidden #5
- file I/O fast paths backed by a memory buffer — only when the contents are input-invariant
  (Category 1) and EOF / short-read / error semantics are reproduced exactly
- cached or fixed syscall results irrelevant to the fuzz target — Category 1
- crypto fast paths only when the material is input-independent (Category 1) and the crypto is not the
  fuzz target; a real integrity or verification check on fuzzer data is Forbidden
- diagnostic or synchronization elision only when it touches no input-dependent control flow and
  preserves every error-detection branch
- inline hints for tiny hot helpers (no semantic change)

Reject any candidate that removes, disables, skips, gates, or short-circuits input-dependent parsing,
validation, optimization passes, or state transitions — including via a `*_NOOPTIMIZE` flag or a
fuzzing-mode `#ifdef`. Do not soften this to "likely contributes to coverage": if input can drive the
path, it is a reject.

## Phase 5 — Rank

For each surviving candidate assign:

- **Category**: `1`, `2`, or `3`. Anything else is not a candidate — drop it.
- **Safety**: `Safe`, `Safe*`, or `Aggressive` (see the risk labels in `fuzz_fold_heuristics.md`)
- **Coverage risk**: `low`, `medium`, `high`
- **Impact**: `high`, `medium`, `low` — expected reduction in frozen-corpus replay time

Write each recommendation as a concrete source change, not a pattern name.

Rank by:

1. expected replay-time reduction on the frozen corpus — with per-execution fixed overhead weighted
   above work that only large inputs reach
2. ease of validating through the build-plus-smoke gate and the replay-timing gate
3. confidence that the rewrite does not destabilize execution

When two candidates target the same subsystem, prefer the one with the larger expected win. Coverage
may legitimately fall when a fold removes Category-1 fuzz-invariant code, so do not rank on coverage
preservation in that case — but a coverage drop on an input-dependent path is a red flag that the fold
is illegal, and no timing win rescues it.

## Phase 6 — Report

```text
## Profile-Guided Fold Report

### Corpus and profile
- frozen corpus: N files, median unit X bytes, max Y bytes
- profile: sample seconds, engine/replay form, top hotspot files

### Optimization Candidates
| Rank | Scope | Function / Subsystem | Inclusive % (Self %) | Category | Safety | Coverage Risk | Impact | Recommendation |

### Detailed Analysis (per candidate)
- location and caller chain
- provenance audit: inputs enumerated, which derive from the fuzzer's mutable bytes, the trace toward
  `data`/`size`, and the assigned Category (1, 2, or 3)
- the category argument: invariance (1), bit-exactness (2), or byte-identical behavior plus
  tie-break and worst-case/threshold reasoning (3)
- coverage-risk argument
- concrete rewrite

### Skipped / Blocked
- candidate and reason

FOLDS_FOUND: N
```

## If `perf` was unavailable

Follow `fallback_profiling.md`, use the same report shape, and mark the pass explicitly as lower
confidence with the profiler or method that was actually used.
