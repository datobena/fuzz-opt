# Hotspot Ranking and Candidate Analysis

How to turn the **one** baseline profile into a ranked working set of fold candidates for
`profile-once-fuzz-folds`.

This is analysis only: it produces candidates, it does not apply them. Do not call `claude`, `codex`,
or any external skill runner from here — do the analysis yourself.

**Cadence reminder.** The harness profiles exactly once, on the frozen corpus, using the baseline
binary, before your session starts. There is no evolving corpus, no refresh window, and no
re-profile after a fold lands — and you never build a corpus, fuzz, or profile yourself. Rank once
from that single profile, then work the list.

## Inputs

- `source_dir` — local project source checkout to edit
- `harness_path` — harness file, relative to `source_dir` or absolute
- `OSS_FUZZ_PROJECT`, `OSS_FUZZ_DIR`
- the profile artifacts the harness wrote to `<FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR>/profile_once/`:
  `hotspots.txt` (primary ranking input) and `hotspots.json`, plus `children.txt`, `callgraph.txt`,
  `flat.txt`, `dso.txt`, `metadata.json`. If `hotspots.txt` is missing or empty, output
  `BLOCKED_LOW_CONFIDENCE` and stop — never profile to replace it
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
3. Rank from **`hotspots.txt`**, by its **caused%** column. Each row is one target-source function
   (project code in the target binary; the harness, fuzz-support code, sanitizer runtime, libc and
   kernel are never rows). A sample is credited to the NEAREST target-source function on its call
   chain, walking from the leaf, so a row's caused% is its own code plus the sanitizer, allocator,
   libc and kernel work it triggers directly — the `__asan` allocator, quarantine, fake-stack and
   interceptor cost that would otherwise sit stranded on uneditable leaf rows — but not the work of
   other target functions it calls, which have rows of their own. Use `children.txt` (inclusive call
   trees) and `callgraph.txt` (who calls a leaf) only to drill into a chosen row; use `flat.txt` for
   self-time detail.
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

The profile artifacts already exist; do not re-record them, and never profile anything yourself.

Read `metadata.json` and the header of `hotspots.txt` first. The header gives the total samples and
splits them into **target-attributed** (credited to some target-source function) and **outside
target** (afl-showmap, the driver and harness, the loader, kernel work with no target function on
the chain), each broken down by class. The harness has already refused profiles in which the
target's own functions got almost no samples; if the table nevertheless has no rows, report
`BLOCKED_LOW_CONFIDENCE` rather than ranking noise.

`hotspots.txt` columns, all in % of ALL samples except `of-tgt%`:

| column | meaning |
|---|---|
| `caused%` | samples credited to this function (nearest target-source frame from the leaf) |
| `of-tgt%` | the same, as % of target-attributed samples |
| `self%` | the leaf is this function's own code |
| `san/cov%` | leaf in the sanitizer or coverage runtime (`__asan*`, `__sanitizer*`, interceptors, fake stack, AFL's coverage callback), triggered directly by this function |
| `3rdp%` | leaf in std-library templates (`std::map`, `std::vector`, ... from the libc++/libstdc++ headers) or third-party code compiled into the binary, called directly |
| `alloc%` | under malloc/free/calloc/realloc/new/delete or the ASan allocator internals, called directly by this function |
| `libc%`, `kern%` | leaf in a shared library / the kernel, reached directly from this function |
| `other%` | leaf in the harness or driver code this function calls back into |
| `incl%` | inclusive: this function anywhere on the chain (counted once per sample) |

`self + san/cov + 3rdp + alloc + libc + kern + other = caused`. Inlined functions appear under the
non-inlined function that contains them.

The `ed` column says whether you can edit the row's file: `y` — it is in your tree and a
`.c/.cc/.cpp/.cxx/.h/.hh/.hpp/.hxx` file; `n` — the hot function's code lives in a generated file
(`hotspots.json` gives the reason in `edit_note`): either a file the build generates that is not in
your tree (an amalgamation: one generated `.c` concatenated from the project's sources), a generator input
the debug info points at (a `.l`/`.y`/`.re` scanner or parser), or a checked-in file of a type you
may not edit (an `.inc` fragment included into a `.c`). Treat an `n` row like this:

- the cost is real, so the row still ranks; but never edit the generated file — the next build
  regenerates it and the fold silently disappears;
- find the function's real source in your tree (`grep -rn` for its name) and fold there if that
  file is editable C/C++;
- if the code exists only in a file you may not edit (`.l`, `.y`, `.inc`), fold the C/C++
  functions it calls or that include it, or the data it is handed, instead; the row itself is then
  out of reach.

What the columns tell you (confirm the editable site in the source and with `children.txt` /
`callgraph.txt` before folding):

- **high `alloc%`** → the function allocates or frees a lot per call; fewer/cheaper allocations,
  buffer reuse, inline storage. Fold at this source site; never the allocator.
- **high `san/cov%`** → sanitizer or coverage-runtime work this function triggers. Drill into
  `callgraph.txt` to see which: `__asan_stack_malloc_*` (a local whose address is taken, so ASan
  builds a fake stack frame on every call — move the buffer into a cold helper), a per-byte
  interceptor call (`memcpy`, `strlen`, `strchr` on tiny inputs), or the coverage callback
  (`__sanitizer_cov_trace_pc_guard`), which only drops when the function executes fewer edges,
  i.e. through an algorithmic fold.
- **high `3rdp%`** → the function spends its time in std-library containers or third-party code
  it calls (`std::map` lookups, a vendored library). You cannot edit that code; a fold replaces the
  container or algorithm the function uses, or calls it less.
- **high `self%`** → the function's own instructions: algorithmic and data-structure folds.
- **a project allocator or string-copy wrapper** (the project's own `malloc`/`strdup` wrapper,
  whose row is nearly all `alloc%`) is where its callers' allocations land. Look up its callers in
  `callgraph.txt` / `children.txt`; the fold is usually in a caller that allocates per call.
- **high `incl%` but low `caused%`** → a wrapper; its cost is in the rows of the functions it calls.
  Do not take it for its `incl%` (a top-level parse or dispatch loop): descend to those rows.
- `memset` / `calloc` / init / reset / teardown / destroy / clear rows high up → capacity-
  proportional per-iteration cost (heuristics Part 2, shapes a and c).
- generic container internals (hash, tree, map, `rehash`, `bucket`) ranking above the project's own
  parsing code → a container provisioned for a regime the fuzzer never reaches.

## Phase 3 — Build the working set

Work down `hotspots.txt` in rank order (by `caused%`):

1. **Rows.** A single row is a candidate when its `caused%` is at least the keep bar of the
   acceptance gate (about 1% of replay time, or the jitter you measured, whichever is larger). That
   is the most a fold confined to that function can save, so a row below the bar cannot pass the
   gate alone.
2. **Groups.** Rows below the bar are candidates only as part of a group that ONE change fixes —
   rows sharing a cause (the same per-character helper family, the same buffer pattern, the same
   subsystem or file) — whose summed `caused%` reaches the bar.

The list is exhausted when no untried row or group clears the bar.

For each item capture: function or group, its `hotspots.txt` rank, `caused%` and dominant
column(s), its source file:line, and a representative caller chain from `children.txt` /
`callgraph.txt`.

The table already leaves out everything you must not fold. Keep these out of your edit targets
when you drill into `children.txt` / `callgraph.txt` / `flat.txt`, which still show them:

- functions defined in the harness file or in shared fuzz-only support code
- kernel, dynamic-loader, and system-library frames you cannot edit from project source
- sanitizer and coverage-runtime frames — build-level, not source-level, and out of scope.
  Match both the C spellings (`__asan_*`, `__sanitizer_cov_*`) **and the C++-namespaced ones**
  (`__asan::*`, `__sanitizer::*`, `__lsan::*`, `__ubsan::*`). They sit inside the target's own DSO,
  so they top `flat.txt`; their cost is already credited to the target rows that trigger them.

**Contract reminder:** reducing genuine, redundant allocations is a behavior-preserving Category 1/3
fold; pooling, interning, or replacing the allocator to *dodge* ASan is Forbidden — every real
allocation the target still makes must keep its sanitizer coverage.

Still report the sanitizer share from the header. It is a large, unfoldable constant in every
profile, and knowing it is the difference between "the target spends 5% in parsing" and "5% in
parsing and 22% in ASan".

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
- profile: target-attributed vs outside-target split from the `hotspots.txt` header, top rows

### Optimization Candidates
| Rank | Scope | Function / Subsystem | caused% (dominant column) | Category | Safety | Coverage Risk | Impact | Recommendation |

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

## If the profile is missing

There is no fall-back profiler and no static-only pass. If `hotspots.txt` is missing or empty,
output `BLOCKED_LOW_CONFIDENCE` and stop.
