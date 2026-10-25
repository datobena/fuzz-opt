# Fuzz Source Fold Heuristics

How to find, classify, and rank source-level fuzzing-throughput optimizations ("folds").

Scope: library and project source reached by the harness. Do **not** edit the harness itself or
shared harness-only support code (`fuzz-common.c`, wrappers, sibling `fuzz/` helpers) unless the
user explicitly expands scope.

---

## Part 1 — The Behavior-Preservation Contract (read first; overrides everything below)

The fuzzer exists to find real bugs. An optimization that makes the fuzzed binary crash **less** than
the original has destroyed the experiment, even at 100× throughput. The asymmetry is the whole point:

- Adding new or false-positive crashes is acceptable — they get triaged later.
- Removing or hiding a real crash is **never** acceptable, and no speedup can buy it back.

Guarantee this by construction, not by hope. Apply a fold **only** if it provably falls into one of
the three categories below. Anything else is out of scope — not "Aggressive", not "document the risk
and proceed". Reject it.

Categories 1 and 2 *eliminate* work (skip it, or cache its result). Category 3 *reimplements*
input-dependent work with a faster method that yields bit-identical observable behavior. All three
are bit-preserving: none may change what the binary does on any input.

### Category 1 — Fuzz-invariant work

The data the fold touches does **not** depend on the fuzzer's mutable input bytes; it would be
identical on every iteration no matter what the fuzzer produced. Safe to precompute once, cache,
reuse, stub, or replace with a constant.

The only kinds of deletion or stubbing that are ever safe:

- keypair / RNG / crypto material generated from a fixed or input-independent seed
- `time()`, `clock_gettime()`, `getpid()`, `getuid()`, `getenv()`, hostname, and other syscalls that
  return the same value every iteration
- a constant config file, fixed test vector, or immutable lookup table loaded once
- a fixed file descriptor whose contents never change across iterations
- one-time setup state built once and reused unchanged

Decision test: *if you captured this value once and returned it forever, could any fuzzer input ever
make the original produce a different value?* If **no**, it is Category 1.

### Category 2 — Bit-exact pure memoization

The work **is** a function of fuzzer-derived input, but the function is pure and you return the
**bit-identical** result the original would have computed for **every reachable input** — not just
the corpus you happened to see. All of these must hold:

- the function is pure (no side effects the rest of the program observes)
- the cache or LUT is keyed on the **full** input, not a lossy or partial key
- the returned value is bit-identical for every input — no approximation, no assumed-complete domain
- the original's allocation, error, and failure semantics are preserved

This is "the same function called repeatedly with the same arguments doing the same work": memoize an
expensive deterministic transform and hand back its identical output.

### Category 3 — Behavior-preserving algorithmic reimplementation

The work **is** a function of fuzzer-derived input and you still **do** it — but you replace the
algorithm or data structure with a faster one producing **bit-identical observable behavior**. You
are not caching a result; you are computing the same result by a cheaper method.

**This is usually where the largest speedups live.** Part 2 explains why and how to find them.

Why it is admissible in a behavior-preserving skill: if observable behavior is bit-identical for
every input, no crash can be added or removed *by construction* — the same argument that makes
Category 2 safe. (Supporting confidence, not the guarantee: the target is a profiled hotspot, so it
is among the most heavily fuzzed code in the binary, and a latent bug on that path was likely already
surfaced. This raises confidence; it does not lower the bar.)

All of these MUST hold — a stricter bar than Category 2, because you are changing the *method*:

- **Bit-identical observable behavior for every reachable input.** Same return value and output
  bytes, same side effects the rest of the program observes, same allocation / error / failure
  semantics. "Does the same *thing*" is not enough; it must produce the same *bytes*, not merely a
  valid answer to the same problem.
  - **Tie-break trap.** If the original's result is only *one* of several valid answers — one of
    several equal-cost shortest paths, an unspecified iteration order, a particular hash-bucket order
    — the replacement must reproduce the **same** choice, *or* you must prove nothing reachable
    observes more than the invariant (e.g. only the path *cost* is ever read, never the path). This
    is exactly the Dijkstra → A\* risk: A\* may return a different equal-cost path. If a different
    valid answer could steer any downstream branch, **REJECT**.
- **Crash / timeout / OOM / hang behavior preserved on all inputs, including large and adversarial
  ones.** See "The one guard you must keep" in Part 2 — this is the failure mode unique to Category 3
  and it has a cheap standard fix.
- **Determinism.** The reimplementation stays a pure function of the *current* input: no ASLR-,
  time-, or iteration-order-dependent behavior, and no cross-iteration input-derived state.

Decision test: *would this produce byte-for-byte the same output and the same crash / timeout / error
behavior as the original on **every** reachable input?* If you cannot argue yes for all inputs — not
just the corpus you saw — make it adaptive, or **REJECT**.

### Per-input determinism (applies to all three categories)

A fold must never make behavior on one input depend on a *previous* input. Input-independent
one-time state (constant tables, parsed config, language keywords, a fixed RNG seed — Category 1) may
persist. Anything derived from the fuzzer's bytes must be freed or reset before the next iteration,
**even if it is memory-bounded**: keep at most a fixed-size *container*, reset its *contents*.

Coverage-guided fuzzing assumes behavior is a function of the current input alone. A stateful target
corrupts coverage feedback, makes crashes non-reproducible in isolation, and injects
history-dependent throughput decay — even when the per-input result looks identical. This is the
string-interning-pool anti-pattern: retaining the interned pool across iterations instead of tearing
it down each time.

### Forbidden — automatic reject, regardless of measured speedup

1. **Fuzzing-mode behavior gates.** Never introduce or rely on
   `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`, `FUZZING_BUILD_MODE`, `LIB_FUZZING_ENGINE`, or any
   fuzz-only macro/flag to change control flow, set a behavior-changing flag (e.g. a `*_NOOPTIMIZE`
   flag, disabling an optimizer or a validation phase), skip work, or otherwise make the fuzzed build
   diverge from production on any path that processes input. The fuzzed binary MUST traverse the same
   input-dependent code as production. *(This is exactly what removed the bug in the worked example
   below.)*
2. Disabling, skipping, or short-circuiting any phase that processes fuzzer-derived data — parsing,
   validation, optimization passes, transforms, normalization, bounds checks.
3. Approximate or lossy "fast paths" on input-derived data.
4. Eliding error detection, validation, or bounds/size checks reachable from input.
5. Memoization or LUT on a fuzzer-derived key whose output domain is assumed complete but not proven
   total and exact.

### Mandatory per-candidate provenance self-audit

Answer in writing for every candidate and record the answers in the pass report. If you cannot answer
them, you do not understand the candidate well enough to fold it — reject it.

1. What are the inputs to the code being folded? Enumerate them.
2. Trace each input back toward the harness `data` / `size` (or the harness's input source). Does any
   input derive from the fuzzer's mutable bytes?
3. If none do → **Category 1**. Allowed.
4. If some do and you are **caching or looking up** the result → is the replacement bit-exact for
   every reachable input, the function pure, and are all side effects and error semantics preserved?
   Yes → **Category 2**. No → **REJECT**.
5. If some do and you are **reimplementing** the algorithm or data structure → does it produce
   byte-for-byte the same observable behavior for every reachable input (same output, same
   tie-break/ordering choice or invariant-only observation), **and** preserve crash / timeout / OOM /
   hang behavior on all inputs including large and adversarial ones (adaptive threshold, or a stated
   bound on N)? Yes → **Category 3**. No → **REJECT**.
6. Does the change alter any branch, bounds/size check, flag, or pointer that input-processing code
   later **reads**, or that decides whether a vulnerable path runs? Yes → **REJECT**. (A Category-3
   fold may change *internal* allocation sizes or layout, but only where nothing input-processing
   observes the difference.)
7. Is the change gated on a fuzzing-only macro or mode, and does it alter any input-dependent path?
   Yes → **REJECT**.

### Anti-pattern: optimizing the bug away (a real failure from an earlier run)

The optimizer added, to the function that allocates a transform object:

```c
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
*dwFlags |= FLAGS_NOOPTIMIZE;   /* library's "skip the optimizer" flag */
#endif
```

The fuzzer always builds with `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`, so this permanently set the
flag, disabling the library's pipeline-optimization pass — the exact path where a known
heap-buffer-overflow lived. The optimized binary scored a ~1.3× "speedup" purely by never running the
vulnerable code, and the PoC stopped crashing. Forbidden #1 + #2: a fuzzing-mode gate that skips an
input-dependent phase.

The valid optimization on the **same** target instead memoized an expensive curve-sampling routine (a
deterministic `pow()` loop rebuilt identically every iteration) and returned an identical duplicated
result — Category 2. The same code paths ran, the bug still reproduced, and it earned a real ~1.1×
speedup.

---

## Part 2 — The fuzzing cost model: why algorithmic folds win

Rank candidates with this in mind. It is the single biggest source of missed speedup.

Production code is tuned for the input distribution production sees: large documents, deep trees, big
tables, long-lived processes. **A coverage-guided fuzzer's distribution is the opposite, by
construction:**

- libFuzzer caps generated inputs at `-max_len` (default 4096, or the longest seed when a corpus is
  supplied). AFL++ trims every queue entry. `-merge=1`, `afl-cmin`, and `afl-tmin` all drive the
  corpus toward the *smallest* input that preserves coverage.
- The fuzzer is rewarded for *keeping inputs small*: small inputs mutate faster and execute faster,
  so the corpus converges on them.
- Therefore on nearly every execution N — elements parsed, nodes in a graph, symbols in a table,
  entries in a map — is **tens to a few hundred**, and the same small work repeats millions of times.

**Asymptotics stop being the right cost model; constants dominate.** For production, an O(log N)
structure with a heavy constant is the right engineering call. Under fuzzing, that same structure — a
64 KB zeroed bucket array, a hash seed, three allocations, a pointer chase per lookup — routinely
loses by an order of magnitude to an O(N) linear scan over twelve contiguous entries in one cache
line. The crossover where the asymptotically better algorithm wins may sit at N in the thousands,
which a minimizing fuzzer reaches approximately never.

Also note what dominates the *total* when units are tiny: **fixed per-execution overhead**. If the
median corpus unit is 40 bytes, a fold that only helps inputs above 1 KB is worth nothing, while
shaving a `calloc` + `memset` from the per-iteration setup is worth everything.

So hunt Category-3 folds **first**, not last. Categories 1 and 2 remove *some* work; a
regime-appropriate algorithm removes cost from *every* execution, including exactly the tiny inputs
the fuzzer spends all its time on.

### The highest-yield shapes

**a. Per-iteration cost that scales with capacity, not with input size.** The classic: a table
provisioned for production scale, cleared wholesale between iterations when eight entries were used.

```c
/* before: O(capacity) every iteration */
memset(tbl->buckets, 0, tbl->capacity * sizeof(*tbl->buckets));

/* after: O(used) — identical observable contents, generation-stamped */
for (size_t i = 0; i < tbl->used_count; i++)
    tbl->buckets[tbl->used[i]] = (bucket_t){0};
tbl->used_count = 0;
```

Equivalent forms: a generation/epoch counter compared on read instead of clearing at all; a dirty
list; grow-on-demand from a small initial capacity instead of a large fixed allocation.

**b. Heavyweight containers at trivial N.** A balanced tree, hash map, or skip list holding a handful
of items where a flat array with a linear scan — or open addressing over a small power-of-two table —
returns the identical answer. Watch the tie-break trap: if iteration order over the container is ever
observable downstream, the replacement must reproduce the original order.

**c. Allocator traffic.** A per-call heap allocation of a small scratch buffer, replaced by an inline
fixed-size buffer that spills to the heap above a threshold:

```c
char inline_buf[256];
char *buf = (n <= sizeof inline_buf) ? inline_buf : malloc(n);
...
if (buf != inline_buf) free(buf);
```

Only when nothing observes the pointer's provenance and the failure semantics of the original
allocation are preserved (a `malloc` that could fail and be handled must still be able to fail on the
spill path).

**d. Multi-allocation layouts collapsed into one** — a header plus payload allocated together — when
the bytes handed back and every observable pointer relationship are identical.

**e. Redundant passes** over the same input-derived buffer fused into one, when the output bytes and
error ordering are identical. Be careful: fusing passes can change *which* error is reported first.
If it can, reject or preserve the original ordering explicitly.

High `alloc%` rows in `hotspots.txt`, and `malloc` / `free` / `memset` / `calloc` and init-teardown
symbols sitting high in `flat.txt`, are the signature of this whole class. So is a profile whose top
entries are generic container or allocator code rather than the project's parsing logic.

### The one guard you must keep

The fuzzer *does* generate large and adversarial inputs, and slow units, timeouts, and OOMs are real
findings it is rewarded for reporting. A blanket swap that turns O(log N) into O(N²) can convert a
large input from "fine" into a timeout — an observable behavior change, and a contract violation.

This is cheap to handle, so it is never a reason to skip the fold:

- **Prefer the adaptive form.** Keep the original above a size threshold, take the fast small-N path
  below it. Exactly what production sort routines do (insertion sort under a threshold, quicksort or
  heapsort above). Cost: one comparison.
- **A blanket swap is fine when N is provably bounded** — by the engine's `-max_len`, a harness-side
  size cap, or a structural limit in the format. State the bound and the resulting worst case in the
  audit, e.g. "at `max_len=4096` the scan is ≤ 4096 iterations of two instructions — microseconds
  against a 25 s timeout."
- **Never trade bounded memory for unbounded memory.** An OOM is an observable behavior change too.

---

## Part 3 — Candidate classes

Ordered by typical yield under the cost model above.

### 1. Algorithmic and data-structure reimplementation (Category 3)

Look for a profiled hotspot doing genuine input-dependent work through an algorithm or data structure
whose cost is dominated by big constants, or provisioned for a larger regime than the fuzzer feeds:

- a fixed structure sized for production-scale data (large hash tables, big preallocations) that the
  fuzzer keeps tiny — the zero/init/teardown of the oversized structure *is* the cost
- an asymptotically-good algorithm with a heavy constant on small inputs (a balanced tree where a
  short linear scan wins; Dijkstra where A\* wins)
- a multi-allocation layout where a single inline allocation returns identical bytes
- per-iteration teardown proportional to capacity rather than to what was used

Prefer:

- a regime-appropriate structure that **grows on demand** from a small initial size — identical
  contents, cheaper capacity management
- a faster algorithm returning the **byte-identical** result, or an **adaptive** fast path below a
  size threshold with the original retained above it
- reset-what-was-used (generation counter, dirty list) instead of clear-everything
- an inline or single-allocation layout handing back the same bytes

Reject when:

- the faster algorithm can return a *different* valid answer (equal-cost path, different ordering)
  that any downstream code observes — the tie-break trap
- the swap regresses the worst case on large inputs and you did **not** guard it with a size
  threshold or a stated bound on N
- you cannot argue byte-identical observable behavior for **every** reachable input, not just the
  corpus you saw

### 2. Immutable setup-state reuse (Category 1)

Data loaded or built once and then reused unchanged: config files, static test certificates or keys,
immutable lookup tables, parsed command-line defaults, canonicalized paths or environment-derived
strings, serialized blobs bundled with the project.

Prefer: parse once and reuse the parsed object; precompute derived fields once into static immutable
state; replace repeated file reads with in-memory bytes or precomputed decoded objects.

### 3. Fixed key or parameter reuse (Category 1)

Repeated per-input generation of asymmetric keypairs, ephemeral KEX parameters, deterministic
test-only credentials, or deterministic session/transport setup objects.

Prefer: generate once at startup and clone or reuse per iteration; pre-generate bounded pools when
callers mutate the object; keep the cryptographic path live whenever crypto generation itself is not
the fuzz target.

Reject when the harness directly targets key generation, signature verification, scalar
multiplication, modular arithmetic, or the exact primitive being frozen.

### 4. Fixed randomness, time, and syscall folding (Category 1)

Hot calls to `genrandom`/`rand`/`getrandom`/`/dev/urandom`, `time`/`clock_gettime`/timestamp helpers,
`getpid`/`getuid`/`getenv`/hostname lookups, or non-coverage-critical socket and filesystem metadata
queries.

Prefer: one-time fixed values cached at init; a deterministic seed reused across iterations;
memory-backed answers for repeated immutable queries. The replacement is **unconditional** — never
gated on a fuzzing macro.

Reject when the randomness or time source influences the code path under test in a bug-relevant way,
or when the rewrite would invalidate cleanup, timeout handling, or parser progress.

### 5. Deterministic helper memoization (Category 2)

Functions that are hot in the profile, pure or nearly pure over the relevant call domain, called with
a small set of normalized inputs, and expensive relative to the surrounding call site.

Prefer: finite-domain lookup tables; hash maps keyed on the full normalized input bytes or enum
combination; one-entry or few-entry caches when the same arguments recur heavily.

Reject when the helper has required side effects, when the key space is effectively unbounded (memory
growth, cache churn), or when the caller relies on allocation, timing, or failure semantics of the
original.

Remember per-input determinism: a memo keyed on fuzzer bytes must be cleared between iterations, or
be provably input-invariant.

### 6. Object reuse, pooling, and one-time decode/build (Category 1 or 3)

Repeated parse/decode of immutable bytes, construction of large helper structs, allocation of scratch
objects with stable shapes, serialization of the same constant prefix or trailer.

Prefer: static immutable objects; resettable object pools (fixed-size container, contents reset each
iteration); cloned prebuilt structures; preserved buffers with explicit reset instead of rebuild.

### 7. Synchronization and bookkeeping elision (Category 1)

Hot synchronization or bookkeeping that exists for production concurrency, observability, or
durability rather than for behavior the fuzz process can observe:

- locks on a fuzz path where the process is genuinely single-threaded (verify: no thread is created
  in the harness or the reachable library setup)
- `fsync`-like durability work irrelevant to in-process fuzzing, where nothing reads the data back
- tracing, logging, metrics, or diagnostic formatting whose output nothing branches on
- listener or network setup paths that are already fake under the harness

Prefer: removing the redundant formatting or I/O outright; a cached lock-free answer when the
execution model is provably single-threaded.

The elision must be **unconditional** — a `#ifdef FUZZING_BUILD_MODE_*` around it is Forbidden #1
even when the elided work is harmless.

Reject when locking protects shared mutable state that still exists in the fuzz process, when any
thread is actually created, or when removing the operation changes reachable parser or state-machine
behavior (including an error branch that a failed write would have taken).

---

## Part 4 — Rewrite patterns

Use the narrowest rewrite that captures the speedup. A cache, clone, precompute, or reimplementation
is better than deleting code outright; prefer preserving call structure.

1. behavior-preserving algorithmic or data-structure reimplementation — a faster method returning
   byte-identical output, or an adaptive small-N fast path with the original retained above a
   threshold
2. capacity-proportional work made proportional to use — generation counter, dirty list,
   grow-on-demand sizing
3. inline / single-allocation layout replacing per-call heap traffic
4. one-time init plus reuse
5. static immutable object reuse
6. compile-time constant replacement
7. bounded object pool with per-iteration content reset
8. finite-domain memoization table (bit-exact and total over the reachable domain)
9. memory-backed file or config fast path (input-invariant contents; EOF, short-read, and error
   semantics reproduced exactly)
10. fixed value for an input-invariant source — RNG seed, clock, environment — applied
    unconditionally, never behind a fuzz-only macro

---

## Part 5 — Inserted function coverage suppression

Every function this skill **inserts** (helpers, cleanup/init routines, wrappers, fast paths,
memoization shims, pool managers) must be excluded from coverage instrumentation *and* named so the
build can exclude it. Existing functions whose **body** changes but whose **name and signature** are
preserved must keep their instrumentation — they are still part of the program's coverage gradient,
and removing them would falsify the comparison.

### Why this matters

Coverage-guided fuzzers — libFuzzer, AFL++, honggfuzz alike — preserve inputs that hit new
instrumented edges and bias mutation toward those inputs. Inserted helpers create new edges that have
nothing to do with the program under test. Even when the inserted code is small, its edges shift the
gradient the fuzzer is climbing: in one measured run, instrumented inserted helpers slowed bug-finding
by roughly 5×, and most of that loss was recovered once the same helpers were suppressed.

This skill's acceptance gate ignores coverage entirely, so nothing downstream will catch a missed
suppression for you.

### Naming: mandatory, and the part that works most broadly

**Give every inserted function the prefix `fold_`.** Where the build's sanitizer denylist excludes
`fun:fold_*`, this is the only mechanism verified to suppress instrumentation under AFL++'s
LLVM-PCGUARD mode. A helper that is not prefixed is instrumented whatever attributes it carries.

Measured on AFL++ 5.02c in LLVM-PCGUARD mode (its own fork of the sancov pass, loaded via
`-fpass-plugin`), **neither attribute below suppressed instrumentation** — a marked and an unmarked
helper emitted identical `__afl_area_ptr` writes. The denylist prefix did work: 0 relocations
against 1.

Do **not** edit build scripts to add a denylist — that is out of scope for this skill. Name the
functions `fold_*` regardless: it costs nothing, and it is what makes suppression possible wherever
the harness or wrapper does supply a denylist. Where no denylist is in play and the engine is AFL++
PCGUARD, assume the attributes will not take effect and therefore **keep inserted functions few and
small**, or fold the new code into an existing function's body instead of adding a function.

### The attributes

Apply both, directly to the function definition (not the declaration), on their own lines above the
return type so multi-line signatures are unaffected. Neither is sufficient alone:

- `no_sanitize("coverage")` suppresses upstream SanitizerCoverage — libFuzzer's mechanism.
- `annotate("afl_coverage_skip")` is AFL++'s documented marker.

C:

```c
__attribute__((no_sanitize("coverage")))
__attribute__((annotate("afl_coverage_skip")))
static void fold_strpool_clear_dynamic_entries(void) {
    ...
}
```

C++:

```cpp
__attribute__((no_sanitize("coverage")))
__attribute__((annotate("afl_coverage_skip")))
inline FoldCache::FoldCache(size_t n) : entries(n) {
    ...
}
```

If the compiler is older than clang 9 / gcc 9 and rejects that spelling, fall back to the legacy form:

```c
__attribute__((no_sanitize_coverage))
static void fold_helper(...) { ... }
```

If the legacy form is also rejected, wrap only the inserted functions in a translation-unit pragma:

```c
#pragma clang attribute push (__attribute__((no_sanitize("coverage"))), apply_to = function)
/* ... newly inserted functions only ... */
#pragma clang attribute pop
```

Do not put these attributes on functions that already existed, on the harness, or on functions whose
body you modified but whose name and signature are unchanged.

### Verification

Before declaring a pass clean:

1. Diff the source-only changes (`verify_source_only_changes.py`) and list every function definition
   this skill added.
2. Confirm each one is named `fold_*` and carries the attributes on its definition.
3. If the build flags pass `-fno-sanitize-coverage=trace-pc-guard` globally, note that no per-function
   suppression is needed — the whole binary skips coverage and the gradient question is moot.
4. Record `inserted_funcs_annotated: N/N` in the pass report so a reviewer can spot a missing one.

---

## Part 6 — Risk labels

These label residual risk *within* the contract. They never widen it: every accepted fold is
Category 1, 2, or 3.

- **`Safe`** — determinism, side effects, and observable behavior are clearly preserved; the
  Category argument is complete.
- **`Safe*`** — the argument is complete for the harness-reachable domain you traced, but you could
  not fully enumerate that domain. Use sparingly, and say in the report exactly which part of the
  domain is unproven. If the gap is "I only checked the corpus", that is not `Safe*` — it is a
  **REJECT** under Category 2/3, or it needs an adaptive guard.
- **`Aggressive`** — reserved for a change that can only *add* crashes (false positives, triaged
  later) while provably never suppressing one and never touching an input-dependent path — for
  example an added assertion on input-independent state. `Aggressive` never authorizes behavior drift
  on a path that processes fuzzer-derived data.

A caller asking for "aggressive mode" is asking for more ambitious folds — bigger Category-3
subsystem rewrites, larger expected wins — not for a weaker contract.

---

## Part 7 — Refusal rules

Reject or demote any candidate that:

1. freezes the primitive the harness is directly fuzzing
2. removes, disables, skips, gates, or short-circuits input-dependent parsing, validation,
   optimization passes, or state transitions — by deletion, early return, a flag, or an `#ifdef`. Do
   not soften this with "likely coverage-bearing": if the path processes fuzzer-derived data,
   touching its behavior is a reject.
3. changes the library's behavior on an input-dependent path specifically in fuzzing builds — gated
   on `FUZZING_BUILD_MODE_*`, `LIB_FUZZING_ENGINE`, or any fuzz-only macro/flag (Forbidden #1)
4. requires harness edits, build-script edits, or project metadata changes
5. depends on hidden mutable global state that cannot be bounded safely
6. retains, caches, or accumulates input-derived state across fuzz iterations — **even if
   memory-bounded** (the string-interning-pool anti-pattern)
7. grows memory without a clear bound, or replaces a bounded worst case with an unbounded one
8. regresses the worst case on large inputs without an adaptive threshold or a stated bound on N
9. relies on compiler folding that already happens under the current build flags
10. introduces obvious UB, deadlock risk, non-termination, or invalid lifetime behavior

---

## Part 8 — Pass review checklist

For every accepted candidate, record:

1. hotspot evidence or heuristic trigger
2. exact file and function
3. the provenance self-audit answers: inputs enumerated, which derive from the fuzzer's mutable bytes,
   the trace toward the harness `data`/`size`
4. the assigned **Category (1, 2, or 3)** and why it qualifies —
   for Category 2, the argument that the replacement is bit-exact for every reachable input;
   for Category 3, the byte-identical-behavior argument, the tie-break/ordering argument, and the
   worst-case argument (adaptive threshold, or the bound on N and the cost at that bound)
5. why the folded work is not itself the fuzz target
6. chosen rewrite pattern
7. expected speedup, and the measured `previous_best → this_median` once the gate has run
8. risk label
9. validation result
10. count of newly inserted functions and `inserted_funcs_annotated: N/N`, confirming each is named
    `fold_*` and carries the suppression attributes
