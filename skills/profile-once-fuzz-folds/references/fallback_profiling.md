# Fallback Profiling

Prefer `perf`. If `perf` is unavailable or blocked, use the strongest available fallback and report
the confidence downgrade explicitly.

Whatever the method, the cadence does not change: profile the **baseline** binary **once** on the
frozen corpus, then work that single ranked list. Never re-profile after a fold lands.

## Fallback order

### 1. `perf` on the host

Try this first:

```bash
perf stat -- true
```

If it works, use `scripts/replay_fuzzer_profile.py` as described in `SKILL.md` step 4 and rank with
`profile_guided_analysis.md`.

### 2. `samply`

If `perf` is unavailable:

```bash
command -v samply
```

If present, capture a short profile of the baseline binary replaying the frozen corpus. Convert the
hottest self-time frames and repeated call chains into the same candidate inventory shape used for
`perf`.

### 3. `callgrind`

If `samply` is unavailable:

```bash
command -v valgrind
```

If present, run a callgrind pass over a small slice of the frozen corpus. Use it only to *rank*
likely hotspots and caller chains — its absolute timings are distorted, and instruction counts
understate cache and allocator effects, which are exactly the costs that dominate the fuzzing regime.

### 4. Static hotspot scan

If no profiler is available, do a lower-confidence static pass:

1. read the harness and map one-time setup plus the per-input flow
2. trace into harness-reachable source code
3. sample the frozen corpus for median and maximum unit size, so you know the N the code actually
   sees
4. search for the expensive patterns in `fuzz_fold_heuristics.md`:
   - per-iteration init/teardown proportional to a production-scale capacity rather than to the input
   - heavyweight containers and algorithms operating on a handful of elements
   - per-call heap allocation of small scratch buffers
   - repeated keygen or KEX parameter generation
   - repeated parse or decode of immutable data
   - randomness, time, environment, or metadata queries in hot helpers
   - repeated finite-domain helper calls suitable for memoization
   - synchronization or bookkeeping on effectively single-threaded fuzz paths
5. rank by expected cost × frequency rather than measured samples

## Confidence rules

When anything other than `perf` is used:

1. mark the pass as lower confidence and name the exact profiler or method used
2. the acceptance gate is unchanged — `replay_timing.py` on the frozen corpus still decides keep vs
   revert, and it is just as trustworthy regardless of how the candidate was found
3. the stop rule is unchanged — finish when the ranked list is exhausted or the safety cap is hit
4. do not claim the hotspot list is complete with the same confidence a successful `perf` run would
   justify

If a static pass yields only weak heuristic candidates and no profiler is available, say so plainly in
the final report.
