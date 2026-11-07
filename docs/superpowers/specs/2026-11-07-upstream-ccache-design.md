# ccache for upstream optimizer rebuilds — design

**Date:** 2026-11-07
**Status:** approved approach (spec + plan + SDD on `feat/aflpp-sandboxed-optimizer`)
**Related:** `fuzzbench-parity-ccache` skill; `prework/fb_ccache.py`, `prework/fb_build.sh`,
`tools/fb_ccache_equivalence.py` (the FuzzBench precedent this mirrors).

## Intent and why

When the optimizer works an upstream target, each accepted round rebuilds the project
from source so the round's edited library code becomes the fuzzed binary. Today that
rebuild is a full, cold `compile`: every translation unit recompiles even though the
optimizer typically edits a handful of files. On the big trees (tpm2-tss, botan, samba,
tor, strongswan) a full rebuild is minutes, and it is paid once per accepted round out
of the optimizer's own time budget (`OPT_TIMEOUT`). Slow rebuilds mean fewer optimizer
rounds fit in a campaign, which directly limits how much the optimized arm can improve.

ccache caches object files keyed on the preprocessed source plus the compiler and flags,
so a rebuild recompiles only the changed units and reuses the rest. FuzzBench targets
already do this (the `fuzzbench-parity-ccache` skill). Upstream targets are explicitly
blocked from it today: `prework.prework_build` raises `ValueError: ccache_dir is only
supported for FuzzBench targets`. This design lifts that block for upstream, reusing the
FuzzBench safety model.

**Why it does not bias the measurement.** ccache changes only how fast a build happens,
never what the build produces (enforced below). The baseline arm is static and is never
rebuilt or cached. The reference baseline is never cached. Only the optimized arm's
rebuilds are cached, and the time saved comes out of the optimizer's build budget, not
the fuzzing duration either arm runs. So the comparison stays baseline-OSS-Fuzz vs
our-optimized-pipeline; making the pipeline's builds faster is part of the pipeline, the
same stance already taken for FuzzBench.

## Goals

1. The optimizer's upstream rebuilds (the harness rebuild and the broker's agent builds)
   use a per-trial ccache, so unchanged translation units are not recompiled.
2. A cached build is provably identical to the uncached build it replaces — byte-identical,
   or identical up to the build's own learned non-determinism (noise) — proven per target
   before any campaign uses the cache.
3. Off by default and fail-safe: a target with no proof, or any setup failure, runs
   uncached exactly as today, with no behaviour change.
4. The image stays the artifact of record: no rebuild of the `bench-upstream/*` images,
   no edit to OSS-Fuzz's `compile`, `--network none` preserved, `/out` the only writable
   mount besides the cache.

## Non-goals / anti-goals

- **Not** caching the baseline arm, the reference baseline, or the onboarding compile. If
  any of those is ever cached, the design has failed.
- **Not** changing any sanitizer, optimization, instrumentation, or engine flag, nor the
  fold denylist, nor the harness. ccache sits under the existing toolchain; the build it
  caches is byte-for-byte the build that runs today.
- **Not** touching the FuzzBench ccache path. Upstream gets its own wiring; FuzzBench's
  `fb_*` code and verified list are left exactly as they are.
- **Not** cmplog or dict2file caching. Upstream builds have neither (those are
  FuzzBench-specific), so upstream caches a single `compile`, which is simpler than the
  FuzzBench two-build case.

## Background: how the upstream build runs today

`prework.prework_build.upstream_compile_args` builds a `docker run` of the project's
`bench-upstream/<project>` image running OSS-Fuzz `compile` with
`FUZZING_ENGINE=afl`, `SANITIZER=<s>`, `ARCHITECTURE=x86_64`,
`FUZZING_LANGUAGE=<lang>`, and `AFL_LLVM_DENYLIST=/src/aflpp_fold_denylist.txt`
(the denylist mounted read-only). With a source tree the tree is mounted read-only at
`/staging/<project>` and, inside the container, `_staged_compile_command` copies it to
`/src/<project>` and runs `compile`; preserved `.git` dirs are copied back from
`/staging-vcs`. `/out` is the only writable mount. `--network none` throughout.

Two properties make upstream a good ccache fit:

- The staged copy always lands at the **same path** `/src/<project>` on every build of
  every trial, so ccache's default path-sensitive keys are stable without `base_dir`
  tricks.
- The **denylist is one fixed file**, so its content is stable across builds unless the
  optimizer changes it (handled below).

## Design

### 1. Injection: ccache under the AFL compiler, via a mounted wrapper

Mirror the FuzzBench rule: ccache runs **below afl-cc**, so `CC`, `CXX`, `CFLAGS`,
`CXXFLAGS`, and `PATH` are untouched and the AFL instrumentation is unchanged. In the
`bench-upstream/*` images `compile_afl` sets `CC`/`CXX` to `/src/aflplusplus/afl-clang-fast[++]`,
ccache is `/usr/local/bin/ccache` (v4.10.2, and it is on `PATH`), and the image bakes
`CCACHE_DIR=/ccache/cache` into its environment.

The injection is a **mounted compiler-wrapper script**, not a bare `AFL_CC=ccache`.
Pointing `AFL_CC` straight at ccache does **not** work: afl-clang-fast execs
`ccache <clang-flags…>`, and ccache, seeing a flag where it expects a compiler, dies with
`ccache: invalid option`. This is confirmed on the image and is exactly why FuzzBench
runs ccache *below* afl-cc through a wrapper rather than as afl-cc's backend directly.

So, injected as `docker run -e` env plus two read-only mounts and one writable cache
mount, with no image or `compile` change:

- A wrapper script, mounted read-only (the same mechanism the denylist already uses), that
  execs `ccache <backend compiler> "$@"`, where the backend compiler is the one
  afl-clang-fast would otherwise invoke — confirmed on the image as `/usr/local/bin/clang`
  (and `clang++` for the CXX twin). `AFL_CC`/`AFL_CXX` point at these wrappers, so
  afl-clang-fast (still `CC`/`CXX`) runs its own instrumentation driver and calls the
  wrapper as its backend; ccache then caches the real clang compile below the
  instrumentation. Verified on the image: ccache miss then hit, with the instrumentation
  surviving in the object (`__afl_area_ptr`, `__sanitizer_cov_trace_pc_guard_init`).
  The wrapper must name the compiler, not afl-clang-fast: pointing `AFL_CC` at the wrapper
  that re-execs afl-clang-fast would recurse, and pointing `AFL_CC` straight at ccache
  makes afl-clang-fast exec `ccache <flags>`, which ccache rejects.
- Mount the per-trial host cache and set `CCACHE_DIR` **explicitly via `-e`** to that mount
  path, overriding the image's baked `/ccache/cache`. The host cache is mounted at exactly
  the chosen `CCACHE_DIR`.
- `CCACHE_COMPILERCHECK=content` (hash the real compiler, not its mtime).
- `CCACHE_EXTRAFILES=/src/aflpp_fold_denylist.txt` so a change to the denylist content
  invalidates the cache. (The upstream denylist is a single static `fun:fold_*` file, so
  there is no FuzzBench-style per-round fold-name hazard here; hashing it is a cheap,
  correct safety margin, not a fix for a live hazard.)
- `CCACHE_STATSLOG` pointed at a per-build file under the cache mount, so the host side can
  read exactly what this build hit and missed (see §2 and §5); the staged command also runs
  `ccache -z` style reset so stats are per-build, mirroring fb_build.sh zeroing its stats.
- `CCACHE_SLOPPINESS` only as the equivalence test proves necessary (e.g. `time_macros`
  if a target embeds `__DATE__`/`__TIME__`), never loosened beyond what the proof allows.

Task 1 of the plan is a spike that confirms this wrapper routing produces a byte-identical
binary via the equivalence test before anything else is built on it.

### 1a. Keeping uncached builds genuinely uncached

Because ccache is on `PATH` and the image bakes `CCACHE_DIR`, a project build system could
silently invoke ccache even when we did not ask for it, which would corrupt the baseline,
the reference baseline, and the equivalence test's uncached builds (`P0`, `P0'`, noise).
FuzzBench prevents this by keeping ccache off `PATH` and refusing any image that has it on
`PATH`; that is not available here without rebuilding the image (Goal 4). Instead, every
upstream build that is **not** a cache-enabled optimized rebuild sets `CCACHE_DISABLE=1`
via `-e`, which makes any ccache on `PATH` a transparent pass-through to the real compiler.
So uncached means provably uncached, by environment, with no image change. The equivalence
test's uncached builds run with `CCACHE_DISABLE=1`; its cached builds run with the wrapper
and a real `CCACHE_DIR`.

### 2. Correctness gate: prove cached == uncached, per target

A target may use ccache only after an **upstream equivalence test** passes for it, an
analogue of `tools/fb_ccache_equivalence.py` for the single `compile` build. Through the
production build command it builds and compares:

- `P0` pristine, no cache, one core (timed reference);
- `P0'` pristine, no cache, multi-core — `P0` vs `P0'` learns the build's own noise;
- `C0` pristine, cold cache — must equal `P0`;
- `W0` pristine, warm cache (a copy of the cache after `C0`), one core, timed — must
  equal `P0` and must report ccache actually in use (read from the §5 stats signal; the
  uncached builds run with `CCACHE_DISABLE=1`, the cached ones with the wrapper);
- `PC` a new `fold_` helper added to a compiled source file plus call sites, no cache —
  then `WC` the same tree on a warm cache copy, must equal `PC` and hit the cache for the
  unchanged units;
- `PH` a new `static __inline__ fold_` helper in a header several compiled files include,
  plus one caller, no cache — then `WH` on a warm cache copy, must equal `PH`.

Each pair compares the sha256 of `/out/<target>` for every built harness. Verdicts:

- `pass` — every pair byte-identical;
- `pass_noise_masked` — some pair differs, but `P0 != P0'` and every differing byte lies
  inside a noise region learned from `P0` vs `P0'` (a NUL-terminated printable string, or
  a block inside a non-loaded section such as `.debug_line`); sizes equal; differences in
  loaded code are never masked;
- `fail` — anything else, including a cached build that did not actually use ccache.

The verdict for a target goes in an upstream verified list
(`prework/upstream_ccache_verified.txt`, `<project>` or `<project> pass_noise_masked`),
the direct analogue of `prework/fuzzbench_ccache_verified.txt`. A `pass_noise_masked`
target runs its campaign-time checks with the learned noise mask.

### 3. Scope, seeding, and per-trial isolation

- Only an **optimized-arm** upstream rebuild mounts a cache. The baseline arm, the
  reference baseline, and the onboarding compile never pass a cache dir; the existing
  `source_dir=None` onboarding path is unchanged.
- Each optimized **trial** gets its **own** cache, so the ten trials stay statistically
  independent (the campaign already gives each trial its own source tree and optimizer).
- A trial's cache is seeded from a **target-level template** built once at campaign setup
  by one extra pristine build (the analogue of `_prepare_fb_ccache_template`), plus, for a
  `pass_noise_masked` target, one more uncached build to learn the noise. The template is
  copied into each trial's cache and is **never mounted into an agent build**. Any failure
  filling or checking the template turns ccache off for the whole campaign, which then
  runs uncached.

### 4. Wiring

- `prework.prework_build`: allow a `ccache_dir` on the upstream build path
  (`upstream_compile_args` / `_staged_compile_command` / `build_prework_rebuild_command` /
  `rebuild_with_prework_image`), adding the wrapper mounts, the env of §1, and the stats
  reset/read of §5. The `ccache_dir is only supported for FuzzBench targets` guard is
  replaced by a guard that still forbids a cache on a baseline/reference/onboarding build,
  and those uncached upstream builds gain `CCACHE_DISABLE=1` (§1a).
- `sandbox/broker.py`: the broker builds the agent's candidate binaries, so it must carry
  the cache too, or verified upstream agent builds silently run uncached. `_build_command`'s
  upstream branch calls `upstream_compile_args` with no cache today, and `_run_build_snapshot`
  gates the cache on `is_fuzzbench_image(ctx.image)`; both need an upstream branch that
  passes the trial's cache dir (from the broker env key below). Name and wire both sites.
- `phase3_online`: for an upstream target on the verified list, create the per-trial cache
  from the template and pass its dir to the harness rebuild and, via a broker env key
  (an upstream analogue of `PHASE2_FB_CCACHE_DIR`), to the broker's agent builds. Every
  other upstream build (baseline, reference, template-noise) passes no cache dir and gets
  `CCACHE_DISABLE=1`. Nothing else receives the cache.
- `round_provenance.json` already carries a `ccache` field (null today); populate it for
  upstream from the §5 stats signal, so a round records whether its binary came from the
  cache.

### 5. ccache stats signal (so "cache in use" is enforceable)

FuzzBench can assert a cached build actually used ccache because `fb_build.sh` prints an
`FB_CCACHE_STATS` JSON line (and zeroes stats per build), which `fb_ccache.parse_stats`
reads. The upstream staged command is just `… && exec compile`, so no such signal exists
yet, and the W0/template checks and the `round_provenance` `ccache` field would have
nothing to read. This design adds the signal: the staged compile command resets ccache
stats before the build and the host reads a per-build stats file (`CCACHE_STATSLOG`, or a
`ccache --show-stats` on the mounted cache dir) after it. A small parser turns that into
the hits/misses already recorded in `round_provenance`. The equivalence gate's "cached
build must report ccache in use" rule and §3's template check both read this signal; a
cached build that shows no ccache activity is a `fail`.

Note the staged command must not `exec compile` if a post-build stats step runs in the
same shell; it runs `compile` and then the stats read (or the stats read happens host-side
on the mounted cache). The builder picks whichever keeps the staged command's existing
copy-in/`.git` behaviour intact.

## Constraints (carried from the upstream-targets spec)

- No flag OSS-Fuzz sets is added, removed, or changed; no instrumentation change; the
  harness is untouched.
- `--network none` on every build; the image is the artifact of record and is not
  rebuilt; `/out` and the cache are the only writable mounts.
- Commit trailers on this branch: the implementing model's own `Co-Authored-By` line and,
  as the last line, the orchestrator model's `Co-Authored-By` line.

## What is left to the builder (implementation detail)

- The exact env set and whether the `AFL_CC` primary or the mounted-wrapper fallback is
  used — decided by Task 1 against the equivalence proof.
- Cache dir layout under the campaign results tree, template path, and cleanup.
- The verified-list file format helpers (may reuse `fb_ccache.read_verified_modes`-style
  parsing, generalised, rather than duplicating it).
- Whether any `fb_ccache.py` helper (noise model, stats parsing) is generalised and shared
  vs. given an upstream twin — the builder picks the lower-duplication option, with the
  FuzzBench path's behaviour unchanged either way.

## Validation (acceptance)

1. The upstream equivalence test passes (`pass` or `pass_noise_masked`) on at least one
   large project — tpm2-tss or botan — and the target is added to the verified list.
2. Measured rebuild time before vs after on that project (one-core warm-cache build vs
   cold), recorded in the ledger; the warm build is materially faster.
3. A short upstream campaign on a verified target shows ccache hits in `round_provenance`
   and the same round outcomes (built, gate, speedup sign) as an uncached run, i.e. the
   cache changed speed, not results.
4. A target **not** on the verified list runs uncached with no behaviour change; the
   baseline arm never mounts a cache.
5. The full existing test suite stays at its known baseline (the pre-existing failures
   only); FuzzBench ccache behaviour is unchanged.
