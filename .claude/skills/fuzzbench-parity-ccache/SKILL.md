---
name: fuzzbench-parity-ccache
description: Audit a FuzzBench target's build so it matches FuzzBench's aflplusplus build (flags, cmplog, dict2file, leak checking) and add ccache to its optimized-arm rebuilds (main and cmplog builds) without changing any output byte. Use when touching prework/fb_build.sh, prework/fuzzbench_image.py, prework/fuzzbench/<dir>, or when a FuzzBench target's optimizer rebuilds are too slow.
---

# FuzzBench build parity + ccache

Repo: /home/sefcom/fuzz-opt. Scope: the 29 FuzzBench targets only (manifest entries with
`"kind": "fuzzbench"` in data/manifests/manifest_fuzzbench.json). ARVO targets are out of scope:
do not change their build or run path.

Never `git checkout`, `git stash`, `git reset` or commit: the tree holds a lot of uncommitted work.

`$SCRATCH` below = /tmp/claude-1000/-home-sefcom-fuzz-opt/16b2ecc0-257d-4576-b178-96d1c673ddbc/scratchpad
(a session scratchpad; if it is gone, clone google/fuzzbench at 3234e151 into a scratch dir).
Built images: `fb-aflpp/<fuzzbench_dir>:latest`. Earlier validation outputs (extracted
source trees, /out dirs, logs) are in `$SCRATCH/validate/<fuzzbench_dir>/`.

## 1. What "the same as FuzzBench" means

Reference code (pinned, read it instead of guessing):
- FuzzBench 3234e151: `prework/fuzzbench_upstream/` (vendored, verbatim) and the full checkout
  at `$SCRATCH/ref/fuzzbench` if present. Key files: `fuzzers/utils.py` (flags),
  `fuzzers/aflplusplus/fuzzer.py` (build + run), `fuzzers/afl/fuzzer.py`,
  `common/sanitizer.py` (ASAN/UBSAN options), `experiment/runner.py` (seeds, env).
- AFL++ 56d5aa31 (4.21a) is what the images build at /afl.

The build is FuzzBench's `fuzzer_build`, run by `prework/fb_build.sh` inside an
`fb-aflpp/<fuzzbench_dir>` image (`prework/fuzzbench_image.py`):
`utils.initialize_env()` then `fuzzers.aflplusplus.fuzzer.build()`, which runs the benchmark's
`build.sh` twice: a main build into /out and a cmplog build (`AFL_LLVM_CMPLOG=1`) into /out/cmplog.
Expected effective settings:

| | type: bug | type: coverage |
|---|---|---|
| CFLAGS | `-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` + `utils.SANITIZER_FLAGS` (ASan + UBSan list, `-fno-sanitize-recover=...`) + `-O1` | FuzzBench's coverage CFLAGS, `-O3`, no sanitizer |
| CXXFLAGS | same + `-stdlib=libc++` | same + `-stdlib=libc++` |
| instrumentation | LLVMNATIVE (array-bounds in CFLAGS flips tracepc -> native) | PCGUARD via `AFL_LLVM_USE_TRACE_PC=1` |
| both | CC/CXX `/afl/afl-clang-fast(++)`, `FUZZER_LIB=/libAFLDriver.a`, `AFL_QUIET=1`, `AFL_MAP_SIZE=2621440`, `AFL_LLVM_DICT2FILE=/out/afl++.dict`, `AFL_LLVM_DICT2FILE_NO_MAIN=1`, cmplog build with `AFL_LLVM_CMPLOG=1` | same |

Do not copy these values from this table into code: compute them by importing FuzzBench's own
`fuzzers.utils` inside the image (`PYTHONPATH=$SRC python3 -c "from fuzzers import utils;
utils.initialize_env(); ..."`) and compare against that.

Runtime (already implemented in `lib/afl_launch.py`, check, don't rewrite): cwd /out,
`afl-fuzz -i <seeds> -o <out> -m none -t 1000 -d -x ./afl++.dict -c /out/cmplog/<t>
[-x <options/target dict>] -- /out/<t> 2147483647`, FuzzBench's AFL_* env, and
`ASAN_OPTIONS`/`UBSAN_OPTIONS` = `config.FUZZ_ASAN_OPTIONS`/`FUZZ_UBSAN_OPTIONS`
(FuzzBench `common/sanitizer.py`, except `detect_leaks=0`: leak detection is off by user
decision, Oct 13 -- the one runtime deviation).

Allowed deviations (decided; each must be commented in code):
- `-t 1000` instead of `1000+`; `-s`, `-V`, AFL_AUTORESUME, cpuset pinning, --user, hot-swap
  restarts; running afl-fuzz in the builder image.
- Copy-in of modified source from /fold/src; fold_* exclusion lists generated in fb_build.sh;
  `afl-showmap` copied into /out.
- Recipe lines marked `# fuzz-opt deviation:` in prework/fuzzbench/<dir> (pins needed to build or
  freeze inputs at the benchmark's commit date).
- ccache for both builds of optimized-arm rebuilds (section 3), once proven equal for that
  target (section 5: pass or pass_noise_masked). Baseline arm and reference baseline uncached.

Anything else that differs is a bug to fix. Typical ARVO leftovers to look for: an `-O` override
(BUILD_OPT_LEVEL / opt_level_env), OSS-Fuzz `compile` env (SANITIZER=, FUZZING_ENGINE=,
LIB_FUZZING_ENGINE pointing somewhere else), ASan-only CFLAGS, `-fsanitize=fuzzer`, a different
clang or AFL++, dynamic libc++, missing cmplog binary or dictionary, `detect_leaks=1`
(leak detection is deliberately off).

## 2. Flag audit for one target

1. Recipe vs upstream: `diff -r $SCRATCH/ref/fuzzbench/benchmarks/<dir> prework/fuzzbench/<dir>`.
   Every hunk must be a `# fuzz-opt deviation:` line with a reason. An unmarked hunk, or a marked
   one that is not needed, is reverted to upstream (keep a backup under $SCRATCH).
2. Effective compiler commands: run a build with the audit logger on (`FB_AUDIT_CC_LOG`, section
   4) and check, for every compile of project code in BOTH builds:
   - the FuzzBench CFLAGS/CXXFLAGS above are present, in FuzzBench's order;
   - no flag comes from our pipeline (anything not in FuzzBench's env and not in the upstream
     build.sh / Dockerfile text). Flags the upstream build.sh itself adds (e.g. its own -O2) are
     parity, not bugs;
   - the compiler is /afl/afl-clang-fast(++) (or what upstream's build.sh calls explicitly);
   - cmplog build: `AFL_LLVM_CMPLOG=1` present; main build: absent.
3. Output: /out/<t>, /out/cmplog/<t>, /out/afl++.dict exist; bug type has ASan+UBSan symbols and
   `__sanitizer_cov_trace_pc_guard`; coverage type has no ASan; `ldd` shows no libc++.so;
   `/out/afl-fuzz` reports ++4.21a.
4. Launch: `lib.afl_launch.build_afl_launch(entry=...)` argv/env equal FuzzBench's for this target
   (compare with `fuzzers/aflplusplus/fuzzer.py fuzz()` + `afl/fuzzer.py run_afl_fuzz`), with
   `-c /out/cmplog/<t>` and `detect_leaks=0`.
5. Pipeline paths that build this target must all go through `fb_build.sh` with no extra env:
   `prework.prework_build` (baseline + harness rebuilds), `sandbox/broker._build_command` (agent
   builds), `tools/preflight_online.py`. Check with `git diff` and by building the command lists.

## 3. ccache design (main and cmplog builds, optimized arm only)

What is cached: BOTH halves of an optimized-arm rebuild -- the main build (/out/<t>, the
binary that is fuzzed and measured) and the cmplog build (/out/cmplog/<t>). The user decided
this on Oct 12 2026 (round 3): the cmplog build is where most of the cost is (php:
`parse_date.c` alone takes ~45 min per cmplog build because cmplog splits every switch and
hooks every compare), but the main build is the other half of every round's rebuild. Caching
the main build is safe only because a cached build is proven byte-identical (or equal up to
the build's own noise) to an uncached one, per target (section 5), and re-checked at
campaign setup and at the end of the campaign. The baseline arm and the reference baseline
are NEVER cached (no /ccache mount = exactly FuzzBench's build).

Rules:
- **Install, never findable:** ccache 3.7.7-1 from the image's Ubuntu 20.04 archive, UNPACKED
  (`apt-get download` + `dpkg-deb -x`, no dpkg install) to `/opt/fb_ccache/ccache` in stage 3 of
  `prework/fuzzbench_image.py` as its own marked last step. Nothing on PATH, no `/usr/lib/ccache`
  masquerade dir, no man page; the step fails if `command -v ccache` finds anything. Why: build
  systems auto-detect ccache. jsoncpp's CMakeLists does `find_program(ccache)` +
  `CMAKE_<LANG>_COMPILER_LAUNCHER`, so with `/usr/bin/ccache` present EVERY jsoncpp build
  (baseline too) went through `~/.ccache`, which does not key on `AFL_LLVM_CMPLOG`: the cmplog
  binary reused main-build objects (603 -> 2 `__cmplog_ins_hook` call sites). fb_build.sh and
  the tools call ccache only by that absolute path. Record `ccache --version` in provenance.
  (Of the 29 source trees only jsoncpp auto-detects; PROJ's `cmake/Ccache.cmake` is opt-in,
  `USE_CCACHE` defaults OFF.)
- **Build-visible env invariance:** everything the build system can observe -- CC, CXX, CFLAGS,
  CXXFLAGS, PATH, argv[0] of the compiler it calls -- must be exactly what the uncached build
  sees. OpenSSL (built by curl_fuzzer) embeds `compiler: $CC $CFLAGS` in libcrypto, so a
  `CC=<ccache wrapper>` changes the binary. So ccache sits BELOW afl-cc: CC stays
  `/afl/afl-clang-fast`, and each build only gets `AFL_CC`/`AFL_CXX` pointing at a Python
  wrapper that afl-cc execs instead of clang (afl-cc.c `add_real_argv0`), one wrapper per build
  kind (`/tmp/fb_ccache/afl/<main|cmplog>/clang[++]`). The wrapper runs
  `/opt/fb_ccache/ccache <real clang> <afl-cc's full clang command>`, where the real clang is the
  one afl-cc would have exec'd (read from its `AFL_DEBUG` trace). Only a plain `-c` compile of
  one input into one determinable object goes through ccache; links, `-E`/`-S`, response files,
  several inputs or output to stdout exec the real clang with the unchanged argv. All `CCACHE_*`
  settings live inside the wrapper, not in the build env. If the build itself sets
  `AFL_CC`/`AFL_CXX`, that build runs uncached. The hook is `utils.build_benchmark` in
  fb_build.sh; FuzzBench calls it once for main (env=None) and once for cmplog
  (`AFL_LLVM_CMPLOG=1`).
- **restore_directory:** FuzzBench runs the main build inside `restore_directory($SRC)` and
  `restore_directory($WORK)` (copy to a /tmp tempdir, rmtree + move back afterwards). Nothing
  the cache needs may live under $SRC or $WORK: wrappers, per-call dict files and key files are
  under /tmp/fb_ccache, the cache is the /ccache mount. Verified on zlib/jsoncpp/mbedtls/curl.
- **Main and cmplog never share a cache entry:** the key has the build KIND (main/cmplog) and
  the whole AFL_* env (`AFL_LLVM_CMPLOG=1` only in cmplog); the afl-cc clang command differs
  too (cmplog pass plugins). The dict sidecar is per kind as well. Unit test:
  `test_key_separates_main_and_cmplog`; real check: the equivalence tool counts `__cmplog_*`
  call sites in P0 and W0 (W0 cmplog must equal P0 cmplog, W0 main must be 0; jsoncpp 603/0).
- **Cache key must cover everything that changes the object:** ccache hashes the preprocessed
  source / include contents, the full clang command line afl-cc built (plugin `-fpass-plugin=`
  paths, `-D`s, instrumentation flags) and the compiler name. On top, the wrapper sets
  `CCACHE_COMPILERCHECK=string:<sha256>` per compile, computed in-process (no compiler-check
  process per call): a toolchain digest the hook computes ONCE per build (sha256 of
  /fold/fb_build.sh -- wrapper and key logic --, /afl/afl-cc and every /afl/*.so plugin, the
  real clang's path, sha256 and `--version`), the build kind, the real compiler path, every
  `AFL_*` variable in the clang process env (sorted; the passes read them there, and afl-cc
  sets some itself) except the per-call `AFL_LLVM_DICT2FILE` (the build's own dict path stands
  in), and the clang-relevant env (`CCC_*`, `CPATH`, `C(PLUS)_INCLUDE_PATH`,
  `SOURCE_DATE_EPOCH`, ...). Any allow/deny/ignore list file other than our fold lists
  (`-fsanitize-coverage-*list=`, `-fsanitize-(black|ignore)list=`,
  `AFL_LLVM_{ALLOW,DENY,BLOCK,WHITE}LIST`, `AFL_LLVM_INSTRUMENT_FILE`) is hashed by CONTENT via
  `CCACHE_EXTRAFILES`. Keep ccache's strict defaults: no `sloppiness`, `hash_dir` on, no
  `CCACHE_BASEDIR`. Unit test: `test_key_covers_round2_inputs`.
- **Wrapper cost:** the wrapper imports only os, sys and hashlib and starts ccache with
  `posix_spawn`. Round 2's subprocess/tempfile imports and per-call compilercheck script cost
  ~32 ms more per cached compile (measured, one core, same hits: zlib cmplog half 3.7 -> 2.2 s,
  curl cmplog half 275 -> 226 s). Don't add imports or per-call processes. What is left of a
  warm build is mostly not compiling: curl warm is still ~225 s per half (configure, OpenSSL's
  Configure, links) vs ~400 s uncached.
- **Fold exclusion lists need no hashing**: they only list fold_ names the optimizer added (an
  identifier is either added or pristine, the same in every round), any file containing such a
  name has different preprocessed text, and the fold-name guard (step 3b of fb_build.sh) turns
  ccache off for a build where a list entry could also match another identifier (`unfold_hash`
  vs `fold_hash`). So their content cannot change an object whose source is unchanged. To keep
  keys stable across rounds, the wrapper always hands clang the fold lists: `AFL_LLVM_DENYLIST`
  (empty list when the tree adds no fold) and, for bug type, the ignorelist flag moved to the end
  of the clang command. This holds for the main build too (bug-type main = clang's native
  trace-pc-guard with the ignorelist). The equivalence test must include a fold added in a
  header to prove this.
- **Dictionary sidecar:** afl-cc's dict2file pass appends each file's constants to
  `/out/afl++.dict` while compiling (both builds append to the same file); a cache hit skips
  that. The cmplog compile writes entries the main build does not (`-fno-builtin-strcmp/
  memcmp/...` keep the calls visible, and the split-switches / cmplog-switches passes), and the
  main build's own entries are lost on a main hit just the same. Fix: each cached compile gets
  its own temp `AFL_LLVM_DICT2FILE` (`/tmp/fb_ccache/dict/d.<pid>`); when the compile produced
  the object, its lines are stored in `/ccache/fb_dict/<kind>/<aa>/<sha256 of the object>` (so
  the store travels with template -> per-trial cache copies); when the per-call file is empty
  and a stored entry exists for that object, it is replayed. The result is appended to the real
  `/out/afl++.dict` with one `O_APPEND` write. The per-call path is NOT in the key. Compiles the
  wrapper does not cache write straight to the real dictionary. The equivalence test still
  compares the *set* of dictionary entries (AFL++ dedups -x entries on load, order varies).
- **Isolation:** one cache directory per optimized trial (the build runs agent-edited code, so a
  shared writable cache could be poisoned across trials). Location under the trial's online dir;
  mount it at /ccache read-write; `CCACHE_DIR=/ccache`, `CCACHE_MAXSIZE` bounded (e.g. 10G),
  `CCACHE_UMASK=002`. Seed each trial's cache by copying a target-level warm cache produced by a
  pristine build at campaign setup; the template is never mounted writable into an agent build.
- **Never for the baseline arm or for the reference baseline binary**: they are built once, uncached.
- **Per-target switch + verified-list format:** a target only gets ccache after it passed
  section 5. The list is `prework/fuzzbench_ccache_verified.txt`, one line per target:
  `<fuzzbench_dir>` or `<fuzzbench_dir> pass` (verdict pass) or
  `<fuzzbench_dir> pass_noise_masked` (verdict pass_noise_masked); `#` comments. A line with
  any other marker counts as not listed (host: `fb_ccache.read_verified_modes`; container:
  fb_build.sh `ccache_verified`, unit-tested to agree). fb_build.sh turns ccache on only when
  the mount is present AND the target is listed (or `FB_CCACHE_FORCE=1`, set only by the
  equivalence tool).
- **Campaign template check** (`phase3_online._prepare_fb_ccache_template`): one extra
  pristine build fills the template (both halves) and is compared with the uncached baseline
  arm binary. Plain entry: byte-identical (strict). `pass_noise_masked` entry: setup runs one
  more UNCACHED build of the same tree, learns the noise from baseline vs that build, and
  accepts the cached build only if it differs from the baseline inside that noise
  (`fb_ccache.compare_with_noise`, the same function the equivalence test and the campaign
  verifier use). Both builds are charged to the optimized arm in the CPU ledger
  (`ccache_template_build`, `ccache_template_noise_build`). Any mismatch, or a template build
  where either half did not use the cache, turns ccache off for the campaign.
- **Provenance:** log `ccache -s` hits/misses after EACH build into the build log
  (`FB_CCACHE_STATS {"build": "main"|"cmplog", ...}`) and the round's provenance (`ccache`
  with per-build records), so every binary says whether it came from cache.
- **End-of-campaign check (tool):** `tools/fb_ccache_verify_campaign.py` rebuilds each trial's
  final accepted tree uncached and compares /out/<t>, /out/cmplog/<t> and the dict entry set
  with the cached build; a mismatch flags that trial. A target marked `pass_noise_masked` gets
  `--noise` automatically (two uncached rebuilds, masked comparison).
- **Known harmless misses:** configure probes named after a pid (zlib's `ztest$$.c`) hit or
  miss at random: docker starts the build at pid 6 or 7, and a main-build miss shifts the
  cmplog build's pids. Only those tiny probe compiles are affected.

## 4. Audit logger (`FB_AUDIT_CC_LOG`)

A debug-only mode of fb_build.sh: when `FB_AUDIT_CC_LOG=<path under /out>` is set, both builds'
CC/CXX go through a pass-through wrapper that appends one JSON line per invocation
(`{"build": "main"|"cmplog", "argv": [...], "env": {AFL_*, CFLAGS, CXXFLAGS, CC, CXX}}`) and then
execs the real compiler. Never set in production builds. Used by section 2.

## 5. Equivalence test (must pass before a target gets ccache)

Tool: `tools/fb_ccache_equivalence.py --dir <dir> --src <validate>/<dir>/source_tree/src/<proj>
--work <scratch> --cpuset <multi> --one-core <n> [--parallel]`. Use a VCS-stripped copy of the
target's extracted source. Run on a pinned cpuset; never touch other agents' cores. Builds go
through `prework.fuzzbench_image.fuzzbench_build_command`. The image must have
`/opt/fb_ccache/ccache` and no ccache on PATH (the tool refuses otherwise). Every cached
build (C0, W0, WC, WH) caches BOTH halves, exactly as production does; P0 and P0' are fully
uncached (no mount).

1. `P0` = pristine, no cache, one core (timed). `P0'` = a second plain build, ALWAYS built: P0 vs
   P0' says whether the build is reproducible and, if not, where its noise is. `C0` = pristine,
   cold cache. `W0` = pristine, warm cache (copy of C0's cache), one core.
2. `PC` / `WC` = a tree with a new `fold_` helper added to one `.c`/`.cc` file and called from
   existing functions, plain vs warm cache. The helper is `__attribute__((noinline, used))`; a
   candidate only counts when the helper SYMBOL is in the main fuzz binary (`nm`), not merely
   when the binary changed (php picked opcache.so code, openssl apps/, systemd unlinked files).
   Harness code is never a candidate (`fb_ccache_probe.is_harness`): a file that mentions
   `LLVMFuzzerTestOneInput` (sqlite3 picked its harness) or DEFINES any `*FuzzerTestOneInput`
   (openssl's `fuzz/x509.c` defines `FuzzerTestOneInput`), and any file under a `fuzz/`,
   `fuzzing/`, `fuzzer(s)/` dir of the project tree (`tests/fuzz/` included). Headers under
   those dirs are not header-fold candidates either.
   Candidates are ranked: objects on the target's link line first, then by how many of the
   file's function names are defined in the main binary (archive members), then path heuristics.
3. `PH` / `WH` = a tree with a new `static __inline__` `fold_` helper added inside the include
   guard of a header several compiled files include, called from one includer, plain vs warm.
   The guard `#define` may be far from the `#ifndef` (lcms2_internal.h defines it at the end).
4. Inserted code: every line <= 79 columns (curl's checksrc fails longer lines); calls go right
   after the body's `{`, splitting one-line bodies (C++ `Reader::Reader() : f_(x) {}`);
   indented file-scope definitions count (FreeType `FT_*_DEF`); constexpr bodies are skipped.
5. Compare for each pair: sha256 of /out/<t>, /out/cmplog/<t>, and the sorted unique set of
   dictionary entries in /out/afl++.dict. Every cached build must report ccache in use for
   BOTH halves (`FB_CCACHE_STATS` has one record per build). `__cmplog_*` call sites are
   counted (objdump) in P0 and W0: W0's cmplog count must equal P0's and W0's main must be 0
   (a main/cmplog cache mix-up would show here even before the hashes differ).
6. Time W0, WC, WH on ONE core (the optimizer builds on one core) vs P0 on one core, and record
   ccache hit/miss counts, separately for the main and the cmplog half (report.txt shows
   main / cmplog seconds, hits, misses, hit rate and speedup vs P0 per half, plus both
   halves together). `--parallel` runs independent builds at once on disjoint core subsets
   (P0 alone on --one-core; W0/WC/WH each alone on its own core); php takes 7-8 h sequentially.

Verdicts (report both kinds of pass separately):
- **pass**: every pair byte-identical.
- **pass_noise_masked**: allowed only when some pair is not byte-identical but (i) P0 and P0'
  differ, (ii) every differing byte of the cached-vs-plain pair lies inside a noise region --
  a byte range where P0 and P0' differ, widened to its enclosing NUL-terminated printable string
  or, inside a NON-loaded ELF section (debug info), to 16-byte aligned blocks; found again in a
  moved layout by the bytes around it (and, for a string, its length and letter/digit shape) --
  (iii) file sizes are equal, and (iv) dict sets are equal. The report lists the masked strings.
  Known cases: php embeds `uname -a` (random container hostname) and `__DATE__`/`__TIME__`;
  openthread `__DATE__ __TIME__`; curl's OpenSSL buildinf.h date changes the DWARF5 .debug_line
  MD5.
- **fail**: anything else. A difference in loaded code/data that is not a string is never noise:
  a build race (woff2: two parallel compiles write one dictionary.o) fails even when P0 != P0'.
  A pair that could not be built (no usable fold variant) is "missing" and fails too.

Add a target to the verified list only on pass or pass_noise_masked, and say which: a plain
line `<dir>` for pass, `<dir> pass_noise_masked` for pass_noise_masked (section 3). The marker
makes the campaign template check learn the noise with one extra uncached build instead of
switching ccache off, and makes the campaign verifier use --noise. A pass verdict from before
round 3 (cmplog-only caching) does not cover the main build: re-run the test before relying on
it for a campaign.

## 6. Report per target

Plain English, short: flag-audit verdict with every deviation found and what was changed;
equivalence verdict with the comparison table (identical / differs + which file); one-core build
times plain vs warm (seconds) and hit rate; anything left that needs the user's decision.
