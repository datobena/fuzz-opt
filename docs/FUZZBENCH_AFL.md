# FuzzBench projects under AFL++ in the optimizer pipeline

*Written 2026-09-30.*

Goal: get the FuzzBench projects building and running through the optimizer
pipeline **with AFL++** (the engine, not the profiler), make the pipeline set
them up, complete the missing benchmarks, and (optionally) speed up rebuilds.

## TL;DR

- **22 of the 24 standard FuzzBench benchmarks now build under AFL++** and are
  registered (`manifest_fuzzbench.json`). Only **curl** and **mbedtls** remain.
- Started from **16** imported (8 building), fixed the broken ones, and **imported
  the 8 that were missing** — all 8 build.
- The failures were never AFL++ or broken benchmarks. They were **import bugs**:
  Dockerfiles cloned source at **HEAD** instead of the pinned commit, and the
  build.sh scripts use FuzzBench env vars (`$FUZZER_LIB`, `$FUZZER`) that OSS-Fuzz's
  `compile` exposes under other names. Fixing those recovered them.
- **Incremental (ccache) builds: investigated, not shipped** (slower here, not
  faster). See that section.

## Working set (22)

| origin | count | projects |
|---|---|---|
| imported, built as-is | 8 | bloaty, jsoncpp, zlib, libjpeg-turbo, libxml2, sqlite3, proj4, openthread |
| imported, fixed (pin + `FUZZER_LIB`) | 6 | libxslt, harfbuzz, re2, freetype2, php, woff2 |
| newly imported from upstream | 8 | **lcms, libpcap, libpng, openh264, openssl, stb, systemd, vorbis** |

(openthread builds `ip6-fuzzer`, not the stale `ot-ip6-send-fuzzer`; libxslt/systemd
return a nonzero rc from a secondary step but produce a working, afl-instrumented
target.)

### Not working (2)

| project | why |
|---|---|
| curl | clones curl + nghttp2/openssl at HEAD; pinning curl alone fixed `buildconf` but the deps still drift |
| mbedtls (**coverage** variant) | clones the `development` branch + boringssl/openssl at HEAD; needs the main commit and dep pins |

Both are recoverable with the same dependency-pinning approach; left as a follow-up
because multi-dep pinning is per-project. (The mbedtls **bug** benchmark is a
different, pinned build and now works — see below.)

## Bug benchmarks (6/6)

All six FuzzBench `type: bug` benchmarks build afl-instrumented and are registered
in `manifest_fuzzbench.json` (`"type":"bug"`): php-fuzz-parser, bloaty fuzz_target,
harfbuzz hb-shape-fuzzer, libxml2 xml, mruby mruby_fuzzer, **mbedtls fuzz_dtlsclient**
(`local_id` 900013/900023–900027).

The mbedtls bug benchmark took two one-line fixes, both the same "written for an older
base-builder" drift as everything else — **not** the dependency drift that blocks the
coverage variant (its boringssl/openssl clones only supply seed corpora for *other*
harnesses; `fuzz_dtlsclient` doesn't touch them, and mbedtls itself is pinned to the
bug commit `7c6b0e`):

1. **Dockerfile**: `ln -s /usr/local/bin/pip3 /usr/local/bin/pip` aborted with
   `File exists` — our pinned base already ships `pip`. Changed to `ln -sf`.
2. **build.sh**: the 2020-era source compiles `-Werror -Wdocumentation`; clang-18
   tightened `-Wdocumentation` (empty `\retval` paragraphs in `psa/crypto.h`), turning
   warnings into hard errors. Added `-DMBEDTLS_FATAL_WARNINGS=OFF` to the cmake line.

## Root cause of the failures

The repo's FuzzBench Dockerfiles do not reproduce the benchmark:

1. **Source cloned at HEAD, not the pinned `benchmark.yaml` commit** — so builds run
   against today's upstream. Confirmed drift: curl removed `buildconf`; mbedtls
   renamed `config.pl`→`config.py`; re2 HEAD fails clang-22; harfbuzz HEAD needs
   meson ≥ 0.60; libpng HEAD moved `contrib/oss-fuzz/build.sh`.
2. **FuzzBench env vars unset.** `build.sh` scripts read `$FUZZER_LIB` (engine
   driver lib → `/usr/lib/libFuzzingEngine.a` for afl) and `$FUZZER` (fuzzer name).
   OSS-Fuzz's `compile` doesn't set them, so `set -u` aborts with `unbound variable`.

This is why FuzzBench's own papers get ~19 compiling — FuzzBench's builder pins every
commit and sets those vars. This repo's import dropped both.

### The fix

- **Dockerfile pins** (added `git checkout <commit>` after the HEAD clone): harfbuzz,
  re2, freetype2, php, woff2, libpng, and the newly-imported lcms/libpcap/openh264/
  stb/vorbis where they cloned HEAD. (freetype2 also moved off the dead `git://`
  mirror.)
- **`FUZZER_LIB` and `FUZZER=afl` in the pipeline build commands**
  (`prework/prework_build.py` `build_prework_rebuild_command`, `sandbox/broker.py`
  `_build_command`). Harmless for ARVO targets.
- Rebuild the affected/new images once with the pinned base:
  `docker build --build-arg BASE=$(cat prework/base.pin) --build-arg AFLPP_REF=$(cat prework/aflpp.pin) -t bench-fb/<dir> -f prework/fuzzbench/<dir>/Dockerfile prework/fuzzbench/<dir>/`

## Importing the missing 8

`prework/fuzzbench/` was **untracked** in git — an unfinished, partial import (16 of
~24). The missing 8 (lcms, libpcap, libpng, openh264, openssl, stb, systemd, vorbis)
were pulled from FuzzBench upstream
(`github.com/google/fuzzbench/benchmarks/<name>`): each benchmark's full directory
(Dockerfile body, build.sh where present, harness `.cc`, seeds) grafted onto this
repo's shared prologue (pinned BASE + AFL++ v5.02c built from source + LLVM-18), with
source pins on the HEAD clones. All 8 build afl-instrumented.

## Pipeline integration

PoC is already optional (`if not ctx.poc_path: bug_survived = "no-poc"` →
throughput-only), and images resolve via `prework_image_for(entry)` =
`image_tag(project, local_id)` = `bench-aflpp/<project>-arvo-<local_id>`.

Added: `manifest_fuzzbench.json` (22 entries, `"kind":"fuzzbench"`, synthetic
`local_id` 900001–900022, real `/src` dir as `project`); image tags (re-creatable
from `.fb_afl_test/working_set.tsv`); `phase2_setup.extract_source_from_image`; a
**fuzzbench branch in `phase3_online._extract_online_target`** (extract source, build
baseline, no PoC); a `seed_corpus.zip` name fallback; and the `FUZZER_LIB`/`FUZZER`
env above.

**Verified** through the actual pipeline functions: `_extract_online_target` builds
an afl-instrumented baseline for libxml2, zlib, proj4 (`PROJ` layout), libxslt, the
recovered re2, and the imported libpng (multi-dep) — each returning the
throughput-only result.

## How to run

```
python3 phase3_online.py --manifest data/manifests/manifest_fuzzbench.json ...   # usual flags
```

The online loop builds the baseline, profiles (kernel-matched perf), runs optimizer
rounds under the replay-speedup gate, and fuzzes with `afl-fuzz`. No bug-survival gate
(no injected bug).

## Incremental builds (ccache) — investigated, not shipped

ccache 4.10.2 is in the images, but: `compile_afl` hardcodes the afl-cc compiler
(must be wrapped preserving the `++` name or C++ links break), cold builds run ~5–6×
slower (ccache double-invokes the heavy afl-cc), and warm builds show no gain because
`build.sh` does a clean build each round (CMake reconfigure isn't cacheable). Truly
incremental rounds need per-project build-dir persistence. Not done.

## Running a FuzzBench target through the ONLINE loop

First real end-to-end online run of a FuzzBench target (mruby bug benchmark,
2026-10-01). Three things were needed; the first is operational, the other two
were latent ARVO-only assumptions in the pipeline that any FuzzBench target hits.

1. **Point the pipeline at the FuzzBench manifest.** `run_benchmark.py` reads
   `config.MANIFEST_PATH` (there is no `--manifest` flag). It now honors
   `BENCHMARK_MANIFEST_PATH`, so:

   ```
   export BENCHMARK_MANIFEST_PATH=manifest_fuzzbench.json
   EXP_PREFIX=online-24h-bug ./run_online_pertrial.sh mruby     # 24h, 10+10, 10 agents
   # verification smoke: DURATION=7200 INTERVAL=300 OPT_TIMEOUT=2700 EXP_PREFIX=smoke ...
   ```

   **Use a collision-free project name.** `--project X` filters the manifest by
   `entry["project"] == X`. `bloaty`, `libxml2`, `harfbuzz` each exist as BOTH a
   coverage and a bug entry, so those names are ambiguous online. The unambiguous
   bug targets are **`mruby`, `mbedtls`, `php-src`** (and the three colliding ones
   once the coverage twin is renamed or removed).

2. **PoC-reproduction gate** (`phase3_online.py`, ~line 1640). The ARVO gate
   "baseline must still crash on the known PoC" aborted every FuzzBench run
   (`baseline did not reproduce -> 0 trials`) because FuzzBench ships no PoC. Now
   skipped for `entry["kind"] == "fuzzbench"` (throughput-only; bug-survival
   informational).

3. **`_clean_build_artifacts` deleted source** (`phase2_setup.py`). It `rm -rf`'d
   *every* directory named `build`/`_build` anywhere in the tree. A dir with that
   name can be OUTPUT or SOURCE, and neither name nor position decides it:
   - mruby's root `build/` is rake OUTPUT, but `lib/mruby/build/` is .rb SOURCE
     (`load_gems.rb`) -> deleting it: `rake aborted! cannot load mruby/build/load_gems`.
   - php-src's root `build/` is autoconf SOURCE (`*.m4`, `config-stubs`) that
     `./buildconf` needs -> deleting it: `cannot open build/*.m4` -> `./configure:
     No such file` -> exit 127.

   Fixed by classifying by **content** (not name/position): remove a `build`/`_build`
   dir only when it holds compiled artifacts (`.o/.a/.so/.lo/.la`) AND no build-system
   source inputs (`.m4/.ac/.am/config-stubs`). Done before the object sweep so the
   `.o/.a` that mark an output dir are still present. cmake caches
   (`CMakeCache.txt`/`CMakeFiles`/`cachedObjs`) and `.libs` still purge recursively.

**Verified**: mruby round 1, one of ten per-trial agents produced a **2.01x**
replay-speedup fold (`outcome=kept`, vs a 0.13% noise floor), hot-swapped
(generation 1) into its trial, which relaunched on the optimized binary. The
agent folded mruby symbol-table / method-cache / ivar hot paths (`mt_rehash`,
`mrb_vm_find_method`, `iv_rehash`, ...). NOTE: a per-round `OPT_TIMEOUT` that is
too tight makes most agents time out (`outcome=agent-failed`); the launcher
default 14400s (4h) is sized for this -- do not shrink it for a real campaign.

## Remaining work

- **curl, mbedtls**: pin their dependencies, then rebuild.
- **Seeds**: several targets fuzz from the 1-byte fallback; provide real seeds before
  a throughput campaign. (Several imported benchmarks ship a `seeds/` dir now.)
- **Standalone per-trial path**: `setup_cve_arvo*` in `phase2_setup.py` is still
  ARVO-only; the online loop (`phase3_online`, `run_online_pertrial.sh`) is wired.
- **Commit**: `prework/fuzzbench/` is still untracked; commit it (plus the pipeline
  edits and `manifest_fuzzbench.json`) to make the import durable.
- **Image tags are local**: recreate on a fresh machine from `working_set.tsv`.
