# Startup contamination in the `profile-once-fuzz-folds` replay profile

Measurement-only investigation (2026-09-28). **No skill, script, or pipeline file was modified.**

Question: the profiler
(`/home/sefcom/.claude/skills/profile-once-fuzz-folds/scripts/replay_fuzzer_profile.py`)
relaunches the replay target in a `while` loop until `--min-sample-seconds` (120 in
production) of wall clock has elapsed, all under **one** `perf record -g --call-graph dwarf
-F 997` session. Every pass therefore pays program startup, dynamic loading, sanitizer
init and one-time target init, and those samples land in the ranked hotspot list.
**How large is that contamination?**

---

## The workload under test

From `replay_fuzzer_profile.py:104-127`, the recorded command is

```
if [ -x /out/afl-showmap ]; then
  end=$(( $(date +%s) + 120 ))
  while [ "$(date +%s)" -lt "$end" ]; do
    /out/afl-showmap -C -i /corpus -o /dev/null -t 5000+ -m none -- /out/<TARGET> >/dev/null 2>&1 || true
  done
else   # libFuzzer form
  ... /out/<TARGET> /corpus -runs=0 -seed=... ...
fi
```

**Every target in this repo's campaigns is an AFL++ build**, so every profile in
`/data/fuzz-opt/results` used the `afl-showmap -C` form (verified: `afl-showmap` is
executable in all 8 `baseline/bin` directories).

Two facts that shape the answer:

1. `afl-showmap -C` starts the target **once** through the fork server (all 8 targets
   report `Persistent mode binary detected` / `Deferred forkserver binary detected`), then
   forks/loops per input. So exec + `ld.so` + ASAN init + target one-time init are paid
   **once per loop pass**, not once per input — the loop pays them ~N_passes times over
   the 120 s window, where N_passes = 120 / t_full.
2. `--out-dir` is the **baseline** bin dir (`phase2_setup.py:1457`,
   `baseline_bin_dir = experiment_dir/baseline/bin`, `phase2_setup.py:3164`); in the online
   loop it is `previous_best_bin` (`phase3_online.py:378`). The runner image is overridden
   to the pinned prework image `bench-aflpp/<project>-arvo-<local_id>` via
   `FUZZ_SOURCE_FOLDS_RUNNER_IMAGE` (`phase2_setup.py:1429`) — **not** `base-runner`, which
   cannot load these binaries at all.

---

## PHASE 1 — artifact inventory

Everything lives under `/data/fuzz-opt/results` (reached through the symlink
`/home/sefcom/fuzz-opt/results -> /data/fuzz-opt/results`; plain `find` on
`/home/sefcom/fuzz-opt` finds nothing because it does not follow that symlink).
A `find -L` over the rest of `/home/sefcom/fuzz-opt` finds **no** `flat.txt`,
`callgraph.txt`, `perf.data`, `metadata.json` or `profile_once` outside `results/`.

```
find /data/fuzz-opt/results -type d -name profile_once      # 264 dirs
find /data/fuzz-opt/results -path '*profile_once/flat.txt'  # 262 files
find /data/fuzz-opt/results -path '*profile_once/perf.data' # 258 files, 313.9 GB total
```

Each `profile_once/` holds `flat.txt`, `callgraph.txt`, `fuzzer.log`, `metadata.json`,
`perf.data`. `metadata.json` confirms the production settings, e.g.

```json
{"corpus_file_count": 25527, "cpu": 9, "min_sample_seconds": 120,
 "mode": "replay", "seed": 1337, "docker_exit_code": 0}
```

| campaign | target | profiles | dates | perf.data |
|---|---|---:|---|---:|
| online-24h-b1-libxml2 | libxml2-arvo-1972 | 6 | 2026-08-03..04 | 6.5 GB |
| online-24h-b1-wolfssl | wolfssl-arvo-26567 | 7 | 2026-08-03..04 | 7.2 GB |
| online-24h-b2-libavc | libavc-arvo-16505 | 6 | 2026-08-05..06 | 8.1 GB |
| online-24h-b2-selinux | selinux-CVE-2021-36085 | 8 | 2026-08-05..06 | 8.7 GB |
| online-24h-b3-yara | yara-arvo-3848 | 8 | 2026-08-09..10 | 8.4 GB |
| online-24h-b3r-yara | yara-arvo-3848 | 7 | 2026-08-14 | 7.2 GB |
| online-24h-b3r2-yara | yara-arvo-3848 | 9 | 2026-08-15..16 | 9.1 GB |
| online-24h-b3r4-yara | yara-arvo-3848 | 8 | 2026-08-20..21 | 8.3 GB |
| online-24h-b3r3-yara | yara-arvo-3848 | 8 | 2026-08-22 | 8.1 GB |
| online-24h-b3r3-lcms | lcms-arvo-756 | 8 | 2026-08-22 | 8.0 GB |
| online-24h-b5-PcapPlusPlus | PcapPlusPlus-arvo-22232 | 8 | 2026-08-24 | 7.9 GB |
| online-24h-b5-assimp | assimp-arvo-24463 | 5 | 2026-08-24 | 22.6 GB |
| online-24h-b6-PcapPlusPlus | PcapPlusPlus-arvo-22232 | 7 | 2026-08-27 | 6.9 GB |
| online-24h-b6-assimp | assimp-arvo-24463 | 5 | 2026-08-27 | 25.7 GB |
| online-24h-c1-libxml2 | libxml2-arvo-1972 | 65 | 2026-09-19..20 | 70.4 GB |
| online-24h-c2-libxml2 | libxml2-arvo-1972 | 73 | 2026-09-22..23 | 79.7 GB |
| _archive/noprofile-b1-libxml2 | libxml2 | 5 | 2026-08-02 | 4.9 GB |
| _archive/noprofile-b1-wolfssl | wolfssl | 6 | 2026-08-02 | 5.7 GB |
| _archive/partial-profilefix-b1 | libxml2, wolfssl | 4 | 2026-08-03 | – |
| _archive/online-24h-c1-libxml2-aborted-authfail-0113 | libxml2 | 8 | 2026-09-19 | 9.2 GB |
| _archive/online-24h-c1-libxml2-aborted-dumptimeout-0337 | libxml2 | 1 | 2026-09-19 | 1.2 GB |

Frozen corpora (`.../profiles/fixed_corpus`) survive next to every profile: 20 002 –
29 054 files, 86 – 275 MB per target. Baseline builds survive at
`<campaign>/<target>/baseline/bin` (the `/out` directory: fuzz target + `afl-showmap` +
the AFL toolchain). **Both halves needed for Phase 3 are present for all 8 targets.**

---

## PHASE 2 — what the existing `flat.txt` files say

Caveat that limits Phase 2 (and is why Phase 3 matters more): the reports are generated
with `perf report ... --percent-limit 0.5`, so **only symbols ≥ 0.5 % appear**. Across the
262 reports the listed rows sum to a median of just **39 – 80 %** of samples; the rest is a
long tail of sub-0.5 % symbols that is invisible here. Any "startup %" below is a **lower
bound**.

### 2a. Symbols classified as startup/init/teardown

Counted: `_dl_*` / `ld-linux*` / `ld-2.31.so`, `__libc_start_main` / `_start` /
`__libc_csu_init`, `__static_initialization*` / `_GLOBAL__sub_I*`, `__asan_init` /
`AsanInitInternal` / `TryAsanInitFromRtl`, `__sanitizer::*Init*`,
`__sanitizer_cov_trace_pc_guard_init` / `__afl_*_init`, plus `__lsan::*` (leak check at
process exit) and `libLLVM*` / `llvm::*` (`llvm-symbolizer` symbolizing sanitizer output).

| campaign/target | n | median startup % | max | flat.txt covers |
|---|---:|---:|---:|---:|
| _archive/noprofile-b1-libxml2 | 5 | **22.65** | 24.07 | 64 % |
| _archive/noprofile-b1-wolfssl | 6 | **24.89** | 27.54 | 67 % |
| online-24h-b6-assimp | 5 | **38.17** | 39.76 | 57 % |
| online-24h-b5-assimp | 5 | **37.15** | 39.16 | 56 % |
| online-24h-b5-PcapPlusPlus | 8 | **9.66** | 16.39 | 52 % |
| online-24h-b6-PcapPlusPlus | 7 | **5.37** | 16.80 | 58 % |
| online-24h-b3r2-yara | 9 | 1.28 | 1.99 | 67 % |
| online-24h-b3r3-yara | 8 | 0.59 | 2.13 | 68 % |
| online-24h-b3r4-yara | 8 | 0.41 | 1.95 | 71 % |
| online-24h-b3-yara / b3r-yara | 15 | 0.00 | 1.45 | 72 % |
| online-24h-b1-libxml2 | 6 | 0.00 | 0.00 | 75 % |
| online-24h-b1-wolfssl | 7 | 0.00 | 0.00 | 80 % |
| online-24h-b2-libavc | 6 | 0.00 | 0.00 | 58 % |
| online-24h-b2-selinux | 8 | 0.00 | 0.00 | 73 % |
| online-24h-b3r3-lcms | 8 | 0.00 | 0.00 | 39 % |
| online-24h-c1-libxml2 | 65 | 0.00 | 0.52 | 74 % |
| online-24h-c2-libxml2 | 73 | 0.00 | 0.00 | 74 % |

Top startup symbols, by campaign:

* **assimp (b5/b6)** — `llvm-symbolizer` frames: `ld-2.31.so [.] _dl_rtld_di_serinfo`
  5.8–5.9 %, `libLLVM-18.so.1 [.] llvm::DataExtractor::getULEB128` 3.3–3.4 %,
  `llvm::DWARFUnit::updateAddressDieMap` 3.0 %, `llvm::DWARFAbbreviationDeclaration::extract`
  2.6–2.7 %, `ELFFile<...>::getSectionContentsAsArray<Elf_Sym_Impl>` 2.5 %.
* **PcapPlusPlus (b5/b6)** — `ld-2.31.so [.] _dl_rtld_di_serinfo` 4.9–6.8 %, plus the same
  libLLVM DWARF frames at 0.2–1.0 %.
* **_archive/noprofile-b1-\*** (the pre-fix libFuzzer-on-`base-runner` profiles) —
  `__lsan::ScanRangeForPointers` 12.9 % (libxml2) / 15.0 % (wolfssl),
  `ld-2.31.so [.] _dl_rtld_di_serinfo` 4.2 % / 5.6 %,
  `__sanitizer_cov_trace_pc_guard_init` 0.9 %.
* **yara** — `ld-2.31.so [.] _dl_rtld_di_serinfo` 0.08–0.99 %,
  `__asan::TryAsanInitFromRtl` 0.17–0.25 %.
* **libxml2 (b1/c1/c2), wolfssl (b1), libavc, selinux, lcms** — no startup symbol reaches
  the 0.5 % reporting floor at all.

### 2b. The bigger story: which *process* the samples belong to

`flat.txt` also carries the `Command` column, which is far more decisive than symbol
matching. Median share of the *listed* samples, per process:

| campaign/target | target proc | afl-showmap | llvm-symbolizer | kernel (in target proc) | covered |
|---|---:|---:|---:|---:|---:|
| online-24h-b6-assimp | **1.53 %** | 0.00 | **52.75 %** | 0.80 | 57 % |
| online-24h-b5-assimp | **2.06 %** | 0.50 | **51.67 %** | 0.83 | 56 % |
| online-24h-b5-PcapPlusPlus | 33.96 % | 4.78 | **13.05 %** | 8.56 | 52 % |
| online-24h-b6-PcapPlusPlus | 46.65 % | 3.91 | 7.12 % | 10.32 | 58 % |
| online-24h-b3r3-lcms | **10.47 %** | **28.45 %** | 0.00 | 8.79 | 39 % |
| online-24h-b3r2-yara | 61.54 % | 4.24 | 0.93 | 4.07 | 67 % |
| online-24h-b3r3-yara | 64.24 % | 2.80 | 0.25 | 2.55 | 68 % |
| online-24h-c1-libxml2 | 64.96 % | 8.71 | 0.00 | 0.00 | 74 % |
| online-24h-c2-libxml2 | 65.80 % | 8.87 | 0.00 | 0.00 | 74 % |
| online-24h-b1-wolfssl | 78.20 % | 2.13 | 0.00 | 0.00 | 80 % |
| online-24h-b2-selinux | 70.42 % | 2.92 | 0.00 | 0.00 | 73 % |
| online-24h-b2-libavc | 58.38 % | 0.00 | 0.00 | 22.27 | 58 % |
| _archive/noprofile-b1-libxml2 | 59.53 % | 0.00 | 0.00 | 23.56 | 64 % |
| _archive/noprofile-b1-wolfssl | 61.64 % | 0.00 | 0.00 | 22.61 | 67 % |

A whole-file DSO breakdown of one assimp `perf.data` confirms the flat report is not
hiding anything (this one needs no symbols, so it runs on the host):

```
perf report -i /data/fuzz-opt/results/online-24h-b6-assimp/assimp-arvo-24463/optimized/\
online/iter_04/source_diff/profiles/profile_once/perf.data \
  --stdio --no-children -g none --sort dso --percent-limit 0

# Samples: 486K of event 'cycles'
   46.23%  libLLVM-18.so.1
   27.96%  [kernel.kallsyms]
    9.68%  libc-2.31.so
    7.15%  ld-2.31.so
    6.37%  assimp_fuzzer      <-- the target binary
    1.10%  afl-showmap
```

**6.4 % of the assimp profile is the target binary.** The ranked hotspot list the optimizer
worked from was 46 % `llvm-symbolizer` DWARF parsing and 7 % dynamic loader.

The existing guard does not catch this: `_profile_has_target_symbols`
(`phase2_setup.py:1486`) accepts a profile if *any* frame is attributed to the target
binary, so a 1.5 %-target profile passes.

---

## PHASE 3 — direct measurement (the decisive one)

### Method, and why "empty corpus" does not work

The task asked for `t_startup` = one replay pass over an **empty** corpus directory. That
measurement is not available for these targets, and the reason is itself a result:

```
/out/afl-showmap -C -i /empty-dir -o /dev/null -t 5000+ -m none -- /out/<TARGET>
[*] Scanning '/probe/c0'...
[-] PROGRAM ABORT : could not read input testcases from /probe/c0
         Location : main(), src/afl-showmap.c:1901
```

`afl-showmap` aborts on an empty input directory **before** it launches the target, so an
empty pass measures only `afl-showmap`'s own process start (12–24 ms) and never pays the
target's exec, dynamic link, ASAN init or fork-server handshake. Using it would understate
the real per-pass startup.

Three substitutes were measured instead, on the **same binary** and the **same replay
form** the profiler uses:

1. **`t_1`** — a complete pass over a **1-file** corpus. This is the closest achievable
   analogue of the empty pass that still launches the target: full process start + dynamic
   link + ASAN init + fork-server handshake + one input + teardown. It is a slight
   *over*-estimate of pure startup (it contains one input's work).
2. **doubling** — `S = 2·t(N) − t(2N)`, where the 2N corpus is every corpus file
   hard-linked **twice** (`a_<name>`, `b_<name>`). Because the 2N input multiset is exactly
   the N multiset doubled, this cancels per-input cost exactly with no sampling assumption.
3. **stratified sizes** — passes over every-k-th file (n = 1, 500, 5000) plus the full
   corpus, as a slope/intercept cross-check.

Also measured: the **exact `while` loop body** from `replay_fuzzer_profile.py` run for 15 s,
to capture the `bash` + `date +%s` per-iteration cost the profiler pays on top of the replay.

Everything ran inside the same pinned prework image the profiler uses, one container per
target, pinned to one idle CPU (20), with `/out` and `/corpus` bind-mounted read-only —
the same shape as `build_replay_profile_docker_command`. Timing is taken **inside** the
container so docker's own start-up is excluded (the profiler starts docker once for the
whole 120 s loop, so its cost is not per-pass).

### Results — all 8 targets

Medians over the repeats shown. `t_1` = one full pass over a 1-file corpus (= startup +
fork-server handshake + 1 input + teardown). `t_full` = one pass over the frozen corpus.
`S = 2·t(N) − t(2N)` is the doubling estimate of the constant per-pass cost.

| target | fuzz target | N units | t_1 (ms) | t_full (s) | spread of t_full | t_2N (s) | S = 2t(N)−t(2N) | **contamination t_1/t_full** |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| lcms | cms_transform_fuzzer | 20 002 | **16.35** | 0.8566 | 0.82 % | 1.6968 | **+16.4 ms** | **1.91 %** |
| libxml2 | libxml2_xml_read_memory_fuzzer | 25 354 | **29.42** | 42.291 | 0.28 % | 85.988 | −1406 ms | **0.070 %** |
| wolfssl | fuzzer-wolfssl-rsa | 21 717 | **14.82** | 13.175 | 0.21 % | 26.248 | +101 ms | **0.112 %** |
| libavc | avc_dec_fuzzer | 29 054 | **20.82** | 135.485 | 0.05 % | 277.210 | −6241 ms | **0.015 %** |
| selinux | secilc-fuzzer | 24 450 | **23.54** | 294.97 | (1 rep) | – | – | **0.008 %** |
| yara | pe_fuzzer | 20 842 | **52.57** | 69.768 | 0.30 % | 138.835 | +701 ms | **0.075 %** |
| assimp | assimp_fuzzer | 22 779 | **90.91** | 1053.33 | (1 rep) | – | – | **0.009 %** |
| PcapPlusPlus | FuzzTarget | 22 080 | **27.17** | 29.506 | 0.001 % | 58.986 | +26 ms | **0.092 %** |

Repeats: `t_1` and `t_500` 5 reps everywhere; `t_full` 5/2/3/2/1/2/1/2 reps; `t_2N` 5/1/2/1/–/1/–/1.
yara, assimp and PcapPlusPlus were run concurrently on separate pinned CPUs (30/31/32) to
save wall clock; the others ran alone on CPU 20. selinux and assimp were cut short after
`t_full` (their passes are 5 min and 17.5 min, so `t_2N` was not affordable).

Empty-corpus passes, for completeness (these **abort before the target starts**, so they are
*not* `t_startup`): lcms 12.40 ms, libxml2 24.29 ms (medians of 5).

The doubling estimate agrees with `t_1` where the replay is linear in N (lcms:
16.4 ms vs 16.35 ms; PcapPlusPlus: 26 ms vs 27 ms). Where it disagrees, the replay is
**not** linear in N:

* libxml2 and libavc give a *negative* `S`, i.e. `t(2N) > 2·t(N)`: per-input cost **rises**
  with pass length (persistent-mode state accumulating across the pass). Per-input cost for
  libxml2 goes 1.537 ms (n=500) → 1.563 ms (n=5 000) → 1.668 ms (full).
* wolfssl and yara give an `S` (101 ms, 701 ms) well above `t_1` (15 ms, 53 ms): the first
  few hundred inputs are *cheaper* than steady state, so the extrapolated intercept absorbs
  a warm-up transient that is not process startup.

Either way both bracketing estimates are far below 5 %: the largest `S` of any target,
yara's 701 ms, is 1.0 % of yara's 69.8 s pass.

### The `while`-loop shell overhead

For lcms (the only target whose pass is short enough for the loop to iterate many times),
the exact loop body from `replay_fuzzer_profile.py` ran 17 iterations in 14.650 s:

```
per_iter = 0.86178 s   vs   t_full = 0.85660 s   ->   bash + 2x `date +%s` = 5.2 ms/pass (0.60 %)
```

So lcms's total per-pass non-per-input cost is **(16.35 + 5.2) / 861.8 = 2.50 %**. For every
other target the pass is ≥ 13 s, so the same ~5 ms is ≤ 0.04 %.

### Cross-check against the archived profiles

`samples / 997 Hz` recovers the recorded session length from each `flat.txt`. Medians:
~117–170 s for every campaign (the 120 s deadline plus the pass that was in flight), except
assimp at **520 s (b5) / 604 s (b6)** — consistent with a single pass overshooting the
deadline. Dividing by the measured `t_full` gives the number of relaunches per profile:
lcms ~137, wolfssl ~9, libxml2 ~3, yara ~2, libavc/selinux/assimp 1. The fraction of the
session spent in startup is `t_1/t_full` regardless of how many passes fit, which is what
the table reports.

(One inconsistency worth recording: selinux's archived sessions are ~129 s but the
iter_08 corpus takes 295 s per pass on the baseline binary today. The archived profiles
used earlier, smaller corpora — median 23 088 files vs 24 450 — and the *previous best*
binary rather than the baseline, so the two are not the same workload. It does not affect
the contamination fraction, which is 0.008 % against either number.)

---

## The contamination that *is* material: sanitizer reporting, not startup

Phase 2 showed some profiles are almost entirely **not** the target binary (assimp: 6.4 %
of samples in `assimp_fuzzer`, 46 % in `libLLVM`). That is not the relaunch loop. Caught in
the act, live, inside a running replay:

```
docker exec <assimp container> ps -eo pid,etimes,pcpu,comm
    PID ELAPSED %CPU COMMAND
   2637     403  0.6 afl-showmap
   2638     403  0.3 assimp_fuzzer
   6905       0  0.0 assimp_fuzzer
   6906       0  0.0 llvm-symbolizer     <-- spawned mid-pass, repeatedly
```

`llvm-symbolizer` is spawned **during** the replay, once per sanitizer report, i.e. roughly
per offending input. Turning the sanitizer's reporting knobs off isolates the cost (same
binary, same corpus, same replay form; medians of 2–3 reps):

| target | corpus | default env (**what the profiler runs**) | `detect_leaks=0` (**what the gate runs**) | `detect_leaks=0:symbolize=0` | leak-check share | symbolize share |
|---|---|---:|---:|---:|---:|---:|
| assimp | s500 | 24.08 s | 22.55 s | 9.93 s | 6.3 % | **52.4 %** |
| PcapPlusPlus | full 22 080 | 29.37 s | – | 17.01 s | – | **42.1 %** (combined) |
| libxml2 | full 25 354 | 42.89 s | 33.86 s | 33.87 s | **21.1 %** | ~0 % |
| yara | full 20 842 | 69.50 s | 60.78 s | 60.40 s | **12.5 %** | 0.5 % |
| lcms | s5000 | 0.238 s | 0.235 s | 0.232 s | ~1 % | ~1 % |
| wolfssl | full 21 717 | 13.45 s | 13.45 s | 13.46 s | 0 % | 0 % |

Two consequences:

1. **This dwarfs startup by one to two orders of magnitude** (42–52 % vs 0.01–1.9 %), and a
   corpus-size floor does nothing about it, because it scales *with* the corpus, not
   against it.
2. **The profile and the acceptance gate do not run the same workload.**
   `replay_fuzzer_profile.py` sets no environment at all, so the profile is taken with
   LeakSanitizer **on**. The gate (`sandbox/broker.py:_replay_command`, used by
   `lib/afl_replay.measure_binary`) exports `ASAN_OPTIONS=detect_leaks=0`. For libxml2 that
   is **21 % of the profiled work that the gate can never reward**; for yara, 12.5 %. That
   is the opposite of the skill's stated "what is profiled is what is measured".

For completeness, the other non-foldable slices visible in the same `flat.txt` files
(median share of listed samples, target process only, project code = everything that is not
sanitizer runtime / libc / ld.so / kernel):

| campaign/target | project code | sanitizer runtime | libc+ld | kernel |
|---|---:|---:|---:|---:|
| online-24h-b6-assimp | **0.00 %** | 0.76 | 0.00 | 0.80 |
| online-24h-b3r3-lcms | **0.00 %** | 1.70 | 0.53 | 8.79 |
| online-24h-b5-PcapPlusPlus | 6.45 % | 16.16 | 3.18 | 8.56 |
| online-24h-b6-PcapPlusPlus | 9.44 % | 22.40 | 3.96 | 10.32 |
| online-24h-b2-libavc | 25.42 % | 2.75 | 8.39 | 22.27 |
| online-24h-c2-libxml2 | 30.20 % | 28.82 | 4.96 | 0.00 |
| online-24h-c1-libxml2 | 33.23 % | 26.32 | 4.84 | 0.00 |
| online-24h-b2-selinux | 34.66 % | 28.08 | 5.12 | 0.00 |
| online-24h-b3r3-yara | 25.94 % | 19.47 | 2.88 | 2.55 |
| online-24h-b1-wolfssl | 65.12 % | 6.60 | 4.06 | 0.00 |

(`0.00 %` means no project symbol cleared the 0.5 % reporting floor — for lcms and assimp
the ranked hotspot list contains essentially **no project code at all**.)

---

## PHASE 4 — verdict

**The hypothesis as stated is false. Process-startup contamination is negligible: 0.008 % –
1.9 % of samples, with 7 of 8 targets under 0.12 %.** The reason is structural: these are
AFL++ builds, so the replay form is `afl-showmap -C`, which starts the target **once per
pass** through a persistent-mode fork server and then forks per input. Startup is amortised
over 20 000 – 29 000 inputs, not paid per input. The `while` loop relaunches the *pass*,
not the *process-per-input*, and a pass is 0.86 s – 1053 s against a 15 – 91 ms startup.

Per target:

| target | contamination | material (>5 %)? |
|---|---:|---|
| lcms | **1.91 %** (2.50 % including the loop's `bash`+`date`) | no — the worst case, and still under half the threshold |
| wolfssl | 0.112 % | no |
| PcapPlusPlus | 0.092 % | no |
| yara | 0.075 % | no |
| libxml2 | 0.070 % | no |
| libavc | 0.015 % | no |
| assimp | 0.009 % | no |
| selinux | 0.008 % | no |

**Scaling with corpus replay time.** Per-pass startup `S` is a per-target constant
(15–91 ms, median 25 ms) that does not depend on corpus size, so
`contamination = S / t_full` and it falls linearly with replay time. The observed range of
`t_full` (0.86 s → 1053 s, a factor of 1230) maps almost exactly onto the observed range of
contamination (1.91 % → 0.009 %, a factor of 220; the rest is `S` varying by target).

A corpus-size floor expressed as a **minimum full-pass wall time `T`** would bound
contamination at `S_max / T`:

| floor T | worst-case contamination (S_max = 91 ms, assimp) | typical (S = 25 ms) |
|---:|---:|---:|
| 1 s | 9.1 % | 2.5 % |
| 2 s | 4.6 % | 1.3 % |
| 5 s | 1.8 % | 0.5 % |
| 10 s | 0.9 % | 0.25 % |

Only lcms (0.86 s) sits below a 5 s floor today; every other target already clears 13 s.
So **a corpus-size floor would fix the only case that is even close, but there is almost
nothing to fix** — 2 % is not what is wrong with these profiles.

**What is actually wrong with these profiles** (found while measuring, and an order of
magnitude larger):

1. **Sanitizer-report symbolization**: `llvm-symbolizer` is 42 % of a PcapPlusPlus pass and
   52 % of an assimp pass, spawned per report *inside* the replay. In the archived assimp
   profiles it is 52 % of all samples while the target binary is 1.5–6.4 %. A corpus-size
   floor does not touch it; `ASAN_OPTIONS=symbolize=0` removes it entirely.
2. **LeakSanitizer running in the profile but not in the gate**: the profiler sets no
   `ASAN_OPTIONS`, the acceptance gate sets `detect_leaks=0`. 21 % of libxml2's profiled
   pass and 12.5 % of yara's is leak-checking work the gate is blind to.
3. **Harness overhead**: `afl-showmap`'s own `execute_testcases` /
   `showmap_run_target_forkserver` is 2–9 % of most profiles and **28 %** of lcms's, whose
   corpus barely reaches the library (44 of 7 232 edges, 0.61 %).
4. The existing sanity check `_profile_has_target_symbols` (`phase2_setup.py:1486`) accepts
   any profile with *one* target frame, so the assimp profiles (1.5 % target) passed it.

---

## Reproduction

All measurements were read-only with respect to the results tree. Temporary hard-link
corpora were built under `/data/fuzz-opt/_startup_probe{,2}/` (outside `results/`) and
deleted afterwards. Scripts used live in the session scratchpad
(`mkprobe.sh`, `mkprobe2.py`, `probe2.sh`, `probe3.sh`, `attr_full.sh`,
`phase2.py`, `phase2b.py`, `phase2c.py`, `analyze_final.py`).

Inventory:

```bash
find /data/fuzz-opt/results -type d -name profile_once | wc -l            # 264
find /data/fuzz-opt/results -path '*profile_once/flat.txt' | wc -l        # 262
find /data/fuzz-opt/results -path '*profile_once/perf.data' \
  -printf '%s\n' | awk '{n++;s+=$1} END{print n, s/1e9" GB"}'             # 258, 313.9 GB
```

DSO breakdown of a recorded profile (host `perf` 6.8.12, no symbols needed):

```bash
perf report -i .../online-24h-b6-assimp/.../profile_once/perf.data \
  --stdio --no-children -g none --sort dso --percent-limit 0
```

Sized hard-link corpora (zero extra disk; `x2` is every unit linked twice):

```bash
python3 mkprobe2.py <tag> <fixed_corpus_dir>   # -> /data/fuzz-opt/_startup_probe2/<tag>/{s1,s500,s5000,x2}
```

The timed replay, exactly the profiler's replay form, timed **inside** the container so
docker start-up is excluded:

```bash
docker run --rm --cpuset-cpus 20 --memory 4g --shm-size 2g --privileged --ulimit core=0 \
  -v <campaign>/<target>/baseline/bin:/out:ro \
  -v <...>/profiles/fixed_corpus:/corpus:ro \
  -v /data/fuzz-opt/_startup_probe2/<tag>:/p2:ro \
  --entrypoint /bin/bash bench-aflpp/<project>-arvo-<local_id>:latest -lc '
    run(){ s=$(date +%s%N)
           /out/afl-showmap -C -i "$1" -o /dev/null -t 5000+ -m none -- /out/<TARGET> >/dev/null 2>&1
           e=$(date +%s%N); awk -v a=$s -v b=$e "BEGIN{printf \"%.5f\", (b-a)/1e9}"; }
    run /p2/s5000 >/dev/null                 # warmup
    for D in /p2/s1 /p2/s500 /p2/s5000 /corpus /p2/x2; do
      printf "%s:" $D; for i in 1 2 3 4 5; do printf " %s" "$(run $D)"; done; echo
    done'
```

The exact `while` loop from `replay_fuzzer_profile.py`, timed for 15 s (lcms):

```bash
s=$(date +%s%N); iters=0; end=$(( $(date +%s) + 15 ))
while [ "$(date +%s)" -lt "$end" ]; do
  /out/afl-showmap -C -i /corpus -o /dev/null -t 5000+ -m none -- /out/cms_transform_fuzzer >/dev/null 2>&1 || true
  iters=$((iters+1))
done
e=$(date +%s%N)   # -> iters=17 wall=14.650 per_iter=0.86178
```

Sanitizer attribution (`attr_full.sh`): the same pass run three times over, with
`ASAN_OPTIONS` unset / `detect_leaks=0` / `detect_leaks=0:symbolize=0`.

### Caveats

* The profiles are recorded under `perf record -g --call-graph dwarf -F 997`; my timings
  are not. perf's overhead appears to be ~25–30 % (libavc: 135 s measured vs a ~170 s
  recorded session) and is time-proportional, so it should not bias the
  startup/per-input *ratio* much, but it is not measured here.
* `t_1` slightly over-states pure startup (it includes one input's work — 42 µs to 1.7 ms
  depending on the target, i.e. at most 2–6 % of `t_1`).
* Profiles in the online loop use `previous_best_bin`, not the pristine baseline; I used
  `baseline/bin` throughout, so per-input cost may differ from the archived runs by
  whatever the accepted folds achieved. The startup constant `S` is unaffected.
* yara / assimp / PcapPlusPlus ran concurrently on separate pinned CPUs; their absolute
  times may be a few percent high. Their contamination fractions (0.009–0.092 %) have
  orders of magnitude of headroom.

---

## Note: the skill script changed under me, mid-measurement (not by this task)

This investigation modified nothing. However,
`/home/sefcom/.claude/skills/profile-once-fuzz-folds/scripts/replay_fuzzer_profile.py` has
an mtime of **2026-09-28 00:47**, inside this session's window, and its new content quotes
this session's interim numbers verbatim ("libLLVM was 46.2% of samples against 6.4% for the
target binary", "__lsan::ScanRangeForPointers at 13-15%", "flat.txt ... can sum to as little
as 39% of samples"). A concurrently running session (`claude --resume Modifier`, pid
2654568) applied them. The changes, relative to the version measured here, are:

* `-e ASAN_OPTIONS=symbolize=0:detect_leaks=0`, `-e UBSAN_OPTIONS=symbolize=0`,
  `-e MSAN_OPTIONS=symbolize=0` added to the profile container — this is exactly the fix
  the symbolization/leak-check findings above imply, and it also aligns the profile with the
  gate's `detect_leaks=0`.
* A new `dso.txt` artifact (`perf report --sort dso --percent-limit 0`), the whole-file DSO
  breakdown used above to show assimp's 6.4 % target share.

**This does not invalidate anything here.** The `while` loop and both replay forms are
byte-identical to the version analysed, and every number in this note was measured either
against the archived profiles (recorded with the *old*, no-env behaviour) or with an
explicit environment stated per measurement. But profiles recorded from now on will have
the symbolizer/leak-check contamination removed, so the Phase 2 tables above describe
historical artifacts only.
