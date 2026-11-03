# ARVO targets on the current pipeline: revalidation

*Written 2026-11-02. Branch `feat/aflpp-sandboxed-optimizer`, the 20-physical-core
test server (cpus 0-19, hyperthread sibling of c is c+20).*

## Purpose

No ARVO target had run through the pipeline since it gained the FuzzBench-parity
path, the held-out gate, the source-scope policy, the per-trial optimizers and
the profiler library supply. This work made the current code run ARVO targets
again without changing how FuzzBench targets build or run. It did not bring ARVO
targets to FuzzBench parity. "Works" means `tools/preflight_online.py` passes
every stage for a target, and libxml2 completes one short online campaign.
Engine flags and instrumentation did not change. One pipeline behaviour did
change: the profiler's library check, in commits e488374 and 392bfef. The design
and its decisions are in
`docs/superpowers/specs/2026-11-01-arvo-revalidation-design.md`.

## TL;DR

- **7 of the 8 in-scope targets are READY** on the final code (all preflighted
  after 392bfef): libxml2, c-blosc2, libavc, assimp, selinux, wolfssl,
  freeradius-server.
- **PcapPlusPlus is dropped** (user decision, 2026-11-02). After the rebuild its
  PoC crashes at a different frame from the historical one (see
  [Dropped targets](#dropped-targets-and-why)).
- **The libxml2 smoke campaign passed** (on the code as of cebd94a, before
  392bfef; see [Campaign record](#campaign-record)):
  `smoke-arvo-final-libxml2-20261102-0114`
  had 4 rounds, 3 of them `kept` (1.0999x, 1.1909x, 1.5827x), and 2 hot-swaps.
- **FuzzBench libxml2 still preflights READY** on the final code (rerun after
  392bfef).
- **Test suite:** 17 failed / 1054 passed before the work, 4 failed / 1081 passed /
  1 skipped after. The 4 remaining failures are k8s and analysis-only tests.

## What was broken

Diagnosed on the unmodified code (spec, "Findings from the diagnostics"):

| Target | Verdict | Stage | Cause |
|---|---|---|---|
| libxml2, c-blosc2, libavc, assimp, selinux, wolfssl | READY | — | — |
| PcapPlusPlus | NOT READY | profile | finding 2 |
| freeradius-server | NOT READY | aflbuild | finding 1 |

**Finding 1: prework images went stale and nothing detected it.** An image is a
snapshot of `prework/targets/<t>/` plus `prework/base.pin` and
`prework/aflpp.pin`. When the definition changed in git, the image stayed as it
was. `bootstrap_server.py --check` only checked that the tag existed, and the
build step skipped any tag that existed.

| Image | Built | Definition last changed | Effect |
|---|---|---|---|
| freeradius-server | 2026-08-28 | 2026-10-04 | build dies on `libfreeradius-make-dlopen.so: undefined symbol: __afl_area_ptr` (missing the `AFL_NOOPT=1` pre-build of make's dlopen helpers) |
| libxml2 | 2026-07-31 | 2026-10-04 | lacked the incremental `build.sh`, so every agent rebuild was a full configure-and-make (~233 s instead of ~19 s) |

Evidence: `git log -1 --format=%cs -- prework/targets/<t>/` compared with
`docker image inspect -f '{{.Created}}' bench-aflpp/<image>`.

**Finding 2: `target_libs.py` refused ARVO builds that copy glibc into /out.**
PcapPlusPlus's historical `build.sh` runs
`cp $(ldd $OUT/FuzzTarget | cut -d" " -f3) $OUT`, which copies the 20.04 build
image's `libc.so.6`, `libpthread.so.0` and the rest into `/out`. The profiler
library supply required every `/out` library to load in the 24.04 profiler
image. `ldd` on `libpthread.so.0` failed with `GLIBC_PRIVATE`, and `prepare`
raised `TARGET LIBS UNRESOLVED`. Trials were unaffected, because ARVO launches
set no `LD_LIBRARY_PATH`. Evidence: the same mark is still in the final-code
PcapPlusPlus preflight (2026-11-02 19:00), now for the case e488374 does not
cover (limitation 3):
`grep -o 'TARGET LIBS UNRESOLVED[^{]*' results/preflight-final-20261102/preflight_PcapPlusPlus.json`.

**Finding 3: the bootstrap image check used the mixed-case project name.**
`check_images` built `bench-aflpp/{project}-arvo-{id}` by hand, but
`build_image.image_tag` lowercases the name. As a result
`bench-aflpp/pcapplusplus-arvo-22232` was reported missing even though it
existed. Evidence: before cbe4496, `python3 bootstrap_server.py --check` listed
`PcapPlusPlus-arvo-22232` as `todo` (the hand-built tag is at lines 183 and 216
of `git show cbe4496^:bootstrap_server.py`).

**Also in the up-front diagnostics:** 17 pre-existing test failures on this
branch (spec table). The shared-path ones were fixed in e9bae67 and cebd94a.

**Found later:**

- The first smoke campaign showed the agent timeout was too short (see
  [Campaign record](#campaign-record)).
- While fixing the `test_sandbox_launch` failure, a real broker defect turned
  up: any non-`OSError` exception closed the broker for the rest of the
  session. Fixed in 871840e.
- freeradius-server's second preflight failure at `profile` led to commit
  392bfef.

## What changed

| Commit | Change |
|---|---|
| 52882bc | `prework/build_image.py`: each image gets the label `bench-aflpp.definition-sha256`, a sha256 over the target's Dockerfile, `meta.json`, `build.sh` and `poc_input` plus both pins (`definition_hash`) |
| cbe4496 | `bootstrap_server.py`: `--check` compares that label with the definition on disk and reports each image as `ok`, `STALE`, `unver.` or `todo`. The build step rebuilds missing and stale images, and `--rebuild-unverified` also rebuilds unlabeled ones. The tag goes through `image_tag`, which fixes finding 3 |
| e488374 | `target_libs.py`: glibc/loader-family files in `/out` are left out of the probed set and recorded as `ignored_libc_out` instead of refusing the target. `VERSION` goes to 3 |
| e9bae67 | tests: `test_build_corpus` and `test_replay_timing` follow the script's current arguments and clock reads |
| 871840e | `sandbox/broker.py`: a failing op gets `{"ok": false, "error": "broker error: <TypeName>; see the host log"}` and the broker keeps serving. Before, the socket was closed for the rest of the session |
| cebd94a | tests: `test_sandbox_egress` follows the credential store's current layout; `test_sandbox_launch` follows the broker's dict reply; the real-topology case in `test_sandbox_session` is skipped on hosts that cannot hold the 2-31 layout |
| 392bfef | `target_libs.py`: the profiler path takes the `/out` directories the build's libraries were found in (`out_dirs`, for example `/out/lib`), not only bare `/out`. `VERSION` goes to 4 |
| 9e0414a, d85e437, df38b7c, 24872e0 | docs: design spec, the spec's image-refresh record, implementation plan, and the plan's Task 10 |

FuzzBench builds and launches are untouched. With a root-level `/out` layout and
no glibc copies, the profiler's library set and path are the same as before.

## How to run an ARVO target on this box

All commands run from the repo root. `config.py` defaults are not changed.
Per-run settings are environment overrides or flags.

**1. Image state.**

```
python3 bootstrap_server.py --check
```

Each `bench-aflpp/<project>-arvo-<id>` row reads one of:

| Mark | Meaning |
|---|---|
| `ok` | the image's label matches the definition on disk |
| `STALE` | the definition changed since the build |
| `unver.` | the image was built before stamping |
| `todo` | the image is missing |

On this box all 14 rows read `ok`. The command exits 1 because of one
prerequisite row: `[ todo ] cpu cores (40) -- config.TOTAL_CORES=80 but this box
has 40`. That row is expected, since the box settings are passed per run. To
rebuild:

```
python3 bootstrap_server.py --rebuild-unverified --work <dir>
```

Build mode rebuilds `STALE` images, and `unver.` images only with
`--rebuild-unverified`. It also builds every **missing**
(`todo`) image, which is how the 6 out-of-scope targets got built (see
[Dropped targets](#dropped-targets-and-why)). Each target's verdict is written to
`<dir>/<target>/prework_result.json`.

**2. Preflight one target** (core 3 for the profile and smoke, cores 2-19 for
builds):

```
python3 tools/preflight_online.py --project <project> --cpu 3 --build-cpus 2-19 --smoke-secs 120
```

The result is `results/preflight-<project>/preflight_<project>.json`. Stages, in
order: `image`, `extract`, `poc`, `source`, `seeds`, `projectsrc`, `stripvcs`,
`aflbuild`, `profile`, `smoke`.

**3. Smoke campaign** (trials on 4-7, optimizers on 2-3, setup on 2, setup builds
on 2-19; agent cores are derived and came out as 0-1,8-19):

```
TRIALS=2 TRIAL_CORES=4-7 OPT_CORES=2-3 SETUP_CPU=2 SETUP_BUILD_CPUS=2-19 DURATION=10800 INTERVAL=300 OPT_TIMEOUT=5400 EXP_PREFIX=smoke-arvo-final BENCHMARK_CLAUDE_MODEL=claude-sonnet-5-5 ./run_online_pertrial.sh libxml2
```

**Do not use `OPT_TIMEOUT=2700` with `claude-sonnet-5-5`.** In the first smoke
every libxml2 round ended `agent-failed` at the 2700 s cap.

**4. FuzzBench non-regression check.** The list1 manifest
(`manifest_fuzzbench_list1.json`, the spec's choice; `config.py`'s default is
the ARVO manifest) names the libxml2 *coverage* entry, and its image is not on
this box. Point the preflight
at the bug manifest:

```
BENCHMARK_MANIFEST_PATH=$PWD/data/manifests/manifest_fuzzbench_bugs.json python3 tools/preflight_online.py --project libxml2 --cpu 3 --build-cpus 2-19 --smoke-secs 120
```

On the final code (rerun 2026-11-02 18:43-18:47, after 392bfef) this was
READY on image `fb-aflpp/libxml2_xml_e85b9b`, profile 20326 of 29373 samples
attributed to target-source functions. Its profiler record is version 4 with
`out_dirs: []` and `ld_library_path: /opt/oss-libs`, the same path as before
392bfef. Result:
`results/preflight-final-20261102/preflight_libxml2_fuzzbench_900025.json`.
Every libxml2 preflight, ARVO or FuzzBench, writes the same
`results/preflight-libxml2/preflight_libxml2.json`, so whichever runs last
overwrites it. Copy the JSON somewhere else after each run.

## Per-target verdicts

Images: freeradius-server and libxml2 were rebuilt from their current
definitions on 2026-11-01. All 14 images were then rebuilt with stamps by
`--rebuild-unverified` on 2026-11-02, between 00:11 and 00:47. The re-stamp
verdict is from `results/restamp-20261102/<target>/prework_result.json`. The
crash reports are in `verify.log` (rebuilt binary) and `arvo_repro.log`
(historical) in the same directory, and the build log is
`results/restamp-20261102/bootstrap_rebuild_unverified.log`. Every preflight
verdict below is from the final code (code as of 392bfef), saved as
`results/preflight-final-20261102/preflight_<project>.json`. The
`README.txt` there records the code (commit 392bfef; later commits are
docs-only) and the run windows (ARVO 17:52-18:43, PcapPlusPlus 19:00,
FuzzBench libxml2 18:43-18:47). `results/` is gitignored, so these evidence
copies exist only on this box.

| Target | Image hash state | Re-stamp verdict | Preflight | Notes |
|---|---|---|---|---|
| libxml2-arvo-1972 | ok | ready | READY (18:01) | stack-buffer-overflow. aflbuild 37 s, smoke 8308.6 execs/s |
| c-blosc2-arvo-24837 | ok | ready | READY (18:27) | same location, kind now reported as use-after-poison (was heap-buffer-overflow) |
| libavc-arvo-16505 | ok | ready | READY (18:30) | heap-buffer-overflow |
| assimp-arvo-24463 | ok | ready | READY (18:34) | heap-buffer-overflow |
| selinux-arvo-42493454 | ok | ready | READY (18:38) | heap-use-after-free. The experiment dir is named `selinux-CVE-2021-36085` |
| wolfssl-arvo-26567 | ok | ready | READY (18:43) | heap-buffer-overflow |
| freeradius-server-arvo-38283 | ok | ready | READY (17:57) | Failed first at `aflbuild` (finding 1), fixed by rebuilding from the current definition. Then failed at `profile`, fixed by 392bfef. Now `ld_library_path=/opt/target-libs:/opt/oss-libs:/out/lib` |
| PcapPlusPlus-arvo-22232 | ok | dropped_wrong_bug | NOT READY (`profile`, 19:00) | **dropped**, see below. The libc++ copies resolve in root-level `/out`, so `out_dirs` is `["/out"]`, the same path as before 392bfef; the refusal is unchanged |

freeradius-server's `profile` failure: its build puts its libraries in
`/out/lib` with an `$ORIGIN/lib` RUNPATH. The profiler check probed
`/out/lib/libfreeradius-util.so` on its own, outside that RUNPATH context, so it
could not find `libtalloc.so.2` or `libkqueue.so.0`. Evidence:
`results/preflight-freeradius-server/freeradius-server-arvo-38283/optimized/online/preflight_profile/profile_once/target_libs/target_libs.json`
(`version: 4`, `out_dirs: ["/out/lib"]`).

## Dropped targets and why

**PcapPlusPlus-arvo-22232.** Dropped by user decision on 2026-11-02.

- **Where the PoC crashes now.** On the rebuilt AFL++ binary the PoC crashes
  with the same ASan class (heap-buffer-overflow) in the same file, but at a
  different place:
  - now: `IPv6Layer.cpp:37`, the `pcpp::IPv6Layer::IPv6Layer` constructor, a
    2-byte `payloadLength` read (`READ of size 2`,
    `results/restamp-20261102/PcapPlusPlus-arvo-22232/verify.log`)
  - historically: `IPv6Layer.cpp:81`, `pcpp::IPv6Layer::parseExtensions`, a
    1-byte `nextHeader` read (`READ of size 1`, `arvo_repro.log` in the same
    directory)
- **Why prework drops it.** `prework/verify.py`'s frame-for-frame rule
  (`matches_reference`, added in 38832cd on 2026-08-27; see
  `git log -S'def matches_reference' -- prework/verify.py`) classifies this as
  `dropped_wrong_bug`.
- **Why the campaign would not.** The campaign's own verifier,
  `phase2_setup.verify_poc_crash`, accepts any sanitizer report: it returns
  True on markers such as `SUMMARY:`, `AddressSanitizer`, `ERROR:` or `SEGV`
  in the output, and never reads the expected class or the reference. That is
  looser than prework's rule, and it is why the preflight `poc` stage passes.
- **Decision.** The user chose to keep the strict rule. The mismatch between the
  two verifiers is a follow-up and is not fixed here.
- **Separate profile failure.** Its preflight also fails at `profile`. The build
  copies libc++ (`libc++.so.1`, `libc++abi.so.1`, `libunwind.so.1`,
  `libgcc_s.so.1`) next to the glibc copies in `/out`. That puts `/out` on the
  profiler path, and the check then finds `libc.so.6` unresolved for those files
  and for `FuzzTarget`. This is a known limitation of the e488374 policy. It is
  recorded here, not fixed.

**This is not a new regression.** August's build would have failed the same
check, for these reasons:

- The image's own layers all date from 2026-08-28 (`docker image history
  bench-aflpp/pcapplusplus-arvo-22232`); the re-stamp reused the layer cache.
- The pins have not changed since 2026-07-31 (8f6e64b), and
  `prework/verify.py`'s `compile_command` is unchanged. So the binary compiled
  now is the binary August compiled.
- August's verification must therefore have failed the same way. The image
  survived because `prework/run_prework.py`, which `bootstrap_server.py`
  invokes for each target, builds and tags the image at step [2/4] and only
  runs `verify_poc` at step [4/4], and `check_images` never re-checks
  verification. The new definition label does not carry verification status
  either.

**Out of scope, not validated.** Build mode also built the 6 targets that had no
images, because they were missing. They were never preflighted, so they are not
validated.

| Target | Re-stamp verdict | Note |
|---|---|---|
| libredwg-arvo-31419 | ready | kind now use-after-poison, same location |
| open62541-arvo-3609 | ready | negative-size-param |
| radare2-arvo-10222 | ready | heap-buffer-overflow |
| yara-arvo-3848 | ready | kind now use-after-poison, same location |
| graphicsmagick-arvo-8280 | dropped_wrong_bug | frame shift under the same rule, consistent with inlining |
| lcms-arvo-756 | dropped_wrong_bug | frame shift under the same rule, consistent with inlining |

## Known remaining test failures

The suite went from 17 failed / 1054 passed to 4 failed / 1081 passed / 1
skipped. The 4 failures are left because they are not on a shared or ARVO path:

| Test | Why it is left |
|---|---|
| `tests/test_phase3_k8s_images.py::test_phase3_k8s_image_matrix_uses_codex4_artifacts` | k8s backend; needs `results/codex-4` |
| `tests/test_phase3_k8s_runner.py::test_metadata_env_to_json_maps_fields_and_parses_stats` | k8s backend; expects older stats keys |
| `tests/test_phase3_k8s_runner.py::test_write_trial_dir_produces_phase4_inputs` | k8s backend; needs `results/codex-4` and older stats keys |
| `tests/test_run_hotspotdiff.py::test_analyze_one_captures_and_reports_with_fakes` | analysis tool; stale `reservoir` attribute |

Skipped: `tests/test_sandbox_session.py::test_agent_cpus_on_the_real_topology_avoid_trial_and_profile_cores`
on hosts that cannot hold the 2-31 trial/profile layout, which includes this box.

## Known limitations and follow-ups

1. **The two PoC verifiers disagree.** The prework verifier
   (`prework/verify.py`) matches frame for frame; the campaign verifier
   (`phase2_setup.verify_poc_crash`) accepts any sanitizer report. PcapPlusPlus
   is the case where this matters.
2. **An image's verification status is not recorded.** An image whose PoC
   verification failed stays tagged. PcapPlusPlus's image has stayed tagged
   since 2026-08-28. `--check` reported it `todo` before cbe4496 (the tag-case
   bug), `unver.` between cbe4496 and the re-stamp, and `ok` since the
   re-stamp. Follow-up: record the verify status with
   the image, either as a label or by untagging the image on failure.
3. **A `/out` with glibc copies plus other runtime copies is still refused.**
   PcapPlusPlus is an example: the other runtime copies put `/out` on the
   profiler path, and the glibc-family exclusion does not cover that case.
4. **`fold-replay-time` before the first `fold-build` fails.** The broker
   returns a bash 127 `/bin/bash: /out/afl-showmap: No such file or directory`.
   This predates this work. It appears 8 times in the FuzzBench 6 h log
   `.shared-cpu-fuzzbench-6h-libxml2-20261028-1755.log`, and once in the first
   smoke (22:21:55, trial_01 round 1).
   - In the final smoke it appears three times: 01:27:35, 01:29:00 and
     03:07:09.
   - `broker_audit.log` shows rc=127 in trial_00/iter_01, trial_01/iter_01 and
     trial_01/iter_02.
   - Every affected round still ended `kept`.
5. **systemd's FuzzBench layout is a pre-existing case this work does not
   change.** It keeps glibc copies beside `$ORIGIN`-RUNPATH libraries under
   `/out/src/shared`. No systemd record exists on this box.
6. **The broker now survives a failing op** (871840e). It answers
   `broker error: <TypeName>; see the host log` and keeps serving, instead of
   closing the socket for the rest of the session. The detail is in the host
   log.

## Campaign record

| Experiment id | Code | Settings | Result |
|---|---|---|---|
| `smoke-arvo-libxml2-20261101-2208` | launched on unmodified code; later rounds picked up commits landing in the checkout (round-2 profile records are version 3) | DURATION=7200 OPT_TIMEOUT=2700 | Benchmark Complete. 3 outcomes, all `agent-failed` at the 2700 s cap; the gate was never reached |
| `smoke-arvo-final-libxml2-20261102-0114` | as of cebd94a | DURATION=10800 OPT_TIMEOUT=5400 | Benchmark Complete. 4 outcomes: 3 `kept`, 1 `agent-failed`; 2 HOT-SWAPs |

**A deviation from the spec's W4 rule.** That rule reruns the smoke once on
the final code when a task touches a skill script that every round runs. The
final smoke predates 392bfef, which changed `target_libs.py`, and no third run
was made, for two reasons:

- 392bfef is inert for libxml2's layout. libxml2 loads no library from `/out`,
  so its record has `out_dirs: []` and the same `ld_library_path` as before
  (`results/preflight-final-20261102/preflight_libxml2.json`, and its
  experiment dir's `target_libs.json`, version 4).
- The freeradius-server preflight on 392bfef exercises the same `target_libs`
  path that a round runs
  (`results/preflight-final-20261102/preflight_freeradius-server.json`).

Logs are in the repo root: `.smoke-arvo-libxml2-20261101-2208.log` and
`.smoke-arvo-final-libxml2-20261102-0114.log`. Results are in
`results/<experiment id>/libxml2-arvo-1972/`.

Pass-criteria readings for the final smoke:

```
grep -E 'outcome=|=== Benchmark Complete ===' .smoke-arvo-final-libxml2-20261102-0114.log
```

```
... online round 1: outcome=kept speedup=1.0999 applied=True built=True poc_reproduces=yes
... online round 1: outcome=kept speedup=1.1909 applied=True built=True poc_reproduces=yes
... online round 2: outcome=agent-failed speedup=None applied=False built=False poc_reproduces=unchecked
... online round 2: outcome=kept speedup=1.5827 applied=True built=True poc_reproduces=yes
=== Benchmark Complete ===
```

```
grep -cE 'Traceback|prebuild error|weekly limit' .smoke-arvo-final-libxml2-20261102-0114.log
```

This prints `0`.

```
grep -H '^run_time' results/smoke-arvo-final-libxml2-20261102-0114/libxml2-arvo-1972/*/trial_*/afl_out/default/fuzzer_stats
```

This gives `run_time` 10800 / 10800 for the baseline trials 00 / 01 and
10752 / 10740 for the optimized ones, so all four `fuzzer_stats` files are
non-empty.

- **The `agent-failed` round** is trial_00 round 2: agent
  `agent-1831251-5b594886ec09`, launched 02:36:43, hit the 5400 s cap at
  04:06:45. The budget then left no time for another round.
- **trial_01 round 2's `kept` fold** (1.5827x) came after the trial ended, so
  it was not swapped in (`trial already terminal, no swap`).
- **Leftover containers:** no `agent-*` container from the campaign was running
  when this was written.
