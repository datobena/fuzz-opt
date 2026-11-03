# ARVO Revalidation on the Current Pipeline — Design

**Date:** 2026-11-01
**Status:** Approved in conversation; written for review
**Branch:** `feat/aflpp-sandboxed-optimizer`
**Host:** the 20-physical-core test server (cpus 0-19, hyperthread sibling of c is c+20)

## Context

The pipeline began as an ARVO benchmark (spec of 2026-07-30) and later gained a
FuzzBench-parity path: its own image chain (`fb-aflpp/<dir>`), FuzzBench's AFL++
commit, cmplog, dict2file, FuzzBench's AFL environment, ccache and fixed -O levels.
Every later change (held-out gate, source-scope policy, per-trial optimizers,
profiler library supply) was exercised on FuzzBench targets. No ARVO target has run
through the pipeline since those changes landed.

This work makes the current code run ARVO targets again without changing how
FuzzBench targets build or run. It does **not** bring ARVO targets to FuzzBench
parity; the user chose "validate and fix the existing ARVO path".

## Decisions (confirmed with the user, 2026-11-01)

| Question | Decision |
|---|---|
| Goal | Validate and fix the existing ARVO path (no FuzzBench-parity treatment for ARVO) |
| Branch | `feat/aflpp-sandboxed-optimizer`; the shared-trial-CPU branch is out of scope |
| Targets | The 8 with prework images on this box: libxml2, c-blosc2, libavc, assimp, selinux, PcapPlusPlus, freeradius-server, wolfssl. The 6 without images are out of scope |
| "Works" means | `tools/preflight_online.py` passes every stage for each target, and libxml2 completes one short online campaign |
| Core layout | Preflight: `--cpu 3 --build-cpus 2-19`. Smoke: trials 4-7, optimizers 2-3, setup core 2, setup builds 2-19, agents derived. `DURATION=7200 INTERVAL=300 OPT_TIMEOUT=2700 TRIALS=2` |
| Agent model for the smoke | `claude-sonnet-5-5` via `BENCHMARK_CLAUDE_MODEL` |
| Pre-existing test failures | Triage; fix the ones on shared or ARVO paths; leave box-specific, k8s and analysis-only ones and list them |
| Target-specific failures | Edit that target's curated Dockerfile/build.sh (recorded in its `meta.json`); a PoC that no longer reproduces drops the target |
| FuzzBench evidence | Full suite with every FuzzBench test green, plus `preflight_online.py` on `libxml2_xml_e85b9b` after all commits |
| Box config | No change to `config.py` defaults; env overrides per run, with the exact command documented |
| Deliverable | Code, tests, commits, and `docs/ARVO_REVALIDATION.md` |
| Agents | Implementer on opus, auditor on the orchestrator's model; auditor runs after every task before the next starts |
| Isolation | Work directly in this checkout (results/, images and the credential store live here) |
| Compute | Rebuilds, preflights and the smoke campaign run without per-step approval while the box is idle |
| Commits | One commit per audited task on this branch; no push |
| Approach | Diagnose first on unmodified code, then fix in audited tasks; rebuild stale images before the smoke |

## Findings from the diagnostics (unmodified code)

### Preflight, 8 targets

| Target | Verdict | Stage | Cause |
|---|---|---|---|
| libxml2, c-blosc2, libavc, assimp, selinux, wolfssl | READY | — | — |
| PcapPlusPlus | NOT READY | profile | pipeline regression in `target_libs.py` (finding 2) |
| freeradius-server | NOT READY | aflbuild | stale prework image (finding 1) |

### Finding 1 — stale prework images, and nothing detects them

A prework image is a snapshot of `prework/targets/<t>/` (Dockerfile, `meta.json`,
optional `build.sh`) plus the pins. When the definition changes in git the image
does not. `bootstrap_server.py --check` only asks whether the tag exists, and the
build step skips any tag that exists.

| Image | Built | Definition last changed | Missing from the image |
|---|---|---|---|
| freeradius-server | 2026-08-28 | 2026-10-04 | `AFL_NOOPT=1` pre-build of make's dlopen helpers, the "patch already applied" guard, the CFLAGS exports. The build dies on `libfreeradius-make-dlopen.so: undefined symbol: __afl_area_ptr` |
| libxml2 | 2026-07-31 | 2026-10-04 | the incremental `build.sh` (reuse `config.status`). Builds, but every agent rebuild is a full configure-and-make (~233 s instead of ~19 s) |

The other six images are current (built on or after their definition's last
change; selinux's August change touched only `meta.json`).

### Finding 2 — `target_libs.py` rejects ARVO builds that copy glibc into /out

PcapPlusPlus's historical `build.sh` runs `cp $(ldd $OUT/FuzzTarget | cut -d" " -f3) $OUT`,
so `/out` holds the 20.04 build image's `libc.so.6`, `libpthread.so.0`, `librt.so.1`,
`libdl.so.2`, `libm.so.6`, `libresolv.so.2`. The profiler library supply added on
2026-10-20 (`skills/profile-once-fuzz-folds/scripts/target_libs.py`) requires every
`/out` shared library to load inside the Ubuntu 24.04 profiler image. A foreign glibc
component never can (`ldd` reports a `GLIBC_PRIVATE` version failure on
`libpthread.so.0`), so `prepare` raises `TARGET LIBS UNRESOLVED` and the campaign
refuses to start. The module's own rule already says the libc/loader family is never
supplied from `/out`. Trials are unaffected: ARVO launches set no `LD_LIBRARY_PATH`,
so the target resolves glibc from the image's system path.

### Finding 3 — bootstrap image check uses the mixed-case project name

`check_images` builds the tag as `bench-aflpp/{project}-arvo-{id}` while
`build_image.image_tag` lowercases it, so PcapPlusPlus is reported missing although
`bench-aflpp/pcapplusplus-arvo-22232` exists.

### Pre-existing test failures (17 on this branch before any change)

| Tests | Cause | Action |
|---|---|---|
| `test_build_corpus` (4) | tests pass `cpu=` and omit `replay_budget_secs`; the skill script's API moved | fix tests (shared path) |
| `test_replay_timing::test_measure_binary_raises_on_failed_run` (1) | fake clock iterator exhausted; script now reads the clock more often | fix test (shared path) |
| `test_sandbox_egress` (6) | tests predate the credential store's `.refresh.lock` and per-backend layout | fix tests (shared path) |
| `test_sandbox_launch::test_agent_tools_speak_the_broker_protocol` (1) | the broker reply contract or the tool's argv changed with the retry-diff work | fix test, unless it exposes a real contract break |
| `test_sandbox_session::test_agent_cpus_on_the_real_topology...` (1) | assumes a host that can hold the 2-31 layout; this box cannot | add a skip when the layout does not fit the host |
| `test_phase3_k8s_*` (3) | k8s backend, needs `results/codex-4` and older stats keys | leave; list in the doc |
| `test_run_hotspotdiff` (1) | analysis tool, `reservoir` attribute | leave; list in the doc |

For every "fix test" row the implementer first confirms the production code is
correct; if the test exposes a real bug, the code is fixed instead and the auditor
confirms which it was.

## Scope

In scope: the five workstreams below, the 8 targets, this box.

Out of scope: FuzzBench-parity for ARVO targets, the 6 targets without images,
the shared-trial-CPU branch, the k8s backend, `config.py` default changes, curl and
mbedtls, any push.

## Workstreams

### W1 — Image refresh (no code change)

Rebuild freeradius-server and libxml2 from their current definitions:

```
python3 -m prework.run_prework --target prework/targets/<t> --work <scratch>/prework_work
```

`run_prework` re-extracts the ARVO source, builds the image, compiles with
`FUZZING_ENGINE=afl` and re-verifies the PoC. Exit 5 (bug gone) drops the target
per policy; any other non-zero exit is reported with its log.

**Done 2026-11-01 22:06.** Both rebuilt in about two minutes each (warm layer
cache); both report `verdict: poc_crash, status: ready`; the previously missing
`build.sh` edits are present in the new images.

### W2 — Smoke campaign on unmodified code

```
TOTAL_CORES=40 TRIALS=2 TRIAL_CORES=4-7 OPT_CORES=2-3 SETUP_CPU=2 SETUP_BUILD_CPUS=2-19 \
DURATION=7200 INTERVAL=300 OPT_TIMEOUT=2700 EXP_PREFIX=smoke-arvo \
BENCHMARK_CLAUDE_MODEL=claude-sonnet-5-5 ./run_online_pertrial.sh libxml2
```

Pass criteria: the log reaches `=== Benchmark Complete ===`; at least one optimizer
round logs `outcome=`; no `Traceback`, `prebuild error` or `weekly limit` line;
every trial's `afl_out/default/fuzzer_stats` is non-empty; no agent, broker or
proxy container is left behind. A campaign that fails for account reasons (rate
limit, expired token) is relaunched once. Anything else the campaign reveals
becomes a task in W3.

### W3 — Code fixes, one audited commit each

**T1. Image staleness detection and the tag-case bug** (`prework/build_image.py`,
`bootstrap_server.py`, tests).
`build_docker_command` adds `--label bench-aflpp.definition-sha256=<hash>`, where the
hash covers the bytes of the target's Dockerfile, `meta.json`, `build.sh` and
`poc_input` when present, plus `base.pin` and `aflpp.pin`. A pure function
`definition_hash(target_dir)` computes it so tests need no docker.
`check_images` resolves the tag through `image_tag` (fixing finding 3), reads the
label, and reports one of: `ok` (hash matches), `STALE` (hash differs), `unverified`
(no label: built before stamping), `todo` (missing). The build step rebuilds
`todo` and `STALE` images; `--rebuild-unverified` rebuilds the unlabeled ones too.
After T1 lands, every image on this box is rebuilt with `--rebuild-unverified` so all
8 carry a label (minutes per image with a warm layer cache; not concurrent with the
campaign).

**T2. Profiler library policy for glibc in /out**
(`skills/profile-once-fuzz-folds/scripts/target_libs.py`, `tests/test_profile_target_libs.py`).
`probe_files` leaves libc/loader-family files (`is_libc_family`) out of the `/out`
library set; `prepare` records them in the result as `ignored_libc_out` so the
provenance shows what was skipped. Nothing else changes: a non-glibc `/out` library
the profiler cannot load still raises. The auditor checks (a) that no FuzzBench
benchmark in `prework/fuzzbench/` copies glibc into `$OUT`, and (b) that
`hotspot_table` cannot attribute samples to a `/out` glibc copy the target never
loads. The cache key `VERSION` is bumped so cached records from before the change
are not reused.

**T3. Stale shared-path tests** as in the table above. One commit per test file
is acceptable if the fixes are unrelated; otherwise one commit.

**T4+. Campaign findings.** Each distinct failure the smoke campaign reveals on the
online path becomes its own task with the same audit loop. The plan is amended, not
the spec, unless a finding changes a decision above.

### W4 — Re-validation

Preflight freeradius-server (after W1) and PcapPlusPlus (after T2). If any W3 task
touched the online path (`phase3_online.py`, `phase3_runner.py`, `phase2_setup.py`,
`sandbox/`, `prework/prework_build.py`, the skill scripts used in a round), the smoke
campaign is rerun once on the final code.

### W5 — FuzzBench non-regression and the doc

Full suite; every `tests/test_fuzzbench_*` and `tests/test_fb_ccache.py` test green;
`python3 tools/preflight_online.py --project libxml2 --cpu 3 --build-cpus 2-19` with
`BENCHMARK_MANIFEST_PATH=data/manifests/manifest_fuzzbench_list1.json` passes.
Then `docs/ARVO_REVALIDATION.md`: what was broken, what changed (per commit), the
exact commands for this box, per-target verdicts, dropped targets with reasons, the
known remaining test failures, and the campaign's experiment id.

## What changes measurement, and what does not

Per the user's rule, only choices that change instrumentation settings, pipeline
behavior or engine flags are decisions for the user; the rest are implementation
details.

- **Engine flags and instrumentation: unchanged.** ARVO launches keep the exact
  argv and environment pinned by `tests/test_fuzzbench_run.py`
  (`-i -o -V -s -m none -t 1000`, `AFL_NO_AFFINITY`, `AFL_SKIP_CPUFREQ`,
  `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`, `AFL_AUTORESUME`). Builds keep
  `arvo_compile_args` (AFL++ v5.02c on LLVM 18, `-O` as the image's CFLAGS, the
  fold denylist). FuzzBench launches and builds are not touched.
- **Pipeline behavior, one change (T2).** The profiler's library check stops
  requiring glibc/loader-family libraries found in `/out` to load in the profiler
  image. For a target whose build copies glibc into `/out` (PcapPlusPlus) this turns
  a refused campaign into a running one; for every other target the supplied
  library set and the profile are identical to before. The trials, the replay gate
  and the hot-swap set never read those files.
- **Operational only (T1, T3, docs):** image staleness reporting, the tag-case
  fix, test updates. No effect on what is compiled or how it is fuzzed.

## Process

The orchestrator never edits code. Two long-lived subagents:

- **Implementer** (opus) gets one task brief at a time: goal, files, the decision
  and its reason, verification steps, commit message shape. Works test-first,
  runs the relevant tests, reports the diff summary, test output and any choice
  the brief did not cover.
- **Auditor** (the orchestrator's model) gets the brief, the report and the diff,
  without the orchestrator's opinion. Checks that the decision is sound for both
  the ARVO and FuzzBench paths, that the diff matches the brief and nothing more,
  and that the tests prove it; reruns the tests itself. Returns ranked findings or
  a pass.
- Findings return to the implementer; the auditor re-reviews. On a pass the
  implementer commits. The next task starts only then. A judgment call the two
  disagree on goes to the user.

Box work (rebuilds, preflights, the campaign) is run by the orchestrator or the
implementer as the task needs, logs kept in the session scratchpad and summarized
in the task report.

## Acceptance criteria

1. Preflight passes every stage for each of the 8 targets, or the target is
   recorded as dropped with its non-reproducing PoC as the reason.
2. The libxml2 smoke campaign meets the W2 pass criteria.
3. Full suite: no new failures; every touched or added test passes; the remaining
   known failures are exactly the 3 k8s tests and the hotspot-diff test.
4. Every FuzzBench test is green and the FuzzBench libxml2 preflight passes after the
   last commit.
5. `docs/ARVO_REVALIDATION.md` exists with the exact commands for this box.
6. One commit per audited task on `feat/aflpp-sandboxed-optimizer`; nothing pushed.

## Risks

- Image rebuilds need the network (apt, the AFL++ clone). A failed rebuild is
  reported with its log, not retried blindly.
- A rebuilt image whose PoC stops reproducing drops the target; recorded, not patched.
- Account-side campaign failures are relaunched once; a gate that accepts no fold is
  not a failure as long as rounds complete with an outcome.
- T2 touches a shared path; the auditor's two checks and the W5 FuzzBench preflight
  are the backstop.
- The campaign occupies cores 2-19 for about 2 h; no preflight or rebuild runs
  concurrently with it.
