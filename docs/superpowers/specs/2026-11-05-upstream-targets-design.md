# Upstream OSS-Fuzz Targets for 0-day Campaigns — Design

**Date:** 2026-11-05
**Status:** Approved in conversation 2026-11-05; written for the plan
**Branch:** `feat/aflpp-sandboxed-optimizer` (on top of the ARVO revalidation work, 0ed4654)
**Host for onboarding:** the 20-physical-core test server; campaigns run wherever the user chooses

## Intent

The paper needs this sentence: *on the same project, under the same 24 h budget, the
optimized arm found a previously unknown bug and the baseline arm did not.* The targets
are therefore OSS-Fuzz projects at today's upstream HEAD, not historical bugs. The user
supplied the candidate list (53 projects, all cryptography, TLS/SSH/VPN/DNS and TPM
software; `data.zip`, read on 2026-11-05), chosen because they are either barely fuzzed
or slow to fuzz, which is where a throughput gain has the best chance of tipping a
crash into reach within 24 h.

This work gets every usable candidate to the state where a campaign can be launched
and works, through the existing online pipeline, and nothing else.

## Decisions the user made (2026-11-05)

| Decision | Choice |
|---|---|
| Harnesses | Existing OSS-Fuzz harnesses only; we never write a harness |
| Build and run configuration | Exactly what OSS-Fuzz sets, project by project; no FuzzBench flags, no pipeline flags beyond mechanics; where OSS-Fuzz provides nothing for a project we may write our own |
| Mutation capture | Optimized arm only; it is part of what the pipeline costs |
| Candidate list | The 53 projects in `data.zip` (`intro_rows.json`), with the OSS-Fuzz build-status files beside it as evidence |
| Process | Implementer agents that make projects build, separate agents that validate and audit every change |
| Leak detection and timeout | `detect_leaks=0` and a fixed `-t 1000` instead of `run_fuzzer`'s leak detection on and `-t 5000+`: the kind's ONE recorded deviation from `run_fuzzer`, applied to both arms (user decision 2026-11-05) |
| Sanitizers | Every sanitizer the project lists in `project.yaml`: ASan for all 50 C/C++ candidates, UBSan for the 29 that list it, MSan for the 16 that list it; one image and one set of entries per project-sanitizer; ASan is built first and an MSan or UBSan build failure never drops the project (the user said only the bug yield matters; this is my call) |
| The other session's FuzzBench-kind attempt | Preserved untouched on branch `wip/crypto-candidates-fuzzbench-kind` (commit on 2026-11-05); this design does not build on it (my call: it contradicts the OSS-Fuzz-exact rule) |

## What "exactly as OSS-Fuzz sets" means (facts read from the images on this box)

Pinned base-builder (`prework/base.pin`, digest built 2026-07-30; bundles AFL++
`++4.34a` precompiled, clang 22) and base-runner (2026-07-09) `run_fuzzer`. The other
base-builder variants (see the Dockerfile bullet below) must be checked to carry the
same `compile_afl` and AFL++ version at their pinned digests; if one differs, the
difference is recorded in `bases.json` and the onboarding report.

**Build** (`compile` with `FUZZING_ENGINE=afl`): `CC=$SRC/aflplusplus/afl-clang-fast`,
`libAFLDriver.a` as `LIB_FUZZING_ENGINE`, the project's own `build.sh` and the CFLAGS
`compile` composes (`-O1 -fno-omit-frame-pointer -gline-tables-only` plus
`SANITIZER_FLAGS_<sanitizer>`), `AFL_QUIET=1 AFL_IGNORE_PROBLEMS=1
AFL_IGNORE_UNKNOWN_ENVS=1`. No CmpLog build and no dict2file unless the project's own
build asks for them (verified: a stock compile emits neither). The image environment
carries `SANITIZER=address FUZZING_ENGINE=libfuzzer ARCHITECTURE=x86_64
UBSAN_OPTIONS=silence_unsigned_overflow=1` and no `ASAN_OPTIONS`.

**Run** (`run_fuzzer`, afl branch): working directory `$OUT`, `PATH=$OUT:$PATH`;

```
afl-fuzz [-c $OUT/<t> if $OUT/afl_cmplog.txt exists] [-x $OUT/afl++.dict if it exists] \
         -t 5000+ -i <corpus> -o <out> [-x <dict from <t>.options or <t>.dict>] -- $OUT/<t>
```

env `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 AFL_TRY_AFFINITY=1
AFL_FAST_CAL=1 AFL_CMPLOG_ONLY_NEW=1 AFL_FORKSRV_INIT_TMOUT=30000 AFL_IGNORE_PROBLEMS=1
AFL_IGNORE_UNKNOWN_ENVS=1`; `ASAN_OPTIONS` = the image's value plus
`abort_on_error=1:symbolize=0:detect_odr_violation=0` plus the `[asan]` section of
`<t>.options` (`key=value` joined by `:`); `UBSAN_OPTIONS` plus `symbolize=0` and the
`[ubsan]` section; `MSAN_OPTIONS` plus `exit_code=86:symbolize=0`. The corpus is
`<t>_seed_corpus.zip` unpacked plus one file named `input` containing `input`. No `-m`
(AFL++ defaults to no memory limit), no persistent-mode count argument.

Note: this is OSS-Fuzz's in-image runner, what `infra/helper.py run_fuzzer` executes.
Production ClusterFuzz layers randomized per-run strategy choices on top; those are not
reproducible and are not replicated. (My call.)

## The new target kind: `upstream`

A third manifest kind beside `arvo` and `fuzzbench`.

### Definition of record, per project: `prework/upstream/<project>/`

- `ossfuzz/` — the project's `projects/<project>/` directory copied verbatim from
  OSS-Fuzz at a pinned OSS-Fuzz commit (Dockerfile, build.sh, `.options`, dictionaries,
  seed files, patches). The local OSS-Fuzz checkout on this box is from 2026-02-19 and
  27 of the 53 project directories changed since; the vendoring takes them from
  `origin/master` as fetched on the onboarding day (commit recorded).
- `Dockerfile` — `ossfuzz/Dockerfile` with exactly one change: its `FROM` line is
  pinned by digest. The base image is something OSS-Fuzz sets per project and it varies
  across the 53: 36 use `gcr.io/oss-fuzz-base/base-builder` (Ubuntu 20.04, the digest
  already in `prework/base.pin`), 13 use `base-builder:ubuntu-24-04`, 2 use
  `base-builder-rust`, 1 uses `base-builder-go`, and 2 (`libressl`, `nettle`) already
  pin an older digest. Each distinct base is resolved to a digest once, on the
  onboarding day, and recorded in `prework/upstream/bases.json`; a project's `FROM`
  becomes that digest. Projects that already pin a digest keep it. Nothing else changes,
  unless a recorded deviation is needed to build (fix policy below). Every base-builder
  variant bundles the same `compile_afl` and AFL++, so the build path below is the same
  for all of them; a 24.04 base means the target's glibc matches the profiler image's,
  which only makes library supply simpler.
- `meta.json` — `project`, `srcdir` (the directory under `$SRC` that holds the project,
  the thing rebuilds bind-mount over), `language` (from `project.yaml`), `sanitizers`
  built, `harnesses` (every fuzz target found in `/out` after the first compile), and
  `deviations: []` in the ARVO targets' format (what / why / affects_measurement / rationale).
- `pins.json` — the OSS-Fuzz commit the config came from, the base-builder digest, and
  the commit of every git checkout found under `$SRC` inside the built image.

**The built image is the artifact of record.** The Dockerfile is not rewritten to pin
clones (53 Dockerfiles with `git clone`, `hg clone`, submodules and `-b` forms make
rewriting brittle); instead the source that landed in the image is what every later
extraction, rebuild and campaign uses, and `pins.json` records which commits that was.
Rebuilding an onboarded image is a deliberate re-pin: `pins.json` must be regenerated
and the image's definition-hash label (from the ARVO revalidation work) must match.
Image tag: `bench-upstream/<project>-<sanitizer>` (lowercase).

### Build path

One image per project-sanitizer pair (`bench-upstream/<project>-<sanitizer>`), built from
the same Dockerfile; `compile` is `docker run <image> compile` with `FUZZING_ENGINE=afl SANITIZER=<sanitizer>
ARCHITECTURE=x86_64 FUZZING_LANGUAGE=<language from project.yaml>` and the one pipeline
addition `AFL_LLVM_DENYLIST=/src/aflpp_fold_denylist.txt` (inert unless a `fold_*`
helper exists). The edited source tree is bind-mounted over `$SRC/<srcdir>` for every
rebuild (baseline, agent builds through the broker, the gate). Not passed: `FUZZER_LIB`,
`FUZZER` (FuzzBench variables the ARVO path carries), `BUILD_OPT_LEVEL`.

### Run path

A third `AflLaunch` flavour in `lib/afl_launch.py` that reproduces `run_fuzzer`'s afl
branch argv and env exactly as listed above, evaluated against the host bin dir for the
optional `-c`/`-x` flags and the `.options` sections (replicating `parse_options.py`
semantics in Python; the builder image has no `parse_options.py`). Trials run in the
project's own builder image (as the FuzzBench kind does), working directory `/out`,
`PATH=/out:$PATH`. The pipeline adds only its mechanics: `-V <budget>`, `-s <seed>`,
`AFL_AUTORESUME=1`, the container's core pin and limits, and the mutation-capture shim
on optimized trials. Two settings deviate from `run_fuzzer`, by the user's decision, and are
recorded in the launch record: `-t 1000` (fixed) in place of `-t 5000+`, and
`detect_leaks=0` appended to `ASAN_OPTIONS` (which also stops AFL++ from exporting its
slow `LSAN_OPTIONS` unwind). The pipeline's `FUZZ_ASAN_OPTIONS` / `FUZZ_UBSAN_OPTIONS`
strings do not apply to this kind; `BENCHMARK_AFL_TIMEOUT` still provides the `1000`.

**The gate, the smoke, the profiler and the trials of an upstream target all run under
the kind's run-time sanitizer options**, so the replay gate times the workload the fuzzer
runs. Today the profiler script hard-codes the FuzzBench option string; the kind must
plumb its own string through the broker replay and the profiler.

Seed corpus staging follows `run_fuzzer`: the zip's contents plus the `input` file.

### What the kind does not have

No PoC, no PoC gate, bug survival recorded as `no-poc` (the FuzzBench kind's behaviour).
No `-O` override. No FuzzBench ccache. The optimizer's source-scope policy applies
unchanged (C/C++ source only, harness and fuzz-support files protected).

### 0-day triage after a campaign

A per-campaign report, produced by a tool run after phase 3 (not a gate):

1. every crash artifact of both arms classified by the existing provenance classifier;
2. deduplicated by sanitizer kind plus top three non-runtime frames;
3. each distinct crash replayed on the **pristine baseline binary** (unmodified source);
   a crash that does not reproduce there is optimizer-induced and is listed separately,
   never counted;
4. per distinct crash: first discovery time per arm, trials that found it, reproducer
   path, stack.

Re-testing at a later upstream HEAD and checking the public OSS-Fuzz tracker are human
steps; the report gives the reproducer and the pinned commit to do them with.

## Candidates: scope, exclusions, fix policy

**In scope:** the 53 projects. Of them, these are excluded up front with the reason
recorded in the onboarding report, not attempted:

- not C/C++ (the optimizer edits C/C++ only; `compile_afl` targets C/C++ harnesses):
  `cryptography` (Python), `num-bigint` (Rust), `circl` (Go).

Everything else is attempted, including the nine whose OSS-Fuzz build is failing or
flaky today (`xmlsec`, `rnp`, `relic`, `bls-signatures`, `tink-cc`, `openvpn`,
`ms-tpm-20-ref`, `samba`, `openssh`) — those are the "not fuzzed" class and the most
interesting — and the four added to OSS-Fuzz after the local checkout (`libmongocrypt`,
`wolfboot`, `wolfssh`, `wolftpm`).

**Editable tree (my call):** the project's own main repository (`main_repo` in OSS-Fuzz's
status data), recorded as `srcdir`; every other checkout under `$SRC` (a crypto backend
built from source, a sibling harness repository) is frozen as part of the image. The
0-day claim is about that project; a hotspot the profiler finds outside the editable
tree is a finding to report, not a reason to widen the tree.

**Rebuilds run with `--network none` (my call):** the image is the artifact of record, so
a rebuild may not fetch anything. A `build.sh` that clones or downloads at compile time
gets that fetch moved into the Dockerfile as a recorded deviation (the "pin a
dependency" category); if that cannot be done, the project is dropped with the log.

**Harness rule (my call):** every C/C++ fuzz target a project's compile leaves in `/out`
becomes a manifest entry. Picking the harness for a campaign is the user's decision,
made from the onboarding report's per-harness execs/s and coverage; the pipeline does
not pre-select.

**Fix policy for a project that does not build or run.** Agents may edit only our
vendored copy of the project's OSS-Fuzz Dockerfile and build.sh:

- allowed: pinning a dependency version, installing a missing package, working around
  toolchain drift the project's own script trips over with the pinned base image, fixing
  a clone URL or branch, the same kind of change OSS-Fuzz maintainers make when a build
  breaks;
- forbidden: adding, removing or changing sanitizer, optimization or instrumentation
  flags; selecting, modifying or removing harnesses; patching the target's source
  (a project whose source does not compile at HEAD in the pinned image is dropped with
  the log, unless the user overrides per project);
- every edit is a recorded deviation in `meta.json`; the auditor checks each against
  this list; at most three fix rounds per project, then it is dropped with its log.

## "Works" means

For every onboarded harness: `tools/preflight_online.py` passes every stage (image,
extract, source, seeds, aflbuild, profile, smoke) with the upstream kind's build and
launch. For the kind as a whole: one short online campaign on one upstream harness
reaches a round outcome, hot-swaps, and produces a triage report; the full suite stays
at the known four failures; nothing under `prework/fuzzbench*`, `lib/afl_launch.py`'s
FuzzBench branch, the ARVO launch, `config.py` defaults changes (the FuzzBench and ARVO
kinds keep their byte-for-byte pins).

## Deliverables

1. The `upstream` kind: manifest schema, image build, compile path, launch flavour,
   seed staging, sanitizer-option plumbing, preflight support, triage tool, tests.
2. `tools/onboard_upstream.py`: for one project, vendor the OSS-Fuzz config at the
   pinned commit, write `Dockerfile`/`meta.json`/`pins.json`, build the image, compile
   with AFL++, discover harnesses, run each harness for two minutes under the kind's
   launch to measure execs/s, and write a per-project result file. Resumable; parallel
   builds bounded by cores and disk.
3. `prework/upstream/<project>/` for every attempted project and
   `data/manifests/manifest_upstream.json` for every harness that passed.
4. `docs/UPSTREAM_TARGETS.md`: per project and harness, build verdict (ok / fixed with
   deviations / dropped with reason), execs/s on this box, coverage and harness count
   from the user's data, sanitizer(s) built, pinned commits, and the exact launch
   commands.

## Sanitizers (decided)

OSS-Fuzz builds each project once per sanitizer in its `project.yaml` and fuzzes each
build separately; ASan and MSan cannot share a binary and OSS-Fuzz never combines any
of them. This design follows OSS-Fuzz: one build and one entry set per listed
sanitizer. Run-time options per sanitizer come from `run_fuzzer` (`MSAN_OPTIONS` gets
`exit_code=86:symbolize=0`, `UBSAN_OPTIONS` gets `symbolize=0`, plus the `.options`
sections) with the leak/timeout deviation above. Campaign selection per project and
sanitizer is the user's, from the onboarding report.

## Process

Same as the ARVO revalidation: implementer agents work one audited task at a time for
the pipeline kind; for onboarding, fixer agents take failing projects in batches, an
auditor checks every deviation against the fix policy, and validation is mechanical
(preflight READY). Every decision made without the user is recorded in the run ledger
and reported at the end.

## Out of scope

Writing harnesses; FuzzBench parity for these targets; running the 24 h campaigns;
reporting bugs upstream; the three non-C/C++ projects above; the kubernetes backend.
