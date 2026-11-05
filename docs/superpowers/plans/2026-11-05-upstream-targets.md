# Upstream OSS-Fuzz Targets Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a third target kind, `upstream`, that builds and fuzzes an OSS-Fuzz project at a pinned HEAD exactly as OSS-Fuzz does, and onboard the 50 C/C++ candidates from `data.zip` so a 0-day campaign can be launched on any of their harnesses and works.

**Architecture:** A `lib/target_kind.py` helper replaces scattered `kind == "fuzzbench"` checks with three kinds. The kind gets its own launch flavour (`run_fuzzer`'s afl branch with two recorded deviations), its own compile path (OSS-Fuzz `compile` in the project's own image, no network), sanitizer-option plumbing so gate, smoke, profile and trials share one option set, and seed staging per `run_fuzzer`. An onboarding tool vendors each project's OSS-Fuzz config at a pinned commit, builds one image per project, compiles once per listed sanitizer, discovers harnesses and writes manifest entries; preflight validates each entry; a triage tool turns a campaign's crashes into a 0-day report.

**Tech Stack:** Python 3, pytest, Docker, OSS-Fuzz base-builder images (pinned by digest), the vendored `profile-once-fuzz-folds` skill scripts.

**Spec:** `docs/superpowers/specs/2026-11-05-upstream-targets-design.md`

## Global Constraints

- Branch `feat/aflpp-sandboxed-optimizer`; one commit per audited task; never push. Commit messages end with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- ARVO and FuzzBench kinds stay byte-for-byte: their launch argv/env (pinned by `tests/test_fuzzbench_run.py`), `arvo_compile_args`, `fuzzbench_build_command`, the broker replay/smoke command strings and the profiler's docker command for those kinds must not change; nothing under `prework/fuzzbench*`, `prework/fb_build.sh`, `prework/fb_ccache.py`, `config.py` defaults changes.
- Upstream kind launch = `run_fuzzer`'s afl branch exactly, with exactly two deviations: `-t` is `config.AFL_TIMEOUT_FLAG` (`1000`) instead of `5000+`, and `detect_leaks=0` is appended to `ASAN_OPTIONS`. Mechanics allowed: `-V`, `-s`, `AFL_AUTORESUME=1`, container pin/limits, mutation capture on optimized trials only, `AFL_LLVM_DENYLIST` at build.
- Upstream rebuilds run with `--network none`. The built image is the artifact of record; `pins.json` records what it holds.
- Fix policy for onboarding (spec): edits only to the vendored Dockerfile/build.sh, dependency pins / missing packages / toolchain drift / clone URL only; never sanitizer, optimization or instrumentation flags, never harness selection, never target source; every edit a `meta.json` deviation; at most three fix rounds per project, then dropped with its log.
- Suite baseline at a137117: 4 failed (3 k8s + `test_run_hotspotdiff`), 1088 passed, 1 skipped. No new failures.
- Box: 20 physical cores (0-19), 564 GB free. Parallel onboarding builds use disjoint cpusets within 2-19; nothing runs on cores 0-1. No campaign runs while onboarding builds run.
- Candidates: the 53 names in `intro_rows.json` minus `cryptography`, `num-bigint`, `circl` (not C/C++). The other session's FuzzBench-kind attempt lives on branch `wip/crypto-candidates-fuzzbench-kind` and is not touched.

## Review Focus

1. A `<t>.options` file whose `[asan]`/`[ubsan]`/`[msan]` values contain `=` or spaces, and whose `[libfuzzer]` section has keys other than `dict`: the sanitizer strings must join `key=value` with `:` exactly as `parse_options.py` does and the libfuzzer keys must be ignored. Test in Task 2.
2. A project whose build leaves `afl_cmplog.txt` (CmpLog build) or a `.dict` only, or neither: `-c` and the `-x` flags appear only when their files exist, in `run_fuzzer`'s order. Test in Task 2.
3. A harness with no `<t>_seed_corpus.zip`: the corpus is the single `input` file and the profile corpus is that file too, never an empty directory. Test in Task 4.
4. An MSan or UBSan compile that fails for a project that lists it: the project's ASan entries survive and the failure is recorded per sanitizer. Test in Task 7.
5. The same harness name under two sanitizers of one project: distinct `local_id`, distinct `cve`, distinct experiment directories, stable across re-runs of the manifest writer. Test in Task 7.

---

### Task 1: Target-kind helper

**Files:**
- Create: `lib/target_kind.py`
- Test: `tests/test_target_kind.py`

**Interfaces:**
- Produces: `ARVO = "arvo"`, `FUZZBENCH = "fuzzbench"`, `UPSTREAM = "upstream"`; `kind_of(entry: dict | None) -> str` (`"fuzzbench"`/`"upstream"` from `entry["kind"]`, else `"arvo"`); `is_upstream(entry) -> bool`; `has_poc(entry) -> bool` (True only for arvo); `UPSTREAM_IMAGE_PREFIX = "bench-upstream/"`; `is_upstream_image(image: str) -> bool`; `sanitizer_of(entry) -> str` (`entry.get("sanitizer") or "address"`); `language_of(entry) -> str` (`entry.get("language") or "c++"`).

- [ ] **Step 1: Write the failing tests**

```python
from lib import target_kind as tk
def test_kinds_and_defaults():
    assert tk.kind_of({"project": "x"}) == "arvo" and tk.kind_of(None) == "arvo"
    assert tk.kind_of({"kind": "fuzzbench"}) == "fuzzbench"
    assert tk.kind_of({"kind": "upstream"}) == "upstream" and tk.is_upstream({"kind": "upstream"})
    assert tk.has_poc({"project": "x"}) and not tk.has_poc({"kind": "fuzzbench"}) and not tk.has_poc({"kind": "upstream"})
    assert tk.is_upstream_image("bench-upstream/libssh") and not tk.is_upstream_image("bench-aflpp/libxml2-arvo-1972")
    assert tk.sanitizer_of({}) == "address" and tk.sanitizer_of({"sanitizer": "memory"}) == "memory"
    assert tk.language_of({}) == "c++" and tk.language_of({"language": "c"}) == "c"
```

- [ ] **Step 2: Run to verify it fails** — `python3 -m pytest tests/test_target_kind.py -q` → `ModuleNotFoundError`.
- [ ] **Step 3: Implement** `lib/target_kind.py` (pure, no imports beyond typing).
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: Commit** `lib: name the three target kinds in one place`.

---

### Task 2: Upstream launch flavour

**Files:**
- Modify: `lib/afl_launch.py` (`build_afl_launch`, `AflLaunch.shell`, `shim_compiler`; new helpers)
- Test: `tests/test_upstream_launch.py`

**Interfaces:**
- Consumes: Task 1.
- Produces: `parse_options_section(options_path: str, section: str) -> str | None` (configparser; `"k=v:k2=v2"` in file order; `None` if no file or section); `upstream_options_dict(host_bin_dir, fuzz_target) -> str | None` (`run_fuzzer`'s `get_dictionary`: last `dict = X` line of `<t>.options` in any section, else `<t>.dict` if present; returned as the container path `/out/<X>` when X is relative); `upstream_sanitizer_env(host_bin_dir: str, fuzz_target: str, sanitizer: str) -> list[tuple[str, str]]` returning exactly three tuples `ASAN_OPTIONS`, `MSAN_OPTIONS`, `UBSAN_OPTIONS` built as: ASAN = `[options[asan]] + ["abort_on_error=1","symbolize=0","detect_odr_violation=0","detect_leaks=0"]`; UBSAN = `["silence_unsigned_overflow=1"] + [options[ubsan]] + ["symbolize=0"]`; MSAN = `[options[msan]] + ["exit_code=86","symbolize=0"]`, empties dropped, joined by `:`; `UPSTREAM_AFL_ENV` = the eight `run_fuzzer` variables in its order (`AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`, `AFL_SKIP_CPUFREQ`, `AFL_TRY_AFFINITY`, `AFL_FAST_CAL`, `AFL_CMPLOG_ONLY_NEW`, `AFL_FORKSRV_INIT_TMOUT=30000`, `AFL_IGNORE_PROBLEMS`, `AFL_IGNORE_UNKNOWN_ENVS`), all `"1"` except the timeout; `build_afl_launch` returns `kind="upstream"` with argv `[/out/afl-fuzz, (-c /out/<t> if afl_cmplog.txt), (-x /out/afl++.dict if present), -t <AFL_TIMEOUT_FLAG>, -i <in>, -o <out>, (-x <options dict>), (-s <seed>), (-V <dur>), --, /out/<t>]`, `afl_env = UPSTREAM_AFL_ENV + [("AFL_AUTORESUME","1")] if autoresume`, `sanitizer_env = upstream_sanitizer_env(...)`, `workdir="/out"`, `extra_env=[]`, `flags` recording `cmplog`, `aflpp_dict`, `options_dict`, `sanitizer`, `deviations: ["-t <AFL_TIMEOUT_FLAG> not 5000+", "detect_leaks=0"]`; `AflLaunch.shell()` for upstream returns `"export PATH=/out:$PATH; " + shlex-quoted argv`; `shim_compiler(entry)` returns `"clang"` for upstream.

- [ ] **Step 1: Write the failing tests** (mirror `tests/test_fuzzbench_run.py`'s `_fb_bin` fixture)

```python
UP = {"project": "libssh", "ossfuzz_project": "libssh", "cve": "upstream-970001", "local_id": 970001,
      "fuzz_target": "ssh_server_fuzzer", "kind": "upstream", "sanitizer": "address", "language": "c"}
def test_upstream_argv_matches_run_fuzzer_with_the_two_deviations(tmp_path):
    b = _bin(tmp_path, "ssh_server_fuzzer", cmplog_marker=True, aflpp_dict=True,
             options="[libfuzzer]\nmax_len = 4096\ndict = ssh.dict\n[asan]\nmax_malloc_fill_size = 100\n")
    (b / "ssh.dict").write_text('"x"\n')
    L = afl_launch.build_afl_launch(entry=UP, host_bin_dir=str(b), fuzz_target="ssh_server_fuzzer",
                                    input_dir="/corpus", output_dir="/afl_out", duration=600, seed=7)
    assert L.argv == ["/out/afl-fuzz", "-c", "/out/ssh_server_fuzzer", "-x", "/out/afl++.dict",
                      "-t", config.AFL_TIMEOUT_FLAG, "-i", "/corpus", "-o", "/afl_out",
                      "-x", "/out/ssh.dict", "-s", "7", "-V", "600", "--", "/out/ssh_server_fuzzer"]
    env = dict(L.env)
    assert env["ASAN_OPTIONS"] == "max_malloc_fill_size=100:abort_on_error=1:symbolize=0:detect_odr_violation=0:detect_leaks=0"
    assert env["UBSAN_OPTIONS"] == "silence_unsigned_overflow=1:symbolize=0"
    assert env["MSAN_OPTIONS"] == "exit_code=86:symbolize=0"
    assert [k for k, _ in L.afl_env] == ["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "AFL_SKIP_CPUFREQ",
        "AFL_TRY_AFFINITY", "AFL_FAST_CAL", "AFL_CMPLOG_ONLY_NEW", "AFL_FORKSRV_INIT_TMOUT",
        "AFL_IGNORE_PROBLEMS", "AFL_IGNORE_UNKNOWN_ENVS", "AFL_AUTORESUME"]
    assert env["AFL_FORKSRV_INIT_TMOUT"] == "30000" and "AFL_NO_AFFINITY" not in env
    assert L.workdir == "/out" and L.shell().startswith("export PATH=/out:$PATH; /out/afl-fuzz ")
    assert L.flags["deviations"] == [f"-t {config.AFL_TIMEOUT_FLAG} not 5000+", "detect_leaks=0"]

def test_optional_flags_appear_only_when_their_files_exist(tmp_path):
    # no afl_cmplog.txt, no afl++.dict, no .options, a <t>.dict present
    ... assert L.argv == ["/out/afl-fuzz", "-t", config.AFL_TIMEOUT_FLAG, "-i", "/corpus", "-o", "/afl_out",
                          "-x", "/out/t.dict", "-s", "7", "-V", "600", "--", "/out/t"]

def test_options_sections_join_like_parse_options(tmp_path):
    # values with '=' and spaces; libfuzzer keys ignored; msan section honoured
    ... assert afl_launch.parse_options_section(p, "asan") == "allocator_may_return_null=1:strip_path_prefix=/a=b c"
    ... assert env["MSAN_OPTIONS"] == "poison_in_dtor=1:exit_code=86:symbolize=0"

def test_arvo_and_fuzzbench_launches_are_unchanged(tmp_path):
    # the existing ARVO and BUG expectations from tests/test_fuzzbench_run.py, re-asserted here verbatim

def test_shim_compiler_for_upstream_is_the_image_clang():
    assert afl_launch.shim_compiler(UP) == "clang"
```

- [ ] **Step 2: Run to verify they fail** — `python3 -m pytest tests/test_upstream_launch.py -q` → `AttributeError`/argv mismatch.
- [ ] **Step 3: Implement** in `lib/afl_launch.py`: the helpers above; a new `elif is_upstream(entry):` branch in `build_afl_launch` placed before the FuzzBench branch; `shell()` and `shim_compiler` cases. Do not touch the ARVO or FuzzBench branches.
- [ ] **Step 4: Run** `python3 -m pytest tests/test_upstream_launch.py tests/test_fuzzbench_run.py tests/test_afl_mutation_capture.py -q` → all pass.
- [ ] **Step 5: Commit** `launch: upstream kind runs OSS-Fuzz's run_fuzzer argv and env`.

---

### Task 3: Upstream image definition and compile path

**Files:**
- Create: `prework/upstream_image.py`
- Modify: `prework/prework_build.py` (`prework_image_for`, `build_prework_rebuild_command`, new `upstream_compile_args`, `build_opt_provenance`)
- Test: `tests/test_upstream_build.py`

**Interfaces:**
- Consumes: Task 1; `prework/build_image.py` (`PREWORK_DIR`).
- Produces (`prework/upstream_image.py`): `UPSTREAM_DIR = PREWORK_DIR / "upstream"`; `BASES_FILE = UPSTREAM_DIR / "bases.json"` (`{"<image ref as written in OSS-Fuzz FROM>": "<ref>@sha256:<digest>", ...}`); `DEFINITION_LABEL = "bench-upstream.definition-sha256"`; `upstream_image_tag(project: str) -> str` (`"bench-upstream/" + project.lower()`); `definition_hash(project_dir) -> str` (sha256 over every file under the dir, relative path + `\0` + file sha256 + `\n`, sorted, excluding `onboard_result.json`); `pinned_dockerfile(text: str, bases: dict) -> str` (every `FROM <ref>[ AS x]` line: if `<ref>` contains `@sha256:` keep it, else replace `<ref>` with `bases[<ref>]`, raising `KeyError` naming the ref when absent; everything else byte-identical); `build_command(project_dir, tag) -> list[str]` (`docker build --label <DEFINITION_LABEL>=<hash> -t <tag> -f <project_dir>/Dockerfile <project_dir>`); `build_upstream_image(project_dir, *, cpuset=None, timeout=7200) -> tuple[bool, str]`; `load_meta(project_dir) -> dict`; `load_pins(project_dir) -> dict`.
- Produces (`prework/prework_build.py`): `upstream_compile_args(*, image, source_dir: str | None, out_dir, project, sanitizer, language) -> list[str]` (with `source_dir=None` the `-v <source_dir>:/src/<project>` pair is omitted and the image's own `$SRC/<project>` is compiled, which is what onboarding does) = `["--network", "none", "-e", "FUZZING_ENGINE=afl", "-e", f"SANITIZER={sanitizer}", "-e", "ARCHITECTURE=x86_64", "-e", f"FUZZING_LANGUAGE={language}", "-e", "AFL_LLVM_DENYLIST=/src/aflpp_fold_denylist.txt", "-v", <denylist>:/src/aflpp_fold_denylist.txt:ro, "-v", <source_dir>:/src/<project>, "-v", <out_dir>:/out, image, "compile"]` (no `FUZZER_LIB`, no `FUZZER`, no `-O` override); `prework_image_for(entry)` returns `upstream_image_tag(entry["ossfuzz_project"])` for upstream (ValueError if the field is missing); `build_prework_rebuild_command` dispatches `is_upstream_image(image)` → upstream args and passes `sanitizer`/`language` keyword args (new, default `"address"`/`"c++"`); `rebuild_with_prework_image(entry=...)` passes `sanitizer_of(entry)`, `language_of(entry)`; `build_opt_provenance(entry)` for upstream returns `{"build_opt_level": <from image CFLAGS>, "build_opt_level_source": "image-cflags", "build_opt": rec}` via the existing `arvo_build_opt_record(image)` with no override.

- [ ] **Step 1: Write the failing tests**

```python
def test_pinned_dockerfile_pins_every_from_and_keeps_the_rest(tmp_path):
    text = "FROM gcr.io/oss-fuzz-base/base-builder\nRUN apt-get install -y x\nFROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04 AS b\n"
    bases = {"gcr.io/oss-fuzz-base/base-builder": "gcr.io/oss-fuzz-base/base-builder@sha256:aa",
             "gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04": "gcr.io/oss-fuzz-base/base-builder@sha256:bb"}
    out = ui.pinned_dockerfile(text, bases)
    assert out == "FROM gcr.io/oss-fuzz-base/base-builder@sha256:aa\nRUN apt-get install -y x\nFROM gcr.io/oss-fuzz-base/base-builder@sha256:bb AS b\n"
    already = "FROM gcr.io/oss-fuzz-base/base-builder@sha256:19782f\n"
    assert ui.pinned_dockerfile(already, bases) == already
    with pytest.raises(KeyError, match="base-builder-go"):
        ui.pinned_dockerfile("FROM gcr.io/oss-fuzz-base/base-builder-go\n", bases)

def test_definition_hash_covers_every_file_and_ignores_results(tmp_path): ...
def test_upstream_compile_args_are_oss_fuzz_compile_without_network(tmp_path):
    args = pb.upstream_compile_args(image="bench-upstream/libssh", source_dir=str(tmp_path/"s"), out_dir=str(tmp_path/"o"),
                                    project="libssh", sanitizer="memory", language="c")
    assert args[:2] == ["--network", "none"] and "SANITIZER=memory" in args and "FUZZING_LANGUAGE=c" in args
    assert not any(a.startswith(("FUZZER_LIB=", "FUZZER=", "CFLAGS=")) for a in args) and args[-2:] == ["bench-upstream/libssh", "compile"]
def test_prework_image_for_upstream_and_rebuild_dispatch(): ...
def test_arvo_and_fuzzbench_commands_are_unchanged(): ...  # arvo_compile_args / fuzzbench_build_command outputs re-asserted
```

- [ ] **Step 2: Run to verify they fail.**
- [ ] **Step 3: Implement** both files. `rebuild_with_prework_image` keeps the ARVO branch for upstream images (clean artifacts, `cpuset_lock`, ownership restore).
- [ ] **Step 4: Run** `python3 -m pytest tests/test_upstream_build.py tests/test_prework_build.py tests/test_prework_build_integration.py tests/test_fuzzbench_build.py -q` → pass.
- [ ] **Step 5: Commit** `prework: upstream kind builds OSS-Fuzz projects in their own pinned image`.

---

### Task 4: Seed staging per run_fuzzer

**Files:**
- Modify: `lib/corpus.py` (new `stage_upstream_seed_corpus`), `phase3_online.py` (`_stage_online_seed_corpus` upstream branch)
- Test: `tests/test_upstream_corpus.py`

**Interfaces:**
- Produces: `stage_upstream_seed_corpus(bin_dir: str, fuzz_target: str, merged_dir: str, build_dir: str) -> dict` returning `{"staged": <files in merged>, "zip": bool, "input_file": True}`: unpack `<bin_dir>/<t>_seed_corpus.zip` into `merged_dir` (flattened like the existing helpers), write `merged_dir/input` with bytes `b"input\n"`; `build_dir` gets the zip's files, or only the `input` file when there is no zip. `_stage_online_seed_corpus(..., entry)` calls it for `is_upstream(entry)` and returns `staged`.

- [ ] **Step 1: Write the failing tests** — with a zip: merged has zip files + `input`, build has zip files only; without a zip: merged == build == [`input`] with content `input\n`; ARVO/FuzzBench branches untouched (call with a fuzzbench entry and assert `stage_fuzzbench_seed_corpus` was used).
- [ ] **Step 2: Run to verify they fail.** **Step 3: Implement.** **Step 4: Run** the file plus `tests/test_fuzzbench_run.py` → pass.
- [ ] **Step 5: Commit** `corpus: stage upstream seeds the way run_fuzzer does`.

---

### Task 5: Sanitizer options reach the gate, smoke and profile

**Files:**
- Modify: `sandbox/broker.py` (`BrokerContext`, `_build_command`, `_replay_command`, the cmin command, the smoke command, the symbolized classify env, `_map_size_prefix`), `sandbox/session.py` (`run_sandboxed_optimizer` signature → `BrokerContext`), `phase2_setup.py` (profiler invocation near line 1603-1630 and the `run_sandboxed_optimizer` call near line 2911), `skills/profile-once-fuzz-folds/scripts/replay_fuzzer_profile.py` (argparse + docker env), `phase3_online.py` (wrapper env keys)
- Test: `tests/test_upstream_sanitizer_env.py`

**Interfaces:**
- Consumes: Task 2 (`upstream_sanitizer_env`), Task 3 (`upstream_compile_args`, `is_upstream_image`).
- Produces: `BrokerContext` gains `sanitizer: str = "address"`, `language: str = "c++"`, `sanitizer_env: dict[str, str] = field(default_factory=dict)`; `_sanitizer_exports(ctx) -> str` returns `"export ASAN_OPTIONS=... UBSAN_OPTIONS=... MSAN_OPTIONS=...; "` from `ctx.sanitizer_env` when non-empty, else the byte-identical strings used today (`config.REPLAY_ASAN_OPTIONS`, `config.REPLAY_UBSAN_OPTIONS`, `MSAN_OPTIONS=symbolize=0`); every command that exports sanitizer options uses it; `_map_size_prefix` applies to upstream images too; `_build_command` dispatches upstream images to `upstream_compile_args(..., sanitizer=ctx.sanitizer, language=ctx.language)`. `run_sandboxed_optimizer(..., sanitizer="address", language="c++", sanitizer_env=None)`. Wrapper env keys `PHASE2_SANITIZER` (= `sanitizer_of(entry)`), `PHASE2_FUZZING_LANGUAGE` (= `language_of(entry)`), `PHASE2_SANITIZER_ENV` (= `json.dumps(dict(afl_launch.upstream_sanitizer_env(<round's bin dir>, fuzz_target, sanitizer_of(entry))))`) set by `phase3_online` next to `PHASE2_FB_CCACHE_DIR` for upstream entries only, read by `phase2_setup` at the `run_sandboxed_optimizer` call and the profiler invocation. `replay_fuzzer_profile.py --sanitizer-env NAME=VALUE` (repeatable) replaces the hard-coded `-e NAME=...` for that NAME; without it the docker command is byte-identical to today.

- [ ] **Step 1: Write the failing tests** — (a) `BrokerContext()` default → `_replay_command` and smoke strings equal today's (assert the exact `export ASAN_OPTIONS=<config.REPLAY_ASAN_OPTIONS> UBSAN_OPTIONS=<config.REPLAY_UBSAN_OPTIONS> MSAN_OPTIONS=symbolize=0;` text); (b) with `sanitizer_env={"ASAN_OPTIONS": "a=1", "MSAN_OPTIONS": "m=1", "UBSAN_OPTIONS": "u=1"}` every command carries exactly those; (c) `_build_command` on `image="bench-upstream/x"` yields `upstream_compile_args` with the ctx sanitizer/language and `--network none`; (d) the profiler command without `--sanitizer-env` is unchanged (snapshot the three `-e` strings) and with `--sanitizer-env ASAN_OPTIONS=a=1` carries `-e ASAN_OPTIONS=a=1` once; (e) `phase2_setup`'s profiler call passes `--sanitizer-env` for each key of `PHASE2_SANITIZER_ENV` and nothing when absent.
- [ ] **Step 2: Run to verify they fail.** **Step 3: Implement.** **Step 4: Run** the new file plus `tests/test_sandbox_broker.py tests/test_sandbox_session.py tests/test_replay_fuzzer_profile.py tests/test_phase2_setup.py -q` → pass.
- [ ] **Step 5: Commit** `sandbox: gate, smoke and profile run under the target kind's sanitizer options`.

---

### Task 6: Pipeline gating for the upstream kind

**Files:**
- Modify: `phase3_online.py` (`_extract_online_target`, `run_online` PoC gate and `_build_afl_baseline` skip, swap set helpers near lines 586-599, wrapper env), `phase3_runner.py` (`_resolve_trial_image`, `_trial_env_record`, `_trial_toolchain`), `tools/preflight_online.py` (`_entry`, kind branches, `--local-id`), `run_benchmark.py` (`--local-id` filter at the three manifest filters), `run_online_pertrial.sh` (`LOCAL_ID` env → `--local-id`; the FB_KIND block treats upstream like fuzzbench for `BUILD_OPT_LEVEL`), `bootstrap_server.py` (`check_images` lists `prework/upstream/*` with `upstream_image_tag` and the upstream label; build mode never builds them)
- Test: `tests/test_upstream_online.py`

**Interfaces:**
- Consumes: Tasks 1-5.
- Produces: `--local-id <int>` on `run_benchmark.py` and `tools/preflight_online.py` (combined with `--project`: entries matching both); upstream swap set = `[fuzz_target] + [cmplog/<t>, afl++.dict if present] + fuzzbench_runtime_libs(bin_dir)`; `_trial_toolchain` for upstream adds `{"upstream": {"sanitizer", "ossfuzz_project", "pins": <pins.json contents>}}`; `_trial_env_record` records the launch for any kind whose record is not `arvo`.

- [ ] **Step 1: Write the failing tests** — `_extract_online_target` with an upstream entry takes the image-extract path (monkeypatch `extract_source_from_image`, `_setup_build`) and returns `(False, None, None, root)`; `requires_poc` false for upstream (monkeypatch to drive `run_online` past the gate or test the helper); `_resolve_trial_image` returns `bench-upstream/<p>` when the image exists; `run_benchmark` filter with `--local-id 970002` keeps exactly that entry; preflight `_entry("libssh", 970002)`; `check_images` lists an upstream dir with state from the upstream label.
- [ ] **Step 2: Run to verify they fail.** **Step 3: Implement.** **Step 4: Run** the new file plus `tests/test_phase3_online.py tests/test_phase3_runner.py tests/test_run_benchmark.py tests/test_fuzzbench_run.py tests/test_bootstrap_images.py -q` → pass.
- [ ] **Step 5: Commit** `pipeline: route the upstream kind through setup, trials, preflight and bootstrap`.

---

### Task 7: Onboarding tool

**Files:**
- Create: `tools/onboard_upstream.py`, `tools/onboard_upstream_batch.sh`, `prework/upstream/bases.json`, `prework/upstream/local_ids.json`
- Test: `tests/test_onboard_upstream.py`

**Interfaces:**
- Consumes: Task 3 (`pinned_dockerfile`, `build_upstream_image`, `upstream_image_tag`), `prework_build.upstream_compile_args`.
- Produces: CLI `python3 tools/onboard_upstream.py <subcommand> --project P [...]` with subcommands:
  - `bases`: resolves each base ref in use (`gcr.io/oss-fuzz-base/base-builder` taken from `prework/base.pin`; `base-builder:ubuntu-24-04`, `base-builder-rust`, `base-builder-go` via `docker manifest inspect`) to `<ref>@sha256:<digest>` and writes `prework/upstream/bases.json`; never overwrites an existing entry without `--refresh`.
  - `vendor --oss-fuzz DIR --commit REF`: `git -C DIR archive REF projects/P` → `prework/upstream/P/ossfuzz/`; writes `Dockerfile` (pinned FROM), `meta.json` (`project`, `srcdir` from `--srcdir` or the basename of `main_repo` in `project.yaml`, `language`, `sanitizers` from `project.yaml` with `address` first, `harnesses: {}`, `deviations: []`), `pins.json` (`ossfuzz_commit`, `bases` used).
  - `build [--cpuset]`: image with label; refuses when the image exists with a matching label unless `--rebuild`.
  - `compile --sanitizer S --work DIR [--cpuset]`: `docker run --rm --cpuset-cpus <c> <upstream_compile_args(... sanitizer=S, language, no source mount ...)>` with `/out` bound to `DIR/P/S/out`, log at `DIR/P/S/compile.log`; verifies `srcdir` exists in the image (`docker run ... test -d $SRC/<srcdir>`) and records `srcdir_verified`; harness discovery = regular files in `/out` that are executable, not named `afl-*` or `llvm-symbolizer`, start with `\x7fELF` and contain the bytes `LLVMFuzzerTestOneInput`; writes `meta.json.harnesses[S]` and `DIR/P/S/harnesses.json`.
  - `pins`: `docker run --rm <image> bash -lc 'for d in $SRC/*/; do ...git -C $d rev-parse HEAD...; done'` → `pins.json.checkouts: {"<dir>": "<sha>"}`.
  - `manifest --projects P1,P2,... --out data/manifests/manifest_upstream.json`: one entry per (project, sanitizer with a non-empty harness list, harness): `{"project": srcdir, "ossfuzz_project": P, "kind": "upstream", "sanitizer": S, "language": L, "fuzz_target": H, "image": upstream_image_tag(P), "local_id": id, "cve": f"upstream-{id}"}`; ids from `prework/upstream/local_ids.json` keyed `"P/S/H"`, allocated from 970001 upward on first sight and never reassigned.
  - `run --sanitizers all|address --work DIR [--cpuset]`: vendor→build→pins→compile per listed sanitizer; `address` first; a non-address compile failure is recorded (`onboard_result.json` `sanitizers[S].status = "compile_failed"`) and does not stop the project; every step resumable (skip when its output exists).
  - `report --out docs/UPSTREAM_TARGETS.md --preflight-dir results/preflight-upstream`: per project/sanitizer/harness table from `onboard_result.json` files, `meta.json` deviations, preflight JSONs, and the user's `intro_rows.json` columns (harness count, coverage %, lines).
  - `tools/onboard_upstream_batch.sh <work-dir> <projects...>`: runs up to 4 projects concurrently on cpusets `2-6`, `7-11`, `12-16`, `17-19`, logs per project, never on cores 0-1.

- [ ] **Step 1: Write the failing tests** (pure parts only; no docker): `vendor` from a fake oss-fuzz git repo in `tmp_path` produces the pinned Dockerfile and a `meta.json` with `sanitizers == ["address", "undefined"]` when `project.yaml` lists `undefined, address`; harness discovery on a fake `/out` (one ELF-with-symbol file, one `afl-fuzz`, one script, one ELF without the symbol) returns exactly the first; `manifest` on a meta with `address` and `memory` harnesses `["t"]` yields two entries with distinct `local_id`/`cve`, and a second run with a new harness keeps the old ids; a `compile_failed` memory record leaves the address entries in the manifest.
- [ ] **Step 2: Run to verify they fail.** **Step 3: Implement.** Resolve `bases.json` once by `docker manifest inspect` (a `bases` subcommand) for the four refs in use: `gcr.io/oss-fuzz-base/base-builder` (use `prework/base.pin`'s digest), `:ubuntu-24-04`, `base-builder-rust`, `base-builder-go`. **Step 4: Run** `python3 -m pytest tests/test_onboard_upstream.py -q` → pass.
- [ ] **Step 5: Commit** `tools: onboard an OSS-Fuzz project as an upstream target`.

---

### Task 8: 0-day triage tool

**Files:**
- Create: `tools/triage_upstream_crashes.py`
- Test: `tests/test_upstream_triage.py`

**Interfaces:**
- Consumes: `lib/afl_triage.collect_crashes`, `lib/provenance.classify_artifact`, `lib/crash_classify.sanitizer_identity`, Task 2 (`upstream_sanitizer_env`, with `symbolize=0` replaced by `symbolize=1` for the classification replay, as the broker's classify path does).
- Produces: `python3 tools/triage_upstream_crashes.py --experiment-id E [--project P] [--local-id N] [--cpu C]` writing `results/E/<project>-<cve>/triage/zero_day_report.json` and `.md`: per distinct crash key `(sanitizer kind, top 3 non-runtime frames)`: `first_seen_s` per arm, trials that found it, the earliest artifact path, the stack, and `reproduces_on_pristine: bool` from replaying the earliest artifact on `results/E/<project>-<cve>/baseline/bin` in the entry's image; crashes that do not reproduce on the pristine binary are listed under `optimizer_induced` and excluded from the counts. Pure helpers `dedupe_key(report_text) -> tuple` and `summarize(records) -> dict` are unit-tested with canned ASan reports; the docker replay is behind an injectable `replay` callable.

- [ ] **Step 1: Write the failing tests** — two reports with the same frames and different addresses dedupe to one key; a different third frame is a second key; `summarize` counts per arm and marks non-reproducing crashes as optimizer-induced; the markdown lists the reproducer path.
- [ ] **Step 2-4** as above; **Step 5: Commit** `tools: triage a campaign's crashes into a 0-day report`.

---

### Task 9: Onboard the candidates (box work, fix rounds with agents)

**Files:** `prework/upstream/<project>/` for each project; `data/manifests/manifest_upstream.json`; per-project `onboard_result.json` under the work dir; no pipeline code unless a fix round finds a pipeline bug (then a new task is appended).

- [ ] **Step 1: Bases and vendoring.** `python3 tools/onboard_upstream.py bases` then `vendor` for all 50 projects with `--oss-fuzz /home/sefcom/asu/project/oss-fuzz --commit origin/master` (fetched 2026-11-05, `f3af0cb37`). Commit the vendored tree in one commit `upstream: vendor the 50 candidate OSS-Fuzz configs at f3af0cb37`.
- [ ] **Step 2: Batch run** `tools/onboard_upstream_batch.sh <work> <projects>` in batches of 4; monitor; collect `onboard_result.json` verdicts (`vendored`, `image_built`, `pins`, per-sanitizer `compiled`/`compile_failed`, harness counts, `srcdir_verified`).
- [ ] **Step 3: Fix rounds.** For each project whose image build or ASan compile failed: dispatch a fixer agent with the log, the fix policy verbatim, and write access only to `prework/upstream/<p>/Dockerfile`, `prework/upstream/<p>/ossfuzz/build.sh` and `meta.json` (deviations); then an auditor agent checks the diff against the policy (allowed/forbidden list) and that each change is recorded; re-run `run` for that project. Three rounds maximum; then `status: dropped` with the log. A failing UBSan/MSan compile gets one fix round at most and is otherwise recorded as `compile_failed` for that sanitizer.
- [ ] **Step 4: Manifest.** `manifest --projects <all with at least one compiled sanitizer> --out data/manifests/manifest_upstream.json`; commit `upstream: manifest for the onboarded candidates` with the `onboard_result.json` files copied to `results/upstream-onboarding-<date>/`.

---

### Task 10: Preflight every entry (box work)

- [ ] **Step 1:** Driver loop over `manifest_upstream.json`: `python3 tools/preflight_online.py --project <project> --local-id <id> --cpu 3 --build-cpus 2-19 --smoke-secs 120`, ASan entries first, results copied to `results/preflight-upstream/<ossfuzz_project>/<sanitizer>/<harness>.json`; up to 3 in parallel on disjoint cpus if the box is otherwise idle.
- [ ] **Step 2:** Triage failures: a failure caused by the pipeline (extraction, library supply, profiler, launch) becomes an appended code task with the usual implementer/auditor loop; a failure caused by the project goes back to Task 9's fix rounds (same policy and cap).
- [ ] **Step 3:** Rerun failed entries after fixes; record final verdicts.

---

### Task 11: One smoke campaign and triage (box work)

- [ ] **Step 1:** Pick the READY ASan entry with the fewest harness-level seconds per preflight stage (smallest build), launch `LOCAL_ID=<id> TRIALS=2 TRIAL_CORES=4-7 OPT_CORES=2-3 SETUP_CPU=2 SETUP_BUILD_CPUS=2-19 DURATION=10800 INTERVAL=300 OPT_TIMEOUT=5400 EXP_PREFIX=smoke-upstream BENCHMARK_CLAUDE_MODEL=claude-sonnet-5-5 BENCHMARK_MANIFEST_PATH=$PWD/data/manifests/manifest_upstream.json ./run_online_pertrial.sh <project>`.
- [ ] **Step 2:** Pass criteria: `=== Benchmark Complete ===`; at least one `outcome=` with `built=True`; no `Traceback|prebuild error|weekly limit`; every `fuzzer_stats` non-empty; the trial launch record shows `kind: upstream`, the `run_fuzzer` AFL env and the two deviations; `python3 tools/triage_upstream_crashes.py --experiment-id <exp>` writes the report (possibly with zero crashes).
- [ ] **Step 3:** Any failure on the online path → appended code task; account-side failures → relaunch once.

---

### Task 12: Doc and non-regression

**Files:** `docs/UPSTREAM_TARGETS.md` (generated by `report` plus a hand-written "How to run" and "What changed" section), the spec's decisions table if any ruling changed it.

- [ ] **Step 1:** `python3 tools/onboard_upstream.py report --out docs/UPSTREAM_TARGETS.md --preflight-dir results/preflight-upstream`, then add: the exact onboarding, preflight, campaign and triage commands for this box; per project: verdict, deviations, sanitizers, harness count, execs/s per harness from the preflight smoke, coverage/lines from `intro_rows.json`, pinned commits; dropped projects with reasons; known limitations.
- [ ] **Step 2:** Full suite: `taskset -c 12-19 python3 -m pytest -q -p no:cacheprovider` → exactly the 4 known failures. Non-regression preflights: ARVO `python3 tools/preflight_online.py --project libxml2 --cpu 3 --build-cpus 2-19 --smoke-secs 120` and FuzzBench with `BENCHMARK_MANIFEST_PATH=$PWD/data/manifests/manifest_fuzzbench_bugs.json` → both READY with unchanged launch records.
- [ ] **Step 3: Commit** `docs: how the upstream OSS-Fuzz candidates were onboarded`.
