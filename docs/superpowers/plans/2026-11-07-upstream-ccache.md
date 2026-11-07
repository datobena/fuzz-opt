# ccache for upstream optimizer rebuilds — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the optimizer's upstream rebuilds use a per-trial ccache so unchanged translation units are not recompiled, proven not to change the produced binary.

**Architecture:** ccache runs below afl-cc via a read-only mounted compiler wrapper (no image or `compile` change), environment-only otherwise. Only the optimized arm caches; baseline/reference/onboarding builds set `CCACHE_DISABLE=1`. A target caches only after an equivalence test proves cached == uncached. Per-trial caches seed from a target-level template built once at setup. Mirrors the FuzzBench ccache path (`prework/fb_ccache.py`, `prework/fb_build.sh`, `tools/fb_ccache_equivalence.py`).

**Tech Stack:** Python 3 (stdlib + pyyaml), Docker CLI, ccache 4.10.2 (already in `bench-upstream/*` images), AFL++ afl-clang-fast.

**Spec:** `docs/superpowers/specs/2026-11-07-upstream-ccache-design.md`

## Global Constraints

- No sanitizer/optimization/instrumentation/engine flag changed; harness untouched; denylist unchanged.
- `--network none` on every build; `bench-upstream/*` images are the artifact of record and are never rebuilt; writable mounts are `/out` and the cache only.
- ccache is **on PATH** in these images and the image bakes `CCACHE_DIR=/ccache/cache`; so uncached builds MUST set `CCACHE_DISABLE=1`, and cached builds MUST set `CCACHE_DIR` explicitly via `-e`.
- `AFL_CC=ccache` directly does NOT work (afl-clang-fast execs `ccache <flags>` → `ccache: invalid option`); only a wrapper that execs `ccache <real-compiler> "$@"` works.
- Only optimized-arm rebuilds (harness rebuild + broker agent builds) cache. Baseline, reference baseline, onboarding compile, and the equivalence test's `P0`/`P0'`/noise builds never cache.
- A cached build that does not actually use ccache is a failure, not a silent pass.
- Onboarding path (`source_dir=None`) must stay byte-identical to today.
- FuzzBench ccache code, image, and verified list are left unchanged.
- Commit trailers: implementing model's own `Co-Authored-By` line, then as the last line `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

## Review Focus

- **Uncached build silently caching:** an on-PATH ccache used by a project build system during a baseline/reference/P0 build. Test asserts `CCACHE_DISABLE=1` is present on every non-cached upstream build's docker args and that a build run under it reports zero ccache activity.
- **False "cache in use":** a cached build whose stats signal is missing or misparsed is reported as cached. Test asserts the stats parser returns "not used" when the stats file is absent/empty and that the equivalence gate treats that as `fail`.
- **Denylist change not invalidating cache:** test asserts `CCACHE_EXTRAFILES` names the denylist, and (equivalence tool) that editing the denylist forces a miss.
- **Template/setup failure not failing safe:** test asserts that a template fill/check failure turns ccache off for the campaign (every trial runs uncached) rather than raising.
- **Loaded-code difference masked as noise:** test (fixture) asserts `pass_noise_masked` never masks a differing byte in a loaded section; such a diff is `fail`.

---

### Task 1: Compiler wrapper + ccache env/arg builder (pure Python)

**Files:**
- Create: `prework/upstream_ccache_wrap/cc`, `prework/upstream_ccache_wrap/cxx` (executable wrapper scripts; `cc` is `#!/bin/sh` + `exec /usr/local/bin/ccache /usr/local/bin/clang "$@"`, `cxx` the `clang++` twin). `AFL_CC`/`AFL_CXX` point at these; they wrap the BACKEND compiler (clang), NOT afl-clang-fast — wrapping afl-clang-fast would recurse, and `AFL_CC=ccache` directly makes afl-clang-fast exec `ccache <flags>` which ccache rejects. The backend path `/usr/local/bin/clang[++]` is confirmed on the image.
- Create: `prework/upstream_ccache.py` (host-side helpers; this task adds only the env/arg builder).
- Test: `tests/test_upstream_ccache_env.py`

**Interfaces:**
- Produces: `upstream_ccache.ccache_docker_args(*, cache_dir: str | None, denylist_path: str = "/src/aflpp_fold_denylist.txt", statslog: str | None) -> list[str]` returning the `-e`/`-v` args. `cache_dir=None` ⇒ the uncached form (`["-e", "CCACHE_DISABLE=1"]`, no mounts). `cache_dir` set ⇒ wrapper mounts, `CCACHE_DIR=<container path>` + cache mount, `CCACHE_COMPILERCHECK=content`, `CCACHE_EXTRAFILES=<denylist>`, `CCACHE_STATSLOG=<statslog>`, `AFL_CC`/`AFL_CXX` pointing at the mounted wrappers.
- Produces: `upstream_ccache.WRAPPER_DIR` (repo path of the wrapper scripts), `CONTAINER_WRAPPER_DIR`, `CONTAINER_CACHE_DIR`.

- [ ] **Step 1: Write failing tests** `tests/test_upstream_ccache_env.py`:
```python
def test_uncached_sets_disable_and_no_mounts():
    a = ccache_docker_args(cache_dir=None, statslog=None)
    assert "-e" in a and "CCACHE_DISABLE=1" in a
    assert not any(":ro" in x and "ccache_wrap" in x for x in a)

def test_cached_mounts_wrapper_and_overrides_ccache_dir():
    a = ccache_docker_args(cache_dir="/host/c", statslog="/host/c/statslog")
    assert any(x.endswith("/cc") for x in a)                     # wrapper mounted
    assert env_val(a, "CCACHE_DIR") == CONTAINER_CACHE_DIR       # overrides baked /ccache/cache
    assert env_val(a, "AFL_CC").startswith(CONTAINER_WRAPPER_DIR)
    assert env_val(a, "CCACHE_EXTRAFILES") == "/src/aflpp_fold_denylist.txt"
    assert env_val(a, "CCACHE_STATSLOG")
    assert "CCACHE_DISABLE=1" not in a
```
- [ ] **Step 2: Run, verify they fail** (`pytest tests/test_upstream_ccache_env.py -v` → import/attr error).
- [ ] **Step 3: Write the two wrapper scripts** (chmod +x; `cc` = `#!/bin/sh` + `exec /usr/local/bin/ccache /usr/local/bin/clang "$@"`, `cxx` = the `clang++` twin).
- [ ] **Step 4: Implement `ccache_docker_args` and the module constants** in `prework/upstream_ccache.py`.
- [ ] **Step 5: Run tests → pass.**
- [ ] **Step 6: Commit.**

---

### Task 2: Thread ccache through the upstream build path

**Files:**
- Modify: `prework/prework_build.py` — `upstream_compile_args`, `_staged_compile_command`, `build_prework_rebuild_command`, `rebuild_with_prework_image`.
- Test: `tests/test_upstream_compile_args.py` (extend if present).

**Interfaces:**
- Consumes: `upstream_ccache.ccache_docker_args` (Task 1).
- Produces: `upstream_compile_args(..., ccache_dir: str | None = None)` injects Task 1's args and, when `ccache_dir` is set, the staged command resets ccache stats before `compile` (so stats are per-build); `source_dir=None` and `ccache_dir=None` output is byte-identical to today. `build_prework_rebuild_command`/`rebuild_with_prework_image` accept `ccache_dir` for upstream images and drop the `ccache_dir is only supported for FuzzBench` rejection for upstream (still rejected for ARVO).

- [ ] **Step 1: Write failing tests:**
```python
def test_onboarding_args_unchanged():       # source_dir=None, ccache_dir=None
    assert upstream_compile_args(..., source_dir=None) == <current exact list>

def test_uncached_staged_build_has_disable():
    a = upstream_compile_args(..., source_dir=SRC, ccache_dir=None)
    assert "CCACHE_DISABLE=1" in a

def test_cached_staged_build_resets_stats_and_mounts_wrapper():
    a = upstream_compile_args(..., source_dir=SRC, ccache_dir="/host/c")
    assert any("afl-clang-fast" in x for x in a)
    cmd = staged_bash_string(a)
    assert "ccache" in cmd and "-z" in cmd   # per-build stats reset before compile
    assert "compile" in cmd

def test_arvo_still_rejects_ccache():
    with pytest.raises(ValueError): build_prework_rebuild_command(image=ARVO_IMG, ccache_dir="/c", ...)
```
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement.** Keep `_staged_compile_command`'s copy-in/`.git` behaviour intact; add the stats reset and (if post-build host-side read is not used) a `--show-stats` tail without breaking the existing `exec compile` semantics (replace `exec compile` with `compile && <stats>` only on the cached path).
- [ ] **Step 4: Run tests → pass.**
- [ ] **Step 5: Commit.**

---

### Task 3: Host-side verified-list, stats parsing, noise model

**Files:**
- Modify: `prework/upstream_ccache.py` (add parsing/verified-list/noise helpers).
- Create: `prework/upstream_ccache_verified.txt` (empty but for a header comment).
- Test: `tests/test_upstream_ccache_host.py`

**Interfaces:**
- Produces: `read_verified_modes(path=None) -> dict[str,str]` (`"pass"`/`"pass_noise_masked"`, same line format as `fb_ccache.read_verified_modes`); `parse_stats(statslog_text_or_path) -> dict` (hits, misses, used: bool); `slim_stats(d) -> dict`; and a noise model for comparing two `/out/<t>` binaries (reuse `fb_ccache`'s noise/compare helpers if they generalise without changing FuzzBench behaviour — prefer import over copy).

- [ ] **Step 1: Write failing tests** with fixture stats logs and verified-list text:
```python
def test_verified_list_modes(tmp_path): ...            # "<p>" -> pass; "<p> pass_noise_masked"
def test_parse_stats_absent_means_unused(): assert parse_stats("")["used"] is False
def test_parse_stats_hits(): assert parse_stats(SAMPLE_STATSLOG)["hits"] == 3
def test_noise_mask_never_masks_loaded_code(): ...     # diff in .text -> not maskable
```
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement**, importing from `fb_ccache` where a helper is already general; otherwise add upstream twins. Do not modify `fb_ccache` in a way that changes FuzzBench behaviour.
- [ ] **Step 4: Run tests → pass.**
- [ ] **Step 5: Commit.**

---

### Task 4: Upstream equivalence test tool

**Files:**
- Create: `tools/upstream_ccache_equivalence.py`
- Test: `tests/test_upstream_ccache_equivalence.py` (the verdict/compare logic only; the docker builds are exercised in Task 7).

**Interfaces:**
- Consumes: Task 1 args, Task 2 build path, Task 3 parsing/noise.
- Produces: a CLI `--project P --src <tree> --work <dir> --cpuset C --one-core N [--parallel]` that builds `P0, P0', C0, W0, PC, WC, PH, WH` (single `compile`, no cmplog) through the production command, compares sha256 of every `/out/<target>`, and writes `report.json`/`report.txt` with verdict `pass|pass_noise_masked|fail`. Uncached builds run with `CCACHE_DISABLE=1`; cached builds must show ccache used (Task 3 stats) or the verdict is `fail`. Exit 0 on pass/pass_noise_masked.

- [ ] **Step 1: Write failing tests** on the pure verdict function with fixtures:
```python
def test_verdict_pass_all_identical(): ...
def test_verdict_fail_when_cached_build_unused(): ...   # stats.used False -> fail
def test_verdict_noise_masked_strings_only(): ...       # P0!=P0' in a string region -> masked
def test_verdict_fail_loaded_code_diff(): ...
```
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the tool; structure so the verdict function is import-testable without docker (the `build_*` steps behind a thin orchestration layer).
- [ ] **Step 4: Run tests → pass.**
- [ ] **Step 5: Commit.**

---

### Task 5: phase3_online wiring (per-trial cache, template, provenance)

**Files:**
- Modify: `phase3_online.py` (per-trial cache creation from template; broker env key; pass cache to the harness rebuild; `CCACHE_DISABLE` on uncached upstream builds; populate `round_provenance["ccache"]`).
- Modify: `prework/upstream_ccache.py` (template fill helper `prepare_upstream_ccache_template` + `BROKER_ENV_KEY`).
- Test: `tests/test_upstream_ccache_phase3.py`

**Interfaces:**
- Consumes: Tasks 1-4.
- Produces: for an upstream target on the verified list, each optimized trial gets its own cache seeded from a target-level template (built once by one extra pristine build; a `pass_noise_masked` target also learns noise with one uncached build). Template fill/check failure ⇒ ccache off for the whole campaign (all trials uncached), never raises. The template is never mounted into an agent build. `round_provenance["ccache"]` carries Task 3 stats per round.

- [ ] **Step 1: Write failing tests** (use fakes for the build calls):
```python
def test_unverified_target_runs_uncached(): ...        # no cache dir passed anywhere
def test_template_failure_disables_campaign_ccache(): ...  # returns off, no raise
def test_broker_env_key_set_only_for_verified_optimized(): ...
def test_round_provenance_ccache_populated_from_stats(): ...
```
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement**, mirroring `_prepare_fb_ccache_template` and the FuzzBench per-trial cache/broker-env flow for the upstream kind.
- [ ] **Step 4: Run tests → pass.**
- [ ] **Step 5: Commit.**

---

### Task 6: broker.py wiring (agent builds)

**Files:**
- Modify: `sandbox/broker.py` — `_build_command` upstream branch and `_run_build_snapshot`'s cache gate.
- Test: `tests/test_broker_upstream_ccache.py`

**Interfaces:**
- Consumes: the broker env key (Task 5), Task 1/2 build path.
- Produces: `_build_command` passes the trial's cache dir to `upstream_compile_args` when the broker env key is set and the image is an upstream image; `_run_build_snapshot` handles the upstream cache the way it currently handles `is_fuzzbench_image(ctx.image)`. With no cache env, upstream agent builds get `CCACHE_DISABLE=1` and run uncached.

- [ ] **Step 1: Write failing tests:**
```python
def test_build_command_upstream_uses_cache_when_env_set(): ...
def test_build_command_upstream_uncached_without_env(): ...   # CCACHE_DISABLE present
def test_run_build_snapshot_upstream_branch(): ...
```
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests → pass.**
- [ ] **Step 5: Commit.**

---

### Task 7: Validation on the box (acceptance)

**Files:**
- Modify: `prework/upstream_ccache_verified.txt` (add the proven target).
- Create: `.superpowers/sdd/2026-11-07-upstream-ccache/validation.md` (results).

**Interfaces:**
- Consumes: the whole feature.

- [ ] **Step 1:** Run `tools/upstream_ccache_equivalence.py` on one large project (tpm2-tss or botan) using a real extracted tree; record verdict. Add the target to the verified list only on `pass`/`pass_noise_masked`.
- [ ] **Step 2:** Record cold vs warm one-core rebuild time for that project (warm must be materially faster); compare against the Task-0 cold baseline in the ledger.
- [ ] **Step 3:** Run a short upstream campaign (small `DURATION`, 2 trials) on the verified target; confirm `round_provenance` shows ccache hits and the round outcomes (built, gate sign) match an uncached run.
- [ ] **Step 4:** Confirm an unverified target still runs uncached (no cache mounted; baseline arm never mounts a cache), and the full test suite is at its known baseline.
- [ ] **Step 5: Commit** the verified list and validation notes.

---

## Notes for the executor

- A cold-rebuild baseline measurement for samba (heaviest tree) was started before execution; its number lands in the ledger as the "before" reference for Task 7 Step 2.
- Prefer importing a `fb_ccache` helper over duplicating it; never change `fb_ccache`/`fb_build.sh`/the FuzzBench verified list in a way that alters FuzzBench behaviour.
- The equivalence test and the campaign need `BENCHMARK_MANIFEST_PATH=$PWD/data/manifests/manifest_upstream.json`.
