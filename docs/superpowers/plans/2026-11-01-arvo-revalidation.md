# ARVO Revalidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the 8 ARVO targets with prework images on this box run through the current online pipeline again, with a staleness check for prework images and a profiler library policy that tolerates ARVO builds, without changing how FuzzBench targets build or run.

**Architecture:** Three code changes (image definition stamping + bootstrap states, a one-rule change in the profiler library supply, test updates for shared paths), each a separate audited commit, followed by box-level re-validation (re-stamped images, two preflights, one smoke campaign on the final code), a FuzzBench non-regression check and a doc. The orchestrator runs box work; the implementer writes code test-first; the auditor reviews every task before the next starts.

**Tech Stack:** Python 3, pytest, Docker, AFL++ v5.02c prework images, the vendored `profile-once-fuzz-folds` skill scripts.

**Spec:** `docs/superpowers/specs/2026-11-01-arvo-revalidation-design.md`

## Global Constraints

- Branch `feat/aflpp-sandboxed-optimizer`; one commit per audited task; never push.
- Engine flags and instrumentation are unchanged: ARVO launches stay byte-for-byte as pinned by `tests/test_fuzzbench_run.py`; `prework_build.arvo_compile_args` is not touched; nothing under `prework/fuzzbench*`, `lib/afl_launch.py`, `prework/fb_build.sh`, `prework/fb_ccache.py` changes.
- No change to `config.py` defaults; box layout comes from env per run.
- Commit messages end with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Run `pytest` from the repo root. Baseline before this plan: 17 failed, 1054 passed.
- Box work never overlaps the running smoke campaign (`smoke-arvo-libxml2-20261101-2208`, cores 2-19 until it logs `=== Benchmark Complete ===`).
- A target whose PoC stops reproducing is dropped and recorded, never patched around.

## Review Focus

1. A target dir with no `build.sh` or `poc_input` (yara-style) must hash deterministically and differently from one that has them. Test in Task 1.
2. An image built before stamping (no label) must report `UNVERIFIED`, never `OK` or `STALE`, and must not be rebuilt without `--rebuild-unverified`. Tests in Task 2.
3. A glibc copy under a `/out` subdirectory (`/out/cmplog/libc.so.6`) must be ignored like a top-level one, and a non-glibc `/out` library the profiler cannot load must still raise. Tests in Task 3.
4. A `target_libs.json` written before the policy change must not be reused. Test in Task 3.
5. The host-topology test must skip, not fail, on a host whose physical cores cannot hold the assumed 2-31 layout. Test in Task 5.

---

### Task 1: Stamp prework images with a definition hash

**Files:**
- Modify: `prework/build_image.py` (`build_docker_command`, `build_image`)
- Test: `tests/test_prework_build.py`

**Interfaces:**
- Produces: `DEFINITION_LABEL = "bench-aflpp.definition-sha256"`; `DEFINITION_FILES = ("Dockerfile", "meta.json", "build.sh", "poc_input")`; `PIN_FILES = ("base.pin", "aflpp.pin")`; `definition_hash(target_dir: str | Path, *, prework_dir: Path = PREWORK_DIR) -> str` (64-char hex); `build_docker_command(*, target_dir, tag, base, aflpp_ref, labels: dict[str, str] | None = None) -> list[str]` emitting `--label k=v` per entry after `-t <tag>`.

- [ ] **Step 1: Write the failing tests** in `tests/test_prework_build.py`

```python
def test_definition_hash_is_stable_and_covers_every_definition_file(tmp_path):
    from prework.build_image import definition_hash
    pins = tmp_path / "pins"; pins.mkdir()
    (pins / "base.pin").write_text("gcr.io/x@sha256:aa\n"); (pins / "aflpp.pin").write_text("v5.02c\n")
    t = tmp_path / "t"; t.mkdir()
    (t / "Dockerfile").write_text("FROM x\n"); (t / "meta.json").write_text("{}")
    h1 = definition_hash(t, prework_dir=pins)
    assert len(h1) == 64 and h1 == definition_hash(t, prework_dir=pins)
    (t / "build.sh").write_text("make\n")
    h2 = definition_hash(t, prework_dir=pins)
    assert h2 != h1, "adding build.sh must change the hash"
    (t / "build.sh").write_text("make all\n")
    assert definition_hash(t, prework_dir=pins) != h2
    (pins / "aflpp.pin").write_text("v5.03c\n")
    assert definition_hash(t, prework_dir=pins) not in (h1, h2), "a pin change must change the hash"

def test_build_docker_command_carries_labels(tmp_path):
    cmd = build_docker_command(target_dir=tmp_path, tag="bench-aflpp/x-arvo-1",
                               base="gcr.io/x@sha256:aa", aflpp_ref="v5.02c",
                               labels={"bench-aflpp.definition-sha256": "abc"})
    assert "--label" in cmd and "bench-aflpp.definition-sha256=abc" in cmd
    assert cmd.index("--label") > cmd.index("-t")

def test_build_image_stamps_the_definition_hash(tmp_path, monkeypatch):
    from prework import build_image as bi
    seen = {}
    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        class R: returncode = 0; stdout = ""; stderr = ""
        return R()
    monkeypatch.setattr(bi.subprocess, "run", fake_run)
    monkeypatch.setattr(bi, "read_pin", lambda n: {"base.pin": "gcr.io/x@sha256:aa", "aflpp.pin": "v5.02c"}[n])
    t = tmp_path / "t"; t.mkdir(); (t / "Dockerfile").write_text("FROM x\n"); (t / "meta.json").write_text("{}")
    src = tmp_path / "src"; src.mkdir(); (src / "p").mkdir()
    ok, _ = bi.build_image(t, src, "bench-aflpp/x-arvo-1")
    assert ok
    expected = f"{bi.DEFINITION_LABEL}={bi.definition_hash(t)}"
    assert expected in seen["cmd"]
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_prework_build.py -q`
Expected: 3 failures, `ImportError`/`TypeError` on the new names.

- [ ] **Step 3: Implement** in `prework/build_image.py`: the three constants; `definition_hash` = sha256 over, in the fixed order `DEFINITION_FILES` then `PIN_FILES`, the bytes `name + b"\0" + (sha256(file bytes).hexdigest() if present else "absent") + b"\n"`; `build_docker_command` gains `labels`; `build_image` computes `definition_hash(target_dir)` and passes `labels={DEFINITION_LABEL: h}`.

- [ ] **Step 4: Run the file's tests to verify they pass**

Run: `python3 -m pytest tests/test_prework_build.py tests/test_prework_build_integration.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add prework/build_image.py tests/test_prework_build.py
git commit -m "prework: stamp each target image with a hash of its definition"
```

---

### Task 2: Bootstrap reports stale and unverified images and rebuilds them

**Files:**
- Modify: `bootstrap_server.py` (`check_images`, `build_target_images`, `report`, `main`)
- Create: `tests/test_bootstrap_images.py`

**Interfaces:**
- Consumes: `prework.build_image.image_tag`, `definition_hash`, `DEFINITION_LABEL` (Task 1).
- Produces: `STALE = "STALE"`, `UNVERIFIED = "UNVERIFIED"`; `image_definition_label(image: str) -> str | None` (docker inspect of `.Config.Labels`); `image_state(tag: str, target_dir: Path, *, exists=_image_exists, label=image_definition_label) -> str` returning one of `OK`, `STALE`, `UNVERIFIED`, `MISSING`; `check_images() -> list[tuple[str, str, str]]` rows named by the lowercase tag; `build_target_images(work: str, *, rebuild_unverified: bool = False)`; CLI flag `--rebuild-unverified`.

- [ ] **Step 1: Write the failing tests** in `tests/test_bootstrap_images.py`

```python
import json
from pathlib import Path
import bootstrap_server as bs
from prework.build_image import DEFINITION_LABEL, definition_hash

def _target(tmp_path, project="PcapPlusPlus", arvo_id=22232):
    t = tmp_path / f"{project}-arvo-{arvo_id}"; t.mkdir()
    (t / "Dockerfile").write_text("FROM x\n")
    (t / "meta.json").write_text(json.dumps({"project": project, "arvo_id": arvo_id}))
    return t

def test_check_images_uses_the_lowercase_tag(tmp_path, monkeypatch):
    t = _target(tmp_path)
    monkeypatch.setattr(bs, "TARGETS_DIR", tmp_path)
    monkeypatch.setattr(bs, "_image_exists", lambda img: img == "bench-aflpp/pcapplusplus-arvo-22232")
    monkeypatch.setattr(bs, "image_definition_label", lambda img: definition_hash(t))
    rows = bs.check_images()
    names = {r[0]: r[1] for r in rows}
    assert names["bench-aflpp/pcapplusplus-arvo-22232"] == bs.OK

def test_image_state_classifies_all_four_cases(tmp_path):
    t = _target(tmp_path)
    h = definition_hash(t)
    assert bs.image_state("x", t, exists=lambda i: False, label=lambda i: None) == bs.MISSING
    assert bs.image_state("x", t, exists=lambda i: True, label=lambda i: None) == bs.UNVERIFIED
    assert bs.image_state("x", t, exists=lambda i: True, label=lambda i: "0" * 64) == bs.STALE
    assert bs.image_state("x", t, exists=lambda i: True, label=lambda i: h) == bs.OK

def test_build_rebuilds_missing_and_stale_but_not_unverified_by_default(tmp_path, monkeypatch):
    t = _target(tmp_path)
    monkeypatch.setattr(bs, "TARGETS_DIR", tmp_path)
    built = []
    monkeypatch.setattr(bs.subprocess, "run", lambda cmd, **kw: built.append(cmd) or type("R", (), {"returncode": 0})())
    for state, expect in [(bs.MISSING, 1), (bs.STALE, 1), (bs.UNVERIFIED, 0), (bs.OK, 0)]:
        built.clear()
        monkeypatch.setattr(bs, "image_state", lambda tag, td, **kw: state)
        bs.build_target_images(str(tmp_path / "work"))
        assert len(built) == expect, state

def test_rebuild_unverified_flag_rebuilds_unlabeled_images(tmp_path, monkeypatch):
    _target(tmp_path)
    monkeypatch.setattr(bs, "TARGETS_DIR", tmp_path)
    built = []
    monkeypatch.setattr(bs.subprocess, "run", lambda cmd, **kw: built.append(cmd) or type("R", (), {"returncode": 0})())
    monkeypatch.setattr(bs, "image_state", lambda tag, td, **kw: bs.UNVERIFIED)
    bs.build_target_images(str(tmp_path / "work"), rebuild_unverified=True)
    assert len(built) == 1

def test_report_prints_a_mark_for_every_state(capsys):
    assert bs.report("t", [("a", bs.STALE, ""), ("b", bs.UNVERIFIED, "")]) is False
    out = capsys.readouterr().out
    assert "STALE" in out and "unver" in out
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_bootstrap_images.py -q`
Expected: failures on missing names (`image_state`, `STALE`, `UNVERIFIED`, `image_definition_label`).

- [ ] **Step 3: Implement** in `bootstrap_server.py`: the two constants; `image_definition_label` via `docker image inspect -f '{{index .Config.Labels "<DEFINITION_LABEL>"}}'` returning `None` for an empty string or a non-zero exit; `image_state` as specified; `check_images` builds the tag with `image_tag(meta["project"], meta["arvo_id"])`, calls `image_state`, and puts the state in the note column (`"stale: definition changed since the image was built"`, `"unverified: built before stamping; rebuild with --rebuild-unverified"`); `build_target_images` rebuilds when state is `MISSING` or `STALE`, or `UNVERIFIED` with the flag, and otherwise appends `(name, OK, "<state>")`; `report`'s mark map gains `STALE: " STALE"` and `UNVERIFIED: "unver."`; `main` gains `--rebuild-unverified`.

- [ ] **Step 4: Run tests**

Run: `python3 -m pytest tests/test_bootstrap_images.py tests/test_prework_build.py -q`
Expected: all pass. Then `python3 bootstrap_server.py --check` on this box: the 8 built images report `unver.`, PcapPlusPlus no longer reports `todo`.

- [ ] **Step 5: Commit**

```bash
git add bootstrap_server.py tests/test_bootstrap_images.py
git commit -m "bootstrap: report stale and unverified prework images, rebuild them on request"
```

---

### Task 3: Profiler library supply ignores glibc copies in /out

**Files:**
- Modify: `skills/profile-once-fuzz-folds/scripts/target_libs.py` (`VERSION`, `probe_files`, `prepare`, module doc)
- Test: `tests/test_profile_target_libs.py`

**Interfaces:**
- Produces: `VERSION = 3`; `libc_in_out(out_dir) -> list[str]` (container paths, sorted, of ELF shared libraries anywhere under `/out` whose basename matches `is_libc_family`); `probe_files` unchanged in signature, its `sos` list no longer contains those paths; the `prepare` record and return gain `"ignored_libc_out": [container paths]`.

- [ ] **Step 1: Write the failing tests** in `tests/test_profile_target_libs.py` (use the file's existing `out` fixture and the fake-probe pattern of `test_an_out_library_its_own_image_cannot_load_is_skipped`)

```python
def test_glibc_copies_in_out_are_ignored_not_required(tmp_path, out, monkeypatch):
    # /out/libc.so.6, /out/librt.so.1 and /out/cmplog/libpthread.so.0 as ELF files
    ...
    main, sos = tl.probe_files(out, "t")
    assert not any(tl.is_libc_family(p) for p in sos)
    assert tl.libc_in_out(out) == ["/out/cmplog/libpthread.so.0", "/out/libc.so.6", "/out/librt.so.1"]
    res = tl.prepare(...)   # fake probes resolve everything the target needs
    assert res["ignored_libc_out"] == ["/out/cmplog/libpthread.so.0", "/out/libc.so.6", "/out/librt.so.1"]

def test_a_non_glibc_out_library_the_profiler_cannot_load_still_fails(tmp_path, out, monkeypatch):
    # /out/libc.so.6 present AND /out/libfoo.so.1 whose profiler ldd reports "not found"
    with pytest.raises(tl.TargetLibsError, match="libfoo"):
        tl.prepare(...)

def test_a_record_from_the_previous_policy_version_is_not_reused(tmp_path, out, monkeypatch):
    # write <libs_dir>/target_libs.json with "key" computed under VERSION=2 (monkeypatch tl.VERSION, call tl.cache_key, restore)
    res = tl.prepare(...)
    assert res["cached"] is False
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_profile_target_libs.py -q -k "glibc or previous_policy or non_glibc"`
Expected: `AttributeError: libc_in_out` / `KeyError: ignored_libc_out`.

- [ ] **Step 3: Implement** in `target_libs.py`: `libc_in_out`; `probe_files` filters `is_libc_family(n)` out of `sos` (keeping the ELF check); `prepare` computes `ignored = libc_in_out(out_dir)` and writes it to the record as `ignored_libc_out`; `VERSION = 3`; add to the module doc the sentence "glibc and loader-family files found under /out are ignored: the module never supplies them and the trials' target image resolves them from its own system path (PcapPlusPlus's historical build.sh copies them into $OUT)". Update any exact-record assertion in the test file (the dict near `"skipped_out_libs": {}`) to include the new key.

- [ ] **Step 4: Run the whole file and the two consumers**

Run: `python3 -m pytest tests/test_profile_target_libs.py tests/test_replay_fuzzer_profile.py tests/test_hotspot_table.py -q`
Expected: all pass.

- [ ] **Step 5: Auditor checks (recorded in the task report):** (a) `grep -rn "ldd\|libc.so\|lib/x86_64" prework/fuzzbench/*/build.sh prework/fuzzbench/*/Dockerfile` shows no FuzzBench benchmark copying glibc into `$OUT`; (b) `hotspot_table.py` attributes samples by the DSO path perf reports, so a `/out/libc.so.6` the process never maps cannot receive samples.

- [ ] **Step 6: Commit**

```bash
git add skills/profile-once-fuzz-folds/scripts/target_libs.py tests/test_profile_target_libs.py
git commit -m "profile: ignore glibc copies in /out instead of refusing the target"
```

---

### Task 4: Bring the corpus and replay-timing tests up to the current script contracts

**Files:**
- Test: `tests/test_build_corpus.py` (4 failing tests), `tests/test_replay_timing.py::test_measure_binary_raises_on_failed_run`
- Reference: `skills/profile-once-fuzz-folds/scripts/build_corpus.py:127` (`build_crash_filter_command`), `:373-396` (`replay_budget_secs`), `skills/profile-once-fuzz-folds/scripts/replay_timing.py` (`measure_binary`)

**Interfaces:**
- Consumes: the scripts' current signatures; nothing produced.

- [ ] **Step 1: Run the five tests and read each failure**

Run: `python3 -m pytest tests/test_build_corpus.py tests/test_replay_timing.py -q --tb=short`
Expected: `TypeError ... unexpected keyword argument 'cpu'`, three `AttributeError: ... 'replay_budget_secs'`, one `StopIteration`.

- [ ] **Step 2: For each, confirm the script is right** by reading the call site that the online path uses (`phase2_setup.py` and `phase3_online.py` callers of `build_crash_filter_command`, `run_build_corpus`, `measure_binary`). If a caller still passes the old argument, that is a production bug: fix the caller and say so in the report.

- [ ] **Step 3: Update the tests** to the current contracts: drop/rename `cpu=` as the script now spells it; add `replay_budget_secs` (and `replay_repeats` if the namespace builder lacks it) to the `SimpleNamespace` factory with the script's defaults; give `measure_binary`'s fake clock enough values (`itertools.count(0.0, 1.0).__next__`). Keep every assertion's intent.

- [ ] **Step 4: Run the two files**

Run: `python3 -m pytest tests/test_build_corpus.py tests/test_replay_timing.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add tests/test_build_corpus.py tests/test_replay_timing.py
git commit -m "tests: follow the current build_corpus and replay_timing contracts"
```

---

### Task 5: Bring the sandbox tests up to the current contracts; skip the topology test on small hosts

**Files:**
- Test: `tests/test_sandbox_egress.py` (6), `tests/test_sandbox_launch.py::test_agent_tools_speak_the_broker_protocol`, `tests/test_sandbox_session.py::test_agent_cpus_on_the_real_topology_avoid_trial_and_profile_cores`
- Reference: `sandbox/egress.py:238` (`CREDENTIAL_LOCK`), `:191` (`seed_store`), `:867` (`stage_credentials`); `sandbox/broker.py` `serve` and the reply shape; `sandbox/agent_tools/_client.py`

- [ ] **Step 1: Run the eight tests and read each failure**

Run: `python3 -m pytest tests/test_sandbox_egress.py tests/test_sandbox_launch.py tests/test_sandbox_session.py -q --tb=short`
Expected: five `FileNotFoundError ... .sandbox-creds/.refresh.lock`, one `KeyError: 'claude'`, one `malformed broker reply`, one `RuntimeError: no physical core is free`.

- [ ] **Step 2: Egress.** Determine why the lock path is the real repo store (`CREDENTIAL_STORE`) rather than the test's tmp dir: the tests must redirect `CREDENTIAL_STORE` and `CREDENTIAL_LOCK` together (one fixture). `KeyError: 'claude'` means `CREDENTIAL_FILES` is keyed differently than the test assumes; read `egress.py:67` and use the current keys. If any test shows the production code writing to the host store, that is a bug: fix the code and report it.

- [ ] **Step 3: Broker protocol.** Run the real `fold-replay-time` against `b.serve` as the test does and capture the raw reply bytes. The reply is either not JSON (a code bug in `serve`'s error path) or the request now needs a field the tool omits. Fix whichever side is wrong; the agent tools are the agent's only interface, so a contract break here is a production bug and must be fixed in code.

- [ ] **Step 4: Topology.** In the session test, after `sib = thread_siblings()`, skip when the trial and profile layout (`parse_cpuset("2-31")` expanded through `sib`) leaves no physical core free: `pytest.skip("host cannot hold the 2-31 trial/profile layout")`. Keep the HT80 assertion for the big box.

- [ ] **Step 5: Run the three files**

Run: `python3 -m pytest tests/test_sandbox_egress.py tests/test_sandbox_launch.py tests/test_sandbox_session.py -q`
Expected: all pass except one skip on this box.

- [ ] **Step 6: Commit** (one commit; two if a production fix was needed, the code fix first)

```bash
git add tests/test_sandbox_egress.py tests/test_sandbox_launch.py tests/test_sandbox_session.py
git commit -m "tests: follow the current credential store and broker contracts; skip the 80-core topology case elsewhere"
```

---

### Task 6: Re-stamp every image on this box and re-validate the two failed targets (box work)

**Files:** none changed. Logs to the session scratchpad.

**Interfaces:**
- Consumes: Task 2's `--rebuild-unverified`; Task 3's policy.

- [ ] **Step 1: Wait** until `.smoke-arvo-libxml2-20261101-2208.log` contains `=== Benchmark Complete ===` and `docker ps` shows only `bench-egress-proxy`.

- [ ] **Step 2: Re-stamp**

Run: `python3 bootstrap_server.py --rebuild-unverified --work <scratch>/prework_work 2>&1 | tee <scratch>/restamp.log`
Expected: every target line `ok`; afterwards `python3 bootstrap_server.py --check` lists the 8 built images as `ok` and the 6 unbuilt ones as `todo`. Any `dropped_bug_gone` result is recorded for the doc and the target is removed from the "works" set.

- [ ] **Step 3: Preflight the two previously failed targets**

Run: `python3 tools/preflight_online.py --project PcapPlusPlus --cpu 3 --build-cpus 2-19 --smoke-secs 120` and the same for `freeradius-server`.
Expected: both `READY`; PcapPlusPlus's `profile` stage reason names a non-zero target DSO share.

- [ ] **Step 4: Preflight the other six once more** on the re-stamped images (same command). Expected: all `READY`. Record each `preflight_<project>.json` path.

---

### Task 7: Evaluate the smoke campaign and rerun it on the final code

**Files:** none changed unless the campaign reveals an online-path bug (then: a new task is appended to this plan with the same structure as Tasks 1-5).

- [ ] **Step 1: Evaluate the first campaign** (`smoke-arvo-libxml2-20261101-2208`) against the spec's W2 criteria:

Run:
```bash
L=.smoke-arvo-libxml2-20261101-2208.log
grep -c "=== Benchmark Complete ===" $L; grep -c "outcome=" $L
grep -c -E "Traceback|prebuild error|weekly limit" $L
for f in results/smoke-arvo-libxml2-20261101-2208/libxml2-arvo-1972/*/trials/*/afl_out/default/fuzzer_stats results/smoke-arvo-libxml2-20261101-2208/libxml2-arvo-1972/*/*/afl_out/default/fuzzer_stats; do [ -s "$f" ] && echo "ok $f" || echo "EMPTY $f"; done
docker ps --format '{{.Names}}'
```
Expected: `1`, `>= 1`, `0`, every stats file `ok`, only `bench-egress-proxy`.

- [ ] **Step 2: Classify any failure.** Account-side (`weekly limit`, `Not logged in`, `Response stalled`): relaunch once, same command. Online-path: append a task, implement and audit it, then continue.

- [ ] **Step 3: Rerun on the final code** (required: Task 3 changes a script every round runs), after Task 6 and after any appended task:

Run: `TRIALS=2 TRIAL_CORES=4-7 OPT_CORES=2-3 SETUP_CPU=2 SETUP_BUILD_CPUS=2-19 DURATION=7200 INTERVAL=300 OPT_TIMEOUT=2700 EXP_PREFIX=smoke-arvo-final BENCHMARK_CLAUDE_MODEL=claude-sonnet-5-5 ./run_online_pertrial.sh libxml2`
Expected: the Step 1 checks pass for the new experiment id.

---

### Task 8: FuzzBench non-regression

**Files:** none changed.

- [ ] **Step 1: Full suite**

Run: `python3 -m pytest -q -p no:cacheprovider 2>&1 | tail -15`
Expected: failures are exactly `tests/test_phase3_k8s_images.py` (1), `tests/test_phase3_k8s_runner.py` (2), `tests/test_run_hotspotdiff.py` (1); every `tests/test_fuzzbench_*` and `tests/test_fb_ccache.py` test passes.

- [ ] **Step 2: FuzzBench preflight** (box idle; after Task 7)

Run: `BENCHMARK_MANIFEST_PATH=$PWD/data/manifests/manifest_fuzzbench_list1.json python3 tools/preflight_online.py --project libxml2 --cpu 3 --build-cpus 2-19 --smoke-secs 120`
Expected: `READY`, image `fb-aflpp/libxml2_xml_e85b9b`, `aflbuild` reported as `fuzzbench: built at extract`.

---

### Task 9: Write `docs/ARVO_REVALIDATION.md`

**Files:**
- Create: `docs/ARVO_REVALIDATION.md`

- [ ] **Step 1: Write the doc** with these sections, in this order: Purpose (one paragraph); What was broken (findings 1-3 from the spec, with the evidence commands); What changed (one line per commit on this plan, with the commit hash); How to run an ARVO target on this box (the exact preflight command, the exact smoke command, the exact `bootstrap_server.py --check` reading); Per-target verdicts (table: target, image hash state, preflight verdict, notes); Dropped targets and why (or "none"); Known remaining test failures (the four, with why they are left); Campaign record (experiment ids, pass-criteria readings, where the logs live).

- [ ] **Step 2: Check every command in the doc runs** as written from the repo root (dry: `bash -n` is not enough; run the `--check` and the two `grep` readings).

- [ ] **Step 3: Commit**

```bash
git add docs/ARVO_REVALIDATION.md
git commit -m "docs: how the ARVO targets were revalidated on the current pipeline"
```

---

### Task 10: Profiler library supply honors /out subdirectories (campaign finding, user-approved 2026-11-02)

**Why:** freeradius-server's historical `build.sh` copies `libfreeradius-*`, `libtalloc.so.2` and `libkqueue.so.0` into `/out/lib` and sets the fuzzer's RUNPATH to `$ORIGIN/lib`. In the target image the fuzzer resolves them from `/out/lib`, so `prepare` classifies them `from_out` and appends bare `/out` to the profiler path. The step-3 re-check then probes `/out/lib/libfreeradius-util.so` standalone (no RUNPATH context), where `libtalloc.so.2`/`libkqueue.so.0` read as unresolved because `/out/lib` is not on the path, and the profile is refused although the real process loads fine (verified: with `/out/lib` on the path both resolve inside the profiler image).

**Files:**
- Modify: `skills/profile-once-fuzz-folds/scripts/target_libs.py` (`VERSION`, `ld_library_path`, `prepare`, module doc)
- Modify: `skills/profile-once-fuzz-folds/scripts/replay_fuzzer_profile.py:503-504` only if the status key set must carry `out_dirs` (optional; see step 3)
- Test: `tests/test_profile_target_libs.py`

**Interfaces:**
- Consumes: the record keys from Task 3 (`ignored_libc_out`), `resolved` (name -> path in the target image), `from_out`.
- Produces: `VERSION = 4`; `ld_library_path(base_ld_path: str, *, libs: bool, out_dirs: list[str]) -> str` (replaces the `append_out: bool` keyword; the path is `[TARGET_LIBS_MOUNT if libs] + [base_ld_path if set] + out_dirs`); record gains `"out_dirs": [container directories, sorted]` = `sorted({posixpath.dirname(resolved[n]) for n in from_out})`; `append_out` stays in the record as `bool(out_dirs)`; `out_libs` unchanged.

- [ ] **Step 1: Write the failing tests** (use the file's `out` fixture and fake-probe pattern; the existing test at the `"/opt/oss-libs:/out"` assertion is the root-level reference)

```python
def test_libraries_found_in_an_out_subdirectory_put_that_directory_on_the_path(tmp_path, out, monkeypatch):
    # /out/t NEEDS libtalloc.so.2; target-image ldd resolves it to /out/lib/libtalloc.so.2 (RUNPATH);
    # /out/lib/libmod.so NEEDS libtalloc.so.2 too; profiler step 2 reports it missing for both;
    # the re-check with the final path resolves it from /out/lib.
    res = tl.prepare(...)
    assert res["out_dirs"] == ["/out/lib"]
    assert res["append_out"] is True
    assert res["ld_library_path"] == "/opt/oss-libs:/out/lib"
    # the re-check probe ran with /out/lib on its LD_LIBRARY_PATH
    assert any("/out/lib" in r[-1] for r in fake.runs)

def test_root_level_out_libraries_keep_the_previous_path(tmp_path, out, monkeypatch):
    # same shape as the existing "/opt/oss-libs:/out" test: from_out resolved at /out/libbuild.so
    res = tl.prepare(...)
    assert res["out_dirs"] == ["/out"] and res["ld_library_path"] == "/opt/oss-libs:/out"

def test_a_record_from_policy_version_3_is_not_reused(tmp_path, out, monkeypatch):
    # key computed with VERSION monkeypatched to 3 -> prepare returns cached False
```

- [ ] **Step 2: Run them to verify they fail**

Run: `python3 -m pytest tests/test_profile_target_libs.py -q -k "subdirectory or root_level or version_3"`
Expected: `TypeError` (unexpected keyword `out_dirs`) / `KeyError: out_dirs`.

- [ ] **Step 3: Implement**: `VERSION = 4`; `ld_library_path` takes `out_dirs`; in `prepare`, after `from_out` is known, `out_dirs = sorted({posixpath.dirname(resolved[n]) for n in from_out})`, pass `out_dirs=out_dirs` to `ld_library_path`, write `"out_dirs": out_dirs` and `"append_out": bool(out_dirs)` into the record. Update the existing call sites and the exact-record assertions in the test file. Module doc: in the step-3 sentence replace "and /out if a build library is found only through it" with "and the /out directories a build library was found in (bare /out for root-level libraries, /out/lib for a build that copies its libraries there with an $ORIGIN/lib RUNPATH)". `replay_fuzzer_profile.py` keeps reading `ld_library_path`/`append_out` unchanged; add `out_dirs` to its copied key set only if the auditor asks.

- [ ] **Step 4: Run the file and its consumers**

Run: `python3 -m pytest tests/test_profile_target_libs.py tests/test_replay_fuzzer_profile.py tests/test_hotspot_table.py -q`
Expected: all pass; then the full suite once (4 failed baseline must not grow).

- [ ] **Step 5: Auditor checks:** (a) for every existing test fixture and for FuzzBench's known /out layouts (php `modules/*.so`, systemd `src/shared/*.so`), state whether `out_dirs` differs from `["/out"]` and what that changes; (b) the re-check still fails for a subdirectory module whose dependency exists nowhere (no false positive introduced).

- [ ] **Step 6: Commit**

```bash
git add skills/profile-once-fuzz-folds/scripts/target_libs.py tests/test_profile_target_libs.py
git commit -m "profile: put the /out directories build libraries were found in on the profiler path"
```

- [ ] **Step 7 (controller, box):** `python3 tools/preflight_online.py --project freeradius-server --cpu 3 --build-cpus 2-19 --smoke-secs 120` must report READY; rerun libxml2's preflight once to show an unchanged `ld_library_path` for a root-level target.
