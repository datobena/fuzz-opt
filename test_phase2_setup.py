import json
import os
import subprocess
from pathlib import Path
from subprocess import TimeoutExpired

import pytest

import phase2_setup


def test_make_phase2_profile_env_uses_seed_corpus_profiles_and_reserved_cpu(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(phase2_setup.config, "RESERVED_CORES", 4)
    monkeypatch.setattr(
        phase2_setup.config, "PHASE2_CORPUS_BUILD_DURATION_SECS", 3600
    )

    experiment_dir = tmp_path / "results" / "exp" / "demo-CVE-1"
    diff_dir = experiment_dir / "optimized" / "source_diff"
    out_dir = tmp_path / "build" / "out" / "demo_opt"

    env = phase2_setup._make_phase2_profile_env(
        experiment_dir=experiment_dir,
        diff_output_dir=diff_dir,
        out_dir=out_dir,
    )

    assert env["FUZZ_SOURCE_FOLDS_CORPUS_DIR"] == str(
        experiment_dir / "seed_corpus" / "merged"
    )
    assert env["FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR"] == str(
        diff_dir / "profiles"
    )
    assert env["FUZZ_SOURCE_FOLDS_OUT_DIR"] == str(out_dir)
    assert env["FUZZ_SOURCE_FOLDS_CORPUS_BUILD_DURATION"] == "3600"
    assert env["FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR"] == str(
        diff_dir / "profiles" / "fixed_corpus"
    )
    assert env["FUZZ_SOURCE_FOLDS_PROFILE_CPU"] == "3"
    # The old evolving-corpus / refresh-profile wiring is gone in this loop.
    assert "FUZZ_SOURCE_FOLDS_EVOLVING_CORPUS_DIR" not in env
    assert "FUZZ_SOURCE_FOLDS_REFRESH_PROFILE_DURATION" not in env


def test_make_phase2_profile_env_respects_explicit_overrides(tmp_path):
    experiment_dir = tmp_path / "results" / "exp" / "demo-CVE-2"
    diff_dir = experiment_dir / "optimized" / "source_diff"
    out_dir = tmp_path / "build" / "out" / "demo_opt"

    env = phase2_setup._make_phase2_profile_env(
        experiment_dir=experiment_dir,
        diff_output_dir=diff_dir,
        out_dir=out_dir,
        profile_cpu=1,
        corpus_build_duration=1800,
    )

    assert env["FUZZ_SOURCE_FOLDS_PROFILE_CPU"] == "1"
    assert env["FUZZ_SOURCE_FOLDS_CORPUS_BUILD_DURATION"] == "1800"


def test_make_phase2_profile_env_sets_fixed_corpus_and_replay(tmp_path):
    experiment_dir = tmp_path / "results" / "exp" / "demo-CVE-3"
    diff_dir = experiment_dir / "optimized" / "source_diff"
    out_dir = tmp_path / "build" / "out" / "demo_opt"
    baseline_out = experiment_dir / "baseline" / "bin"

    env = phase2_setup._make_phase2_profile_env(
        experiment_dir=experiment_dir,
        diff_output_dir=diff_dir,
        out_dir=out_dir,
        baseline_out_dir=baseline_out,
    )

    # Fixed corpus snapshot lives under the profiles dir and is built once.
    assert env["FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR"] == str(
        diff_dir / "profiles" / "fixed_corpus"
    )
    assert "FUZZ_SOURCE_FOLDS_EVOLVING_CORPUS_DIR" not in env
    # Baseline binary is exposed for the replay-timing acceptance gate.
    assert env["FUZZ_SOURCE_FOLDS_BASELINE_OUT_DIR"] == str(baseline_out)
    assert "FUZZ_SOURCE_FOLDS_REPLAY_REPEATS" in env


def test_make_phase2_profile_env_omits_baseline_out_when_absent(tmp_path):
    env = phase2_setup._make_phase2_profile_env(
        experiment_dir=tmp_path / "exp",
        diff_output_dir=tmp_path / "diff",
        out_dir=tmp_path / "out",
    )
    assert "FUZZ_SOURCE_FOLDS_BASELINE_OUT_DIR" not in env


def test_phase2_corpus_source_bundled_only_no_gcs(tmp_path):
    # Policy: ONLY the seed corpus provided with the project (bundled), never GCS.
    #   seed_corpus/build -> bundled <target>_seed_corpus.zip -> local cache.
    import zipfile as _zip
    ed = tmp_path / "exp"
    entry = {"project": "p", "cve": "C", "fuzz_target": "demo_fuzzer"}

    # nothing usable -> merged fallback, duration 0 (no fuzz-generate anymore)
    (ed / "seed_corpus" / "merged").mkdir(parents=True, exist_ok=True)
    cdir, dur = phase2_setup._phase2_corpus_source(ed, entry)
    assert dur == 0 and Path(cdir).name == "merged"

    # bundled zip in baseline/bin -> extract to 'bundled', no grow
    bb = ed / "baseline" / "bin"
    bb.mkdir(parents=True, exist_ok=True)
    with _zip.ZipFile(bb / "demo_fuzzer_seed_corpus.zip", "w") as zf:
        zf.writestr("s0", "a")
        zf.writestr("s1", "b")
    cdir, dur = phase2_setup._phase2_corpus_source(ed, entry)
    assert dur == 0 and Path(cdir).name == "bundled"
    assert sum(1 for _ in Path(cdir).iterdir()) == 2

    # seed_corpus/build (the shipped default seed corpus) wins over the zip
    build = ed / "seed_corpus" / "build"
    build.mkdir(parents=True, exist_ok=True)
    (build / "b0").write_text("x")
    cdir, dur = phase2_setup._phase2_corpus_source(ed, entry)
    assert dur == 0 and Path(cdir).name == "build"

    # GCS present must be IGNORED now -> still 'build'
    gcs = ed / "seed_corpus" / "gcs"
    gcs.mkdir(parents=True, exist_ok=True)
    (gcs / "g0").write_text("x")
    cdir, dur = phase2_setup._phase2_corpus_source(ed, entry)
    assert dur == 0 and Path(cdir).name == "build"


def test_make_phase2_profile_env_adds_mutation_image_for_arvo_entry(monkeypatch, tmp_path):
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MUTATION_ENABLED", True)
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MUTATION_CAP", 40000)
    ed = tmp_path / "results" / "exp" / "selinux-CVE-1"
    diff_dir = ed / "optimized" / "source_diff"

    # ARVO reproducer entry (local_id) -> gcr.io/oss-fuzz/<id> + `compile`
    env = phase2_setup._make_phase2_profile_env(
        experiment_dir=ed, diff_output_dir=diff_dir, out_dir=tmp_path / "o",
        entry={"project": "selinux", "cve": "CVE-1", "fuzz_target": "t",
               "local_id": 42493454},
    )
    assert env["FUZZ_SOURCE_FOLDS_MUTATION_IMAGE"] == "gcr.io/oss-fuzz/42493454"
    assert env["FUZZ_SOURCE_FOLDS_MUTATION_COMPILE_CMD"] == "compile"
    assert env["FUZZ_SOURCE_FOLDS_MUTATION_CAP"] == "40000"

    # n132 image entry -> `arvo compile`
    env2 = phase2_setup._make_phase2_profile_env(
        experiment_dir=ed, diff_output_dir=diff_dir, out_dir=tmp_path / "o",
        entry={"project": "p", "cve": "C", "fuzz_target": "t",
               "image": "n132/arvo:10222-vul"},
    )
    assert env2["FUZZ_SOURCE_FOLDS_MUTATION_IMAGE"] == "n132/arvo:10222-vul"
    assert env2["FUZZ_SOURCE_FOLDS_MUTATION_COMPILE_CMD"] == "arvo compile"

    # OSV entry (no local_id/image) -> seed-only, no mutation image
    env3 = phase2_setup._make_phase2_profile_env(
        experiment_dir=ed, diff_output_dir=diff_dir, out_dir=tmp_path / "o",
        entry={"project": "p", "cve": "C", "fuzz_target": "t"},
    )
    assert "FUZZ_SOURCE_FOLDS_MUTATION_IMAGE" not in env3

    # feature flag off -> no mutation image even for ARVO
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MUTATION_ENABLED", False)
    env4 = phase2_setup._make_phase2_profile_env(
        experiment_dir=ed, diff_output_dir=diff_dir, out_dir=tmp_path / "o",
        entry={"project": "p", "cve": "C", "fuzz_target": "t", "local_id": 1},
    )
    assert "FUZZ_SOURCE_FOLDS_MUTATION_IMAGE" not in env4


def test_augment_corpus_with_mutations_combines_seed_and_mutations(monkeypatch, tmp_path):
    import mutation_capture
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "s0").write_text("a")
    (seed / "s1").write_text("b")
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    env = {
        "FUZZ_SOURCE_FOLDS_MUTATION_IMAGE": "gcr.io/oss-fuzz/1",
        "FUZZ_SOURCE_FOLDS_CORPUS_DIR": str(seed),
        "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR": str(profiles),
        "FUZZ_SOURCE_FOLDS_MUTATION_CAP": "10",
        "FUZZ_SOURCE_FOLDS_MUTATION_DURATION": "5",
    }

    def fake_capture(**kw):
        frozen = Path(kw["frozen_dir"])
        frozen.mkdir(parents=True, exist_ok=True)
        for i in range(4):
            (frozen / f"unit_{i:08d}").write_text(f"m{i}")
        return frozen, {"frozen_count": 4}

    monkeypatch.setattr(mutation_capture, "run_mutation_capture", fake_capture)
    combined = phase2_setup._augment_corpus_with_mutations(env, "t")
    assert combined is not None
    names = sorted(p.name for p in Path(combined).iterdir())
    assert sum(1 for f in names if f.startswith("seed_")) == 2
    assert sum(1 for f in names if f.startswith("mut_")) == 4
    # env CORPUS_DIR is repointed to the combined corpus for build_corpus.py
    assert env["FUZZ_SOURCE_FOLDS_CORPUS_DIR"] == combined


def test_augment_corpus_required_hard_fails_without_image(monkeypatch, tmp_path):
    # New contract: mutation-augmented profiling is required (no seed-only fall-back).
    # No ARVO builder image => hard fail, not a silent seed-only degradation.
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MUTATION_REQUIRED", True)
    env = {"FUZZ_SOURCE_FOLDS_CORPUS_DIR": str(tmp_path),
           "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR": str(tmp_path)}
    with pytest.raises(phase2_setup.MutationAugmentationError):
        phase2_setup._augment_corpus_with_mutations(env, "t")


def test_augment_corpus_required_hard_fails_on_capture_failure(monkeypatch, tmp_path):
    import mutation_capture
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MUTATION_REQUIRED", True)
    seed = tmp_path / "seed"; seed.mkdir(); (seed / "s0").write_text("a")
    profiles = tmp_path / "profiles"; profiles.mkdir()
    env = {"FUZZ_SOURCE_FOLDS_MUTATION_IMAGE": "img",
           "FUZZ_SOURCE_FOLDS_CORPUS_DIR": str(seed),
           "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR": str(profiles)}

    def boom(**kw):
        raise RuntimeError("shim build failed")

    monkeypatch.setattr(mutation_capture, "run_mutation_capture", boom)
    # required => capture failure is a hard error; NO seed-only fall-back.
    with pytest.raises(phase2_setup.MutationAugmentationError):
        phase2_setup._augment_corpus_with_mutations(env, "t")
    assert env["FUZZ_SOURCE_FOLDS_CORPUS_DIR"] == str(seed)  # not repointed


def test_augment_corpus_required_hard_fails_on_zero_mutations(monkeypatch, tmp_path):
    import mutation_capture
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MUTATION_REQUIRED", True)
    seed = tmp_path / "seed"; seed.mkdir(); (seed / "s0").write_text("a")
    profiles = tmp_path / "profiles"; profiles.mkdir()
    env = {"FUZZ_SOURCE_FOLDS_MUTATION_IMAGE": "img",
           "FUZZ_SOURCE_FOLDS_CORPUS_DIR": str(seed),
           "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR": str(profiles)}

    def empty_capture(**kw):
        frozen = Path(kw["frozen_dir"]); frozen.mkdir(parents=True, exist_ok=True)
        return frozen, {"frozen_count": 0}  # captured nothing

    monkeypatch.setattr(mutation_capture, "run_mutation_capture", empty_capture)
    with pytest.raises(phase2_setup.MutationAugmentationError):
        phase2_setup._augment_corpus_with_mutations(env, "t")


def test_augment_corpus_seed_only_when_not_required(monkeypatch, tmp_path):
    # Legacy opt-out (PHASE2_MUTATION_REQUIRED=0): failures still degrade to
    # seed-only (return None) instead of hard-failing.
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MUTATION_REQUIRED", False)
    env = {"FUZZ_SOURCE_FOLDS_CORPUS_DIR": str(tmp_path),
           "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR": str(tmp_path)}
    assert phase2_setup._augment_corpus_with_mutations(env, "t") is None


def test_run_replay_speedup_freezes_snapshot_and_compares(monkeypatch, tmp_path):
    diff_dir = tmp_path / "diff"
    experiment_dir = tmp_path / "exp"
    # Provide a fixed corpus snapshot to be frozen and replayed.
    fixed = phase2_setup._phase2_fixed_corpus_dir(diff_dir)
    fixed.mkdir(parents=True)
    (fixed / "deep_a").write_text("aaaa")
    (fixed / "deep_b").write_text("bbbb")

    captured = {}

    def fake_measure(*, out_dir, corpus_dir, fuzz_target, cpu, repeats,
                     seed, memory, shm_size, run_timeout, min_partial_units=0):
        captured.setdefault("corpus_dirs", []).append(corpus_dir)
        captured.setdefault("out_dirs", []).append(out_dir)
        # baseline slower than optimized -> speedup > 1
        median = 10.0 if "baseline" in str(out_dir) else 4.0
        return {"median_time_s": median, "times_s": [median], "repeats": repeats,
                "executed_units": 2, "partial": False}

    result = phase2_setup.run_replay_speedup(
        diff_output_dir=diff_dir,
        baseline_bin_dir=tmp_path / "baseline" / "bin",
        optimized_bin_dir=tmp_path / "optimized" / "bin",
        fuzz_target="demo_fuzzer",
        experiment_dir=experiment_dir,
        profile_cpu=2,
        repeats=3,
        measure_fn=fake_measure,
    )

    assert result["replay_speedup"] == 2.5
    assert result["corpus_source"] == "fixed"
    assert result["corpus_file_count"] == 2
    # Both binaries replayed the SAME frozen snapshot directory.
    assert len(set(captured["corpus_dirs"])) == 1
    snapshot = Path(captured["corpus_dirs"][0])
    assert snapshot == diff_dir / "profiles" / "replay_snapshot"
    assert sorted(p.name for p in snapshot.iterdir()) == [
        "unit_00000000", "unit_00000001",
    ]


def test_download_seed_corpus_falls_back_to_local_cache(monkeypatch, tmp_path):
    # No GCS (403), no build corpus, no local_id -> the local corpus cache
    # should be merged in as the seed source.
    monkeypatch.setattr(phase2_setup.config, "LOCAL_CORPUS_CACHE_DIR",
                        str(tmp_path / "cache"))
    cache = tmp_path / "cache" / "demo" / "tgt"
    cache.mkdir(parents=True)
    (cache / "seed1").write_bytes(b"abc")

    monkeypatch.setattr(phase2_setup.corpus_util, "download_corpus",
                        lambda *a, **k: False)
    monkeypatch.setattr(phase2_setup.corpus_util, "collect_build_corpus",
                        lambda *a, **k: 0)
    monkeypatch.setattr(phase2_setup.corpus_util, "ensure_fallback_seed",
                        lambda d: None)

    captured = {}

    def fake_merge(srcs, dst):
        captured["srcs"] = list(srcs)
        os.makedirs(dst, exist_ok=True)
        return len(srcs)

    monkeypatch.setattr(phase2_setup.corpus_util, "merge_corpus_dirs", fake_merge)

    exp = tmp_path / "exp"
    exp.mkdir()
    # no local_id -> ARVO branch skipped
    phase2_setup.download_seed_corpus({"project": "demo", "fuzz_target": "tgt"}, str(exp))

    assert any(str(cache) == s for s in captured.get("srcs", []))


def test_run_replay_speedup_returns_none_without_corpus(tmp_path):
    result = phase2_setup.run_replay_speedup(
        diff_output_dir=tmp_path / "diff",
        baseline_bin_dir=tmp_path / "b",
        optimized_bin_dir=tmp_path / "o",
        fuzz_target="demo_fuzzer",
        experiment_dir=tmp_path / "exp",
        measure_fn=lambda **k: {"median_time_s": 1.0},
    )
    assert result is None


def test_make_apply_fuzz_source_folds_prompt_uses_skill_name():
    prompt = phase2_setup._make_apply_fuzz_source_folds_prompt("fuzz/target.cc")

    assert "$profile-once-fuzz-folds" in prompt
    assert "current directory" in prompt
    assert "fuzz/target.cc" in prompt
    assert "outer phase 2 wrapper" in prompt
    assert "do not stop" in prompt
    assert "BLOCKED_LOW_CONFIDENCE" in prompt


def test_make_retry_prompt_references_codex_skill_and_build_errors():
    prompt = phase2_setup._make_retry_prompt(
        fuzz_target="demo_fuzzer",
        build_log="line 1\nline 2\nfatal build error",
    )

    assert "demo_fuzzer" in prompt
    assert "profile-once-fuzz-folds" in prompt
    assert "Build errors:" in prompt
    assert "fatal build error" in prompt
    assert "fold-deterministic-calls" not in prompt
    assert "outer phase 2 wrapper" in prompt


def test_invoke_codex_uses_dangerous_bypass_and_model_env(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout="done",
            stderr="",
        )

    monkeypatch.setattr(phase2_setup.subprocess, "run", fake_run)
    monkeypatch.setenv("BENCHMARK_CODEX_MODEL", "gpt-5-codex")

    ok = phase2_setup._invoke_codex(
        "/tmp/src",
        "Use $apply-fuzz-source-folds. harness.cc",
        timeout=123,
        project="demo-project",
    )

    assert ok is True
    assert len(calls) == 1

    cmd, kwargs = calls[0]
    assert cmd[0] == "codex"
    assert cmd[1] == "exec"
    assert "--dangerously-bypass-approvals-and-sandbox" in cmd
    assert "--model" in cmd
    assert cmd[cmd.index("--model") + 1] == "gpt-5-codex"
    assert cmd[-1] == "Use $apply-fuzz-source-folds. harness.cc"
    assert kwargs["cwd"] == "/tmp/src"
    assert kwargs["timeout"] == 123
    assert kwargs["env"]["OSS_FUZZ_PROJECT"] == "demo-project"
    assert kwargs["env"]["FUZZ_TARGET"] == ""


def test_invoke_codex_defaults_to_no_timeout(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout="done", stderr="")

    monkeypatch.setattr(phase2_setup.subprocess, "run", fake_run)

    ok = phase2_setup._invoke_codex(
        "/tmp/src",
        "Use $apply-fuzz-source-folds. harness.cc",
        project="demo-project",
    )

    assert ok is True
    assert len(calls) == 1
    _cmd, kwargs = calls[0]
    assert kwargs["timeout"] is None


def test_invoke_codex_includes_extra_env(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout="done", stderr="")

    monkeypatch.setattr(phase2_setup.subprocess, "run", fake_run)

    ok = phase2_setup._invoke_codex(
        "/tmp/src",
        "Use $apply-fuzz-source-folds. harness.cc",
        project="demo-project",
        extra_env={
            "FUZZ_SOURCE_FOLDS_VALIDATION_MODE": "wrapper",
            "FUZZ_SOURCE_FOLDS_BUILD_COMMAND": "echo build",
        },
    )

    assert ok is True
    assert len(calls) == 1
    _cmd, kwargs = calls[0]
    assert kwargs["env"]["FUZZ_SOURCE_FOLDS_VALIDATION_MODE"] == "wrapper"
    assert kwargs["env"]["FUZZ_SOURCE_FOLDS_BUILD_COMMAND"] == "echo build"


def test_invoke_claude_capture_uses_skip_permissions_and_model_env(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout="done", stderr="")

    monkeypatch.setattr(phase2_setup.subprocess, "run", fake_run)
    monkeypatch.setenv("BENCHMARK_CLAUDE_MODEL", "claude-opus-4-8")

    result = phase2_setup._invoke_claude_capture(
        "/tmp/src",
        "Use the apply-fuzz-source-folds skill. harness.cc",
        timeout=123,
        project="demo-project",
    )

    assert result["ok"] is True
    assert len(calls) == 1
    cmd, kwargs = calls[0]
    assert cmd[0] == "claude"
    assert "-p" in cmd
    assert "--dangerously-skip-permissions" in cmd
    assert "Use the apply-fuzz-source-folds skill. harness.cc" in cmd
    assert "--model" in cmd
    assert cmd[cmd.index("--model") + 1] == "claude-opus-4-8"
    assert kwargs["cwd"] == "/tmp/src"
    assert kwargs["timeout"] == 123
    assert kwargs["env"]["OSS_FUZZ_PROJECT"] == "demo-project"
    # Claude keeps the session env vars (unlike the Codex path).
    assert "codex" not in cmd[0]


def test_invoke_agent_capture_dispatches_by_backend(monkeypatch):
    seen = {}

    monkeypatch.setattr(
        phase2_setup, "_invoke_claude_capture",
        lambda *a, **k: {"ok": True, "backend": "claude"},
    )
    monkeypatch.setattr(
        phase2_setup, "_invoke_codex_capture",
        lambda *a, **k: {"ok": True, "backend": "codex"},
    )

    assert phase2_setup._invoke_agent_capture(
        "/tmp/src", "p", backend="claude")["backend"] == "claude"
    assert phase2_setup._invoke_agent_capture(
        "/tmp/src", "p", backend="codex")["backend"] == "codex"

    # Default follows config/env.
    monkeypatch.setenv("BENCHMARK_OPTIMIZER", "claude")
    assert phase2_setup._invoke_agent_capture(
        "/tmp/src", "p")["backend"] == "claude"
    monkeypatch.setenv("BENCHMARK_OPTIMIZER", "codex")
    assert phase2_setup._invoke_agent_capture(
        "/tmp/src", "p")["backend"] == "codex"


def test_prompt_skill_mention_is_backend_aware():
    codex_prompt = phase2_setup._make_apply_fuzz_source_folds_prompt(
        "fuzz/target.cc", backend="codex")
    claude_prompt = phase2_setup._make_apply_fuzz_source_folds_prompt(
        "fuzz/target.cc", backend="claude")

    assert "$profile-once-fuzz-folds" in codex_prompt
    assert "$profile-once-fuzz-folds" not in claude_prompt
    assert "the profile-once-fuzz-folds skill" in claude_prompt

    claude_retry = phase2_setup._make_retry_prompt(
        "demo_fuzzer", "fatal error", backend="claude")
    assert "$profile-once-fuzz-folds" not in claude_retry
    assert "profile-once-fuzz-folds skill" in claude_retry


def test_is_rate_limited_ignores_successful_codex_runs():
    result = subprocess.CompletedProcess(
        ["codex", "exec"],
        0,
        stdout="DONE\n",
        stderr="The previous tool mentioned a usage limit, but this run succeeded.\n"
               "tokens used\n343,115\n",
    )

    assert phase2_setup._is_rate_limited(result) is False


def test_project_workdir_from_dockerfile_handles_relative_workdir(
    monkeypatch, tmp_path
):
    dockerfile = tmp_path / "projects" / "demo" / "Dockerfile"
    dockerfile.parent.mkdir(parents=True)
    dockerfile.write_text("FROM scratch\nWORKDIR demo/subdir\n")

    monkeypatch.setattr(phase2_setup.config, "OSS_FUZZ_DIR", str(tmp_path))

    assert phase2_setup._project_workdir_from_dockerfile("demo") == "/src/demo/subdir"


def test_merge_missing_support_tree_copies_non_source_files_only(tmp_path):
    support_src = tmp_path / "support" / "fuzz"
    support_src.mkdir(parents=True)
    (support_src / "oss_fuzz_build.sh").write_text("#!/bin/bash\n")
    (support_src / "meson.build").write_text("build rules\n")
    (support_src / "jpegsave_file_fuzzer.cc").write_text("new harness\n")

    source_fuzz = tmp_path / "source" / "fuzz"
    source_fuzz.mkdir(parents=True)
    (source_fuzz / "jpegsave_file_fuzzer.cc").write_text("historical harness\n")

    copied = phase2_setup._merge_missing_support_tree(support_src, source_fuzz)

    assert (source_fuzz / "oss_fuzz_build.sh").read_text() == "#!/bin/bash\n"
    assert (source_fuzz / "meson.build").read_text() == "build rules\n"
    assert (source_fuzz / "jpegsave_file_fuzzer.cc").read_text() == "historical harness\n"
    assert copied == ["meson.build", "oss_fuzz_build.sh"]


def test_make_apply_fuzz_source_folds_prompt_mentions_wrapper_validation():
    prompt = phase2_setup._make_apply_fuzz_source_folds_prompt(
        "fuzz/target.cc",
        use_wrapper_validation=True,
    )

    assert "FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND" in prompt
    assert "FUZZ_SOURCE_FOLDS_BUILD_COMMAND" in prompt
    assert "FUZZ_SOURCE_FOLDS_SMOKE_COMMAND" in prompt
    assert "wrapper-provided external validation commands" in prompt


def test_codex_output_is_low_confidence_detects_fallback_static_scan():
    stdout = (
        "Profiler: fallback static hotspot scan only.\n"
        "Lower confidence: yes\n"
        "Internal OSS-Fuzz build: failed for a pre-existing reason.\n"
        "Two-clean-pass stop condition: reached, heuristically.\n"
    )

    assert phase2_setup._codex_output_is_low_confidence(stdout, "")
    assert not phase2_setup._codex_output_is_low_confidence(
        "Profiler: perf.\nLower confidence: no\n", ""
    )


def test_codex_output_is_low_confidence_ignores_prompt_echo_in_stderr():
    stdout = (
        "Applied `apply-fuzz-source-folds` in `aggressive` mode.\n"
        "Profiling used `perf` throughout, so this is not a "
        "fallback/lower-confidence result.\n"
    )
    stderr = (
        "user\n"
        "Treat those commands as the real historical-image build/smoke loop "
        "for this extracted tree. If they remain unusable for a pre-existing "
        "reason, output exactly BLOCKED_LOW_CONFIDENCE and stop instead of "
        "silently falling back to static-only heuristics.\n"
    )

    assert not phase2_setup._codex_output_is_low_confidence(stdout, stderr)


def test_invoke_codex_capture_timeout_is_not_success(monkeypatch):
    def fake_run(*_args, **_kwargs):
        raise TimeoutExpired(cmd=["codex", "exec"], timeout=123)

    monkeypatch.setattr(phase2_setup.subprocess, "run", fake_run)

    result = phase2_setup._invoke_codex_capture(
        "/tmp/src",
        "Use $apply-fuzz-source-folds. harness.cc",
        timeout=123,
        project="demo-project",
    )

    assert result["ok"] is False
    assert result["timed_out"] is True


def test_make_arvo_wrapper_validation_env_uses_historical_clone_container(
    tmp_path,
):
    source_root = tmp_path / "captured"
    (source_root / "src").mkdir(parents=True)
    state_root = tmp_path / "validator"

    env = phase2_setup._make_arvo_wrapper_validation_env(
        local_id=42477534,
        issue={"job_type": "libfuzzer_asan_x86_64"},
        source_dir=source_root,
        fuzz_target="demo_fuzzer",
        state_dir=state_root,
    )

    build_cmd = env["FUZZ_SOURCE_FOLDS_BUILD_COMMAND"]
    smoke_cmd = env["FUZZ_SOURCE_FOLDS_SMOKE_COMMAND"]
    validate_cmd = env["FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND"]

    assert env["FUZZ_SOURCE_FOLDS_VALIDATION_MODE"] == "wrapper"
    assert "gcr.io/oss-fuzz/42477534" in build_cmd
    assert f"{state_root / 'src-clone'}:/src" in build_cmd
    assert f"{source_root / 'src'}:/src" not in build_cmd
    assert f"{state_root / 'out'}:/out" in build_cmd
    assert f"{state_root / 'work'}:/work" in build_cmd
    assert "FUZZING_ENGINE=libfuzzer" in build_cmd
    assert "SANITIZER=address" in build_cmd
    assert "gcr.io/oss-fuzz-base/base-runner" in smoke_cmd
    assert f"{state_root / 'out'}:/out:ro" in smoke_cmd
    assert "/out/demo_fuzzer" in smoke_cmd
    assert build_cmd in validate_cmd
    assert smoke_cmd in validate_cmd
    assert env["FUZZ_SOURCE_FOLDS_OUT_DIR"] == str(state_root / "out")


PROFILE_ONCE_SKILL_PATH = Path(
    "/home/sefcom/.codex/skills/profile-once-fuzz-folds/SKILL.md"
)
PROFILE_ONCE_SKILL_PATH_CLAUDE = Path(
    "/home/sefcom/.claude/skills/profile-once-fuzz-folds/SKILL.md"
)
PROFILE_ONCE_SCRIPTS_DIRS = (
    Path("/home/sefcom/.codex/skills/profile-once-fuzz-folds/scripts"),
    Path("/home/sefcom/.claude/skills/profile-once-fuzz-folds/scripts"),
)


def test_profile_once_skill_documents_wrapper_validation():
    text = PROFILE_ONCE_SKILL_PATH.read_text()

    assert "FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND" in text
    assert "FUZZ_SOURCE_FOLDS_BUILD_COMMAND" in text
    assert "FUZZ_SOURCE_FOLDS_SMOKE_COMMAND" in text
    assert "wrapper-provided" in text


def test_profile_once_skill_does_not_document_claude_fallback():
    text = PROFILE_ONCE_SKILL_PATH.read_text()

    assert "../apply-fold-steps/scripts/invoke_fold_step.py" not in text
    assert "Treat Claude-reported source-file candidates exactly like Codex-found candidates" not in text
    assert "both Codex and Claude" not in text
    assert "Claude second-opinion" not in text


def test_profile_once_skill_does_not_document_codex_timeout_or_turn_cap():
    text = PROFILE_ONCE_SKILL_PATH.read_text()

    assert "APPLY_FOLD_STEPS_CODEX_TIMEOUT" not in text
    assert "APPLY_FOLD_STEPS_CODEX_MAX_TURNS" not in text


def test_profile_once_skill_documents_corpus_build_and_profile_env():
    text = PROFILE_ONCE_SKILL_PATH.read_text()

    assert "FUZZ_SOURCE_FOLDS_CORPUS_DIR" in text
    assert "FUZZ_SOURCE_FOLDS_PROFILE_CPU" in text
    assert "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR" in text
    assert "FUZZ_SOURCE_FOLDS_CORPUS_BUILD_DURATION" in text
    assert "FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR" in text


def test_profile_once_skill_documents_profile_once_loop():
    text = PROFILE_ONCE_SKILL_PATH.read_text()
    low = text.lower()

    assert "fixed corpus" in low
    assert "replay" in low
    assert "cumulative speedup" in low
    assert "previous best" in low
    assert "re-profile" in low  # appears as "do not re-profile"
    # The old always-on baseline-profile + refresh loop is not operative here.
    assert "Run one long baseline profile" not in text


def test_profile_once_skill_trees_are_identical():
    assert (
        PROFILE_ONCE_SKILL_PATH.read_text()
        == PROFILE_ONCE_SKILL_PATH_CLAUDE.read_text()
    )


def test_profile_once_skill_scripts_are_self_contained():
    # PHASE2_SKILL_SCRIPTS_DIR points here; the benchmark loads replay_timing.py
    # from this dir, and the new profiler imports real_fuzzer_profile from it.
    for scripts in PROFILE_ONCE_SCRIPTS_DIRS:
        assert (scripts / "replay_timing.py").is_file()
        assert (scripts / "verify_source_only_changes.py").is_file()
        assert (scripts / "phase2_build_check.py").is_file()
        assert (scripts / "real_fuzzer_profile.py").is_file()
        assert (scripts / "replay_fuzzer_profile.py").is_file()
        assert (scripts / "build_corpus.py").is_file()


def test_setup_cve_arvo_downloads_seed_corpus_before_optimize(
    monkeypatch, tmp_path
):
    call_order = []

    class FakeArvo:
        def __init__(self, source_root):
            self.source_root = source_root

        def fetch_arvo_issue(self, _local_id):
            return {"id": 1}

        def get_arvo_fuzz_target(self, _issue):
            return "demo_fuzzer"

        def get_arvo_crash_type(self, _issue):
            return "crash"

        def download_arvo_poc(self, _issue, poc_dir):
            poc_path = Path(poc_dir) / "poc"
            poc_path.parent.mkdir(parents=True, exist_ok=True)
            poc_path.write_text("poc")
            return poc_path

        def build_arvo_with_source_intercept(self, _local_id, _issue):
            return self.source_root

    source_root = tmp_path / "captured"
    harness = source_root / "src" / "libvips" / "fuzz" / "demo_fuzzer.cc"
    harness.parent.mkdir(parents=True, exist_ok=True)
    harness.write_text("int main() { return 0; }\n")

    monkeypatch.setattr(phase2_setup.config, "RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.setattr(
        phase2_setup, "_lazy_import_arvo", lambda: FakeArvo(source_root)
    )

    def fake_copy_arvo_output(_local_id, bin_dir):
        Path(bin_dir).mkdir(parents=True, exist_ok=True)
        (Path(bin_dir) / "demo_fuzzer").write_text("binary")
        return True

    def fake_download_seed_corpus(entry, experiment_dir):
        call_order.append("download")
        merged = Path(experiment_dir) / "seed_corpus" / "merged"
        merged.mkdir(parents=True, exist_ok=True)
        (merged / "seed").write_text("seed")
        return True

    def fake_optimize(source_dir, fuzz_target, diff_output_dir, **kwargs):
        call_order.append("optimize")
        merged = (
            tmp_path / "results" / "exp-arvo" / "libvips-CVE-TEST"
            / "seed_corpus" / "merged"
        )
        assert merged.is_dir()
        env = kwargs["codex_extra_env"]
        assert env["FUZZ_SOURCE_FOLDS_CORPUS_DIR"] == str(merged)
        # Corpus policy: a real seed corpus is used as-is (no grow) -> duration 0.
        assert env["FUZZ_SOURCE_FOLDS_CORPUS_BUILD_DURATION"] == "0"
        assert "FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR" in env
        assert env["FUZZ_SOURCE_FOLDS_PROFILE_CPU"] == "3"
        assert env["FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR"].endswith(
            "optimized/source_diff/profiles"
        )
        Path(diff_output_dir).mkdir(parents=True, exist_ok=True)
        (Path(diff_output_dir) / "optimization.diff").write_text("diff")
        return True

    monkeypatch.setattr(phase2_setup, "copy_arvo_output", fake_copy_arvo_output)
    monkeypatch.setattr(phase2_setup, "verify_poc_crash", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(phase2_setup, "download_seed_corpus", fake_download_seed_corpus)
    monkeypatch.setattr(phase2_setup, "optimize_and_build", fake_optimize)
    # This test exercises download-before-optimize, not the replay gate; give it a
    # passing replay speedup so the strict no-speedup gate doesn't revert the fold.
    monkeypatch.setattr(phase2_setup, "run_replay_speedup",
                        lambda **_kw: {"replay_speedup": 1.5})

    entry = {
        "project": "libvips",
        "cve": "CVE-TEST",
        "local_id": 1,
    }

    ok = phase2_setup.setup_cve_arvo(entry, "exp-arvo")

    assert ok is True
    assert call_order[:2] == ["download", "optimize"]


def test_setup_cve_osv_downloads_seed_corpus_before_optimize(
    monkeypatch, tmp_path
):
    call_order = []
    oss_fuzz_dir = tmp_path / "oss-fuzz"
    (oss_fuzz_dir / "build" / "out" / "demo_opt").mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(phase2_setup.config, "RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.setattr(phase2_setup.config, "OSS_FUZZ_DIR", str(oss_fuzz_dir))
    monkeypatch.setattr(phase2_setup, "resolve_vulnerable_commit", lambda entry: "deadbeef")
    monkeypatch.setattr(
        phase2_setup, "resolve_oss_fuzz_project_commit", lambda entry: "cafebabe"
    )
    monkeypatch.setattr(phase2_setup, "build_baseline_ossfuzz", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(phase2_setup, "restore_oss_fuzz_project", lambda *_args, **_kwargs: None)

    def fake_extract_source_from_build(_project, output_dir):
        harness = Path(output_dir) / "src" / "demo" / "fuzz" / "demo_fuzzer.cc"
        harness.parent.mkdir(parents=True, exist_ok=True)
        harness.write_text("int main() { return 0; }\n")
        return True

    def fake_download_seed_corpus(entry, experiment_dir):
        call_order.append("download")
        merged = Path(experiment_dir) / "seed_corpus" / "merged"
        merged.mkdir(parents=True, exist_ok=True)
        (merged / "seed").write_text("seed")
        return True

    def fake_optimize(source_dir, fuzz_target, diff_output_dir, **kwargs):
        call_order.append("optimize")
        merged = (
            tmp_path / "results" / "exp-osv" / "demo-CVE-TEST"
            / "seed_corpus" / "merged"
        )
        env = kwargs["codex_extra_env"]
        assert merged.is_dir()
        assert env["FUZZ_SOURCE_FOLDS_CORPUS_DIR"] == str(merged)
        assert env["FUZZ_SOURCE_FOLDS_OUT_DIR"] == str(
            oss_fuzz_dir / "build" / "out" / "demo_opt"
        )
        # Corpus policy: a real seed corpus is used as-is (no grow) -> duration 0.
        assert env["FUZZ_SOURCE_FOLDS_CORPUS_BUILD_DURATION"] == "0"
        assert "FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR" in env
        assert env["FUZZ_SOURCE_FOLDS_PROFILE_CPU"] == "3"
        Path(diff_output_dir).mkdir(parents=True, exist_ok=True)
        (Path(diff_output_dir) / "optimization.diff").write_text("diff")
        return True

    monkeypatch.setattr(phase2_setup, "extract_source_from_build", fake_extract_source_from_build)
    monkeypatch.setattr(phase2_setup, "prepare_optimized_project", lambda project: f"{project}_opt")
    monkeypatch.setattr(phase2_setup, "optimize_and_build", fake_optimize)
    monkeypatch.setattr(phase2_setup, "verify_crash_reproduction", lambda *_args, **_kwargs: {
        "baseline": True,
        "optimized": True,
    })
    monkeypatch.setattr(phase2_setup, "download_seed_corpus", fake_download_seed_corpus)
    # download-before-optimize test, not the replay gate: pass a real speedup.
    monkeypatch.setattr(phase2_setup, "run_replay_speedup",
                        lambda **_kw: {"replay_speedup": 1.5})

    entry = {
        "project": "demo",
        "cve": "CVE-TEST",
        "fuzz_target": "demo_fuzzer",
        "repo_url": "https://example.invalid/demo.git",
    }

    ok = phase2_setup.setup_cve_osv(entry, "exp-osv")

    assert ok is True
    assert call_order[:2] == ["download", "optimize"]


def test_setup_cve_arvo_fails_when_optimization_is_not_applied(
    monkeypatch, tmp_path
):
    class FakeArvo:
        def __init__(self, source_root):
            self.source_root = source_root

        def fetch_arvo_issue(self, _local_id):
            return {"id": 1}

        def get_arvo_fuzz_target(self, _issue):
            return "demo_fuzzer"

        def get_arvo_crash_type(self, _issue):
            return "crash"

        def download_arvo_poc(self, _issue, poc_dir):
            poc_path = Path(poc_dir) / "poc"
            poc_path.parent.mkdir(parents=True, exist_ok=True)
            poc_path.write_text("poc")
            return poc_path

        def build_arvo_with_source_intercept(self, _local_id, _issue):
            return self.source_root

    source_root = tmp_path / "captured"
    harness = source_root / "src" / "libvips" / "fuzz" / "demo_fuzzer.cc"
    harness.parent.mkdir(parents=True, exist_ok=True)
    harness.write_text("int main() { return 0; }\n")

    monkeypatch.setattr(phase2_setup.config, "RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.setattr(
        phase2_setup, "_lazy_import_arvo", lambda: FakeArvo(source_root)
    )

    def fake_copy_arvo_output(_local_id, bin_dir):
        Path(bin_dir).mkdir(parents=True, exist_ok=True)
        (Path(bin_dir) / "demo_fuzzer").write_text("binary")
        return True

    monkeypatch.setattr(phase2_setup, "copy_arvo_output", fake_copy_arvo_output)
    monkeypatch.setattr(phase2_setup, "verify_poc_crash", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(phase2_setup, "optimize_and_build", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(phase2_setup, "download_seed_corpus", lambda *_args, **_kwargs: True)

    entry = {
        "project": "libvips",
        "cve": "CVE-TEST",
        "local_id": 1,
    }

    ok = phase2_setup.setup_cve_arvo(entry, "exp-test")

    assert ok is False


def test_setup_cve_arvo_writes_failure_metadata_when_baseline_build_fails(
    monkeypatch, tmp_path
):
    class FakeArvo:
        def fetch_arvo_issue(self, _local_id):
            return {"id": 1}

        def get_arvo_fuzz_target(self, _issue):
            return "demo_fuzzer"

        def get_arvo_crash_type(self, _issue):
            return "crash"

        def download_arvo_poc(self, _issue, poc_dir):
            poc_path = Path(poc_dir) / "poc"
            poc_path.parent.mkdir(parents=True, exist_ok=True)
            poc_path.write_text("poc")
            return poc_path

        def build_arvo_with_source_intercept(self, _local_id, _issue):
            return None

    monkeypatch.setattr(phase2_setup.config, "RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.setattr(phase2_setup, "_lazy_import_arvo", lambda: FakeArvo())

    entry = {
        "project": "demo",
        "cve": "CVE-FAIL",
        "local_id": 1,
    }

    ok = phase2_setup.setup_cve_arvo(entry, "exp-fail")

    metadata_path = (
        tmp_path
        / "results"
        / "exp-fail"
        / "demo-CVE-FAIL"
        / "setup_metadata.json"
    )
    assert ok is False
    assert metadata_path.exists()
    metadata = json.loads(metadata_path.read_text())
    assert metadata["verification"]["baseline"] is False
    assert metadata["verification"]["optimized"] is False
    assert metadata["failure"]["stage"] == "baseline_build"
    assert "ARVO build failed" in metadata["failure"]["reason"]
    metadata_path = (
        tmp_path
        / "results"
        / "exp-test"
        / "libvips-CVE-TEST"
        / "setup_metadata.json"
    )
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text())
        assert metadata["verification"]["optimization_applied"] is False
        assert metadata["verification"]["optimized"] is False


def _bins(tmp_path, opt_content="OPTIMIZED"):
    baseline = tmp_path / "baseline" / "bin"
    optimized = tmp_path / "optimized" / "bin"
    baseline.mkdir(parents=True); optimized.mkdir(parents=True)
    (baseline / "fuzzer").write_text("BASELINE")
    (optimized / "fuzzer").write_text(opt_content)
    return baseline, optimized


def test_reject_no_replay_speedup_reverts_when_no_speedup(tmp_path, monkeypatch):
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MIN_REPLAY_SPEEDUP", 1.0)
    baseline, optimized = _bins(tmp_path)
    ready, failure = phase2_setup._reject_if_no_replay_speedup(
        project="sleuthkit", cve="arvo-24893", optimization_ready=True,
        replay={"replay_speedup": 0.999},  # no speedup (slightly slower)
        baseline_bin_dir=str(baseline), optimized_bin_dir=str(optimized))
    assert ready is False
    assert failure["stage"] == "replay_no_speedup"
    assert (optimized / "fuzzer").read_text() == "BASELINE"  # reverted


def test_reject_no_replay_speedup_reverts_when_unmeasurable(tmp_path, monkeypatch):
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MIN_REPLAY_SPEEDUP", 1.0)
    baseline, optimized = _bins(tmp_path)
    # replay None (measurement crashed, e.g. libjxl SIGSEGV) -> not worth keeping
    ready, failure = phase2_setup._reject_if_no_replay_speedup(
        project="libjxl", cve="arvo-35172", optimization_ready=True, replay=None,
        baseline_bin_dir=str(baseline), optimized_bin_dir=str(optimized))
    assert ready is False
    assert failure["stage"] == "replay_no_speedup"
    assert "unmeasurable" in failure["reason"]
    assert (optimized / "fuzzer").read_text() == "BASELINE"


def test_reject_no_replay_speedup_keeps_real_speedup(tmp_path, monkeypatch):
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MIN_REPLAY_SPEEDUP", 1.0)
    baseline, optimized = _bins(tmp_path)
    ready, failure = phase2_setup._reject_if_no_replay_speedup(
        project="yara", cve="arvo-3848", optimization_ready=True,
        replay={"replay_speedup": 1.35},
        baseline_bin_dir=str(baseline), optimized_bin_dir=str(optimized))
    assert ready is True
    assert failure is None
    assert (optimized / "fuzzer").read_text() == "OPTIMIZED"  # kept


def test_reject_no_replay_speedup_honors_margin(tmp_path, monkeypatch):
    # With a 2% margin, a 1.01x fold is not worth keeping.
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MIN_REPLAY_SPEEDUP", 1.02)
    baseline, optimized = _bins(tmp_path)
    ready, failure = phase2_setup._reject_if_no_replay_speedup(
        project="p", cve="c", optimization_ready=True,
        replay={"replay_speedup": 1.01},
        baseline_bin_dir=str(baseline), optimized_bin_dir=str(optimized))
    assert ready is False
    assert (optimized / "fuzzer").read_text() == "BASELINE"


def test_reject_no_replay_speedup_noop_when_not_ready(tmp_path):
    baseline, optimized = _bins(tmp_path)
    ready, failure = phase2_setup._reject_if_no_replay_speedup(
        project="p", cve="c", optimization_ready=False, replay=None,
        baseline_bin_dir=str(baseline), optimized_bin_dir=str(optimized))
    assert ready is False and failure is None
    assert (optimized / "fuzzer").read_text() == "OPTIMIZED"  # untouched


def test_reject_no_replay_speedup_partial_demands_wider_margin(tmp_path, monkeypatch):
    # A partial (crash-tolerant) measurement is weaker evidence: a 1.03x that
    # would pass the 1.02 clean gate is rejected under the 1.05 partial margin.
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MIN_REPLAY_SPEEDUP", 1.02)
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MIN_REPLAY_SPEEDUP_PARTIAL", 1.05)
    baseline, optimized = _bins(tmp_path)
    ready, failure = phase2_setup._reject_if_no_replay_speedup(
        project="radare2", cve="arvo-10222", optimization_ready=True,
        replay={"replay_speedup": 1.03, "partial": True},
        baseline_bin_dir=str(baseline), optimized_bin_dir=str(optimized))
    assert ready is False
    assert failure["stage"] == "replay_no_speedup"
    assert "partial" in failure["reason"]
    assert (optimized / "fuzzer").read_text() == "BASELINE"  # reverted


def test_reject_no_replay_speedup_partial_kept_above_wider_margin(tmp_path, monkeypatch):
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MIN_REPLAY_SPEEDUP", 1.02)
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MIN_REPLAY_SPEEDUP_PARTIAL", 1.05)
    baseline, optimized = _bins(tmp_path)
    ready, failure = phase2_setup._reject_if_no_replay_speedup(
        project="p", cve="c", optimization_ready=True,
        replay={"replay_speedup": 1.08, "partial": True},  # clears the 1.05 partial bar
        baseline_bin_dir=str(baseline), optimized_bin_dir=str(optimized))
    assert ready is True and failure is None
    assert (optimized / "fuzzer").read_text() == "OPTIMIZED"  # kept


def test_run_replay_speedup_rate_normalizes_partial(monkeypatch, tmp_path):
    # When both binaries crash (partial), speedup is rate-normalized by
    # executed_units so it stays fair even if the crash points differ slightly.
    diff_dir = tmp_path / "diff"
    fixed = phase2_setup._phase2_fixed_corpus_dir(diff_dir)
    fixed.mkdir(parents=True)
    (fixed / "a").write_text("aaaa")

    def fake_measure(*, out_dir, corpus_dir, fuzz_target, cpu, repeats,
                     seed, memory, shm_size, run_timeout, min_partial_units=0):
        # baseline: 2616 units in 9.34s; optimized: 2700 units in 9.25s (partial)
        if "baseline" in str(out_dir):
            return {"median_time_s": 9.34, "executed_units": 2616, "partial": True}
        return {"median_time_s": 9.25, "executed_units": 2700, "partial": True}

    result = phase2_setup.run_replay_speedup(
        diff_output_dir=diff_dir,
        baseline_bin_dir=tmp_path / "baseline" / "bin",
        optimized_bin_dir=tmp_path / "optimized" / "bin",
        fuzz_target="demo_fuzzer", experiment_dir=tmp_path / "exp",
        profile_cpu=2, repeats=3, measure_fn=fake_measure)
    assert result["partial"] is True
    expected = round((2700 / 9.25) / (2616 / 9.34), 4)  # rate ratio, not time ratio
    assert result["replay_speedup"] == expected


def test_bug_removal_is_recorded_not_reverted(tmp_path):
    """Bug survival is MEASURED, not enforced (2026-07-30 design spec).

    The gate that used to revert a bug-removing fold is gone: enforcing it tells
    you nothing about how often optimization removes bugs, and a gate the agent
    can observe is an oracle it can bisect against to localize the bug.
    """
    baseline = tmp_path / "baseline" / "bin"
    optimized = tmp_path / "optimized" / "bin"
    baseline.mkdir(parents=True)
    optimized.mkdir(parents=True)
    (baseline / "fuzzer").write_text("BASELINE")
    (optimized / "fuzzer").write_text("BUG_REMOVED")

    ready, record = phase2_setup._reject_if_optimization_removed_bug(
        project="lcms",
        cve="arvo-756",
        optimization_ready=True,
        baseline_reproduced=True,
        opt_crashes=False,  # optimized no longer reproduces the PoC
        baseline_bin_dir=str(baseline),
        optimized_bin_dir=str(optimized),
    )

    assert ready is True, "the fold must be kept, not rejected"
    assert record is not None
    assert record["stage"] == "optimized_poc_verify"
    assert record["outcome"] == "bug_removed"
    assert record["blocking"] is False
    # The optimized binary is left exactly as the optimizer built it.
    assert (optimized / "fuzzer").read_text() == "BUG_REMOVED"


def test_reject_keeps_optimization_that_still_crashes(tmp_path):
    baseline = tmp_path / "baseline" / "bin"
    optimized = tmp_path / "optimized" / "bin"
    baseline.mkdir(parents=True)
    optimized.mkdir(parents=True)
    (baseline / "fuzzer").write_text("BASELINE")
    (optimized / "fuzzer").write_text("OPTIMIZED")

    ready, failure = phase2_setup._reject_if_optimization_removed_bug(
        project="lcms",
        cve="arvo-756",
        optimization_ready=True,
        baseline_reproduced=True,
        opt_crashes=True,  # optimized still reproduces the PoC -> valid
        baseline_bin_dir=str(baseline),
        optimized_bin_dir=str(optimized),
    )

    assert ready is True
    assert failure is None
    assert (optimized / "fuzzer").read_text() == "OPTIMIZED"


def test_reject_noops_when_baseline_did_not_reproduce(tmp_path):
    baseline = tmp_path / "baseline" / "bin"
    optimized = tmp_path / "optimized" / "bin"
    baseline.mkdir(parents=True)
    optimized.mkdir(parents=True)
    (optimized / "fuzzer").write_text("OPTIMIZED")

    ready, failure = phase2_setup._reject_if_optimization_removed_bug(
        project="x",
        cve="CVE-x",
        optimization_ready=True,
        baseline_reproduced=False,  # no real bug to remove
        opt_crashes=False,
        baseline_bin_dir=str(baseline),
        optimized_bin_dir=str(optimized),
    )

    assert ready is True
    assert failure is None
    assert (optimized / "fuzzer").read_text() == "OPTIMIZED"


def test_claude_invocation_lifts_bash_tool_timeout(monkeypatch, tmp_path):
    captured = {}

    def fake_run_agent_cli(cmd, *, cwd, child_env, timeout, label, resume_cmd=None):
        captured["env"] = child_env
        captured["cmd"] = cmd
        captured["resume_cmd"] = resume_cmd
        return {"ok": True, "stdout": "", "stderr": "", "timed_out": False,
                "returncode": 0}

    monkeypatch.setattr(phase2_setup, "_run_agent_cli", fake_run_agent_cli)
    monkeypatch.delenv("BASH_MAX_TIMEOUT_MS", raising=False)
    monkeypatch.delenv("BASH_DEFAULT_TIMEOUT_MS", raising=False)

    phase2_setup._invoke_claude_capture(str(tmp_path), "optimize this", project="demo")

    env = captured["env"]
    # The default Claude Bash cap is 600000ms (10min) which forces the agent to
    # background long docker steps; we must lift it well above that.
    assert int(env["BASH_MAX_TIMEOUT_MS"]) > 600000
    assert int(env["BASH_DEFAULT_TIMEOUT_MS"]) > 600000

    # The initial cmd pins a --session-id; the resume cmd reuses that same id via
    # --resume so a usage-limit interruption continues the session, not restarts.
    cmd, resume = captured["cmd"], captured["resume_cmd"]
    assert "--session-id" in cmd
    sid = cmd[cmd.index("--session-id") + 1]
    assert resume is not None and "--resume" in resume
    assert resume[resume.index("--resume") + 1] == sid
    assert "--session-id" not in resume  # resuming, not creating


def test_run_agent_cli_continues_session_on_rate_limit(monkeypatch):
    # First call returns a session-limit notice; second (resume) succeeds.
    calls = []

    class R:
        def __init__(self, out, rc=0):
            self.stdout, self.stderr, self.returncode = out, "", rc

    seq = [R("You've hit your session limit · resets 2:50pm"),
           R("applied fold; done")]

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return seq[len(calls) - 1]

    monkeypatch.setattr(phase2_setup.subprocess, "run", fake_run)
    monkeypatch.setattr(phase2_setup, "RATE_LIMIT_WAIT_SECS", 0)  # no real sleep

    res = phase2_setup._run_agent_cli(
        ["claude", "-p", "PROMPT", "--session-id", "abc"],
        cwd=".", child_env={}, timeout=None, label="Claude",
        resume_cmd=["claude", "-p", "NUDGE", "--resume", "abc"],
    )
    assert res["ok"] is True
    assert len(calls) == 2
    assert calls[0][:3] == ["claude", "-p", "PROMPT"]      # first = original
    assert "--resume" in calls[1]                           # retry = resume
    assert "NUDGE" in calls[1]


def test_honest_no_fold_not_flagged_low_confidence():
    # The agent denies a block; must NOT be treated as low-confidence.
    wolfssl = ("Cumulative speedup 1.00x. 1.00x is the honest, contract-compliant "
               "result - not a `BLOCKED_LOW_CONFIDENCE` (the pipeline, corpus, and "
               "profile all succeeded).")
    libxml2 = ("(Not `BLOCKED_LOW_CONFIDENCE`: corpus, profile, and build/smoke gate "
               "were all valid and usable - the result is a genuine 'no qualifying fold'.)")
    assert phase2_setup._codex_output_is_low_confidence(wolfssl, "") is False
    assert phase2_setup._codex_output_is_low_confidence(libxml2, "") is False


def test_genuine_blocked_status_is_flagged():
    assert phase2_setup._codex_output_is_low_confidence("BLOCKED_LOW_CONFIDENCE", "") is True
    assert phase2_setup._codex_output_is_low_confidence(
        "Status: BLOCKED_LOW_CONFIDENCE", "") is True
    # existing prose patterns still flag
    assert phase2_setup._codex_output_is_low_confidence(
        "Used the fallback static hotspot scan only.", "") is True


def test_is_rate_limited_catches_session_limit_even_on_exit_zero():
    from types import SimpleNamespace
    r0 = SimpleNamespace(returncode=0, stdout="You've hit your session limit · resets 2:50pm",
                         stderr="")
    assert phase2_setup._is_rate_limited(r0) is True
    ok = SimpleNamespace(returncode=0, stdout="all good, applied fold", stderr="")
    assert phase2_setup._is_rate_limited(ok) is False
    rl = SimpleNamespace(returncode=1, stdout="", stderr="429 Too many requests")
    assert phase2_setup._is_rate_limited(rl) is True


def _prebuild_env(tmp_path):
    return {
        "FUZZ_SOURCE_FOLDS_BASELINE_OUT_DIR": str(tmp_path / "baseline" / "out"),
        "FUZZ_SOURCE_FOLDS_CORPUS_DIR": str(tmp_path / "corpus"),
        "FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR": str(tmp_path / "fixed"),
        "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR": str(tmp_path / "profiles"),
        "FUZZ_SOURCE_FOLDS_CORPUS_BUILD_DURATION": "0",
        "FUZZ_SOURCE_FOLDS_PROFILE_CPU": "0",
    }


def _fake_scripts_dir(tmp_path, monkeypatch):
    sc = tmp_path / "scripts"
    sc.mkdir()
    (sc / "build_corpus.py").write_text("# stub")
    (sc / "replay_fuzzer_profile.py").write_text("# stub")
    monkeypatch.setattr(phase2_setup.config, "PHASE2_SKILL_SCRIPTS_DIR", str(sc))
    return sc


def _proc(returncode=0, stderr=""):
    from types import SimpleNamespace
    return SimpleNamespace(returncode=returncode, stderr=stderr, stdout="")


def test_prebuild_sets_flag_and_runs_both_scripts_on_success(monkeypatch, tmp_path):
    _fake_scripts_dir(tmp_path, monkeypatch)
    # Isolate the corpus-build/profile mechanics from the mutation contract: no
    # mutation image in this env, so opt out of the required-mutation hard-fail.
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MUTATION_REQUIRED", False)
    env = _prebuild_env(tmp_path)
    # fixed corpus is empty at the idempotent check, populated after build_corpus
    seq = iter([False, True])
    monkeypatch.setattr(phase2_setup, "_dir_has_files", lambda d: next(seq, True))

    ran = []
    def fake_run(cmd, **kw):
        ran.append(cmd[1])
        return _proc(returncode=0)
    monkeypatch.setattr(phase2_setup.subprocess, "run", fake_run)

    ok = phase2_setup._prebuild_phase2_corpus_and_profile(env, "demo_fuzzer")
    assert ok is True
    assert env.get("FUZZ_SOURCE_FOLDS_PREBUILT_CORPUS") == "1"
    assert any("build_corpus.py" in c for c in ran)
    assert any("replay_fuzzer_profile.py" in c for c in ran)


def test_prebuild_idempotent_when_corpus_already_present(monkeypatch, tmp_path):
    _fake_scripts_dir(tmp_path, monkeypatch)
    env = _prebuild_env(tmp_path)
    monkeypatch.setattr(phase2_setup, "_dir_has_files", lambda d: True)

    def boom(*a, **k):
        raise AssertionError("must not run scripts when the corpus is already frozen")
    monkeypatch.setattr(phase2_setup.subprocess, "run", boom)

    ok = phase2_setup._prebuild_phase2_corpus_and_profile(env, "demo_fuzzer")
    assert ok is True
    assert env.get("FUZZ_SOURCE_FOLDS_PREBUILT_CORPUS") == "1"


def test_prebuild_falls_back_when_build_fails(monkeypatch, tmp_path):
    _fake_scripts_dir(tmp_path, monkeypatch)
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MUTATION_REQUIRED", False)
    env = _prebuild_env(tmp_path)
    monkeypatch.setattr(phase2_setup, "_dir_has_files", lambda d: False)
    monkeypatch.setattr(phase2_setup.subprocess, "run",
                        lambda cmd, **kw: _proc(returncode=1, stderr="boom"))

    ok = phase2_setup._prebuild_phase2_corpus_and_profile(env, "demo_fuzzer")
    assert ok is False
    # flag NOT set -> the agent will build the corpus itself (graceful fallback)
    assert "FUZZ_SOURCE_FOLDS_PREBUILT_CORPUS" not in env


def test_prebuild_hard_fails_when_mutation_required_and_no_image(monkeypatch, tmp_path):
    # New contract: with mutation required and no ARVO builder image, the prebuild
    # propagates MutationAugmentationError (no seed-only corpus is built).
    _fake_scripts_dir(tmp_path, monkeypatch)
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MUTATION_REQUIRED", True)
    env = _prebuild_env(tmp_path)  # no FUZZ_SOURCE_FOLDS_MUTATION_IMAGE
    monkeypatch.setattr(phase2_setup, "_dir_has_files", lambda d: False)

    def must_not_run(*a, **k):
        raise AssertionError("build_corpus must not run when mutation capture is unavailable")
    monkeypatch.setattr(phase2_setup.subprocess, "run", must_not_run)

    with pytest.raises(phase2_setup.MutationAugmentationError):
        phase2_setup._prebuild_phase2_corpus_and_profile(env, "demo_fuzzer")
    assert "FUZZ_SOURCE_FOLDS_PREBUILT_CORPUS" not in env


def test_prebuild_noop_without_corpus_env(tmp_path):
    env = {"FUZZ_SOURCE_FOLDS_BASELINE_OUT_DIR": str(tmp_path)}  # missing the rest
    ok = phase2_setup._prebuild_phase2_corpus_and_profile(env, "demo_fuzzer")
    assert ok is False
    assert "FUZZ_SOURCE_FOLDS_PREBUILT_CORPUS" not in env


def test_setup_cve_arvo_records_bug_removal_and_keeps_the_fold(monkeypatch, tmp_path):
    """A fold that removes the bug is KEPT and recorded, not reverted.

    Bug survival is measured rather than enforced, so the fold still goes to
    phase 3 and the verdict is written to setup_metadata.json for phase 4 to
    separate "no finding because slower" from "no finding because the bug is
    not in the binary". The replay-speedup gate still runs -- it is unaffected."""
    source_root = tmp_path / "captured"
    harness = source_root / "src" / "libvips" / "fuzz" / "demo_fuzzer.cc"
    harness.parent.mkdir(parents=True, exist_ok=True)
    harness.write_text("int main() { return 0; }\n")

    class FakeArvo:
        def fetch_arvo_issue(self, _local_id):
            return {"id": 1}

        def get_arvo_fuzz_target(self, _issue):
            return "demo_fuzzer"

        def get_arvo_crash_type(self, _issue):
            return "crash"

        def download_arvo_poc(self, _issue, poc_dir):
            poc_path = Path(poc_dir) / "poc"
            poc_path.parent.mkdir(parents=True, exist_ok=True)
            poc_path.write_text("poc")
            return poc_path

        def build_arvo_with_source_intercept(self, _local_id, _issue):
            return source_root

    monkeypatch.setattr(phase2_setup.config, "RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.setattr(phase2_setup, "_lazy_import_arvo", lambda: FakeArvo())

    def fake_copy_arvo_output(_local_id, bin_dir):
        Path(bin_dir).mkdir(parents=True, exist_ok=True)
        (Path(bin_dir) / "demo_fuzzer").write_text("BASELINE")
        return True

    def fake_optimize_and_build(_src, _target, diff_dir, **_kwargs):
        os.makedirs(diff_dir, exist_ok=True)
        with open(os.path.join(diff_dir, "optimization.diff"), "w") as f:
            f.write("--- a\n+++ b\n@@ fake fold @@\n")
        return True

    # Baseline crashes with the PoC; the optimized binary does not.
    def fake_verify(bin_dir, *_args, **_kwargs):
        return "optimized" not in str(bin_dir)

    replay_calls = []

    def fake_replay(*_args, **_kwargs):
        replay_calls.append(1)
        # key must match _reject_if_no_replay_speedup, which reads replay_speedup
        return {"replay_speedup": 1.5}

    monkeypatch.setattr(phase2_setup, "copy_arvo_output", fake_copy_arvo_output)
    monkeypatch.setattr(phase2_setup, "optimize_and_build", fake_optimize_and_build)
    monkeypatch.setattr(phase2_setup, "verify_poc_crash", fake_verify)
    monkeypatch.setattr(phase2_setup, "download_seed_corpus", lambda *_a, **_k: True)
    monkeypatch.setattr(phase2_setup, "run_replay_speedup", fake_replay)

    entry = {"project": "libvips", "cve": "CVE-REMOVED", "local_id": 1}

    ok = phase2_setup.setup_cve_arvo(entry, "exp-reject")

    assert ok is True, "a bug-removing fold is no longer a setup failure"
    assert replay_calls, "the replay-speedup gate must still run"
    metadata_path = (
        tmp_path / "results" / "exp-reject" / "libvips-CVE-REMOVED" / "setup_metadata.json"
    )
    metadata = json.loads(metadata_path.read_text())
    assert metadata["verification"]["baseline"] is True
    assert metadata["poc_verdict"] == "no_crash"
    assert "failure" not in metadata, "bug removal is not a blocking failure"
    # Nothing copied baseline over the optimized build. The fake build never
    # produces a binary, so under the OLD gate this path existed only because
    # the revert created it -- its absence is the evidence that no revert ran.
    optimized_bin = (
        tmp_path / "results" / "exp-reject" / "libvips-CVE-REMOVED"
        / "optimized" / "bin" / "demo_fuzzer"
    )
    assert not optimized_bin.exists() or optimized_bin.read_text() != "BASELINE"


def test_retry_prompt_scrubs_sanitizer_traces_from_the_build_log():
    """The retry prompt feeds the failed build's tail back to the agent.

    A failing build can end in a sanitizer report, which names the bug's file,
    line, and function outright -- handing the agent exactly what the sandbox
    exists to withhold.
    """
    build_log = (
        "valid.c:120:5: error: use of undeclared identifier 'foo'\n"
        "==10==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f\n"
        "    #1 0x64b872 in xmlSnprintfElementContent /src/libxml2/valid.c:1279:3\n"
        "SUMMARY: AddressSanitizer: stack-buffer-overflow /src/libxml2/valid.c:1279\n"
    )
    prompt = phase2_setup._make_retry_prompt("demo_fuzzer", build_log)
    for leak in ("xmlSnprintfElementContent", "AddressSanitizer",
                 "stack-buffer-overflow", "valid.c:1279"):
        assert leak not in prompt, f"{leak!r} leaked into the retry prompt"


def test_retry_prompt_keeps_plain_compiler_errors():
    """Scrubbing must not blind the agent to its own compile break."""
    build_log = "parser.c:88:1: error: expected ';' after expression\n"
    prompt = phase2_setup._make_retry_prompt("demo_fuzzer", build_log)
    assert "expected ';' after expression" in prompt
