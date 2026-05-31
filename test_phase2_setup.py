import json
import os
import subprocess
from pathlib import Path
from subprocess import TimeoutExpired

import phase2_setup


def test_make_phase2_profile_env_uses_seed_corpus_profiles_and_reserved_cpu(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(phase2_setup.config, "RESERVED_CORES", 4)
    monkeypatch.setattr(
        phase2_setup.config, "PHASE2_BASELINE_PROFILE_DURATION_SECS", 1200
    )
    monkeypatch.setattr(
        phase2_setup.config, "PHASE2_REFRESH_PROFILE_DURATION_SECS", 300
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
    assert env["FUZZ_SOURCE_FOLDS_BASELINE_PROFILE_DURATION"] == "1200"
    assert env["FUZZ_SOURCE_FOLDS_REFRESH_PROFILE_DURATION"] == "300"
    assert env["FUZZ_SOURCE_FOLDS_PROFILE_DURATION"] == "1200"
    assert env["FUZZ_SOURCE_FOLDS_PROFILE_CPU"] == "3"


def test_make_phase2_profile_env_respects_explicit_overrides(tmp_path):
    experiment_dir = tmp_path / "results" / "exp" / "demo-CVE-2"
    diff_dir = experiment_dir / "optimized" / "source_diff"
    out_dir = tmp_path / "build" / "out" / "demo_opt"

    env = phase2_setup._make_phase2_profile_env(
        experiment_dir=experiment_dir,
        diff_output_dir=diff_dir,
        out_dir=out_dir,
        profile_cpu=1,
        baseline_profile_duration=1800,
        refresh_profile_duration=600,
    )

    assert env["FUZZ_SOURCE_FOLDS_PROFILE_CPU"] == "1"
    assert env["FUZZ_SOURCE_FOLDS_BASELINE_PROFILE_DURATION"] == "1800"
    assert env["FUZZ_SOURCE_FOLDS_REFRESH_PROFILE_DURATION"] == "600"
    assert env["FUZZ_SOURCE_FOLDS_PROFILE_DURATION"] == "1800"


def test_make_phase2_profile_env_sets_evolving_corpus_and_replay(tmp_path):
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

    # Evolving corpus lives under the profiles dir and persists across windows.
    assert env["FUZZ_SOURCE_FOLDS_EVOLVING_CORPUS_DIR"] == str(
        diff_dir / "profiles" / "evolving_corpus"
    )
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


def test_run_replay_speedup_freezes_snapshot_and_compares(monkeypatch, tmp_path):
    diff_dir = tmp_path / "diff"
    experiment_dir = tmp_path / "exp"
    # Provide an evolving corpus (the deep corpus) to be frozen and replayed.
    evolving = phase2_setup._phase2_evolving_corpus_dir(diff_dir)
    evolving.mkdir(parents=True)
    (evolving / "deep_a").write_text("aaaa")
    (evolving / "deep_b").write_text("bbbb")

    captured = {}

    def fake_measure(*, out_dir, corpus_dir, fuzz_target, cpu, repeats,
                     seed, memory, shm_size, run_timeout):
        captured.setdefault("corpus_dirs", []).append(corpus_dir)
        captured.setdefault("out_dirs", []).append(out_dir)
        # baseline slower than optimized -> speedup > 1
        median = 10.0 if "baseline" in str(out_dir) else 4.0
        return {"median_time_s": median, "times_s": [median], "repeats": repeats,
                "executed_units": 2}

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
    assert result["corpus_source"] == "evolving"
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

    assert "$apply-fuzz-source-folds" in prompt
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
    assert "apply-fuzz-source-folds" in prompt
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

    assert "$apply-fuzz-source-folds" in codex_prompt
    assert "$apply-fuzz-source-folds" not in claude_prompt
    assert "the apply-fuzz-source-folds skill" in claude_prompt

    claude_retry = phase2_setup._make_retry_prompt(
        "demo_fuzzer", "fatal error", backend="claude")
    assert "$apply-fuzz-source-folds" not in claude_retry
    assert "apply-fuzz-source-folds skill" in claude_retry


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


CODEX_SKILL_PATH = Path(
    "/home/sefcom/.codex/skills/apply-fuzz-source-folds/SKILL.md"
)


def test_apply_fuzz_source_folds_skill_documents_wrapper_validation():
    text = CODEX_SKILL_PATH.read_text()

    assert "FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND" in text
    assert "FUZZ_SOURCE_FOLDS_BUILD_COMMAND" in text
    assert "FUZZ_SOURCE_FOLDS_SMOKE_COMMAND" in text
    assert "wrapper-provided" in text


def test_apply_fuzz_source_folds_skill_does_not_document_claude_fallback():
    text = CODEX_SKILL_PATH.read_text()

    assert "../apply-fold-steps/scripts/invoke_fold_step.py" not in text
    assert "Treat Claude-reported source-file candidates exactly like Codex-found candidates" not in text
    assert "both Codex and Claude" not in text
    assert "Claude second-opinion" not in text


def test_skill_does_not_document_codex_timeout_or_turn_cap():
    text = CODEX_SKILL_PATH.read_text()

    assert "APPLY_FOLD_STEPS_CODEX_TIMEOUT" not in text
    assert "APPLY_FOLD_STEPS_CODEX_MAX_TURNS" not in text


def test_apply_fuzz_source_folds_skill_documents_real_fuzzer_profile_env():
    text = CODEX_SKILL_PATH.read_text()

    assert "FUZZ_SOURCE_FOLDS_CORPUS_DIR" in text
    assert "FUZZ_SOURCE_FOLDS_PROFILE_CPU" in text
    assert "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR" in text
    assert "FUZZ_SOURCE_FOLDS_BASELINE_PROFILE_DURATION" in text
    assert "FUZZ_SOURCE_FOLDS_REFRESH_PROFILE_DURATION" in text
    assert "real fuzz target" in text


def test_apply_fuzz_source_folds_skill_documents_hybrid_refresh_stop_rule():
    text = CODEX_SKILL_PATH.read_text()

    assert "Run one long baseline profile" in text
    assert "Reuse the active profile across passes" in text
    assert "would otherwise declare `NO_MORE_FOLDS`" in text
    assert "one validated post-refresh clean pass" in text


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
        assert env["FUZZ_SOURCE_FOLDS_BASELINE_PROFILE_DURATION"] == "1200"
        assert env["FUZZ_SOURCE_FOLDS_REFRESH_PROFILE_DURATION"] == "300"
        assert env["FUZZ_SOURCE_FOLDS_PROFILE_DURATION"] == "1200"
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
        assert env["FUZZ_SOURCE_FOLDS_BASELINE_PROFILE_DURATION"] == "1200"
        assert env["FUZZ_SOURCE_FOLDS_REFRESH_PROFILE_DURATION"] == "300"
        assert env["FUZZ_SOURCE_FOLDS_PROFILE_DURATION"] == "1200"
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
