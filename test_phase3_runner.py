import subprocess
from pathlib import Path

import phase3_runner


def test_start_trial_clears_existing_trial_corpus(monkeypatch, tmp_path):
    experiment_id = "exp"
    trial = phase3_runner.Trial(
        project="demo",
        cve="CVE-0000-0001",
        variant="baseline",
        trial_id=0,
        seed=1337,
    )

    monkeypatch.setattr(phase3_runner.config, "RESULTS_DIR", str(tmp_path))

    trial_dirs = phase3_runner.get_trial_dirs(experiment_id, trial)
    corpus_dir = Path(trial_dirs["corpus"])
    corpus_dir.mkdir(parents=True, exist_ok=True)
    stale_file = corpus_dir / "stale_seed"
    stale_file.write_text("old-seed")

    empty_seed_dir = tmp_path / "empty-seed"
    empty_seed_dir.mkdir()
    monkeypatch.setattr(
        phase3_runner, "get_seed_corpus_dir", lambda _exp, _trial: str(empty_seed_dir)
    )

    fuzzer_binary = tmp_path / "demo_fuzzer"
    fuzzer_binary.write_text("#!/bin/sh\nexit 0\n")
    monkeypatch.setattr(
        phase3_runner, "get_fuzzer_binary", lambda _exp, _trial: str(fuzzer_binary)
    )

    def fake_run(cmd, capture_output=True, text=False, timeout=None):
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(phase3_runner, "_launch_container", lambda *args, **kwargs: True)

    assert phase3_runner.start_trial(trial, experiment_id, duration=123) is True
    assert not stale_file.exists()
    assert list(corpus_dir.iterdir()) == []


# --------------------------------------------------------------------------- #
# AFL++ launch. The engine change is the point of the migration: libFuzzer
# stopped at the first crash, so every trial was truncated at exactly the event
# being measured.
# --------------------------------------------------------------------------- #
def _afl_trial(tmp_path):
    trial = phase3_runner.Trial(
        project="demo", cve="CVE-0000-0001", variant="baseline",
        trial_id=0, seed=1337, cpu=2,
    )
    trial._docker_image = "bench-aflpp/demo-arvo-1"
    trial._bin_dir = str(tmp_path / "bin")
    trial._fuzz_target_name = "demo_fuzzer"
    trial._dirs = {
        "corpus": str(tmp_path / "corpus"),
        "crashes": str(tmp_path / "crashes"),
        "afl_out": str(tmp_path / "afl_out"),
        "base": str(tmp_path),
    }
    return trial


def _capture_launch(monkeypatch, trial, duration=321):
    captured = {}

    def fake_run(cmd, capture_output=True, text=False, timeout=None):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="container-id\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert phase3_runner._launch_container(trial, "exp", duration) is True
    return captured["cmd"]


def test_launch_runs_afl_fuzz_not_libfuzzer(monkeypatch, tmp_path):
    shell = _capture_launch(monkeypatch, _afl_trial(tmp_path))[-1]
    assert "afl-fuzz" in shell
    assert "-max_total_time" not in shell, "libFuzzer flag must be gone"
    assert "-artifact_prefix" not in shell


def test_launch_passes_duration_seed_and_memory_flags(monkeypatch, tmp_path):
    shell = _capture_launch(monkeypatch, _afl_trial(tmp_path), duration=321)[-1]
    assert "-V 321" in shell          # time-limited campaign
    assert "-s 1337" in shell         # deterministic RNG seed
    assert "-m none" in shell         # ASAN needs an unlimited memory cap
    assert "-t 5000+" in shell        # per-exec timeout, auto-scaling


def test_launch_target_comes_last_after_the_separator(monkeypatch, tmp_path):
    shell = _capture_launch(monkeypatch, _afl_trial(tmp_path))[-1]
    assert "-- /out/demo_fuzzer" in shell


def test_launch_disables_afl_cpu_affinity(monkeypatch, tmp_path):
    """The container is already pinned with --cpuset-cpus; AFL binding on top of
    that makes it fail to find a free core and abort."""
    cmd = _capture_launch(monkeypatch, _afl_trial(tmp_path))
    joined = " ".join(cmd)
    assert "AFL_NO_AFFINITY=1" in joined
    assert "--cpuset-cpus" in cmd


def test_launch_mounts_a_writable_afl_output_dir(monkeypatch, tmp_path):
    """/out is read-only, so AFL needs a separate writable output directory."""
    cmd = _capture_launch(monkeypatch, _afl_trial(tmp_path))
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    out_mounts = [m for m in mounts if m.endswith(":/out:ro")]
    afl_mounts = [m for m in mounts if m.endswith(":/afl_out")]
    assert out_mounts, "binary mount should stay read-only"
    assert afl_mounts, "AFL needs a writable output mount"


def test_launch_sets_asan_options_for_afl(monkeypatch, tmp_path):
    """AFL cannot see a crash unless the sanitizer aborts on error."""
    joined = " ".join(_capture_launch(monkeypatch, _afl_trial(tmp_path)))
    assert "abort_on_error=1" in joined
    assert "detect_leaks=0" in joined
