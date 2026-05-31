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


def test_launch_container_disables_libfuzzer_leak_detection(monkeypatch, tmp_path):
    trial = phase3_runner.Trial(
        project="demo",
        cve="CVE-0000-0001",
        variant="baseline",
        trial_id=0,
        seed=1337,
        cpu=2,
    )
    trial._docker_image = "gcr.io/oss-fuzz/demo"
    trial._bin_dir = str(tmp_path / "bin")
    trial._fuzz_target_name = "demo_fuzzer"
    trial._dirs = {
        "corpus": str(tmp_path / "corpus"),
        "crashes": str(tmp_path / "crashes"),
    }

    captured = {}

    def fake_run(cmd, capture_output=True, text=False, timeout=None):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="container-id\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert phase3_runner._launch_container(trial, "exp", 321) is True

    shell_cmd = captured["cmd"][-1]
    assert " -detect_leaks=0" in shell_cmd
