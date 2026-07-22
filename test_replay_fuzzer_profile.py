import importlib.util
import json
import subprocess
import types
from pathlib import Path


SCRIPTS_DIR = Path(
    "/home/sefcom/.codex/skills/profile-once-fuzz-folds/scripts"
)


def _load_module(name):
    path = SCRIPTS_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_replay_profile_command_perf_records_a_readonly_replay_loop(tmp_path):
    profile = _load_module("replay_fuzzer_profile")

    cmd = profile.build_replay_profile_docker_command(
        out_dir=tmp_path / "out",
        corpus_dir=tmp_path / "fixed",
        artifact_dir=tmp_path / "artifacts",
        fuzz_target="demo_fuzzer",
        min_sample_seconds=60,
        seed=1337,
        cpu=3,
        memory="4g",
        shm_size="2g",
    )

    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "--cpuset-cpus" in cmd
    assert cmd[cmd.index("--cpuset-cpus") + 1] == "3"
    assert "gcr.io/oss-fuzz-base/base-runner" in cmd

    joined = " ".join(str(part) for part in cmd)
    # Corpus and binary are read-only: a profile pass must never mutate the
    # frozen evaluation set.
    assert f"{tmp_path / 'fixed'}:/corpus:ro" in joined
    assert f"{tmp_path / 'out'}:/out:ro" in joined
    assert f"{tmp_path / 'artifacts'}:/artifacts" in joined

    script = cmd[-1]
    assert "apt-get install -y linux-tools-generic" in script
    assert "record -g --call-graph dwarf -F 997" in script
    assert "-o /artifacts/perf.data --" in script
    # Replay loop: -runs=0, fixed seed, looped until the sample floor elapses.
    assert "/bin/bash -c '" in script
    assert "-runs=0" in script
    assert "-seed=1337" in script
    assert "while [" in script and "$(date +%s)" in script
    assert "+ 60 ))" in script
    # Reports are generated in-container (symbol resolution).
    assert "report --stdio --no-children -g none --percent-limit 0.5" in script
    assert "report --stdio -g callee,0.5 --percent-limit 0.5" in script
    assert "/artifacts/flat.txt" in script
    assert "/artifacts/callgraph.txt" in script
    assert "chmod a+r /artifacts/perf.data /artifacts/fuzzer.log" in script


def test_replay_profile_command_resolves_relative_paths_to_absolute():
    profile = _load_module("replay_fuzzer_profile")
    cmd = profile.build_replay_profile_docker_command(
        out_dir="rel/out", corpus_dir="rel/corpus", artifact_dir="rel/art",
        fuzz_target="t", min_sample_seconds=60, seed=1337, cpu=3,
        memory="4g", shm_size="2g",
    )
    # Every bind-mount source must be absolute, else docker treats it as a named
    # volume ("invalid characters for a local volume name").
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    assert mounts, "expected -v mounts"
    for m in mounts:
        assert m.startswith("/"), f"mount source not absolute: {m}"
    assert any(m.endswith(":/out:ro") for m in mounts)
    assert any(m.endswith(":/corpus:ro") for m in mounts)


def test_replay_profile_reuses_real_fuzzer_profile_helpers():
    profile = _load_module("replay_fuzzer_profile")
    # It imports the sibling module rather than duplicating its helpers.
    assert profile.rfp.__name__ == "real_fuzzer_profile"
    assert profile.RUNNER_IMAGE == profile.rfp.RUNNER_IMAGE
    assert hasattr(profile.rfp, "_write_perf_reports")


def test_run_replay_profile_writes_reports_and_metadata(tmp_path, monkeypatch):
    profile = _load_module("replay_fuzzer_profile")

    corpus = tmp_path / "fixed"
    corpus.mkdir()
    (corpus / "unit_00000000").write_text("aaa")
    artifact_dir = tmp_path / "artifacts"

    def fake_run(cmd, *, timeout=None):
        # Simulate the container producing perf.data + the in-container reports
        # (symbol-resolved flat.txt / callgraph.txt).
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "perf.data").write_bytes(b"PERF")
        (artifact_dir / "flat.txt").write_text(
            "    13.00%  secilc-fuzzer  secilc-fuzzer  [.] hashtab_map\n"
        )
        (artifact_dir / "callgraph.txt").write_text("callgraph")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(profile, "_run", fake_run)

    args = types.SimpleNamespace(
        out_dir=tmp_path / "out",
        corpus_dir=corpus,
        artifact_dir=artifact_dir,
        fuzz_target="demo_fuzzer",
        min_sample_seconds=60,
        loop_timeout=1800,
        seed=1337,
        cpu=3,
        memory="4g",
        shm_size="2g",
    )

    rc = profile.run_replay_profile(args)
    assert rc == 0
    assert "hashtab_map" in (artifact_dir / "flat.txt").read_text()
    assert (artifact_dir / "callgraph.txt").read_text() == "callgraph"

    metadata = json.loads((artifact_dir / "metadata.json").read_text())
    assert metadata["mode"] == "replay"
    assert metadata["corpus_file_count"] == 1
    assert metadata["min_sample_seconds"] == 60


def test_run_replay_profile_retries_once_on_transient_failure(tmp_path, monkeypatch):
    profile = _load_module("replay_fuzzer_profile")
    corpus = tmp_path / "fixed"
    corpus.mkdir()
    (corpus / "u0").write_text("a")
    artifact_dir = tmp_path / "artifacts"
    calls = {"n": 0}

    def fake_run(cmd, *, timeout=None):
        calls["n"] += 1
        artifact_dir.mkdir(parents=True, exist_ok=True)
        if calls["n"] == 1:
            # Transient failure: container produced nothing.
            return subprocess.CompletedProcess(cmd, 1, "", "transient docker error")
        (artifact_dir / "perf.data").write_bytes(b"PERF")
        (artifact_dir / "flat.txt").write_text("10% foo\n")
        (artifact_dir / "callgraph.txt").write_text("cg")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(profile, "_run", fake_run)
    args = types.SimpleNamespace(
        out_dir=tmp_path / "out", corpus_dir=corpus, artifact_dir=artifact_dir,
        fuzz_target="t", min_sample_seconds=60, loop_timeout=1800, seed=1337,
        cpu=3, memory="4g", shm_size="2g",
    )
    assert profile.run_replay_profile(args) == 0
    assert calls["n"] == 2  # retried once


def test_run_replay_profile_raises_with_docker_output(tmp_path, monkeypatch):
    profile = _load_module("replay_fuzzer_profile")
    corpus = tmp_path / "fixed"
    corpus.mkdir()
    (corpus / "u0").write_text("a")

    def fake_run(cmd, *, timeout=None):
        return subprocess.CompletedProcess(cmd, 1, "", "perf: cannot open perf.data")

    monkeypatch.setattr(profile, "_run", fake_run)
    args = types.SimpleNamespace(
        out_dir=tmp_path / "out", corpus_dir=corpus, artifact_dir=tmp_path / "a",
        fuzz_target="t", min_sample_seconds=60, loop_timeout=1800, seed=1337,
        cpu=3, memory="4g", shm_size="2g",
    )
    try:
        profile.run_replay_profile(args)
    except RuntimeError as exc:
        assert "perf: cannot open" in str(exc)  # docker output surfaced
    else:
        raise AssertionError("expected RuntimeError after 2 failed attempts")


def test_run_replay_profile_rejects_empty_corpus(tmp_path):
    profile = _load_module("replay_fuzzer_profile")
    empty = tmp_path / "empty"
    empty.mkdir()
    args = types.SimpleNamespace(
        out_dir=tmp_path / "out",
        corpus_dir=empty,
        artifact_dir=tmp_path / "artifacts",
        fuzz_target="demo_fuzzer",
        min_sample_seconds=60,
        loop_timeout=1800,
        seed=1337,
        cpu=3,
        memory="4g",
        shm_size="2g",
    )
    try:
        profile.run_replay_profile(args)
    except RuntimeError as exc:
        assert "empty" in str(exc)
    else:
        raise AssertionError("expected RuntimeError on empty corpus")
