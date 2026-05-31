import importlib.util
import subprocess
from pathlib import Path


def _load_profile_module():
    path = Path(
        "/home/sefcom/.codex/skills/apply-profile-guided-folds/scripts/"
        "real_fuzzer_profile.py"
    )
    spec = importlib.util.spec_from_file_location("real_fuzzer_profile", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_build_profile_commands_use_real_fuzzer_seed_duration_and_cpu(tmp_path):
    profile = _load_profile_module()

    docker_cmd = profile.build_profile_docker_command(
        out_dir=tmp_path / "out",
        corpus_dir=tmp_path / "corpus",
        artifact_dir=tmp_path / "artifacts",
        fuzz_target="demo_fuzzer",
        duration=300,
        seed=1337,
        cpu=3,
        memory="4g",
        shm_size="2g",
    )
    perf_cmd = profile.build_perf_record_command(
        pid=1234,
        duration=300,
        output_path=tmp_path / "perf.data",
    )

    assert docker_cmd[:3] == ["docker", "run", "--rm"]
    assert "--cpuset-cpus" in docker_cmd
    assert docker_cmd[docker_cmd.index("--cpuset-cpus") + 1] == "3"
    assert "gcr.io/oss-fuzz-base/base-runner" in docker_cmd
    joined = " ".join(str(part) for part in docker_cmd)
    assert f"{tmp_path / 'artifacts'}:/artifacts" in joined
    assert "apt-get install -y linux-tools-generic" in joined
    assert "find /usr/lib -path '*/linux-tools*' -name perf" in joined
    assert "rc=0;" in joined
    assert "|| rc=$?;" in joined
    assert "-o /artifacts/perf.data -- /out/demo_fuzzer /corpus" in joined
    assert "chmod a+r /artifacts/perf.data /artifacts/fuzzer.log" in joined
    assert "-seed=1337" in joined
    assert "-max_total_time=300" in joined
    assert "-print_final_stats=1" in joined
    assert "-artifact_prefix=/tmp/profile-artifacts/" in joined

    assert perf_cmd[:2] == ["perf", "record"]
    assert "-p" in perf_cmd
    assert perf_cmd[perf_cmd.index("-p") + 1] == "1234"
    assert perf_cmd[-2:] == ["sleep", "300"]


def test_sanitize_corpus_copy_filters_crashing_and_timed_out_inputs(tmp_path):
    profile = _load_profile_module()

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "good").write_text("ok")
    (src_dir / "bad").write_text("boom")
    (src_dir / "slow").write_text("zzz")

    dest_dir = tmp_path / "dest"

    def fake_probe(path):
        if path.name == "bad":
            return "crash"
        if path.name == "slow":
            return "timeout"
        return "ok"

    summary = profile.sanitize_corpus_copy(
        source_dir=src_dir,
        dest_dir=dest_dir,
        probe_seed=fake_probe,
    )

    assert sorted(p.name for p in dest_dir.iterdir()) == ["good"]
    assert summary["kept_files"] == ["good"]
    assert summary["removed_files"] == [
        {"file": "bad", "reason": "crash"},
        {"file": "slow", "reason": "timeout"},
    ]


def test_profile_command_mounts_corpus_readwrite_when_evolving(tmp_path):
    profile = _load_profile_module()

    docker_cmd = profile.build_profile_docker_command(
        out_dir=tmp_path / "out",
        corpus_dir=tmp_path / "evolving",
        artifact_dir=tmp_path / "artifacts",
        fuzz_target="demo_fuzzer",
        duration=300,
        seed=1337,
        cpu=3,
        memory="4g",
        shm_size="2g",
        corpus_writable=True,
    )

    joined = " ".join(str(part) for part in docker_cmd)
    # The evolving corpus must be writable so libFuzzer can persist new units.
    assert f"{tmp_path / 'evolving'}:/corpus " in joined + " "
    assert f"{tmp_path / 'evolving'}:/corpus:ro" not in joined
    # Default (one-shot) profiling stays read-only.
    ro_cmd = profile.build_profile_docker_command(
        out_dir=tmp_path / "out",
        corpus_dir=tmp_path / "corpus",
        artifact_dir=tmp_path / "artifacts",
        fuzz_target="demo_fuzzer",
        duration=300,
        seed=1337,
        cpu=3,
        memory="4g",
        shm_size="2g",
    )
    assert f"{tmp_path / 'corpus'}:/corpus:ro" in " ".join(str(p) for p in ro_cmd)


def test_snapshot_corpus_freezes_flat_copy(tmp_path):
    profile = _load_profile_module()

    src = tmp_path / "evolving"
    (src / "sub").mkdir(parents=True)
    (src / "a").write_text("aaa")
    (src / "sub" / "b").write_text("bbb")

    dst = tmp_path / "snapshot"
    count = profile.snapshot_corpus(src, dst)

    assert count == 2
    names = sorted(p.name for p in dst.iterdir())
    assert names == ["unit_00000000", "unit_00000001"]
    # Re-snapshotting replaces wholesale (no stale leftovers).
    (src / "a").unlink()
    assert profile.snapshot_corpus(src, dst) == 1


def test_seed_evolving_corpus_seeds_once_then_reuses(tmp_path):
    profile = _load_profile_module()

    seed_dir = tmp_path / "merged"
    seed_dir.mkdir()
    (seed_dir / "good").write_text("ok")
    (seed_dir / "bad").write_text("boom")

    evolving = tmp_path / "evolving"

    def fake_probe(path):
        return "crash" if path.name == "bad" else "ok"

    first = profile.seed_evolving_corpus(
        evolving_dir=evolving, seed_corpus_dir=seed_dir, probe_seed=fake_probe,
    )
    assert first["seeded"] is True
    assert first["file_count"] == 1  # crash filtered out

    # Simulate libFuzzer having grown the corpus during the window.
    (evolving / "discovered_unit").write_text("new")

    second = profile.seed_evolving_corpus(
        evolving_dir=evolving, seed_corpus_dir=seed_dir,
        probe_seed=lambda p: (_ for _ in ()).throw(AssertionError("should not reseed")),
    )
    assert second["seeded"] is False
    assert second["file_count"] == 2  # reused as-is, including the discovered unit


def test_probe_seed_uses_single_file_corpus_directory(tmp_path, monkeypatch):
    profile = _load_profile_module()

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    seed_path = tmp_path / "seed"
    seed_path.write_text("x")
    seen = {}

    def fake_run(cmd, *, timeout=None):
        seen["cmd"] = cmd
        seen["timeout"] = timeout
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(profile, "_run", fake_run)

    result = profile._probe_seed(
        out_dir=out_dir,
        fuzz_target="demo_fuzzer",
        seed_path=seed_path,
        memory="4g",
        shm_size="2g",
        timeout_s=17,
    )

    assert result == "ok"
    assert seen["timeout"] == 17
    cmd = seen["cmd"]
    assert f"{out_dir}:/out:ro" in cmd
    corpus_mount = cmd[cmd.index("-v", cmd.index("-v") + 1) + 1]
    assert corpus_mount.endswith(":/corpus:ro")
    assert "/seed:ro" not in " ".join(cmd)
    assert cmd[-1].startswith("exec /out/demo_fuzzer /corpus ")
