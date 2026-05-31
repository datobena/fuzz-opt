import importlib.util
import subprocess
from pathlib import Path


def _load_replay_module():
    path = Path(
        "/home/sefcom/.codex/skills/apply-profile-guided-folds/scripts/"
        "replay_timing.py"
    )
    spec = importlib.util.spec_from_file_location("replay_timing", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_replay_command_is_deterministic_non_mutating(tmp_path):
    replay = _load_replay_module()

    cmd = replay.build_replay_docker_command(
        out_dir=tmp_path / "out",
        corpus_dir=tmp_path / "snapshot",
        fuzz_target="demo_fuzzer",
        seed=1337,
        cpu=5,
        memory="4g",
        shm_size="2g",
    )

    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "--cpuset-cpus" in cmd
    assert cmd[cmd.index("--cpuset-cpus") + 1] == "5"
    assert "gcr.io/oss-fuzz-base/base-runner" in cmd
    joined = " ".join(str(part) for part in cmd)
    # Read-only mounts: a replay must never mutate the frozen evaluation set.
    assert f"{tmp_path / 'out'}:/out:ro" in joined
    assert f"{tmp_path / 'snapshot'}:/corpus:ro" in joined
    # No mutation runs; fixed seed; deterministic.
    assert "-runs=0" in joined
    assert "-seed=1337" in joined
    assert "exec /out/demo_fuzzer /corpus" in joined


def test_median_of_takes_middle_value():
    replay = _load_replay_module()
    assert replay.median_of([3.0, 1.0, 2.0]) == 2.0
    assert replay.median_of([5.0]) == 5.0


def test_compare_is_baseline_over_optimized():
    replay = _load_replay_module()
    speedup = replay.compare(
        {"median_time_s": 10.0}, {"median_time_s": 4.0},
    )
    assert speedup == 2.5
    assert replay.compare({"median_time_s": 0}, {"median_time_s": 4.0}) is None


def test_parse_replay_stats_pulls_executed_units():
    replay = _load_replay_module()
    log = (
        "Running: /corpus/unit_0\n"
        "stat::number_of_executed_units: 412\n"
        "stat::average_exec_per_sec:     0\n"
    )
    stats = replay.parse_replay_stats(log)
    assert stats["executed_units"] == 412


def test_measure_binary_medians_repeats_and_counts_units():
    replay = _load_replay_module()

    # (start, end) per run -> deltas 1.0, 3.0, 5.0 -> median 3.0
    elapsed_seq = iter([100.0, 101.0, 100.0, 103.0, 100.0, 105.0])

    def fake_clock():
        return next(elapsed_seq)

    calls = {"n": 0}

    def fake_runner(cmd, *, timeout=None):
        calls["n"] += 1
        return subprocess.CompletedProcess(
            cmd, 0, "stat::number_of_executed_units: 50\n", ""
        )

    result = replay.measure_binary(
        out_dir="/out",
        corpus_dir="/corpus",
        fuzz_target="demo_fuzzer",
        cpu=3,
        repeats=3,
        seed=1337,
        memory="4g",
        shm_size="2g",
        run_timeout=600,
        runner=fake_runner,
        clock=fake_clock,
    )

    assert calls["n"] == 3
    # clock() is read as (start, end) per run: deltas 1.0, 3.0, 5.0 -> median 3.0
    assert result["median_time_s"] == 3.0
    assert result["repeats"] == 3
    assert result["executed_units"] == 50


def test_measure_binary_raises_on_failed_run():
    replay = _load_replay_module()

    def fake_runner(cmd, *, timeout=None):
        return subprocess.CompletedProcess(cmd, 1, "", "boom")

    try:
        replay.measure_binary(
            out_dir="/out",
            corpus_dir="/corpus",
            fuzz_target="demo_fuzzer",
            cpu=3,
            repeats=1,
            seed=1337,
            memory="4g",
            shm_size="2g",
            run_timeout=600,
            runner=fake_runner,
            clock=iter([0.0, 1.0]).__next__,
        )
    except RuntimeError as exc:
        assert "boom" in str(exc)
    else:
        raise AssertionError("expected RuntimeError on non-zero replay exit")
