"""Live mutation capture from running trials.

Previously each optimization round re-fuzzed a corpus snapshot for 600s purely to
regenerate mutations the live trial had ALREADY executed -- about 4 hours of
redundant fuzzing per target over a 24h run. The shim is a runtime .so, so a live
trial can carry it and a round just picks up what it produced.
"""
import phase3_runner
from phase3_online import collect_round_mutations, request_mutation_dump


def _trial(variant="optimized", capture=False):
    t = phase3_runner.Trial(project="demo", cve="arvo-1", variant=variant,
                            trial_id=2, seed=99, cpu=3)
    t.capture_mutations = capture
    t._docker_image = "bench-aflpp/demo-arvo-1"
    t._fuzz_target_name = "demo_fuzzer"
    return t


def _launch(monkeypatch, trial, tmp_path):
    import subprocess
    trial._bin_dir = str(tmp_path / "bin")
    trial._dirs = {
        "corpus": str(tmp_path / "corpus"), "crashes": str(tmp_path / "crashes"),
        "afl_out": str(tmp_path / "afl_out"), "base": str(tmp_path),
        "mutations": str(tmp_path / "mutations"),
    }
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="cid\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    phase3_runner._launch_container(trial, "exp", 60)
    # _launch_container issues `docker rm -f` first; we want the launch itself.
    launches = [c for c in calls if len(c) > 1 and c[1] == "run"]
    assert launches, f"no docker run issued; calls={calls}"
    return launches[-1]


def test_capture_trials_load_the_shim(monkeypatch, tmp_path):
    joined = " ".join(_launch(monkeypatch, _trial(capture=True), tmp_path))
    assert "AFL_CUSTOM_MUTATOR_LIBRARY" in joined
    assert "MUTATION_DUMP_DIR=/mutations" in joined
    assert "MUTATION_DUMP_MODE=reservoir" in joined


def test_non_capture_trials_are_untouched(monkeypatch, tmp_path):
    """A trial not flagged for capture must be byte-identical to before, or the
    two arms are no longer running the same thing."""
    joined = " ".join(_launch(monkeypatch, _trial(capture=False), tmp_path))
    assert "AFL_CUSTOM_MUTATOR_LIBRARY" not in joined
    assert "MUTATION_DUMP_DIR" not in joined
    assert "/mutations" not in joined


def test_shim_build_failure_does_not_kill_the_trial(monkeypatch, tmp_path):
    """Losing capture costs an optimization round; losing the trial costs a data
    point. The build must be non-fatal."""
    shell = _launch(monkeypatch, _trial(capture=True), tmp_path)[-1]
    assert "||" in shell and "continuing without capture" in shell
    assert shell.index("continuing without capture") < shell.index("afl-fuzz")


def test_dump_request_clears_the_previous_batch_and_asks_for_a_new_one(tmp_path):
    """The shim samples across the whole window and writes only on request, so a
    round must ASK. Requesting also stamps the window boundary."""
    import threading
    import time as _t

    d = tmp_path / "mutations"
    d.mkdir()
    for i in range(5):
        (d / f"mut_1_{i:08d}").write_bytes(b"stale")
    (d / ".batch_complete").write_text("5\n")

    def fake_shim():
        # Stand in for the shim: notice the request, write a batch, mark it done.
        for _ in range(100):
            if (d / ".dump_now").exists():
                (d / "mut_1_00000000").write_bytes(b"fresh")
                (d / ".batch_complete").write_text("1\n")
                (d / ".dump_now").unlink()
                return
            _t.sleep(0.02)

    threading.Thread(target=fake_shim, daemon=True).start()
    ready = request_mutation_dump([str(d)], timeout=10)

    assert ready == [str(d)]
    files = list(d.glob("mut_*"))
    assert len(files) == 1
    assert files[0].read_bytes() == b"fresh", "stale batch was not cleared"


def test_a_silent_trial_is_skipped_not_waited_on(tmp_path):
    """A stalled or just-restarted trial must not hold up an optimization round."""
    d = tmp_path / "silent"
    d.mkdir()
    ready = request_mutation_dump([str(d)], timeout=1, poll=0.1)
    assert ready == []
    assert not (d / ".dump_now").exists(), "request should be withdrawn on timeout"


def test_collect_samples_across_all_capture_trials(tmp_path):
    """Mutations come from several online trials; the round should draw from all
    of them rather than privileging one."""
    dirs = []
    for t in range(3):
        d = tmp_path / f"t{t}"
        d.mkdir()
        for i in range(50):
            (d / f"mut_{t}_{i:08d}").write_bytes(bytes([t]) * (i + 1))
        (d / ".batch_complete").write_text("50\n")
        dirs.append(str(d))

    dest = tmp_path / "round"
    n = collect_round_mutations(dirs, dest, cap=30, seed=7)

    assert n == 30
    origins = {p.read_bytes()[0] for p in dest.iterdir()}
    assert len(origins) > 1, "sample was drawn from a single trial"


def test_collect_is_deterministic_for_a_seed(tmp_path):
    d = tmp_path / "t"
    d.mkdir()
    for i in range(40):
        (d / f"mut_0_{i:08d}").write_bytes(str(i).encode())
    (d / ".batch_complete").write_text("40\n")

    a, b = tmp_path / "a", tmp_path / "b"
    collect_round_mutations([str(d)], a, cap=10, seed=5)
    collect_round_mutations([str(d)], b, cap=10, seed=5)
    assert sorted(p.read_bytes() for p in a.iterdir()) == \
           sorted(p.read_bytes() for p in b.iterdir())


def test_collect_ignores_an_incomplete_batch(tmp_path):
    """No marker means the shim is mid-dump; consuming it would take a partial,
    truncated set and silently profile the wrong thing."""
    d = tmp_path / "t"
    d.mkdir()
    for i in range(10):
        (d / f"mut_0_{i:08d}").write_bytes(b"x")
    # no .batch_complete written
    assert collect_round_mutations([str(d)], tmp_path / "out", cap=10, seed=1) == 0


def test_collect_takes_everything_when_under_cap(tmp_path):
    d = tmp_path / "t"
    d.mkdir()
    for i in range(6):
        (d / f"mut_0_{i:08d}").write_bytes(b"y")
    (d / ".batch_complete").write_text("6\n")
    assert collect_round_mutations([str(d)], tmp_path / "o", cap=999, seed=1) == 6


# --- phase-2 short circuit ---------------------------------------------------

def test_phase2_reuses_live_mutations_without_refuzzing(tmp_path, monkeypatch):
    """The whole point: ~600s per round of re-fuzzing removed."""
    import phase2_setup

    live = tmp_path / "live"
    live.mkdir()
    for i in range(12):
        (live / f"mut_{i:08d}").write_bytes(bytes([i]))
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "s0").write_bytes(b"seed")
    profiles = tmp_path / "profiles"
    profiles.mkdir()

    def fail(*_a, **_k):
        raise AssertionError("re-fuzzed despite live mutations being available")

    monkeypatch.setattr(phase2_setup, "_phase2_mutation_builder", fail)

    env = {
        "FUZZ_SOURCE_FOLDS_PREBUILT_MUTATIONS": str(live),
        "FUZZ_SOURCE_FOLDS_CORPUS_DIR": str(seeds),
        "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR": str(profiles),
    }
    combined = phase2_setup._augment_corpus_with_mutations(env, "demo_fuzzer")

    from pathlib import Path
    files = list(Path(combined).iterdir())
    assert len(files) == 13, "expected 1 seed + 12 mutations"
    assert any(f.name.startswith("seed_") for f in files)
    assert any(f.name.startswith("mut_") for f in files)
    assert env["FUZZ_SOURCE_FOLDS_CORPUS_DIR"] == combined


def test_empty_live_dir_does_not_short_circuit(tmp_path, monkeypatch, caplog):
    """An empty harvest must fall through to phase-2 capture, never be treated as
    a valid mutation set -- profiling seeds alone measures the wrong workload."""
    import logging

    import phase2_setup

    live = tmp_path / "live"
    live.mkdir()
    profiles = tmp_path / "p"
    profiles.mkdir()
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MUTATION_ENABLED", True)
    monkeypatch.setattr(phase2_setup.config, "PHASE2_MUTATION_REQUIRED", False)

    env = {
        "FUZZ_SOURCE_FOLDS_PREBUILT_MUTATIONS": str(live),
        "FUZZ_SOURCE_FOLDS_CORPUS_DIR": str(tmp_path),
        "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR": str(profiles),
    }
    with caplog.at_level(logging.INFO):
        result = phase2_setup._augment_corpus_with_mutations(env, "demo_fuzzer")

    # It must NOT have reported reusing live mutations, and must not have built a
    # combined corpus out of an empty directory.
    assert not any("reusing" in r.message for r in caplog.records)
    assert not (profiles / "corpus_combined").exists()
    assert result is None
