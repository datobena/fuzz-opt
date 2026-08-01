"""Tests for the AFL port of the online-optimization loop.

Online optimization snapshots a LIVE trial's accumulated corpus and feeds it to
phase 2. Under libFuzzer that corpus was the trial's own corpus/ directory, which
libFuzzer wrote into directly. AFL keeps its corpus in <afl_out>/default/queue
and treats -i as read-only input, so pointing the snapshot at corpus/ would feed
the optimizer the SEED corpus forever -- the loop would appear to work while
optimizing against inputs that never grow.
"""
import pathlib

import pytest

import phase3_runner
from phase3_online import snapshot_live_corpus


def _trial():
    return phase3_runner.Trial(
        project="demo", cve="arvo-1", variant="optimized", trial_id=3, seed=1,
    )


def test_live_corpus_dir_points_at_the_afl_queue(monkeypatch, tmp_path):
    monkeypatch.setattr(phase3_runner.config, "RESULTS_DIR", str(tmp_path))
    d = phase3_runner.get_live_corpus_dir("exp", _trial())
    assert d.endswith("afl_out/default/queue"), d


def test_live_corpus_dir_is_not_the_seed_input_dir(monkeypatch, tmp_path):
    """-i is read-only under AFL; snapshotting it would never grow."""
    monkeypatch.setattr(phase3_runner.config, "RESULTS_DIR", str(tmp_path))
    dirs = phase3_runner.get_trial_dirs("exp", _trial())
    assert phase3_runner.get_live_corpus_dir("exp", _trial()) != dirs["corpus"]


def test_corpus_count_reads_the_queue(monkeypatch, tmp_path):
    import phase3_online

    monkeypatch.setattr(phase3_runner.config, "RESULTS_DIR", str(tmp_path))
    t = _trial()
    q = tmp_path / phase3_runner.get_live_corpus_dir("exp", t).split(str(tmp_path))[1].lstrip("/")
    q.mkdir(parents=True)
    for i in range(4):
        (q / f"id:00000{i},time:{i}000,execs:1").write_bytes(b"x")

    assert phase3_online._corpus_file_count("exp", t) == 4


def test_snapshot_skips_in_flight_queue_entries(tmp_path):
    """AFL queue entries are write-once like libFuzzer units, so the stable
    mtime/size filter still yields a consistent set."""
    import os
    import time

    src = tmp_path / "queue"
    src.mkdir()
    old = src / "id:000000,time:1000,execs:1"
    old.write_bytes(b"settled")
    os.utime(old, (time.time() - 60, time.time() - 60))
    fresh = src / "id:000001,time:2000,execs:2"
    fresh.write_bytes(b"in-flight")

    meta = snapshot_live_corpus(src, tmp_path / "snap", now=time.time())
    assert meta["file_count"] == 1
    assert meta["skipped_in_flight"] == 1
    assert (tmp_path / "snap" / old.name).exists()


def test_relaunch_resumes_rather_than_restarting(monkeypatch, tmp_path):
    """A hot-swap must not discard the corpus the round was built from.

    AFL_AUTORESUME lets afl-fuzz continue from an existing -o directory instead
    of refusing to start or wiping it.
    """
    import subprocess

    t = _trial()
    t.cpu = 1
    t._docker_image = "bench-aflpp/demo-arvo-1"
    t._bin_dir = str(tmp_path / "bin")
    t._fuzz_target_name = "demo_fuzzer"
    t._dirs = {
        "corpus": str(tmp_path / "corpus"), "crashes": str(tmp_path / "crashes"),
        "afl_out": str(tmp_path / "afl_out"), "base": str(tmp_path),
    }
    captured = {}

    def fake_run(cmd, capture_output=True, text=False, timeout=None):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="cid\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert phase3_runner._launch_container(t, "exp", 60) is True
    assert "AFL_AUTORESUME=1" in " ".join(captured["cmd"])


def test_online_finalize_reads_afl_stats_not_console_text(monkeypatch, tmp_path):
    """parse_fuzzer_stats takes AFL's output DIRECTORY now.

    Passing the container log (as the libFuzzer version did) silently yields
    empty stats for every online trial -- no exec counts, no coverage.
    """
    import phase3_online

    monkeypatch.setattr(phase3_runner.config, "RESULTS_DIR", str(tmp_path))
    t = _trial()
    dirs = phase3_runner.get_trial_dirs("exp", t)
    d = tmp_path / "x"
    d.mkdir()
    default = tmp_path / "afl" / "default"
    default.mkdir(parents=True)
    (default / "fuzzer_stats").write_text(
        "execs_done        : 4242\nexecs_per_sec     : 99.5\nedges_found       : 77\n")

    stats = phase3_runner.parse_fuzzer_stats(str(tmp_path / "afl"))
    assert stats["total_execs"] == 4242
    assert stats["edges_found"] == 77

    src = pathlib.Path("phase3_online.py").read_text()
    assert 'parse_fuzzer_stats(dirs["afl_out"])' in src
    assert "parse_fuzzer_stats(logs)" not in src

