"""Tests for AFL-native replay timing (the replay-speedup gate's measurement)."""
from __future__ import annotations

import subprocess

import pytest

from lib import afl_replay


# What a REAL afl-showmap -C run prints. The fakes below must carry it: the
# measurer judges by this report, not by exit code, because afl-showmap exits 0
# even when it aborted before the forkserver. These tests originally used empty
# output and asserted on the exit code -- encoding the very assumption that let a
# broken gate look healthy.
_REPORT = ("[+] Captured 3064 tuples (map size 53291) in '/dev/null'.\n"
           "[+] A coverage of 3064 edges were achieved out of 53312 "
           "existing (5.75%) with 5904 input files.")


class _Result:
    def __init__(self, rc, out=_REPORT):
        self.returncode, self.stdout, self.stderr = rc, out, ""


@pytest.fixture
def corpus(tmp_path):
    d = tmp_path / "c"
    (d / "nested").mkdir(parents=True)          # afl-showmap -i walks the dir
    for i in range(3):
        (d / f"u{i}").write_bytes(b"x")
    (d / "nested" / "u3").write_bytes(b"y")
    return d


def test_replays_in_the_named_image_not_base_runner(corpus, tmp_path, monkeypatch):
    """base-runner lacks the pinned LLVM's libc++, so a -stdlib=libc++ target dies
    at exit 127 before main -- the failure that silently rejected every round."""
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return _Result(0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    afl_replay.measure_binary(
        out_dir=tmp_path, corpus_dir=corpus, fuzz_target="t", cpu=7, repeats=1,
        memory="4g", shm_size="2g", run_timeout=60, image="bench-aflpp/x")

    joined = " ".join(seen["cmd"])
    assert "bench-aflpp/x" in joined
    assert "base-runner" not in joined
    assert "afl-showmap -C -i" in joined   # -C, or -o /dev/null aborts instantly
    assert "-runs=0" not in joined         # not libFuzzer
    assert "--cpuset-cpus" in seen["cmd"]   # pinned, or the timing is noise


def test_reports_median_and_full_unit_count(corpus, tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: _Result(0))
    r = afl_replay.measure_binary(
        out_dir=tmp_path, corpus_dir=corpus, fuzz_target="t", cpu=1, repeats=3,
        memory="4g", shm_size="2g", run_timeout=60, image="img")

    assert len(r["times_s"]) == 3
    assert r["median_time_s"] == sorted(r["times_s"])[1]
    # Recursive: both binaries always replay the WHOLE frozen snapshot, which is
    # why partial is False -- afl-showmap forks per input instead of aborting.
    assert r["executed_units"] == 4
    assert r["partial"] is False


def test_a_nonzero_exit_with_a_real_report_is_still_timed(corpus, tmp_path, monkeypatch):
    """exit 2 means some input timed out, not that the measurement is invalid --
    the coverage report is what says the corpus actually ran."""
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: _Result(2))
    r = afl_replay.measure_binary(
        out_dir=tmp_path, corpus_dir=corpus, fuzz_target="t", cpu=1, repeats=1,
        memory="4g", shm_size="2g", run_timeout=60, image="img")
    assert r["median_time_s"] > 0


def test_a_binary_that_cannot_run_raises_instead_of_returning_a_time(
    corpus, tmp_path, monkeypatch,
):
    """127 is the loader failure. Returning a number here would feed the gate a
    fabricated speedup; the caller turns the raise into an explicit None."""
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: _Result(127, out=""))
    with pytest.raises(RuntimeError, match="no coverage report"):
        afl_replay.measure_binary(
            out_dir=tmp_path, corpus_dir=corpus, fuzz_target="t", cpu=1,
            repeats=1, memory="4g", shm_size="2g", run_timeout=60, image="img")


def test_libfuzzer_only_kwargs_are_accepted_and_ignored(corpus, tmp_path, monkeypatch):
    """run_replay_speedup still passes seed/min_partial_units to whichever measurer
    it picked; this one must not reject them."""
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: _Result(0))
    r = afl_replay.measure_binary(
        out_dir=tmp_path, corpus_dir=corpus, fuzz_target="t", cpu=1, repeats=1,
        memory="4g", shm_size="2g", run_timeout=60, image="img",
        seed=1337, min_partial_units=500)
    assert r["runner"] == "afl-showmap"
