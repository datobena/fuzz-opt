"""The deterministic-replay command must actually replay the corpus.

afl-showmap with `-i <dir>` needs `-C`: without it, `-o` is treated as a
DIRECTORY to write one bitmap per input into, so `-o /dev/null` aborts with
"cannot create output directory /dev/null (File exists)" -- while still exiting
0 after ~0.5s. Both the agent's fold decisions and the harness's accept/reject
gate were timing that failure instead of execution.
"""
from __future__ import annotations

import pytest

from sandbox.broker import BrokerContext, _replay_command


def _ctx(**kw):
    base = dict(image="img", source_dir="/s", out_dir="/o", corpus_dir="/c",
                fuzz_target="t", project="p", cpu=3)
    base.update(kw)
    return BrokerContext(**base)


def test_replay_uses_collect_coverage_mode():
    cmd = " ".join(_replay_command(_ctx()))
    assert "afl-showmap -C -i /corpus" in cmd
    assert "-o /dev/null" in cmd          # valid only because -C makes -o a file


def test_replay_is_pinned_to_one_cpu():
    """Timing is the whole point; an unpinned replay is noise."""
    assert "--cpuset-cpus" in _replay_command(_ctx(cpu=7))
    assert "7" in _replay_command(_ctx(cpu=7))


def test_replay_mounts_binary_and_corpus_read_only():
    cmd = " ".join(_replay_command(_ctx()))
    assert "/o:/out:ro" in cmd
    assert "/c:/corpus:ro" in cmd         # a replay must never mutate the set


@pytest.mark.parametrize("blob", [
    "SYSTEM ERROR : cannot create output directory /dev/null",
    "",
    "afl-showmap++5.02c by Michal Zalewski\nExecuting ...",
])
def test_a_replay_with_no_coverage_report_is_not_timed(blob, monkeypatch, tmp_path):
    """Exit code is not evidence: afl-showmap exits 0 having done nothing."""
    from lib import afl_replay

    class R:
        returncode, stdout, stderr = 0, blob, ""

    monkeypatch.setattr(afl_replay.subprocess, "run", lambda *a, **k: R())
    (tmp_path / "u").write_bytes(b"x")
    with pytest.raises(RuntimeError, match="no coverage report"):
        afl_replay.measure_binary(
            out_dir=tmp_path, corpus_dir=tmp_path, fuzz_target="t", cpu=1,
            repeats=1, memory="4g", shm_size="2g", run_timeout=60, image="img")


def test_a_real_coverage_report_is_timed(monkeypatch, tmp_path):
    from lib import afl_replay

    class R:
        returncode = 0
        stdout = ("[+] Captured 3064 tuples (map size 53291) in '/dev/null'.\n"
                  "[+] A coverage of 3064 edges were achieved out of 53312 "
                  "(5.75%) with 5904 input files.")
        stderr = ""

    monkeypatch.setattr(afl_replay.subprocess, "run", lambda *a, **k: R())
    (tmp_path / "u").write_bytes(b"x")
    r = afl_replay.measure_binary(
        out_dir=tmp_path, corpus_dir=tmp_path, fuzz_target="t", cpu=1,
        repeats=2, memory="4g", shm_size="2g", run_timeout=60, image="img")
    assert r["median_time_s"] > 0
    assert r["runner"] == "afl-showmap"
