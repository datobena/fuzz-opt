"""Tests for the optimization CPU-cost ledger."""
from __future__ import annotations

import json
import os
import threading

import pytest

from lib import cpu_ledger


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    monkeypatch.delenv(cpu_ledger.LEDGER_ENV, raising=False)
    monkeypatch.delenv(cpu_ledger.PROJECT_ENV, raising=False)
    monkeypatch.delenv(cpu_ledger.ITER_ENV, raising=False)
    yield


def _rows(path):
    return [json.loads(l) for l in open(path).read().splitlines() if l.strip()]


# --- recording is opt-in: no path configured means no side effects ----------
def test_record_is_a_noop_without_a_ledger_path():
    assert cpu_ledger.record("stage", wall_s=1.0, cores=1) is None


def test_timed_is_a_noop_without_a_ledger_path():
    with cpu_ledger.timed("stage"):
        pass  # must not raise despite no configured path


# --- core-seconds are the headline number ----------------------------------
def test_core_seconds_is_wall_times_cores(tmp_path):
    cpu_ledger.set_ledger_path(tmp_path / "l.jsonl")
    cpu_ledger.record("rebuild", wall_s=120.0, cores=4)
    row = _rows(tmp_path / "l.jsonl")[0]
    assert row["core_s"] == 480.0
    assert row["wall_s"] == 120.0


def test_uncounted_stage_contributes_zero_core_seconds(tmp_path):
    """Agent model-wait must never enter the CPU cost, however long it ran."""
    cpu_ledger.set_ledger_path(tmp_path / "l.jsonl")
    cpu_ledger.record("agent_wait", wall_s=3600.0, cores=0, counts=False)
    row = _rows(tmp_path / "l.jsonl")[0]
    assert row["core_s"] == 0.0
    assert row["counts"] is False
    # ...and it is still on record, so round wall-clock stays reconstructable.
    assert row["wall_s"] == 3600.0


# --- the context manager ----------------------------------------------------
def test_timed_records_extras_added_by_the_caller(tmp_path):
    cpu_ledger.set_ledger_path(tmp_path / "l.jsonl")
    with cpu_ledger.timed("mutation_harvest", cores=1) as info:
        info["mutations"] = 20000
    row = _rows(tmp_path / "l.jsonl")[0]
    assert row["stage"] == "mutation_harvest"
    assert row["mutations"] == 20000


def test_timed_records_a_stage_that_raises(tmp_path):
    """Failed work burns CPU exactly like successful work; dropping it would
    understate a round that failed late."""
    cpu_ledger.set_ledger_path(tmp_path / "l.jsonl")
    with pytest.raises(RuntimeError):
        with cpu_ledger.timed("rebuild", cores=1):
            raise RuntimeError("build blew up")
    row = _rows(tmp_path / "l.jsonl")[0]
    assert row["stage"] == "rebuild"
    assert row["error"] == "RuntimeError"


def test_timed_spans_are_consistent(tmp_path):
    cpu_ledger.set_ledger_path(tmp_path / "l.jsonl")
    with cpu_ledger.timed("corpus_snapshot"):
        pass
    row = _rows(tmp_path / "l.jsonl")[0]
    assert row["t_end"] >= row["t_start"]
    assert row["wall_s"] == pytest.approx(row["t_end"] - row["t_start"], abs=0.01)


# --- round tagging travels through the environment -------------------------
def test_round_tag_is_picked_up_from_the_environment(tmp_path):
    """The broker and phase-2 sit several layers below the code that knows the
    round, so the tag rides in the environment rather than every signature."""
    cpu_ledger.set_ledger_path(tmp_path / "l.jsonl")
    cpu_ledger.set_round(project="libxml2", iter_n=7)
    cpu_ledger.record("broker_build", wall_s=10.0, cores=1)
    row = _rows(tmp_path / "l.jsonl")[0]
    assert row["project"] == "libxml2"
    assert row["iter"] == 7


def test_explicit_arguments_beat_the_environment(tmp_path):
    cpu_ledger.set_ledger_path(tmp_path / "l.jsonl")
    cpu_ledger.set_round(project="libxml2", iter_n=7)
    cpu_ledger.record("x", wall_s=1.0, cores=1, project="wolfssl", iter_n=2)
    row = _rows(tmp_path / "l.jsonl")[0]
    assert (row["project"], row["iter"]) == ("wolfssl", 2)


# --- concurrent writers (broker thread + orchestrator) ---------------------
def test_concurrent_writers_do_not_corrupt_lines(tmp_path):
    """The broker serves the agent from its own thread while the round writes
    its own stages; O_APPEND single-line writes must interleave cleanly."""
    cpu_ledger.set_ledger_path(tmp_path / "l.jsonl")

    def spam(stage):
        for _ in range(50):
            cpu_ledger.record(stage, wall_s=0.01, cores=1)

    threads = [threading.Thread(target=spam, args=(f"s{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    rows = _rows(tmp_path / "l.jsonl")  # raises if any line is malformed
    assert len(rows) == 200


def test_load_skips_a_torn_trailing_line(tmp_path):
    p = tmp_path / "l.jsonl"
    p.write_text(json.dumps({"stage": "a", "core_s": 1.0}) + "\n{\"stage\": \"b\"")
    rows = cpu_ledger.load(p)
    assert [r["stage"] for r in rows] == ["a"]


# --- summarisation ---------------------------------------------------------
def _row(stage, it, core_s, wall_s=None, counts=True):
    return {"stage": stage, "iter": it, "core_s": core_s,
            "wall_s": core_s if wall_s is None else wall_s,
            "counts": counts, "t_start": 100.0 * it, "t_end": 100.0 * it + 1}


def test_summarize_totals_per_round_and_cumulatively():
    rows = [_row("profile_prebuild", 1, 300), _row("rebuild", 1, 200),
            _row("profile_prebuild", 2, 100)]
    s = cpu_ledger.summarize(rows)
    assert s["total_core_s"] == 600
    by_iter = {b["iter"]: b for b in s["rounds"]}
    assert by_iter[1]["core_s"] == 500
    assert by_iter[2]["core_s"] == 100
    assert by_iter[2]["cumulative_core_s"] == 600


def test_summarize_charges_each_replicate_the_full_optimizer_cost():
    """Each online trial is a replicate of a campaign that runs its OWN optimizer.

    900 core-seconds costs every replicate 900s, not 900/9: sharing one optimizer
    across the arm is an economy of the experiment, not of the method.
    """
    s = cpu_ledger.summarize([_row("rebuild", 1, 900)], trial_cores=9)
    assert s["charge_model"] == "per-replicate"
    assert s["rounds"][0]["fuzz_seconds_equivalent"] == 900.0
    assert s["total_fuzz_seconds_equivalent"] == 900.0


def test_summarize_as_run_amortises_over_the_arm():
    """as-run answers "what did this machine spend", so it divides by the arm."""
    s = cpu_ledger.summarize([_row("rebuild", 1, 900)], trial_cores=9,
                             charge="as-run")
    assert s["rounds"][0]["fuzz_seconds_equivalent"] == 100.0
    assert s["total_fuzz_seconds_equivalent"] == 100.0


def test_summarize_reports_both_framings():
    """Both numbers travel together so a reader never has to re-run to compare."""
    s = cpu_ledger.summarize([_row("rebuild", 1, 900)], trial_cores=9)
    assert s["total_fuzz_seconds_equivalent"] == 900.0
    assert s["total_fuzz_seconds_equivalent_as_run"] == 100.0


def test_summarize_keeps_agent_wait_out_of_the_cost():
    rows = [_row("rebuild", 1, 60),
            _row("agent_wait", 1, 0.0, wall_s=1800.0, counts=False)]
    s = cpu_ledger.summarize(rows, trial_cores=9)
    assert s["total_core_s"] == 60
    assert s["rounds"][0]["agent_wait_s"] == 1800.0
    assert s["rounds"][0]["wall_s"] == 60


def test_summarize_does_not_report_shared_setup_as_agent_wait():
    """The baseline AFL build is uncounted because both arms get it -- but it is
    CPU work, not model latency, and must not inflate agent_wait_s."""
    rows = [_row("baseline_afl_build", 0, 0.0, wall_s=240.0, counts=False),
            _row("agent_wait", 0, 0.0, wall_s=600.0, counts=False)]
    s = cpu_ledger.summarize(rows)
    assert s["rounds"][0]["agent_wait_s"] == 600.0
    assert s["rounds"][0]["uncounted_wall_s"] == 840.0
    assert s["total_core_s"] == 0


def test_summarize_ranks_stages_by_cost():
    rows = [_row("rebuild", 1, 50), _row("profile_prebuild", 1, 500),
            _row("replay_gate", 1, 100)]
    s = cpu_ledger.summarize(rows)
    assert list(s["by_stage"]) == ["profile_prebuild", "replay_gate", "rebuild"]


def test_summarize_handles_an_empty_ledger():
    s = cpu_ledger.summarize([], trial_cores=9)
    assert s["total_core_s"] == 0
    assert s["rounds"] == []
