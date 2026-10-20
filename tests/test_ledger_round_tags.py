"""Every CPU-ledger row must name the optimizer (trial_id) and round (iter) that
paid for it -- the coverage plot places each trial's cost at the finish of the
round it belongs to, and cannot do that from a row that says neither.

Two ways it went wrong before Oct 2026, each pinned here:
  * per-trial mode tagged the optimizer thread iter=0 once and thread-local beats
    the environment, so run_round's env tag never landed: every round said 0;
  * the broker serves from its own thread, which never saw the round thread's
    tags: broker rows had no trial_id and the LAST optimizer's iter.
And the crash monitor's live_binary call, which raised NameError on every crash.
"""
from __future__ import annotations

import json
import threading
import types
from pathlib import Path

import pytest

import phase3_online
from lib import cpu_ledger


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv(cpu_ledger.LEDGER_ENV, raising=False)
    monkeypatch.delenv(cpu_ledger.PROJECT_ENV, raising=False)
    monkeypatch.delenv(cpu_ledger.ITER_ENV, raising=False)
    cpu_ledger.clear_thread_round()
    yield
    cpu_ledger.clear_thread_round()


def _rows(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def _round_ctx(tmp_path, tid):
    online = tmp_path / f"trial_{tid:02d}"
    ctx = phase3_online.RoundContext(
        entry={"cve": "x"}, experiment_id="e", experiment_dir=str(tmp_path),
        online_dir=str(online), source_tree="", source_root="",
        project="php-src", image="", fuzz_target="t", poc_path=None,
        previous_best_bin="", prev_tag="iter_00", optimized_bin_dir="",
        ledger_path=str(online / "ledger.json"), swap_timeline_path="",
        profile_cpu=1)
    ctx.trial = types.SimpleNamespace(trial_id=tid, project="php-src", cve="x",
                                      variant="optimized")
    return ctx


# --- explicit tags ------------------------------------------------------------
def test_explicit_trial_id_beats_the_thread_tag(tmp_path):
    cpu_ledger.set_ledger_path(tmp_path / "l.jsonl")
    cpu_ledger.set_thread_round(project="p", iter_n=1, trial_id=2)
    cpu_ledger.record("broker_build", wall_s=1.0, cores=1, trial_id=7, iter_n=4)
    row = _rows(tmp_path / "l.jsonl")[0]
    assert (row["trial_id"], row["iter"]) == (7, 4)


def test_current_tags_reports_this_threads_round():
    cpu_ledger.set_thread_round(project="p", iter_n=3, trial_id=5)
    assert cpu_ledger.current_tags() == {"project": "p", "iter": 3, "trial_id": 5}
    seen = {}
    t = threading.Thread(target=lambda: seen.update(cpu_ledger.current_tags()))
    t.start(); t.join()
    # Another thread does NOT see these -- which is why the broker is handed them.
    assert seen["trial_id"] is None and seen["iter"] is None


# --- orchestrator rows: run_round re-tags its own thread every round -----------
def test_run_round_tags_rows_with_its_trial_and_round(monkeypatch, tmp_path):
    """Two optimizers in two threads, each first tagged iter 0 the way _drive
    does. Every row must carry its own (trial, round), not (trial, 0)."""
    cpu_ledger.set_ledger_path(tmp_path / "l.jsonl")
    monkeypatch.setattr(phase3_online.config, "ONLINE_FIXED_MUTATION_CORPUS", False)
    monkeypatch.setattr(phase3_online.config, "ONLINE_LIVE_MUTATION_CAPTURE", True)
    # Empty harvest -> the round records mutation_harvest and bails out early;
    # that one row is all this test needs.
    monkeypatch.setattr(phase3_online, "request_mutation_dump", lambda d, **k: [])
    monkeypatch.setattr(phase3_online, "collect_round_mutations", lambda *a, **k: 0)
    errors = []

    def drive(tid, iter_n):
        try:
            cpu_ledger.set_thread_round(project="php-src", iter_n=0, trial_id=tid)
            phase3_online.run_round(_round_ctx(tmp_path, tid),
                                    phase3_online.OnlineState(), iter_n)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=drive, args=a) for a in ((3, 2), (7, 5))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    got = {(r["trial_id"], r["iter"]) for r in _rows(tmp_path / "l.jsonl")
           if r["stage"] == "mutation_harvest"}
    assert got == {(3, 2), (7, 5)}


# --- broker rows: tagged from the session's snapshot, plus the broker core -----
def test_broker_rows_carry_the_sessions_trial_round_and_core(monkeypatch, tmp_path):
    import sandbox.broker as b
    cpu_ledger.set_ledger_path(tmp_path / "l.jsonl")
    # The process environment says another optimizer's round -- must not win.
    cpu_ledger.set_round(project="php-src", iter_n=9)
    monkeypatch.setattr(b, "_run_build", lambda ctx: (True, "ok"))
    monkeypatch.setattr(b, "_run_smoke", lambda ctx: (True, "ok"))
    monkeypatch.setattr(b, "_run_replay", lambda ctx, n: {"seconds": 1.0})
    ctx = b.BrokerContext(image="i", source_dir=str(tmp_path), out_dir=str(tmp_path),
                          corpus_dir=str(tmp_path), fuzz_target="t", project="php-src",
                          cpu=17, ledger_trial_id=4, ledger_iter=3)
    # Served from a thread with no tags of its own, exactly like serve().
    t = threading.Thread(target=lambda: [b.handle_request({"op": op}, ctx)
                                         for op in ("build", "smoke", "replay_time")])
    t.start(); t.join()
    rows = _rows(tmp_path / "l.jsonl")
    assert [r["stage"] for r in rows] == ["broker_build", "broker_smoke", "broker_replay"]
    assert all((r["trial_id"], r["iter"], r["cpus"]) == (4, 3, "17") for r in rows)


def test_session_hands_the_rounds_tags_to_its_broker(monkeypatch, tmp_path):
    """run_sandboxed_optimizer runs on the round's thread; the BrokerContext it
    builds must carry that thread's (trial, round)."""
    from sandbox import session
    seen = {}

    class Stop(Exception):
        pass

    def fake_ctx(**kw):
        seen.update(kw)
        raise Stop

    monkeypatch.setattr(session, "assert_sandbox_available", lambda: None)
    monkeypatch.setattr(session, "ensure_network", lambda: "net")
    monkeypatch.setattr(session.tempfile, "mkdtemp", lambda prefix="": str(tmp_path))
    monkeypatch.setattr(session.broker_mod, "BrokerContext", fake_ctx)
    cpu_ledger.set_thread_round(project="php-src", iter_n=6, trial_id=1)
    with pytest.raises(Stop):
        session.run_sandboxed_optimizer(
            source_dir=str(tmp_path), profile_dir=str(tmp_path),
            out_dir=str(tmp_path / "iter_06" / "validation_out"),
            corpus_dir=str(tmp_path), image="i", fuzz_target="t",
            project="php-src", prompt="p", agent_cpus="40")
    assert (seen["ledger_trial_id"], seen["ledger_iter"]) == (1, 6)


# --- crash monitor: live_binary is recorded, and after a swap it is that round -
def test_a_crash_after_a_swap_records_that_rounds_binary(monkeypatch, tmp_path):
    key = tmp_path / "php-src-x"
    base = key / "optimized" / "trial_03"
    crashes = base / "afl_out" / "default" / "crashes"
    crashes.mkdir(parents=True)
    start = 1_000_000.0
    # 250 s into the run (AFL time: is milliseconds) -- after this trial's
    # round-2 swap at +100 s, before its round-4 swap at +400 s.
    (crashes / "id:000000,sig:06,src:000001,time:250000,execs:9,op:havoc").write_text("x")
    tdir = key / "optimized" / "online" / "trials" / "trial_03"
    for it in ("iter_02", "iter_04"):
        (tdir / it / "bin").mkdir(parents=True)
    (tdir / "swap_timeline.json").write_text(json.dumps([
        {"iter": 2, "ts": start + 100, "trial_id": 3},
        {"iter": 3, "ts": start + 150, "trial_id": 8},   # another trial's swap
        {"iter": 4, "ts": start + 400, "trial_id": 3},
    ]))
    trial = types.SimpleNamespace(trial_id=3, container_id="c")
    monkeypatch.setattr(phase3_online.phase3_runner, "get_trial_dirs",
                        lambda e, t: {"base": str(base), "afl_out": str(base / "afl_out")})
    monkeypatch.setattr(phase3_online.phase3_runner, "classify_crash", lambda p: "asan")
    monkeypatch.setattr(phase3_online.docker_util, "container_is_running", lambda c: False)
    monkeypatch.setattr(phase3_online, "classify_exit", lambda **k: "budget_done")
    monkeypatch.setattr(phase3_online, "_finalize_online_trial", lambda *a, **k: None)
    state = phase3_online.OnlineState()
    state.trials[3] = {"overall_start": start, "crash_times": [],
                       "seen_crashes": set(), "state": "running"}
    phase3_online._monitor_online_trial(trial, "e", 86400, state)
    recs = state.trials[3]["crash_times"]
    assert [r["live_binary"] for r in recs] == ["iter_02"]
