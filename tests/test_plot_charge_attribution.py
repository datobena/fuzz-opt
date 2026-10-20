"""plot_coverage_growth charges each trial its own optimizer CPU at the finish of
the round it belongs to, and the charges CONSERVE the ledger's counted total.

The version this replaces put every trial-tagged row at the first round (they
all said iter 0), dropped broker shares of trials that sat a round out, and
never charged setup: php r2 plotted ~8.8 h/trial against a true 13.8 h.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "analysis"))
import plot_coverage_growth as P  # noqa: E402

T0 = 1_000_000.0


def _row(stage, t_start, t_end, core_s, trial_id=None, it=0, counts=True):
    return {"stage": stage, "t_start": t_start, "t_end": t_end,
            "wall_s": t_end - t_start, "core_s": core_s if counts else 0.0,
            "counts": counts, "trial_id": trial_id, "iter": it}


def _total(att):
    return sum(sum(v.values()) for v in att["charges"].values()) + att["setup_core_s"]


def test_new_style_rows_go_straight_to_their_trial_and_round():
    rows = [
        _row("ccache_template_build", T0 - 500, T0 - 100, 1000.0),
        _row("rebuild", T0 + 10, T0 + 20, 30.0, trial_id=0, it=1),
        _row("broker_build", T0 + 30, T0 + 40, 50.0, trial_id=0, it=2),
        _row("broker_build", T0 + 30, T0 + 40, 70.0, trial_id=1, it=1),
        _row("agent_wait", T0 + 25, T0 + 45, 0.0, trial_id=1, it=1, counts=False),
    ]
    att = P.attribute_ledger(rows, optimizers=[0, 1],
                             finishes={0: {1: T0 + 25, 2: T0 + 50}, 1: {1: T0 + 60}},
                             campaign_start=T0)
    assert att["style"] == "new"
    assert att["charges"] == {0: {1: 30.0, 2: 50.0}, 1: {1: 70.0}}
    assert att["setup_core_s"] == 1000.0
    assert _total(att) == pytest.approx(att["ledger_core_s"])


def test_old_style_rows_are_placed_by_timestamp_and_session_overlap():
    """Old ledger: every trial-tagged row says iter 0, broker rows have no
    trial. Rounds: trial 0 finishes at +100 and +200; trial 1 at +150."""
    rows = [
        _row("mutation_harvest", T0 + 10, T0 + 12, 2.0, trial_id=0),
        _row("replay_gate", T0 + 90, T0 + 99, 9.0, trial_id=0),
        _row("mutation_harvest", T0 + 120, T0 + 121, 1.0, trial_id=0),   # round 2
        _row("mutation_harvest", T0 + 15, T0 + 16, 1.0, trial_id=1),
        _row("agent_wait", T0 + 20, T0 + 80, 0.0, trial_id=0, counts=False),
        _row("agent_wait", T0 + 60, T0 + 140, 0.0, trial_id=1, counts=False),
        # Inside trial 0's session only -> all to trial 0, round 1.
        _row("broker_build", T0 + 30, T0 + 50, 40.0),
        # Inside both sessions -> split evenly.
        _row("broker_replay", T0 + 65, T0 + 75, 10.0),
        _row("rebuild", T0 + 180, T0 + 190, 10.0, trial_id=0),            # round 2
        _row("replay_gate", T0 + 145, T0 + 148, 3.0, trial_id=1),
        # Inside no session -> split over the optimizers ACTIVE then (trial 1's
        # last row ended at +148), into the round whose window holds it.
        # Never dropped.
        _row("broker_smoke", T0 + 160, T0 + 161, 6.0),
    ]
    att = P.attribute_ledger(rows, optimizers=[0, 1],
                             finishes={0: {1: T0 + 100, 2: T0 + 200}, 1: {1: T0 + 150}},
                             campaign_start=T0)
    assert att["style"] == "old"
    assert att["charges"][0] == pytest.approx({1: 2 + 9 + 40 + 5, 2: 1 + 10 + 6})
    assert att["charges"][1] == pytest.approx({1: 1 + 3 + 5})
    assert (att["split_by_session"], att["split_by_activity"]) == (2, 1)
    assert _total(att) == pytest.approx(att["ledger_core_s"])


def _campaign(tmp_path, rows, finishes, starts):
    exp = tmp_path / "proj-cve"
    online = exp / "optimized" / "online"
    online.mkdir(parents=True)
    (online / "cpu_ledger.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows))
    for t, s in starts.items():
        m = exp / "optimized" / f"trial_{t:02d}" / "metadata.json"
        m.parent.mkdir(parents=True)
        m.write_text(json.dumps({"start_time": s}))
    for t, rounds in finishes.items():
        for it, f in rounds.items():
            p = online / "trials" / f"trial_{t:02d}" / f"iter_{it:02d}" / "round_provenance.json"
            p.parent.mkdir(parents=True)
            p.write_text("{}")
            os.utime(p, (f, f))
    return exp


def test_windows_put_setup_at_zero_and_rounds_at_their_finish(tmp_path, capsys):
    rows = [
        _row("ccache_template_noise_build", T0 - 900, T0 - 10, 2000.0),
        _row("rebuild", T0 + 1000, T0 + 1100, 100.0, trial_id=0, it=1),
        _row("rebuild", T0 + 5000, T0 + 5100, 300.0, trial_id=0, it=2),
        _row("rebuild", T0 + 2000, T0 + 2100, 200.0, trial_id=1, it=1),
    ]
    exp = _campaign(tmp_path, rows,
                    finishes={0: {1: T0 + 1200, 2: T0 + 5200}, 1: {1: T0 + 2200}},
                    starts={0: T0, 1: T0 + 5})
    # Trial 0 stopped 20 s for a swap at run_time 1300, before its round 2.
    w = P.per_trial_charge_windows(exp, {0: [(1300.0, 20.0)]})
    assert w[0] == [(0.0, 1000.0), (1200.0, 100.0), (5180.0, 300.0)]
    assert w[1] == [(0.0, 1000.0), (2195.0, 200.0)]
    assert sum(c for v in w.values() for _, c in v) == pytest.approx(2600.0)
    out = capsys.readouterr().out
    assert "charged at run_time 0" in out and "diff +0.000" in out


# --- old ledgers: broker rows placed by each session's broker_audit.log -------
def _audit(*entries):
    """{(trial, iter): [(ts, op)]}, entries given as (trial, iter, op, ts)."""
    out = {}
    for t, it, op, ts in entries:
        out.setdefault((t, it), []).append((ts, op))
    return {k: sorted(v) for k, v in out.items()}


def test_audit_log_places_broker_rows_exactly_where_one_session_fits():
    """Both trials' agent sessions overlap every broker row, so the old split
    gave each row half to each trial. The audit logs say who ran what."""
    rows = [
        _row("agent_wait", T0 + 10, T0 + 300, 0.0, trial_id=0, counts=False),
        _row("agent_wait", T0 + 10, T0 + 300, 0.0, trial_id=1, counts=False),
        # trial 0's build: its audit entry 2 s before the row closes
        # (restore_ownership runs after the audit write).
        _row("broker_build", T0 + 20, T0 + 80.4, 60.0),
        # trial 1's replay: two passes, closed by the bracket entry.
        _row("broker_replay", T0 + 30, T0 + 90.2, 60.0, ),
        # Both sessions close a smoke in the same second: ambiguous -> split.
        _row("broker_smoke", T0 + 100, T0 + 110.1, 10.0),
        # No session logged anything near its end: unmatched -> split.
        _row("broker_smoke", T0 + 200, T0 + 210.0, 4.0),
    ]
    audit = _audit((0, 1, "build", T0 + 78), (1, 1, "replay", T0 + 60),
                   (1, 1, "replay", T0 + 90), (1, 1, "replay-bracket", T0 + 90),
                   (0, 1, "smoke", T0 + 110), (1, 1, "smoke", T0 + 110))
    att = P.attribute_ledger(rows, optimizers=[0, 1],
                             finishes={0: {1: T0 + 400}, 1: {1: T0 + 400}},
                             campaign_start=T0, audit=audit)
    assert att["charges"][0] == pytest.approx({1: 60 + 5 + 2})
    assert att["charges"][1] == pytest.approx({1: 60 + 5 + 2})
    assert att["untagged_core_s"] == pytest.approx(
        {"matched": 120.0, "ambiguous": 10.0, "unmatched": 4.0})
    assert _total(att) == pytest.approx(att["ledger_core_s"])
    # Without the logs every row is split: same totals, nothing matched.
    plain = P.attribute_ledger(rows, optimizers=[0, 1],
                               finishes={0: {1: T0 + 400}, 1: {1: T0 + 400}},
                               campaign_start=T0)
    assert plain["untagged_core_s"]["matched"] == 0.0
    assert _total(plain) == pytest.approx(_total(att))


def test_a_session_busy_with_another_row_or_op_is_not_a_candidate():
    """Two trials replay concurrently and both close a replay in the second
    one of the rows ends. Trial 1's log has a build entry INSIDE row A, so it
    cannot have been serving A (one request at a time) -> A is trial 0's.
    Row B overlaps A, whose owner is now known -> B is trial 1's."""
    rows = [
        _row("broker_replay", T0 + 100, T0 + 200.1, 50.0),          # A
        _row("broker_replay", T0 + 150, T0 + 200.3, 30.0),          # B
    ]
    audit = _audit((0, 2, "replay", T0 + 150), (0, 2, "replay", T0 + 200),
                   (1, 3, "build", T0 + 120), (1, 3, "replay", T0 + 200))
    att = P.attribute_ledger(rows, optimizers=[0, 1],
                             finishes={0: {2: T0 + 500}, 1: {3: T0 + 500}},
                             campaign_start=T0, audit=audit)
    assert att["charges"] == {0: {2: 50.0}, 1: {3: 30.0}}
    assert att["untagged_core_s"]["matched"] == pytest.approx(80.0)


# --- round finish: provenance, not transcripts written after the round --------
def test_round_finish_is_provenance_not_late_transcripts(tmp_path):
    it1 = tmp_path / "iter_01"
    (it1 / "sandbox" / "transcripts").mkdir(parents=True)
    for rel, t in (("round_provenance.json", T0 + 100),
                   ("live_mutation_meta.json", T0 + 10),
                   ("sandbox/transcripts/s.jsonl", T0 + 900)):
        (it1 / rel).write_text("{}")
        os.utime(it1 / rel, (t, t))
    # No provenance: the agent ran, so its sandbox is the finish evidence.
    it2 = tmp_path / "iter_02"
    (it2 / "sandbox").mkdir(parents=True)
    for rel, t in (("live_mutation_meta.json", T0 + 1000),
                   ("sandbox/broker_audit.log", T0 + 1500)):
        (it2 / rel).write_text("{}")
        os.utime(it2 / rel, (t, t))
    # Bailed before the agent: only the meta file.
    (tmp_path / "iter_03").mkdir()
    (tmp_path / "iter_03" / "round_corpus_meta.json").write_text("{}")
    os.utime(tmp_path / "iter_03" / "round_corpus_meta.json", (T0 + 2000,) * 2)
    assert P._round_finishes(tmp_path) == {1: T0 + 100, 2: T0 + 1500, 3: T0 + 2000}


def test_a_finish_past_the_budget_is_clamped_to_the_end_and_said(tmp_path, capsys):
    end = P.HOURS * 3600
    rows = [_row("rebuild", T0 + 1000, T0 + 1100, 100.0, trial_id=0, it=1),
            _row("rebuild", T0 + end, T0 + end + 50, 40.0, trial_id=0, it=2)]
    exp = _campaign(tmp_path, rows,
                    finishes={0: {1: T0 + 1200, 2: T0 + end + 1800}},
                    starts={0: T0})
    w = P.per_trial_charge_windows(exp, {0: [(1300.0, 20.0)]})
    assert w[0] == [(1200.0, 100.0), (end - 20.0, 40.0)]
    out = capsys.readouterr().out
    assert "clamped to the end" in out and "diff +0.000" in out


def test_caption_names_setup_only_when_there_was_some(tmp_path):
    online = tmp_path / "optimized" / "online"
    online.mkdir(parents=True)
    (online / "cpu_cost.json").write_text(json.dumps({"optimizers": 10}))
    assert "setup" not in P._charge_caption(tmp_path, True, setup_core_s=0.0)
    assert "+ setup / 10 at t=0" in P._charge_caption(
        tmp_path, True, setup_core_s=3600.0, optimizers=10)


def test_a_session_with_two_brokers_is_never_excluded_by_the_one_request_rule():
    """Old sessions sometimes had two brokers on one audit log (a retried or
    orphaned agent). Trial 0's log shows a replay finishing INSIDE its own
    1500 s build: the one-request-at-a-time rule does not hold for it, so it
    must not be used to hand trial 0's replay to trial 1."""
    rows = [
        _row("agent_wait", T0 + 10, T0 + 2000, 0.0, trial_id=0, counts=False),
        _row("agent_wait", T0 + 10, T0 + 2000, 0.0, trial_id=1, counts=False),
        _row("broker_build", T0 + 100, T0 + 1600.5, 1500.0),        # only trial 0
        _row("broker_replay", T0 + 200, T0 + 237.2, 30.0),          # 0 or 1
    ]
    audit = _audit((0, 1, "replay", T0 + 237), (0, 1, "build", T0 + 1599),
                   (1, 1, "replay", T0 + 237))
    att = P.attribute_ledger(rows, optimizers=[0, 1],
                             finishes={0: {1: T0 + 3000}, 1: {1: T0 + 3000}},
                             campaign_start=T0, audit=audit)
    assert att["untagged_core_s"] == pytest.approx(
        {"matched": 1500.0, "ambiguous": 30.0, "unmatched": 0.0})
    assert att["charges"][0] == pytest.approx({1: 1515.0})
    assert att["charges"][1] == pytest.approx({1: 15.0})


def test_a_flagged_session_does_not_win_a_row_its_rival_also_fails():
    """bug-php trial_02 round 3: two builds closing in one second -- its own
    two brokers, never flagged -- so it failed the one-request test on both.
    Flagged trial_00 failed it too, but only trial_00 was exempt, so it took
    both rows (3474 core-s). Exemption is symmetric: neither is held to it."""
    rows = [
        _row("agent_wait", T0 + 10, T0 + 4000, 0.0, trial_id=0, counts=False),
        _row("agent_wait", T0 + 10, T0 + 4000, 0.0, trial_id=2, counts=False),
        # trial 0 shows two brokers: a replay closes inside its own build.
        _row("broker_build", T0 + 100, T0 + 1600.5, 1500.0),
        _row("broker_build", T0 + 2000, T0 + 3000.4, 1000.0),
        _row("broker_build", T0 + 2100, T0 + 3000.6, 900.0),
    ]
    audit = _audit((0, 3, "replay", T0 + 237), (0, 3, "build", T0 + 1599),
                   (0, 3, "replay", T0 + 2500), (0, 3, "build", T0 + 2996),
                   (2, 3, "build", T0 + 3000), (2, 3, "build", T0 + 3000))
    fin = {0: {3: T0 + 5000}, 2: {3: T0 + 5000}}
    att = P.attribute_ledger(rows, optimizers=[0, 2], finishes=fin,
                             campaign_start=T0, audit=audit)
    assert att["untagged_core_s"] == pytest.approx(
        {"matched": 1500.0, "ambiguous": 1900.0, "unmatched": 0.0})
    assert att["charges"][2] == pytest.approx({3: 950.0})
    # With trial 0's own build closing on its 2996 entry, that entry backs
    # that row alone: both disputed builds are trial 2's.
    rows.append(_row("broker_build", T0 + 2900, T0 + 2996.3, 90.0))
    att = P.attribute_ledger(rows, optimizers=[0, 2], finishes=fin,
                             campaign_start=T0, audit=audit)
    assert att["charges"][0] == pytest.approx({3: 1590.0})
    assert att["charges"][2] == pytest.approx({3: 1900.0})
    assert _total(att) == pytest.approx(att["ledger_core_s"])


def test_one_audit_entry_backs_one_row_and_a_late_owner_is_found():
    """r2 mbedtls: trial 2's build entry landed 5.7 s before its row closed --
    outside the old 5 s lead -- so trial 7, finishing a build that second, was
    the sole candidate for BOTH rows on one entry and got flagged two-broker.
    With 10 s the owner is a candidate, trial 2's smoke (issued after its
    build returned) rules it out of the other row, and trial 7's single entry
    then backs that row alone."""
    rows = [
        _row("broker_build", T0 + 100, T0 + 201.7, 100.0),          # trial 2's
        _row("broker_build", T0 + 110, T0 + 203.2, 90.0),           # trial 7's
        _row("broker_smoke", T0 + 201.9, T0 + 203.4, 1.0),
        _row("broker_smoke", T0 + 203.5, T0 + 204.6, 2.0),
    ]
    audit = _audit((2, 1, "build", T0 + 196), (2, 1, "smoke", T0 + 203),
                   (7, 1, "build", T0 + 201), (7, 1, "smoke", T0 + 205))
    m = P._AuditMatcher(audit)
    assert m.resolve(rows) == [[(2, 1)], [(7, 1)], [(2, 1)], [(7, 1)]]
    assert m.flagged == set()
    att = P.attribute_ledger(rows, optimizers=[2, 7],
                             finishes={2: {1: T0 + 500}, 7: {1: T0 + 500}},
                             campaign_start=T0, audit=audit)
    assert att["charges"][2] == pytest.approx({1: 101.0})
    assert att["charges"][7] == pytest.approx({1: 92.0})
