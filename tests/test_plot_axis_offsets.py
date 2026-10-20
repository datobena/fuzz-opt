"""plot_coverage_growth converts each trial's AFL run_time to wall-clock with
offsets MEASURED per segment, not summed from the logged swap downtime.

The logged downtime (HOT-SWAP -> swap complete, ~15 s) misses the minutes a
relaunched AFL spends re-calibrating its queue before its clock resumes: r2
bloaty's online curves were drawn ~18 min early by 24 h, and every swap gap
as ~15 s when it was ~4 min.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "analysis"))
import plot_coverage_growth as P  # noqa: E402

S = 1_000_000.0


def _trial(root, arm, tid, start, *, final_rt, stats_wall, end_wall,
           plot=(), rows=None):
    d = root / arm / f"trial_{tid:02d}"
    (d / "afl_out" / "default").mkdir(parents=True)
    (d / "metadata.json").write_text(json.dumps({
        "start_time": start, "end_time": end_wall,
        "final_stats": {"run_time": final_rt}}))
    fs = d / "afl_out" / "default" / "fuzzer_stats"
    fs.write_text(f"start_time        : 1\nrun_time          : {final_rt}\n")
    os.utime(fs, (stats_wall, stats_wall))
    (d / "afl_out" / "default" / "plot_data").write_text(
        "# relative_time, ...\n" + "".join(f"{x}, 0\n" for x in plot))
    if rows is not None:
        tl = root / "optimized" / "online" / "trials" / f"trial_{tid:02d}"
        tl.mkdir(parents=True, exist_ok=True)
        (tl / "swap_timeline.json").write_text(json.dumps(rows))
    return d


def _campaign(tmp_path, row_extra=None):
    """One online trial, one swap. It fuzzed 2.5 s late (start-up), was killed
    at run_time 1000 -- its last stats write said 980 -- and resumed 250 s
    later at that stale 980; its last write: run_time 2000. The baseline
    started 1.5 s late and never stopped."""
    exp = tmp_path / "proj-cve"
    row = {"iter": 1, "ts": S + 1002.5, "trial_id": 0,
           "state_at_swap": {"run_time": "980"}, **(row_extra or {})}
    plot = list(range(0, 1001, 5)) + list(range(1040, 2001, 5))
    _trial(exp, "optimized", 0, S, final_rt=2000, stats_wall=S + 2272.5,
           end_wall=S + 2290.0, plot=plot, rows=[row])
    _trial(exp, "baseline", 0, S + 0.5, final_rt=3600,
           stats_wall=S + 0.5 + 3601.5, end_wall=S + 0.5 + 3620.0)
    return exp


def test_to_run_time_is_the_inverse_of_to_wall():
    w = [(0.0, 5.0), (100.0, 60.0), (300.0, 20.0)]
    for t in (0.0, 50.0, 99.0, 100.0, 250.0, 400.0):
        assert P.to_run_time(float(P.to_wall([t], w)[0]), w) == pytest.approx(t)
    # An instant inside a stop is the run_time the trial stopped at.
    assert P.to_run_time(130.0, w) == 100.0
    assert P.to_run_time(-5.0, w) == 0.0


def test_offsets_are_measured_per_segment_for_both_arms(tmp_path, capsys,
                                                         monkeypatch):
    monkeypatch.chdir(tmp_path)
    exp = _campaign(tmp_path)
    ax = P.axis_windows(exp, "e", {0: [(1000.0, 15.0)]})
    # Segment 0: ts against the run_time it STOPPED at (plot_data: 1000, not
    # the stale 980). Segment 1: the last fuzzer_stats write.
    assert ax["optimized"][0] == [pytest.approx((0.0, 2.5)),
                                  pytest.approx((1000.0, 270.0))]
    assert ax["stops"][0] == [pytest.approx((1000.0, 270.0))]
    assert ax["lead"][0] == pytest.approx(2.5)
    assert ax["baseline"][0] == [pytest.approx((0.0, 1.5))]
    w = ax["optimized"][0]
    assert P.to_wall([500.0], w)[0] == pytest.approx(502.5)
    assert P.to_wall([1500.0], w)[0] == pytest.approx(1772.5)
    out = capsys.readouterr().out
    assert "MEASURED" in out and "15.0 s logged downtime -> 272.5 s measured" in out
    assert "FALLBACK" not in out


def test_newer_rows_read_both_clocks_exactly(tmp_path, monkeypatch):
    """stats_ts pins the stale run_time to its own instant; resumed_* is the
    relaunched AFL's first write. Both make the offset exact -- the latter
    stands in for an end measurement that is not (stats file touched since,
    so end_time's teardown would add 17.5 s)."""
    monkeypatch.chdir(tmp_path)
    exp = _campaign(tmp_path, {"stats_ts": S + 982.0,
                               "resumed_ts": S + 1252.5,
                               "resumed_run_time": 980})
    fs = exp / "optimized" / "trial_00" / "afl_out" / "default" / "fuzzer_stats"
    os.utime(fs, (S + 5000.0, S + 5000.0))
    ax = P.axis_windows(exp, "e", {0: [(1000.0, 15.0)]}, report=False)
    assert ax["lead"][0] == pytest.approx(2.0)          # 982 - 980
    assert ax["stops"][0] == [pytest.approx((1000.0, 270.5))]


def test_a_trial_without_matching_rows_falls_back_and_says_so(tmp_path, capsys,
                                                              monkeypatch):
    monkeypatch.chdir(tmp_path)
    exp = _campaign(tmp_path)
    (exp / "optimized" / "online" / "trials" / "trial_00" / "swap_timeline.json").unlink()
    ax = P.axis_windows(exp, "e", {0: [(1000.0, 15.0)]})
    assert ax["optimized"][0] == [(1000.0, 15.0)] and ax["lead"][0] == 0.0
    assert "FALLBACK to the logged swap downtime: trial_00 (0 swap_timeline " \
           "rows vs 1 logged swaps)" in capsys.readouterr().out


def test_a_restarted_baseline_stays_on_run_time(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    exp = _campaign(tmp_path)
    (tmp_path / ".e.log").write_text(
        "x Started trial proj-cve-baseline-trial_00 (container=a)\n" * 2)
    ax = P.axis_windows(exp, "e", {0: [(1000.0, 15.0)]})
    assert 0 not in ax["baseline"]
    assert "baseline left on run_time: trial_00 (restarted)" in capsys.readouterr().out


def test_the_end_offset_falls_back_to_end_time_for_a_touched_stats_file(tmp_path):
    d = _trial(tmp_path, "baseline", 0, S, final_rt=3600,
               stats_wall=S + 9999.0, end_wall=S + 3620.0)
    md = json.loads((d / "metadata.json").read_text())
    assert P._end_offset(d, md) == (pytest.approx(20.0), "end_time", 3600.0)


def test_charges_sit_on_the_measured_axis(tmp_path):
    """A round finishing inside a stop is charged at the run_time the trial
    stopped at; one after it, net of the whole measured stop."""
    exp = tmp_path / "proj-cve"
    online = exp / "optimized" / "online"
    online.mkdir(parents=True)
    rows = [{"stage": "rebuild", "t_start": S + 10, "t_end": S + 20,
             "wall_s": 10, "core_s": c, "counts": True, "trial_id": 0, "iter": it}
            for it, c in ((1, 100.0), (2, 200.0))]
    (online / "cpu_ledger.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    m = exp / "optimized" / "trial_00" / "metadata.json"
    m.parent.mkdir(parents=True)
    m.write_text(json.dumps({"start_time": S}))
    for it, f in ((1, S + 1100.0), (2, S + 1500.0)):
        p = online / "trials" / "trial_00" / f"iter_{it:02d}" / "round_provenance.json"
        p.parent.mkdir(parents=True)
        p.write_text("{}")
        os.utime(p, (f, f))
    w = P.per_trial_charge_windows(exp, {0: [(0.0, 2.5), (1000.0, 270.0)]},
                                   report=False)
    assert w[0] == [(1000.0, 100.0), pytest.approx((1500.0 - 272.5, 200.0))]
