import json
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analysis"))
import plot_coverage_growth as P


def test_pause_events_are_wall_time_and_do_not_shift_samples(tmp_path):
    control = tmp_path / "optimized/online/trials/trial_03/pause_control"
    control.mkdir(parents=True)
    (control / "trial.json").write_text(json.dumps({"wall_start": 1000}))
    (control / "events.jsonl").write_text('\n'.join(json.dumps(row) for row in [
        {"event": "pause", "token": "a", "wall_ts": 1020},
        {"event": "resume", "token": "a", "wall_ts": 1040},
    ]) + '\npartial')
    intervals = P.pause_intervals(tmp_path)
    assert intervals == {3: [(20, 40)]}
    xs, ys = P.mark_pauses(([0, 10, 50], [1, 2, 9]), intervals[3])
    assert xs[-1] == 50 and ys[-1] == 9  # No +20s CPU charge / clock correction.
    assert np.all(ys[(xs >= 20) & (xs <= 40)] == 2)
    rx, ry = P.mark_pauses(([0, 10, 30, 50], [100, 100, 100, 100]), intervals[3], zero=True)
    assert np.all(ry[(rx >= 20) & (rx <= 40)] == 0)
    assert rx[-1] == 50


def test_shared_core_plots_ignore_stale_cost_files(tmp_path):
    online = tmp_path / "optimized/online"
    online.mkdir(parents=True)
    (online / "campaign_provenance.json").write_text(json.dumps({"resource_policy": "shared-trial-core"}))
    (online / "cpu_cost.json").write_text(json.dumps({"total_core_s": 99999}))
    (online / "cpu_ledger.jsonl").write_text(json.dumps({"stage": "rebuild", "core_s": 99999}) + '\n')
    assert P.cpu_charge_windows(tmp_path, "p", []) == []
    assert P.per_trial_charge_windows(tmp_path, {}) == {}
    assert "no synthetic charge" in P._charge_caption(tmp_path)


def test_plot_span_follows_the_campaign_budget(tmp_path):
    """A 6 h campaign is drawn on a 6 h axis; --hours overrides; no provenance -> 24 h.
    set_plot_span resizes the GRID every loader shares."""
    import json
    import numpy as np
    import plot_coverage_growth as P
    root = tmp_path / "exp"
    prov = root / "libxml2-x" / "optimized" / "online" / "campaign_provenance.json"
    prov.parent.mkdir(parents=True)
    prov.write_text(json.dumps({"duration_s": 21600}))
    assert P.plot_hours(root, None) == 6.0
    assert P.plot_hours(root, 24) == 24.0
    assert P.plot_hours(tmp_path / "none", None) == 24.0
    old_hours, old_grid = P.HOURS, P.GRID
    try:
        P.set_plot_span(6.0)
        assert P.HOURS == 6.0 and P.GRID[-1] == 6 * 3600 and np.all(np.diff(P.GRID) == 30)
    finally:
        P.set_plot_span(old_hours)
        assert P.GRID.shape == old_grid.shape
