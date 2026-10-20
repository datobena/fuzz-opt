"""live_binary compares a crash's AFL run_time against each swap's own run_time
(state_at_swap.run_time) when the swap row has one. The wall-clock fallback runs
early by everything the run_time clock lost before the crash, so a crash shortly
after a swap resolved to the previous round."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib.live_binary import live_binary  # noqa: E402


def _trial(tmp_path, rows):
    d = tmp_path / "trials" / "trial_02"
    for it in ("iter_01", "iter_02"):
        (d / it / "bin").mkdir(parents=True)
    (d / "swap_timeline.json").write_text(json.dumps(rows))
    return d


def test_crash_just_after_a_swap_resolves_by_run_time(tmp_path):
    # Swap 1 at wall +1000 s, when the trial's run_time read 900 s (fuzzer_stats
    # values are strings). A crash at run_time 950 fired 50 s after the swap;
    # read as wall-clock (+950 < +1000) it would land on the baseline.
    d = _trial(tmp_path, [
        {"iter": 1, "ts": 1000.0, "trial_id": 2, "state_at_swap": {"run_time": "900"}},
        {"iter": 2, "ts": 5000.0, "trial_id": 2, "state_at_swap": {"run_time": "4700"}},
    ])
    base = tmp_path / "baseline"
    assert live_binary(d, 0.0, 899.9, base)[1] == "iter_00"
    assert live_binary(d, 0.0, 900.0, base)[1] == "iter_01"
    assert live_binary(d, 0.0, 950.0, base)[1] == "iter_01"
    assert live_binary(d, 0.0, 4750.0, base)[1] == "iter_02"


def test_rows_without_a_run_time_keep_the_wall_clock_comparison(tmp_path):
    # _fuzzer_state records {} when fuzzer_stats was unreadable.
    d = _trial(tmp_path, [
        {"iter": 1, "ts": 1000.0, "trial_id": 2, "state_at_swap": {}},
        {"iter": 2, "ts": 5000.0, "trial_id": 2},
    ])
    base = tmp_path / "baseline"
    assert live_binary(d, 0.0, 950.0, base)[1] == "iter_00"
    assert live_binary(d, 0.0, 1001.0, base)[1] == "iter_01"
    assert live_binary(d, 0.0, 5001.0, base)[1] == "iter_02"
