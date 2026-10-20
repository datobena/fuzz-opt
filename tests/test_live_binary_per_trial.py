"""verify_crash_signatures.live_binary reads only THIS trial's swaps: a per-trial
swap_timeline.json lists every trial's swaps."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "analysis"))
import verify_crash_signatures as V  # noqa: E402


def test_other_trials_swaps_are_ignored(tmp_path):
    d = tmp_path / "trials" / "trial_03"
    for it in ("iter_01", "iter_02", "iter_03"):
        (d / it / "bin").mkdir(parents=True)
    (d / "swap_timeline.json").write_text(json.dumps([
        {"iter": 1, "ts": 100, "trial_id": 3},
        {"iter": 2, "ts": 200, "trial_id": 8},      # another trial's round 2
        {"iter": 3, "ts": 300, "trial_id": 3},
    ]))
    base = tmp_path / "baseline"
    assert V.live_binary(d, 0, 50, base)[1] == "iter_00"
    assert V.live_binary(d, 0, 250, base)[1] == "iter_01"
    assert V.live_binary(d, 0, 350, base)[1] == "iter_03"


def test_campaign_level_dir_keeps_every_row(tmp_path):
    d = tmp_path / "online"
    (d / "iter_02" / "bin").mkdir(parents=True)
    (d / "swap_timeline.json").write_text(json.dumps([{"iter": 2, "ts": 200}]))
    assert V.live_binary(d, 0, 250, tmp_path / "b")[1] == "iter_02"
