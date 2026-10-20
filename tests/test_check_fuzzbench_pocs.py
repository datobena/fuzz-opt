"""tools/check_fuzzbench_pocs.py --per-trial: newest deployed binary first, walking
back only while a PoC does not reproduce."""
import importlib.util
import json
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "check_fuzzbench_pocs",
    Path(__file__).resolve().parent.parent / "tools" / "check_fuzzbench_pocs.py")
cfp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cfp)

BENCH = "bloaty_fuzz_target_52948c"


def _trial(root: Path, outcomes: dict) -> Path:
    t = root / "optimized" / "online" / "trials" / "trial_00"
    for it, outcome in outcomes.items():
        (t / it / "bin").mkdir(parents=True)
        (t / it / "bin" / "fuzz_target").write_bytes(b"x")
        if outcome:
            (t / it / "round_provenance.json").write_text(json.dumps({"outcome": outcome}))
    return t


def test_deployed_bins_skip_rejected_and_unfinished(tmp_path):
    t = _trial(tmp_path, {"iter_00": None, "iter_01": "kept",
                          "iter_02": "rejected-no-speedup", "iter_03": "kept",
                          "iter_04": None})
    assert [b.parent.name for b in cfp.deployed_bins(t, "fuzz_target")] == [
        "iter_00", "iter_01", "iter_03"]


def _fake_check(repro_on):
    seen = []

    def check(bench, b, cpus, image):
        seen.append(b.parent.name)
        return {"pocs": {"p": b.parent.name in repro_on}, "negatives": {"n": True}}
    return check, seen


def test_per_trial_stops_at_latest_when_it_reproduces(tmp_path, monkeypatch, capsys):
    _trial(tmp_path, {"iter_00": None, "iter_01": "kept", "iter_02": "kept"})
    check, seen = _fake_check({"iter_00", "iter_01", "iter_02"})
    monkeypatch.setattr(cfp, "check", check)
    assert not cfp.per_trial(BENCH, tmp_path, "0", None)
    assert seen == ["iter_02"]


def test_per_trial_walks_back_to_the_fixing_round(tmp_path, monkeypatch, capsys):
    _trial(tmp_path, {"iter_00": None, "iter_01": "kept", "iter_02": "kept",
                      "iter_03": "kept"})
    check, seen = _fake_check({"iter_00", "iter_01"})
    monkeypatch.setattr(cfp, "check", check)
    assert not cfp.per_trial(BENCH, tmp_path, "0", None)
    assert seen == ["iter_03", "iter_02", "iter_01"]
    assert "stops reproducing at iter_02" in capsys.readouterr().out


def test_per_trial_flags_a_trial_that_never_reproduces(tmp_path, monkeypatch):
    _trial(tmp_path, {"iter_00": None, "iter_01": "kept"})
    check, seen = _fake_check(set())
    monkeypatch.setattr(cfp, "check", check)
    assert cfp.per_trial(BENCH, tmp_path, "0", None)
    assert seen == ["iter_01", "iter_00"]
