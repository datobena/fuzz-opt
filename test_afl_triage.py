"""Tests for lib/afl_triage.py — which of many crashes is the TARGET bug.

Under libFuzzer a trial ended at its first crash, so "did it crash" and "did it
find the target bug" were nearly the same question. AFL keeps going, so a trial
now yields many crashes of which only some are the bug under study. Counting all
of them would inflate the find rate; taking the earliest would corrupt TTB.
"""
import pytest

from lib.afl_triage import summarize_triage, target_bug_ttb, triage_trial


def _mk(d, name):
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(b"x")


def test_only_the_matching_signature_counts_as_the_target_bug(tmp_path, monkeypatch):
    import lib.afl_triage as t

    crashes = tmp_path / "crashes"
    _mk(crashes, "id:000000,sig:06,time:1000,execs:10")   # different bug
    _mk(crashes, "id:000001,sig:06,time:5000,execs:50")   # the target bug
    _mk(crashes, "id:000002,sig:06,time:9000,execs:90")   # different bug

    verdicts = {
        "id:000000,sig:06,time:1000,execs:10": ("other_crash", "heap-use-after-free"),
        "id:000001,sig:06,time:5000,execs:50": ("poc_crash", "stack-buffer-overflow"),
        "id:000002,sig:06,time:9000,execs:90": ("other_crash", "heap-use-after-free"),
    }
    monkeypatch.setattr(t, "_replay", lambda ctx, path: verdicts[path.name])

    got = triage_trial(crashes, image="i", out_dir="o", fuzz_target="f",
                       expected_signature="Stack-buffer-overflow WRITE {*}")
    assert sum(1 for g in got if g["verdict"] == "poc_crash") == 1


def test_ttb_is_the_matching_crash_not_the_earliest(tmp_path, monkeypatch):
    """The earliest crash is usually a shallower, different bug."""
    import lib.afl_triage as t

    crashes = tmp_path / "crashes"
    _mk(crashes, "id:000000,sig:06,time:1000,execs:10")
    _mk(crashes, "id:000001,sig:06,time:5000,execs:50")

    verdicts = {
        "id:000000,sig:06,time:1000,execs:10": ("other_crash", "heap-use-after-free"),
        "id:000001,sig:06,time:5000,execs:50": ("poc_crash", "stack-buffer-overflow"),
    }
    monkeypatch.setattr(t, "_replay", lambda ctx, path: verdicts[path.name])

    got = triage_trial(crashes, image="i", out_dir="o", fuzz_target="f",
                       expected_signature="Stack-buffer-overflow WRITE {*}")
    assert target_bug_ttb(got) == pytest.approx(5.0)


def test_ttb_is_none_when_nothing_matched(tmp_path, monkeypatch):
    import lib.afl_triage as t

    crashes = tmp_path / "crashes"
    _mk(crashes, "id:000000,sig:06,time:1000,execs:10")
    monkeypatch.setattr(t, "_replay", lambda ctx, path: ("other_crash", "other"))

    got = triage_trial(crashes, image="i", out_dir="o", fuzz_target="f",
                       expected_signature="Stack-buffer-overflow WRITE {*}")
    assert target_bug_ttb(got) is None


def test_did_not_run_is_never_silently_treated_as_no_crash(tmp_path, monkeypatch):
    """An artifact that failed to execute must be surfaced as an error, not
    quietly counted as 'not the target bug'."""
    import lib.afl_triage as t

    crashes = tmp_path / "crashes"
    _mk(crashes, "id:000000,sig:06,time:1000,execs:10")
    monkeypatch.setattr(t, "_replay", lambda ctx, path: ("did_not_run", ""))

    got = triage_trial(crashes, image="i", out_dir="o", fuzz_target="f",
                       expected_signature="Stack-buffer-overflow WRITE {*}")
    assert got[0]["verdict"] == "did_not_run"
    assert summarize_triage(got)["errors"] == 1


def test_readme_is_not_triaged(tmp_path, monkeypatch):
    import lib.afl_triage as t

    crashes = tmp_path / "crashes"
    _mk(crashes, "README.txt")
    monkeypatch.setattr(t, "_replay", lambda ctx, path: ("poc_crash", "x"))
    assert triage_trial(crashes, image="i", out_dir="o", fuzz_target="f",
                        expected_signature="s") == []


def test_summarize_counts_each_verdict(tmp_path):
    triaged = [
        {"verdict": "poc_crash", "timestamp_s": 5.0},
        {"verdict": "other_crash", "timestamp_s": 1.0},
        {"verdict": "other_crash", "timestamp_s": 2.0},
        {"verdict": "did_not_run", "timestamp_s": 3.0},
    ]
    s = summarize_triage(triaged)
    assert s == {"total": 4, "poc_crash": 1, "other_crash": 2, "errors": 1}


def test_missing_crash_dir_is_empty(tmp_path):
    assert triage_trial(tmp_path / "nope", image="i", out_dir="o",
                        fuzz_target="f", expected_signature="s") == []
