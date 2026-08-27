"""The online arm must detect AFL crashes -- it is the headline measurement.

The online monitor scanned dirs["crashes"] (the libFuzzer-era artifact dir,
always empty under AFL) for libFuzzer filenames ("crash-", "oom-", "timeout-").
AFL writes <afl_out>/default/crashes/id:000000,sig:06,...,time:MS. The baseline
arm reads the AFL location, so ONLY the online arm's time-to-bug was censored --
a result that would have read as "optimization destroyed bug-finding" while the
optimized binaries had in fact already crashed 5 times.
"""
from __future__ import annotations

import phase3_online
from lib import afl


def _crash(ms, idx=0):
    return f"id:{idx:06d},sig:06,src:001535,time:{ms},execs:1,op:havoc,rep:1"


def test_afl_crash_names_are_parsed(tmp_path):
    """The names the old prefix filter could never match."""
    (tmp_path / _crash(11456452)).write_bytes(b"x")
    (tmp_path / "README.txt").write_text("not an artifact")
    found = afl.collect_crashes(tmp_path)
    assert len(found) == 1
    assert found[0]["timestamp_s"] == 11456.452


def test_the_monitor_reads_the_afl_directory_not_the_libfuzzer_one():
    src = __import__("inspect").getsource(phase3_online._monitor_online_trial)
    assert 'os.path.join(' in src and '"default", "crashes"' in src
    assert 'crashes_dir = dirs["crashes"]' not in src
    assert '"crash-", "oom-", "timeout-"' not in src   # libFuzzer prefixes gone
    assert "afl.collect_crashes" in src                # shared with the baseline arm


def test_no_per_session_offset_is_applied():
    """AFL_AUTORESUME restores the previous run_time, so `time:` is already
    campaign-cumulative. Measured on a live campaign: an online trial relaunched
    at 07:46 reported run_time 25976s at 11:56, matching the never-relaunched
    baseline's 26096s to within the swap downtime. Adding an offset would
    overstate every online crash by hours -- the same bias as censoring, inverted."""
    src = __import__("inspect").getsource(phase3_online._monitor_online_trial)
    assert "session_offset" not in src
    assert 'entry["timestamp_s"]' in src


def test_both_arms_use_the_same_crash_source():
    """The two monitors disagreeing is what produced the censored arm."""
    import inspect, phase3_runner
    assert "afl.collect_crashes" in inspect.getsource(
        phase3_online._monitor_online_trial)
    assert "afl.collect_crashes" in inspect.getsource(phase3_runner.monitor_trial)


# --- AFL archives crashes/ on every resume ---------------------------------
def _mk(d, ms, idx):
    d.mkdir(parents=True, exist_ok=True)
    (d / f"id:{idx:06d},sig:06,src:1,time:{ms},execs:1,op:havoc,rep:1").write_bytes(b"x")


def test_archived_crash_dirs_are_included(tmp_path):
    """AFL++ renames crashes/ to crashes.<ts> on resume and starts a fresh one.
    The online arm relaunches on every hot swap; the baseline arm never does. So
    reading only crashes/ loses the online arm's earlier finds and biases
    time-to-bug against exactly the arm under test -- one trial's first crash
    read as 21.4h when the artifact was written at 8.6 minutes."""
    base = tmp_path / "afl_out" / "default"
    _mk(base / "crashes.2026-08-03-10:23:52", 515200, 0)     # earliest, archived
    _mk(base / "crashes.2026-08-03-14:09:39", 10404910, 2)
    _mk(base / "crashes", 76958971, 7)                        # since last swap

    found = afl.collect_crashes(base / "crashes")
    assert len(found) == 3
    assert found[0]["timestamp_s"] == 515.2                   # not 76958.971


def test_a_never_relaunched_trial_is_unaffected(tmp_path):
    """The baseline arm has no archives; behaviour must not change for it."""
    base = tmp_path / "afl_out" / "default"
    _mk(base / "crashes", 4615200, 0)
    found = afl.collect_crashes(base / "crashes")
    assert len(found) == 1 and found[0]["timestamp_s"] == 4615.2


def test_duplicate_names_across_archives_are_counted_once(tmp_path):
    base = tmp_path / "afl_out" / "default"
    _mk(base / "crashes", 100000, 0)
    _mk(base / "crashes.2026-08-03-10:00:00", 100000, 0)      # same filename
    assert len(afl.collect_crashes(base / "crashes")) == 1


def test_missing_directory_still_returns_empty(tmp_path):
    assert afl.collect_crashes(tmp_path / "nope") == []
