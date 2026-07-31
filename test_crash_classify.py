"""Tests for the canonical bug-find classifier (lib/crash_classify).

These lock in the definition that the pipeline previously lacked: only a real
sanitizer crash, before the run cutoff, that is not the empty-input boundary
artifact, counts as finding the target bug.
"""
from lib import crash_classify as cc

CUTOFF = 28800
EMPTY = f"crash-{cc.EMPTY_INPUT_SHA1}"


def _crash(ts, art="crash-abc123", ctype="crash"):
    return {"timestamp_s": ts, "artifact": art, "crash_type": ctype}


# --- is_target_bug_find: the three contamination sources it must reject ------
def test_real_crash_is_a_find():
    assert cc.is_target_bug_find(_crash(100.0), CUTOFF) is True


def test_slow_unit_is_not_a_find():
    # slow-units are crash_type "unknown" — the libavc contamination
    assert cc.is_target_bug_find(
        _crash(100.0, "slow-unit-xyz", "unknown"), CUTOFF) is False


def test_timeout_and_oom_are_not_finds():
    assert cc.is_target_bug_find(_crash(100.0, "timeout-x", "timeout"), CUTOFF) is False
    assert cc.is_target_bug_find(_crash(100.0, "oom-x", "oom"), CUTOFF) is False


def test_empty_input_boundary_artifact_is_not_a_find():
    # the libxml2 contamination: crash-<sha1("")> written at run shutdown
    assert cc.is_target_bug_find(_crash(28801.0, EMPTY, "crash"), CUTOFF) is False


def test_crash_at_or_after_cutoff_is_not_a_find():
    assert cc.is_target_bug_find(_crash(28800.0), CUTOFF) is False
    assert cc.is_target_bug_find(_crash(28850.0), CUTOFF) is False


def test_cutoff_none_still_filters_type_and_empty_input():
    # without a cutoff, type + empty-input exclusion must still apply
    assert cc.is_target_bug_find(_crash(999999.0), None) is True
    assert cc.is_target_bug_find(_crash(999999.0, EMPTY, "crash"), None) is False
    assert cc.is_target_bug_find(_crash(50.0, "slow-unit-x", "unknown"), None) is False


# --- trial_time_to_bug / trial_found_bug -------------------------------------
def test_ttb_skips_earlier_slow_units_and_returns_first_real_crash():
    # earliest event is a slow-unit; the real crash comes later -> TTB is the crash
    ct = [
        _crash(281.9, "slow-unit-a", "unknown"),
        _crash(4087.9, "crash-real", "crash"),
        _crash(9000.0, "slow-unit-b", "unknown"),
    ]
    assert cc.trial_time_to_bug(ct, CUTOFF) == 4087.9
    assert cc.trial_found_bug(ct, CUTOFF) is True


def test_trial_with_only_slow_units_is_censored():
    ct = [_crash(100.0, "slow-unit-a", "unknown"), _crash(200.0, "timeout-b", "timeout")]
    assert cc.trial_time_to_bug(ct, CUTOFF) is None
    assert cc.trial_found_bug(ct, CUTOFF) is False


def test_trial_with_only_boundary_artifact_is_censored():
    ct = [_crash(28801.8, EMPTY, "crash")]
    assert cc.trial_found_bug(ct, CUTOFF) is False


def test_empty_and_missing_crash_times():
    assert cc.trial_found_bug([], CUTOFF) is False
    assert cc.trial_found_bug(None, CUTOFF) is False
    assert cc.trial_time_to_bug(None, CUTOFF) is None


# --- summarize_trials --------------------------------------------------------
def test_summarize_uses_per_trial_cutoff():
    results = [
        {"crash_times": [_crash(50.0)], "max_total_time": CUTOFF},          # find
        {"crash_times": [_crash(28801.0, EMPTY, "crash")], "max_total_time": CUTOFF},  # boundary
        {"crash_times": [_crash(10.0, "slow-unit", "unknown")], "max_total_time": CUTOFF},  # slow
    ]
    s = cc.summarize_trials(results)
    assert s == {"found": 1, "total": 3, "ttbs": [50.0]}


# --- normalize_signature -----------------------------------------------------
def test_normalize_signature_matches_manifest_style():
    assert cc.normalize_signature("Heap-use-after-free READ 8") == "heap-use-after-free"
    assert (cc.normalize_signature("Heap-use-after-free READ 8")
            == cc.normalize_signature("heap-use-after-free"))
    assert cc.normalize_signature("Stack-buffer-overflow WRITE {*}") == "stack-buffer-overflow"
    assert cc.normalize_signature("") == ""


def test_summary_regex_is_not_polluted_by_a_relative_path():
    """A relative path in SUMMARY must not be absorbed into the bug class.

    Regression: the class previously allowed spaces, so
    "stack-buffer-overflow valid.c:1279" parsed as the class
    "stack-buffer-overflow valid" and silently failed to match the manifest --
    scoring a genuine target-bug crash as a different bug.
    """
    from lib.crash_classify import _SUMMARY_RE, normalize_signature

    blob = "SUMMARY: AddressSanitizer: stack-buffer-overflow valid.c:1279 in xmlS\n"
    detected = _SUMMARY_RE.search(blob).group(1).strip()
    assert detected == "stack-buffer-overflow"
    assert normalize_signature(detected) == normalize_signature(
        "Stack-buffer-overflow WRITE {*}")


def test_summary_regex_handles_the_usual_absolute_path():
    from lib.crash_classify import _SUMMARY_RE

    blob = ("SUMMARY: AddressSanitizer: heap-use-after-free "
            "/src/p/foo.c:12:5 in bar\n")
    assert _SUMMARY_RE.search(blob).group(1).strip() == "heap-use-after-free"
