"""Tests for phase-4 bug-survival classification.

With the bug-preservation gate removed, an optimized arm that finds nothing is
ambiguous: either it was slower/unlucky, or the optimizer removed the bug and it
was structurally incapable of finding it. Pooling those two would make a removed
bug look like a performance regression -- and bug-survival rate is now a headline
result, not a diagnostic.
"""
from phase4_analysis import classify_trial_outcome, summarize_bug_survival


def test_finding_the_bug_is_found_regardless_of_verdict():
    assert classify_trial_outcome(ttb=12.5, poc_verdict="reproduced") == "found"


def test_no_finding_with_a_live_bug_is_not_found():
    """The bug is present; the trial was slower or unlucky. Censored, not excluded."""
    assert classify_trial_outcome(ttb=None, poc_verdict="reproduced") == "not_found"


def test_no_finding_with_a_removed_bug_is_bug_absent():
    """The binary cannot express the bug -- excluding this from TTB stats is the
    whole point of recording the PoC verdict."""
    assert classify_trial_outcome(ttb=None, poc_verdict="no_crash") == "bug_absent"


def test_a_find_despite_a_no_crash_verdict_is_flagged():
    """Contradiction: the PoC did not reproduce but fuzzing found the bug. Never
    silently resolve it -- it means the verdict or the triage is wrong."""
    assert classify_trial_outcome(ttb=3.0, poc_verdict="no_crash") == "found"


def test_unverified_arms_are_not_assumed_present():
    """A missing or failed verdict must not be read as 'bug is there'."""
    assert classify_trial_outcome(ttb=None, poc_verdict="did_not_run") == "unverified"
    assert classify_trial_outcome(ttb=None, poc_verdict=None) == "unverified"


def test_survival_summary_counts_and_rates():
    arms = [
        {"variant": "optimized", "poc_verdict": "reproduced"},
        {"variant": "optimized", "poc_verdict": "reproduced"},
        {"variant": "optimized", "poc_verdict": "no_crash"},
        {"variant": "optimized", "poc_verdict": "wrong_crash"},
    ]
    s = summarize_bug_survival(arms)
    assert s["total"] == 4
    assert s["survived"] == 2
    assert s["removed"] == 2          # no_crash and wrong_crash both lost the bug
    assert s["survival_rate"] == 0.5


def test_survival_summary_excludes_unverified_from_the_rate():
    """An arm we could not verify is not evidence in either direction."""
    arms = [
        {"variant": "optimized", "poc_verdict": "reproduced"},
        {"variant": "optimized", "poc_verdict": "no_crash"},
        {"variant": "optimized", "poc_verdict": "did_not_run"},
    ]
    s = summarize_bug_survival(arms)
    assert s["total"] == 3
    assert s["unverified"] == 1
    assert s["survival_rate"] == 0.5   # 1 of 2 verified, not 1 of 3


def test_survival_rate_is_none_when_nothing_is_verified():
    s = summarize_bug_survival([{"variant": "optimized", "poc_verdict": "did_not_run"}])
    assert s["survival_rate"] is None
