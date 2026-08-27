"""A round that succeeds on a RETRY must record its result where the round looks.

optimization.diff is what run_round reads for opt_applied. The retry path wrote
attempt_<n>.diff instead, so a round whose first attempt died (expired token) and
whose second attempt succeeded was recorded as "no changes made" and reverted --
discarding a gate-validated 1.276x speedup.
"""
from __future__ import annotations

import inspect

import phase2_setup as ps


def test_optimization_diff_is_written_regardless_of_attempt():
    src = inspect.getsource(ps.optimize_and_build)
    assert '"optimization.diff" if attempt == 0 else' not in src
    assert 'os.path.join(diff_output_dir, "optimization.diff")' in src


def test_per_attempt_copy_is_still_kept_for_forensics():
    src = inspect.getsource(ps.optimize_and_build)
    assert 'f"attempt_{attempt}.diff"' in src
    assert "if attempt > 0:" in src


def test_the_round_reads_optimization_diff():
    """Pin the coupling that made the mismatch silent."""
    import phase3_online
    src = inspect.getsource(phase3_online.run_round)
    assert '"optimization.diff"' in src


def test_retry_resets_the_tree_to_the_profiled_state():
    """The profile is taken once per round. A retry that inherits the previous
    attempt's half-finished edits is optimizing a tree the profile no longer
    describes -- the agent reported wasting three cycles re-folding code that had
    already been folded."""
    src = inspect.getsource(ps.optimize_and_build)
    i = src.index("credential refreshed")
    window = src[max(0, i - 900):i + 200]
    assert '"reset", "--hard", "HEAD"' in window
    assert '"clean", "-fd"' in window
