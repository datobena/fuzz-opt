"""lib/swap_signal: which baseline trials mirror which hot swap.

Per-trial mode (hot_swap_one) has ten optimizers swapping ten binaries. Each
swap used to bump ONE global generation that every baseline monitor restarted
on, so every baseline restarted ~10x more often than any single optimized
trial. Baseline trial k must mirror only optimized trial k (same trial_id, the
common-random-numbers seed pair); the legacy shared-binary swap still reaches
every baseline.
"""
from lib import swap_signal


def test_per_trial_swap_reaches_only_its_paired_baseline():
    sig = swap_signal.SwapSignal()
    assert sig.record_swap(1, 1, 3) == 1
    assert sig.generation_for(3) == 1
    for other in (0, 7, 9):
        assert sig.generation_for(other) == 0, "trial 3's swap is not trial %d's" % other


def test_ten_optimizers_swapping_once_each_restart_each_baseline_once():
    sig = swap_signal.SwapSignal()
    for tid in range(10):
        sig.record_swap(1, 1, tid)
    assert sig.generation == 10, "global count still sees every swap (logging)"
    assert all(sig.generation_for(tid) == 1 for tid in range(10))


def test_shared_swap_reaches_every_baseline_as_before():
    sig = swap_signal.SwapSignal()
    assert sig.record_swap(1, 10) == 1
    assert sig.record_swap(2, 10) == 2
    assert all(sig.generation_for(tid) == 2 for tid in range(10))
    assert sig.generation == 2


def test_shared_and_per_trial_counts_add_up_for_the_pair():
    sig = swap_signal.SwapSignal()
    sig.record_swap(1, 10)          # shared
    sig.record_swap(2, 1, 4)        # trial 4 only
    assert sig.generation_for(4) == 2
    assert sig.generation_for(5) == 1


def test_swap_that_reached_no_trial_is_not_recorded():
    sig = swap_signal.SwapSignal()
    assert sig.record_swap(5, 0, 2) == 0
    assert sig.record_swap(5, 0) == 0
    assert sig.generation == 0 and sig.generation_for(2) == 0
    assert sig.swaps() == []


def test_swaps_log_names_the_trial():
    sig = swap_signal.SwapSignal()
    sig.record_swap(3, 1, 6)
    sig.record_swap(4, 10)
    rows = sig.swaps()
    assert [r["trial_id"] for r in rows] == [6, None]
    assert rows[0]["mirror_generation"] == 1


def test_reset_clears_per_trial_counts():
    sig = swap_signal.SwapSignal()
    sig.record_swap(1, 1, 2)
    sig.record_swap(1, 10)
    sig.reset()
    assert sig.generation == 0 and sig.generation_for(2) == 0
