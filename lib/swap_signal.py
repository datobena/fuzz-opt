"""Cross-arm restart signal.

The online (optimized) arm is relaunched whenever a fold is accepted -- a hot
swap. That restart is not free: AFL's in-memory crash-dedup bitmap is NOT
restored on resume, and the queue is re-calibrated on start, so an arm that
restarts more accumulates more crash ARTIFACTS while losing queue
prioritisation and energy state.

Batch b6 tried to equalise that by restarting the baseline on a fixed 3h
cadence. It over-corrected: the baseline took 7 restarts against the online
arm's 2, and on a slow target (assimp, ~68 exec/s) the baseline could not
rebuild its queue state inside a 3h window -- late-stage detections fell from 6
to 1 and coverage dropped 20.8%. The headline separation that produced was an
artifact of handicapping the baseline, not a property of the optimizer.

This module mirrors the swaps instead of guessing a cadence: the online loop
records each EFFECTIVE swap here, and baseline monitors restart once per
recorded swap. Count parity is then exact by construction, and timing parity is
bounded by the monitor poll interval.

Two kinds of swap, because there are two designs:

  shared     legacy hot_swap: ONE binary is swapped into every optimized trial
             at once, so every baseline trial mirrors it. record_swap(iter, n).
  per-trial  hot_swap_one: optimizer k swaps only optimized trial k. Only
             baseline trial k mirrors it -- the pairing the common-random-numbers
             seeds already use (same trial_id, seeds BASELINE/OPTIMIZED offset
             apart). record_swap(iter, 1, k).

A baseline monitor reads generation_for(its trial_id), which counts the shared
swaps plus its own partner's. Before this split every per-trial swap bumped the
one global counter and every baseline restarted on any bump: with ten
optimizers each baseline restarted ~10x more than any single optimized trial,
the b6 over-correction again, multiplied by ten.

Both arms are monitored by one ThreadPoolExecutor in a single process
(phase3_runner.run_trials), so a module-level object is sufficient -- no IPC.
"""
from __future__ import annotations

import threading
import time


class SwapSignal:
    """Monotonic counters of hot swaps that actually reached running trials."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._generation = 0              # every recorded swap, either kind
        self._shared = 0                  # shared-binary swaps (all trials)
        self._per_trial: dict[int, int] = {}  # trial_id -> its own swaps
        self._swaps: list[dict] = []

    @property
    def generation(self) -> int:
        """All swaps recorded, of either kind. For logging; a baseline monitor
        must use generation_for(), or it mirrors every optimizer's swaps."""
        with self._lock:
            return self._generation

    def generation_for(self, trial_id: int) -> int:
        """Swaps baseline trial `trial_id` should have mirrored so far: every
        shared swap plus the per-trial swaps of ITS paired optimized trial.

        In a shared-binary campaign the per-trial term stays 0, so this equals
        the old global generation and legacy mirroring is unchanged."""
        with self._lock:
            return self._shared + self._per_trial.get(int(trial_id), 0)

    def record_swap(self, iter_n: int, n_trials: int,
                    trial_id: int | None = None) -> int:
        """Record one hot swap; returns the generation the mirroring baseline(s)
        will now see: generation_for(trial_id) for a per-trial swap, the shared
        count for a shared one.

        `trial_id` None = a shared-binary swap (legacy hot_swap). An int = a
        per-trial swap that reached only that optimized trial (hot_swap_one).

        A swap that relaunched ZERO trials is not recorded. Those happen when a
        round is accepted after the last trial has already exited (b6 assimp r5
        at 24.32h, b5 assimp r5 at 26.74h, selinux r8 at 24.56h). Mirroring one
        would restart a baseline to match an event the online arm never
        experienced.
        """
        with self._lock:
            if n_trials <= 0:
                return self._shared + (self._per_trial.get(int(trial_id), 0)
                                       if trial_id is not None else 0)
            self._generation += 1
            if trial_id is None:
                self._shared += 1
                mirrored = self._shared
            else:
                tid = int(trial_id)
                self._per_trial[tid] = self._per_trial.get(tid, 0) + 1
                mirrored = self._shared + self._per_trial[tid]
            self._swaps.append({"iter": iter_n, "ts": time.time(),
                                "trials": n_trials, "generation": self._generation,
                                "trial_id": trial_id, "mirror_generation": mirrored})
            return mirrored

    def swaps(self) -> list[dict]:
        with self._lock:
            return list(self._swaps)

    def reset(self) -> None:
        """Test hook only."""
        with self._lock:
            self._generation = 0
            self._shared = 0
            self._per_trial = {}
            self._swaps = []


SIGNAL = SwapSignal()
