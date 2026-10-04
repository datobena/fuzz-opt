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

Both arms are monitored by one ThreadPoolExecutor in a single process
(phase3_runner.run_trials), so a module-level object is sufficient -- no IPC.
"""
from __future__ import annotations

import threading
import time


class SwapSignal:
    """Monotonic counter of hot swaps that actually reached running trials."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._generation = 0
        self._swaps: list[dict] = []

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    def record_swap(self, iter_n: int, n_trials: int) -> int:
        """Record one hot swap; returns the new generation.

        A swap that relaunched ZERO trials is not recorded. Those happen when a
        round is accepted after the last trial has already exited (b6 assimp r5
        at 24.32h, b5 assimp r5 at 26.74h, selinux r8 at 24.56h). Mirroring one
        would restart a baseline to match an event the online arm never
        experienced.
        """
        if n_trials <= 0:
            return self.generation
        with self._lock:
            self._generation += 1
            self._swaps.append({"iter": iter_n, "ts": time.time(),
                                "trials": n_trials, "generation": self._generation})
            return self._generation

    def swaps(self) -> list[dict]:
        with self._lock:
            return list(self._swaps)

    def reset(self) -> None:
        """Test hook only."""
        with self._lock:
            self._generation = 0
            self._swaps = []


SIGNAL = SwapSignal()
