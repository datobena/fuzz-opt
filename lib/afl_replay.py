"""Deterministic corpus replay timing for AFL++ builds.

The replay-speedup gate is what decides whether an optimization round is kept, so
it has to be able to run the binary it is judging. The optimizer skill ships a
replay_timing.py written for the libFuzzer era:

    RUNNER_IMAGE = "gcr.io/oss-fuzz-base/base-runner"
    exec /out/<target> /corpus -runs=0 -seed=N -print_final_stats=1

Neither half survives the AFL++ migration. base-runner does not carry the pinned
LLVM's libc++, so a target built with -stdlib=libc++ dies at exit 127 before main
("error while loading shared libraries: libc++.so.1"); and aflpp_driver
implements none of those libFuzzer flags, so even in a working image it would
never print the stat:: line the skill parses. run_replay_speedup catches the
failure and returns None, the gate reads that as "no measured speedup", and every
round of a 24h campaign is rejected -- a misconfiguration that looks exactly like
an optimizer that never found anything.

afl-showmap -i replays every file in a directory exactly once through the
forkserver: the AFL analogue of -runs=0. sandbox/broker.py already uses it for the
timings the AGENT sees, so this module reuses that command builder rather than
defining a second notion of "deterministic replay" -- the gate and the agent must
be measuring the same thing or the agent optimizes for one metric and is scored on
another.
"""
from __future__ import annotations

import logging
import statistics
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def measure_binary(
    *, out_dir: str | Path, corpus_dir: str | Path, fuzz_target: str, cpu: int,
    repeats: int, memory: str, shm_size: str, run_timeout: int, image: str,
    **_ignored,
) -> dict:
    """Median wall-clock of ``repeats`` deterministic replays, in seconds.

    Shaped like the skill's measure_binary so run_replay_speedup can consume
    either: returns ``median_time_s``, ``executed_units``, ``partial``.

    ``partial`` is always False. The skill needed it because a crashing input
    aborts a libFuzzer replay, truncating one binary's run and making the two
    incomparable; afl-showmap forks per input and keeps going, so both binaries
    always execute the whole frozen snapshot. ``executed_units`` is therefore the
    file count -- reported so the caller's rate-normalisation still reduces to
    baseline_time / optimized_time.

    ``**_ignored`` absorbs the libFuzzer-only knobs the caller still passes
    (seed, min_partial_units): replay order here is the directory walk and there
    is no prefix to salvage.
    """
    from sandbox.broker import BrokerContext, _replay_command

    ctx = BrokerContext(
        image=image, source_dir="", out_dir=str(out_dir),
        corpus_dir=str(corpus_dir), fuzz_target=fuzz_target, project="",
        cpu=int(cpu),
    )
    cmd = _replay_command(ctx)
    units = sum(1 for p in Path(corpus_dir).rglob("*") if p.is_file())

    times: list[float] = []
    for i in range(max(int(repeats), 1)):
        t0 = time.monotonic()
        r = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=run_timeout + 60)
        elapsed = time.monotonic() - t0
        # afl-showmap exits non-zero for ordinary conditions (2 = a target
        # timeout on some input). Only a run that produced no timing at all is
        # fatal; raising here is what makes a broken gate loud instead of a
        # silent None that reads as "no speedup".
        blob = (r.stdout or "") + (r.stderr or "")
        # Judge by what afl-showmap REPORTS, not by exit code: it exits 0 even
        # when it aborted before the forkserver (e.g. a bad -o), and the elapsed
        # time then measures start-up rather than execution -- a broken gate that
        # returns a confident number.
        if "coverage of" not in blob and "Captured" not in blob:
            raise RuntimeError(
                f"afl-showmap replay {i} produced no coverage report "
                f"(exit {r.returncode}): {blob[-300:]}"
            )
        times.append(elapsed)

    return {
        "median_time_s": statistics.median(times),
        "executed_units": units,
        "partial": False,
        "times_s": times,
        "runner": "afl-showmap",
    }
