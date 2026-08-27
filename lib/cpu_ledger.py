"""Record the CPU cost of optimization work, in core-seconds.

The online arm pays for its speedup with CPU the baseline arm never spends:
profiling, corpus/mutation handling, rebuilds, the replay-timing gate, and the
build/smoke/replay operations the agent requests through the broker. On this
machine that work is pinned away from the fuzzing cores, so it costs the
campaign nothing -- but a coverage plot comparing the two arms has to be able to
answer "what would this have cost if it had run on the fuzzing cores?".

That question is answered in CORE-SECONDS, not wall-clock: a stage pinned to one
core for 300s costs 300 core-seconds, and on a 36-core trial pool that is 8.3
seconds of lost fuzzing wall-clock. Wall-clock alone would not compose across
stages of different widths.

What is deliberately NOT counted: time the optimizer spends waiting on the
model. It is recorded (cores=0, counts=False) so the timeline shows where a
round's wall-clock went, but it consumes no CPU that fuzzing could have used.
That is the whole reason the two are separated here rather than timing the round
end to end.

The ledger path travels in the environment because the writers are not one
process: the broker (sandbox/broker.py) serves the sandboxed agent from a
separate host process, and phase 2 runs in the orchestrator. Both append to the
same file. Appends are a single write() of one line under O_APPEND, which the
kernel keeps atomic well past any line this module produces, so concurrent
writers interleave by line rather than corrupting each other.
"""
from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager

LEDGER_ENV = "FUZZ_BENCH_CPU_LEDGER"
PROJECT_ENV = "FUZZ_BENCH_CPU_LEDGER_PROJECT"
ITER_ENV = "FUZZ_BENCH_CPU_LEDGER_ITER"


def ledger_path() -> str:
    """Where to append. Empty string disables recording entirely."""
    return os.environ.get(LEDGER_ENV, "")


def set_ledger_path(path: str | os.PathLike) -> None:
    """Point this process AND everything it spawns at `path`."""
    os.environ[LEDGER_ENV] = str(path)


def set_round(project: str | None = None, iter_n: int | None = None) -> None:
    """Tag subsequent records with the current project/round.

    Set in the environment rather than passed down because the deepest writers
    (the broker, phase 2's prebuild) are several layers below the code that
    knows which round is running, and threading it through every signature would
    touch far more surface than it is worth.
    """
    if project is not None:
        os.environ[PROJECT_ENV] = str(project)
    if iter_n is not None:
        os.environ[ITER_ENV] = str(iter_n)


def _current_iter() -> int | None:
    raw = os.environ.get(ITER_ENV, "")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def record(
    stage: str, *, wall_s: float, cores: float, counts: bool = True,
    project: str | None = None, iter_n: int | None = None,
    t_start: float | None = None, **extra,
) -> dict | None:
    """Append one stage record. Returns it, or None when recording is off.

    Never raises: a failure to record must not take down an optimization round
    that is otherwise fine.
    """
    path = ledger_path()
    if not path:
        return None
    now = time.time()
    t0 = now - wall_s if t_start is None else t_start
    row = {
        "stage": stage,
        "project": project if project is not None else os.environ.get(PROJECT_ENV, ""),
        "iter": iter_n if iter_n is not None else _current_iter(),
        "t_start": round(t0, 3),
        "t_end": round(t0 + wall_s, 3),
        "wall_s": round(wall_s, 3),
        "cores": cores,
        # The headline number. Zero for uncounted stages so a naive sum over the
        # whole file still yields the CPU cost.
        "core_s": round(wall_s * cores, 3) if counts else 0.0,
        "counts": counts,
        "pid": os.getpid(),
    }
    row.update(extra)
    line = json.dumps(row, sort_keys=True) + "\n"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            os.write(fd, line.encode())
        finally:
            os.close(fd)
    except OSError:
        return row
    return row


@contextmanager
def timed(stage: str, *, cores: float = 1, counts: bool = True,
          project: str | None = None, iter_n: int | None = None, **extra):
    """Time a block and record it, including when it raises.

    Yields a dict the caller may add fields to (outcome, file counts, ...); they
    are merged into the record. A stage that raises is still recorded, tagged
    ``error``, because failed work consumes CPU exactly like successful work --
    dropping it would understate the cost of a round that failed late.
    """
    t0 = time.time()
    info: dict = {}
    try:
        yield info
    except BaseException as exc:  # noqa: BLE001 - re-raised immediately
        record(stage, wall_s=time.time() - t0, cores=cores, counts=counts,
               project=project, iter_n=iter_n, t_start=t0,
               error=type(exc).__name__, **{**extra, **info})
        raise
    record(stage, wall_s=time.time() - t0, cores=cores, counts=counts,
           project=project, iter_n=iter_n, t_start=t0, **{**extra, **info})


def load(path: str | os.PathLike) -> list[dict]:
    """Read a ledger, skipping any partial trailing line."""
    rows: list[dict] = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return rows
    return rows


def summarize(rows: list[dict], *, trial_cores: int | None = None,
              charge: str = "per-replicate") -> dict:
    """Per-round and cumulative core-seconds, ready to overlay on a timeline.

    ``fuzz_seconds_equivalent`` converts core-seconds into the wall-clock a
    trial gives up to pay for optimization -- the number that belongs on a
    coverage-vs-time plot. Which conversion is right depends on what the trials
    represent:

    ``per-replicate`` (default)
        Charge every trial the FULL optimizer cost. Each online trial is one
        replicate of "a campaign run with online optimization", and a real
        campaign runs its own optimizer -- it does not get to share one with
        eight other campaigns. Sharing a single optimizer across the arm is an
        economy of the EXPERIMENT, not a property of the method, so dividing by
        the trial count would understate the method's cost by that factor.

    ``as-run``
        Charge ``core_s / trial_cores``, i.e. what this machine actually spent:
        one optimizer amortised over the arm. Correct for "what did this
        campaign cost me", wrong for "what does this method cost".

    The two differ by ``trial_cores`` (9 in the standard layout), which is large
    enough to flip a verdict: b5's PcapPlusPlus reads 1.01x net under as-run and
    0.85x -- a net LOSS against simply fuzzing longer -- per-replicate.
    """
    if charge not in ("per-replicate", "as-run"):
        raise ValueError(f"charge must be per-replicate or as-run, got {charge!r}")
    divisor = 1 if charge == "per-replicate" else (trial_cores or 1)
    per_round: dict = {}
    per_stage: dict = {}
    for r in rows:
        it = r.get("iter")
        cs = float(r.get("core_s") or 0.0)
        b = per_round.setdefault(it, {
            "iter": it, "core_s": 0.0, "wall_s": 0.0, "agent_wait_s": 0.0,
            "uncounted_wall_s": 0.0,
            "t_start": r.get("t_start"), "t_end": r.get("t_end"), "stages": {},
        })
        b["core_s"] += cs
        b["stages"][r.get("stage")] = round(
            b["stages"].get(r.get("stage"), 0.0) + cs, 3)
        if r.get("counts"):
            b["wall_s"] += float(r.get("wall_s") or 0.0)
        else:
            # Uncounted is not synonymous with model-wait: the shared baseline
            # build is uncounted too (both arms get it, so it is not a cost of
            # optimizing). Keep agent_wait_s to the agent_wait stage alone,
            # otherwise a four-minute build reads as four minutes of LLM latency.
            b["uncounted_wall_s"] += float(r.get("wall_s") or 0.0)
            if r.get("stage") == "agent_wait":
                b["agent_wait_s"] += float(r.get("wall_s") or 0.0)
        if r.get("t_start") is not None:
            b["t_start"] = min(b["t_start"], r["t_start"]) if b["t_start"] is not None else r["t_start"]
        if r.get("t_end") is not None:
            b["t_end"] = max(b["t_end"], r["t_end"]) if b["t_end"] is not None else r["t_end"]
        per_stage[r.get("stage")] = round(per_stage.get(r.get("stage"), 0.0) + cs, 3)

    rounds = sorted(per_round.values(),
                    key=lambda b: (b["iter"] is None, b["iter"]))
    cumulative = 0.0
    for b in rounds:
        cumulative += b["core_s"]
        b["core_s"] = round(b["core_s"], 3)
        b["wall_s"] = round(b["wall_s"], 3)
        b["agent_wait_s"] = round(b["agent_wait_s"], 3)
        b["uncounted_wall_s"] = round(b["uncounted_wall_s"], 3)
        b["cumulative_core_s"] = round(cumulative, 3)
        if trial_cores:
            b["fuzz_seconds_equivalent"] = round(b["core_s"] / divisor, 3)
            b["cumulative_fuzz_seconds_equivalent"] = round(cumulative / divisor, 3)
    total = {
        "total_core_s": round(cumulative, 3),
        "rounds": rounds,
        "by_stage": dict(sorted(per_stage.items(), key=lambda kv: -kv[1])),
        "trial_cores": trial_cores,
        "charge_model": charge,
    }
    if trial_cores:
        total["total_fuzz_seconds_equivalent"] = round(cumulative / divisor, 3)
        # Kept alongside so a reader can see both framings without re-running.
        total["total_fuzz_seconds_equivalent_as_run"] = round(
            cumulative / (trial_cores or 1), 3)
    return total
