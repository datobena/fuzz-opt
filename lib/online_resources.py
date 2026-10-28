"""Actual one-core budgets for per-trial online optimization.

The optimizer thread and its children inherit the trial's affinity. Docker
work and the agent are explicitly pinned to that same CPU. Profiling/replay
quiesce both the fuzzer and agent; builds and smoke compete with fuzzing.
There is no per-operation CPU-time accounting in this mode.
"""
from contextlib import contextmanager, nullcontext
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

_LOCAL = threading.local()
EXCLUSIVE_STAGES = frozenset({"profile_prebuild", "baseline_profile", "broker_replay",
                               "replay_gate", "crash_filter"})


def current():
    return getattr(_LOCAL, "policy", None)


@contextmanager
def bind(policy):
    """Bind explicitly on broker threads too; never use process-global routing."""
    previous = current()
    affinity = os.sched_getaffinity(0)
    try:
        _LOCAL.policy = policy
        if policy is not None:
            os.sched_setaffinity(0, {policy.cpu})
        yield policy
    finally:
        _LOCAL.policy = previous
        os.sched_setaffinity(0, affinity)


@contextmanager
def freeze_agent(container, deadline):
    """Freeze the agent while its host-side broker measures, with crash recovery.

    The guard inherits this CPU affinity and a pipe owned only by this process.
    EOF (controller death) or the trial deadline removes the owned agent, so an
    agent cannot remain frozen forever or later write an abandoned source tree.
    Normal unpause sends 'done' and exits the guard without removing anything.
    Fuzzers use the cooperative lease protocol instead of this Docker freezer.
    """
    if not container:
        yield
        return
    guard = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--guard", container, str(deadline)],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    thawed = False
    try:
        subprocess.run(["docker", "pause", container], capture_output=True, check=True, timeout=30)
        try:
            yield
        finally:
            subprocess.run(["docker", "unpause", container], capture_output=True,
                           check=True, timeout=30)
            thawed = True
    finally:
        if guard.stdin:
            try:
                if thawed:
                    guard.stdin.write(b"done\n")
                    guard.stdin.flush()
                guard.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        try:
            guard.wait(timeout=35)
        except subprocess.TimeoutExpired:
            # Removal is safer than leaving a suspended writer behind.
            subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=30)
            guard.kill()
            guard.wait()


class TrialResources:
    def __init__(self, trial, *, deadline=None):
        if getattr(trial, "pause_controller", None) is None:
            raise RuntimeError("shared-core optimization requires a pause-capable trial")
        self.trial = trial
        self.cpu = int(trial.cpu)
        self.deadline = deadline
        self.agent_container = None
        self._exclusive = threading.RLock()
        self._depth = threading.local()

    @contextmanager
    def operation(self, stage):
        if stage not in EXCLUSIVE_STAGES:
            yield
            return
        with self._exclusive:
            depth = getattr(self._depth, "value", 0)
            self._depth.value = depth + 1
            try:
                if depth:
                    yield
                    return
                deadline = self.deadline or self.trial.pause_controller.deadline or time.time() + 3600
                with self.trial.pause_controller.paused(max_pause=3600, deadline=deadline):
                    with freeze_agent(self.agent_container, deadline):
                        yield
            finally:
                self._depth.value = depth


def operation(stage):
    policy = current()
    return policy.operation(stage) if policy else nullcontext()


def validate_trial_cpus(trials):
    from lib.core_lock import thread_siblings
    siblings = thread_siblings()
    occupied = set()
    allowed = os.sched_getaffinity(0)
    for trial in trials:
        cpu = int(trial.cpu)
        physical = set(siblings.get(cpu, {cpu}))
        if cpu not in allowed or physical & occupied:
            raise RuntimeError("shared-core trials need distinct available physical cores (including HT siblings)")
        occupied.update(physical)


if __name__ == "__main__":
    import select
    container, deadline = sys.argv[2], float(sys.argv[3])
    ready, _, _ = select.select([sys.stdin], [], [], max(0, deadline - time.time()))
    if not ready or sys.stdin.readline() != "done\n":
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=30)
