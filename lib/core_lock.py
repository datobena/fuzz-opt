"""Cross-process exclusive lock for a single optimizer CPU core.

Each optimizer pins its docker work -- the agent's broker build/smoke/replay AND
the harness-side rebuild -- to one dedicated core. The broker's own accept loop is
serial, so two broker ops never overlap; but the broker and the harness rebuild are
*different processes* that share that one core, so a replay-timing measurement can
still run while a build is compiling on the same core. That inflates the replay wall
clock and corrupts the accept/reject gate (observed: an in-sandbox baseline inflated
~1.8x by a concurrent build).

This advisory ``flock`` makes the invariant explicit and process-independent: every
docker operation pinned to core N takes ``core_lock(N)`` first, so at most one build
OR replay OR smoke runs on that core at any instant. A replay simply waits for an
in-flight build to finish, then measures a quiet core. No-op when ``cpu is None``
(unpinned / legacy paths), so it is safe to wrap everywhere.
"""
from __future__ import annotations

import contextlib
import errno
import fcntl
import logging
import os
import tempfile
import time

logger = logging.getLogger(__name__)

# Shared by the broker and the harness, which are separate processes, so the lock
# directory must be a path both see. A single host runs both, so the default temp
# dir is correct; overridable for tests or an unusual layout.
LOCK_DIR = os.environ.get("FOLD_CORE_LOCK_DIR", tempfile.gettempdir())


def _lock_path(cpu: int) -> str:
    return os.path.join(LOCK_DIR, f"fold-core-{int(cpu)}.lock")


@contextlib.contextmanager
def core_lock(cpu: int | None, *, timeout: float | None = None):
    """Hold an exclusive lock on ``cpu`` for the duration of the ``with`` block.

    ``cpu is None`` -> no-op (unpinned path). ``timeout is None`` -> block until the
    core is free (the common case: a replay waits out a build). A finite ``timeout``
    proceeds UNLOCKED rather than failing the round if it expires -- a missed lock
    only risks a noisier measurement, never a lost round, so it must never raise.
    """
    if cpu is None:
        yield
        return
    path = _lock_path(cpu)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o666)
    acquired = False
    try:
        if timeout is None:
            fcntl.flock(fd, fcntl.LOCK_EX)
            acquired = True
        else:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except OSError as e:
                    if e.errno not in (errno.EAGAIN, errno.EACCES):
                        raise
                    if time.monotonic() >= deadline:
                        logger.warning("core %s lock busy after %.0fs; proceeding "
                                       "unlocked (measurement may be noisier)",
                                       cpu, timeout)
                        break
                    time.sleep(0.5)
        yield
    finally:
        if acquired:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


def parse_cpuset(spec) -> list[int]:
    """'2-5,9' / '7' / 7 -> sorted unique core ids ([] for None or '')."""
    if spec is None:
        return []
    cpus: set[int] = set()
    for tok in str(spec).split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            a, b = tok.split("-", 1)
            cpus.update(range(int(a), int(b) + 1))
        else:
            cpus.add(int(tok))
    return sorted(cpus)


@contextlib.contextmanager
def cpuset_lock(spec, *, timeout: float | None = None):
    """core_lock for every core of a cpuset spec (an int, '7' or '2-39').

    A multi-core setup build occupies all of its cores, so it takes all of their
    locks, always in ascending order so two holders can never deadlock. None or
    '' -> no-op, like core_lock(None)."""
    with contextlib.ExitStack() as stack:
        for c in parse_cpuset(spec):
            stack.enter_context(core_lock(c, timeout=timeout))
        yield


def format_cpuset(cpus) -> str:
    """[0, 1, 32, 33, ..., 39] -> '0-1,32-39' (the inverse of parse_cpuset)."""
    out: list[str] = []
    run: list[int] = []
    for c in sorted(set(int(x) for x in cpus)):
        if run and c == run[-1] + 1:
            run.append(c)
            continue
        if run:
            out.append(f"{run[0]}-{run[-1]}" if len(run) > 1 else str(run[0]))
        run = [c]
    if run:
        out.append(f"{run[0]}-{run[-1]}" if len(run) > 1 else str(run[0]))
    return ",".join(out)


SYS_CPU_DIR = "/sys/devices/system/cpu"


def thread_siblings(sys_cpu_dir: str = SYS_CPU_DIR) -> dict[int, frozenset[int]]:
    """{logical cpu: every logical cpu on the same PHYSICAL core, itself included}.

    Read from cpu*/topology/thread_siblings_list (this host: 80 logical, sibling of
    c is c+40 -> {0: {0, 40}, 40: {0, 40}, ...}). Two hyperthreads share one core's
    execution units, so "not on core c" has to mean "not on c or its sibling".
    Empty dict when the topology cannot be read; the caller decides what that means.
    """
    sib: dict[int, frozenset[int]] = {}
    try:
        names = os.listdir(sys_cpu_dir)
    except OSError:
        return {}
    for name in names:
        if not (name.startswith("cpu") and name[3:].isdigit()):
            continue
        path = os.path.join(sys_cpu_dir, name, "topology", "thread_siblings_list")
        try:
            with open(path) as f:
                sib[int(name[3:])] = frozenset(parse_cpuset(f.read().strip()))
        except (OSError, ValueError):
            continue                                # offline cpu: no topology
    return sib
