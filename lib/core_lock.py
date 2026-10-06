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
