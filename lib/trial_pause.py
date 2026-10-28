"""Experimental AFL testcase-boundary pause, with an expiring host lease.

This deliberately does not use Docker's freezer: an in-flight testcase's
wall-clock timeout keeps advancing during a Docker pause. The pass-through
custom mutator acknowledges only between executions. No target/harness edits.
The trial remains Docker-running, so normal monitoring must not treat this as
an exit. Deadlines are wall time; pausing never extends a trial's budget.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import threading
import time
import uuid
import weakref

_controllers = weakref.WeakValueDictionary()
_registry_lock = threading.Lock()


class PauseError(RuntimeError):
    """An exclusive measurement must be discarded if its pause was lost."""


class TrialPause:
    def __init__(self, directory, *, lease_seconds=2.0, is_running=None):
        if lease_seconds < 0.2:
            raise ValueError("pause lease must be at least 0.2 seconds")
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.lease_seconds = lease_seconds
        self._lock = threading.RLock()
        self._generation = 0
        self._container = None
        self._active = None
        self._reason = "trial has not started"
        self.deadline = None
        self._is_running = is_running

    def _running(self, container_id):
        if self._is_running is not None:
            return self._is_running(container_id)
        from lib import docker_util
        return docker_util.container_is_running(container_id)

    def started(self, container_id, *, deadline=None):
        """Call only after the old container is gone and a new one is launched."""
        with self._lock:
            with _registry_lock:
                if self._container:
                    _controllers.pop(self._container, None)
                _controllers[container_id] = self
            self._generation += 1
            self._active = None
            self._container = container_id
            self.deadline = deadline
            self._reason = None
            for name in ("request", "ack"):
                (self.directory / name).unlink(missing_ok=True)

    def cancel(self, reason="trial stopping"):
        """Invalidate an in-flight measurement BEFORE stop, swap, or shutdown.

        Never wait for the measurement thread: cancellation must be able to
        resume/stop the trial even when that thread is blocked in a build/tool.
        New pause scopes are refused until started() attaches a new container.
        """
        with self._lock:
            self._generation += 1
            self._reason = reason
            self._active = None
            (self.directory / "request").unlink(missing_ok=True)

    def _acknowledged(self, token):
        try:
            fields = (self.directory / "ack").read_text().split()
            return len(fields) == 2 and fields[0] == token and int(fields[1]) > 0
        except (OSError, ValueError):
            return False

    @contextmanager
    def paused(self, *, timeout=10.0, max_pause=120.0, deadline=None):
        """Acknowledge a boundary, hold it for this scope, then resume.

        deadline is the trial's absolute time.time() deadline, not a renewed
        fuzzing-time budget. If the lease, deadline, or container generation is
        lost, raise PauseError so the caller cannot keep that measurement.
        finally resumes on exceptions. A dead controller's lease expires in
        the C hook; there is no frozen container needing a live watchdog.
        """
        if timeout <= 0 or max_pause <= 0:
            raise ValueError("pause bounds must be positive")
        token = uuid.uuid4().hex
        stop = threading.Event()
        errors = []
        with self._lock:
            if self._reason or not self._container:
                raise PauseError(self._reason or "trial has not started")
            if self._active:
                raise PauseError("trial already has an active pause scope")
            now = time.monotonic()
            end = now + max_pause
            for bound in (self.deadline, deadline):
                if bound is not None:
                    end = min(end, now + bound - time.time())
            if end <= now:
                raise PauseError("trial deadline already reached")
            generation = self._generation
            container = self._container
            self._active = token

        def renew():
            with self._lock:
                if self._generation != generation or self._active != token:
                    raise PauseError(self._reason or "trial container changed")
                now = time.monotonic()
                if now >= end:
                    raise PauseError("pause or trial deadline reached")
                until = min(end, now + self.lease_seconds)
                tmp = self.directory / ("request." + token)
                try:
                    tmp.write_text(f"{token} {int(until * 1000)}\n")
                    os.replace(tmp, self.directory / "request")
                finally:
                    tmp.unlink(missing_ok=True)

        def heartbeat():
            while not stop.wait(self.lease_seconds / 4):
                try:
                    renew()
                except Exception as exc:
                    errors.append(exc)
                    return  # Existing lease expires even if cleanup cannot run.

        worker = None
        try:
            if not self._running(container):
                raise PauseError("trial container exited before pause")
            renew()
            worker = threading.Thread(target=heartbeat, daemon=True)
            worker.start()
            wait_until = min(end, time.monotonic() + timeout)
            while not self._acknowledged(token):
                if errors:
                    raise PauseError(str(errors[0]))
                if time.monotonic() >= wait_until:
                    raise PauseError("fuzzer did not acknowledge a testcase-boundary pause")
                time.sleep(0.01)
            renew()  # A simultaneous stop/relaunch must prevent entering the scope.
            if not self._running(container):
                raise PauseError("trial container exited while waiting for pause")
            yield container
            # Check before renewing: a lease that expired must not be resurrected
            # and accepted as if the fuzzer had stayed paused throughout.
            if errors or not self._acknowledged(token):
                raise PauseError(str(errors[0]) if errors else "pause acknowledgement lost")
            if not self._running(container):
                raise PauseError("trial container exited during measurement")
            renew()  # Includes generation and wall-clock deadline checks.
        finally:
            stop.set()
            if worker:
                worker.join(timeout=self.lease_seconds)
            with self._lock:
                if self._active == token:
                    self._active = None
                    (self.directory / "request").unlink(missing_ok=True)
            # Wait for the actual hook to release, rather than claiming resume
            # merely because the request was removed. Do not remove its ack.
            limit = time.monotonic() + self.lease_seconds + 0.2
            while self._acknowledged(token) and time.monotonic() < limit:
                time.sleep(0.01)
            if self._acknowledged(token):
                raise PauseError("fuzzer did not release pause acknowledgement")


def cancel_trial(trial, reason):
    controller = getattr(trial, "pause_controller", None)
    if controller is not None:
        controller.cancel(reason)


def cancel_container(container_id, reason):
    with _registry_lock:
        controller = _controllers.get(container_id)
    if controller is not None:
        with controller._lock:
            if controller._container == container_id:
                controller.cancel(reason)
