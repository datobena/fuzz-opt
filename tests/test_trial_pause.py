"""Exercise the real pass-through C hook and host lease, without Docker."""
import ctypes
from pathlib import Path
import subprocess
import threading
import time

import pytest

from lib import docker_util
from lib.trial_pause import PauseError, TrialPause, cancel_container


@pytest.fixture(scope="module")
def shim(tmp_path_factory):
    so = tmp_path_factory.mktemp("pause-shim") / "shim.so"
    source = Path(__file__).resolve().parents[1] / "mutation_dump_afl.c"
    subprocess.run(["cc", "-O2", "-shared", "-fPIC", "-o", str(so), str(source)], check=True)
    lib = ctypes.CDLL(str(so))
    lib.afl_custom_init.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    lib.afl_custom_init.restype = ctypes.c_void_p
    lib.afl_custom_post_process.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                          ctypes.POINTER(ctypes.c_void_p)]
    lib.afl_custom_post_process.restype = ctypes.c_size_t
    lib.afl_custom_deinit.argtypes = [ctypes.c_void_p]
    return lib


@pytest.fixture
def fuzzer(shim, tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAL_PAUSE_DIR", str(tmp_path))
    monkeypatch.setenv("MUTATION_DUMP_CAP", "1")
    monkeypatch.delenv("MUTATION_DUMP_DIR", raising=False)
    state = shim.afl_custom_init(None, 7)
    controller = TrialPause(tmp_path, lease_seconds=0.3, is_running=lambda cid: True)
    controller.started("container-one")
    stop, progress = threading.Event(), []

    def run():
        buf, out = ctypes.create_string_buffer(b"original bytes"), ctypes.c_void_p()
        while not stop.is_set():
            length = shim.afl_custom_post_process(state, buf, 14, ctypes.byref(out))
            progress.append(ctypes.string_at(out.value, length))
            time.sleep(0.002)

    worker = threading.Thread(target=run)
    worker.start()
    yield controller, progress
    controller.cancel("test cleanup")
    stop.set()
    worker.join(timeout=2)
    assert not worker.is_alive()
    shim.afl_custom_deinit(state)
    assert all(data == b"original bytes" for data in progress)


def wait_for(predicate, timeout=2):
    end = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < end, "condition did not become true"
        time.sleep(0.01)


def test_pause_preserves_bytes_and_resumes_without_restart(fuzzer):
    controller, progress = fuzzer
    for _ in range(3):
        with controller.paused() as container:
            assert container == "container-one"
            n = len(progress)
            time.sleep(0.12)
            assert len(progress) == n
        wait_for(lambda: len(progress) > n)


def test_exception_resumes_fuzzer(fuzzer):
    controller, progress = fuzzer
    with pytest.raises(ValueError, match="tool failed"):
        with controller.paused():
            n = len(progress)
            raise ValueError("tool failed")
    wait_for(lambda: len(progress) > n)


def test_owner_death_lease_expires_and_cannot_be_resurrected(fuzzer):
    controller, progress = fuzzer
    request = controller.directory / "request"
    token = "abandoned-owner"
    request.write_text(f"{token} {int((time.monotonic() + 0.3) * 1000)}\n")
    wait_for(lambda: controller._acknowledged(token))
    n = len(progress)
    wait_for(lambda: len(progress) > n)
    request.write_text(f"{token} {int((time.monotonic() + 1) * 1000)}\n")
    n = len(progress)
    time.sleep(0.15)
    assert len(progress) > n and not controller._acknowledged(token)


def test_deadline_resumes_and_invalidates_measurement(fuzzer):
    controller, progress = fuzzer
    with pytest.raises(PauseError, match="deadline|acknowledgement"):
        with controller.paused(deadline=time.time() + 0.2):
            n = len(progress)
            time.sleep(0.4)
    assert len(progress) > n


def test_cancel_for_swap_prevents_new_pause_and_invalidates_old_measurement(fuzzer):
    controller, progress = fuzzer
    with pytest.raises(PauseError, match="swap|changed|acknowledgement"):
        with controller.paused():
            controller.cancel("hot swap")
    with pytest.raises(PauseError, match="hot swap"):
        with controller.paused():
            pytest.fail("measurement entered after cancellation")
    controller.started("container-two")
    # A late cleanup for the old container cannot unpause its replacement.
    with controller.paused():
        cancel_container("container-one", "old cleanup")
        n = len(progress)
        time.sleep(0.08)
        assert len(progress) == n


def test_stop_and_shutdown_cancel_before_docker_command(fuzzer, monkeypatch):
    controller, _ = fuzzer
    calls = []

    def run(command, **kwargs):
        assert not (controller.directory / "request").exists()
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(docker_util.subprocess, "run", run)
    with pytest.raises(PauseError):
        with controller.paused():
            docker_util.stop_container("container-one")
    assert calls[0][:2] == ["docker", "stop"]
    controller.started("container-two")
    with pytest.raises(PauseError):
        with controller.paused():
            docker_util.remove_container("container-two")
    assert calls[1][:3] == ["docker", "rm", "-f"]


def test_missing_hook_fails_without_running_operation(tmp_path):
    controller = TrialPause(tmp_path, is_running=lambda cid: True)
    controller.started("missing-hook")
    with pytest.raises(PauseError, match="did not acknowledge"):
        with controller.paused(timeout=0.05):
            pytest.fail("operation entered without an acknowledgement")
    assert not (tmp_path / "request").exists()


def test_nested_pause_cannot_release_outer_pause(fuzzer):
    controller, _ = fuzzer
    with controller.paused():
        with pytest.raises(PauseError, match="active pause"):
            with controller.paused():
                pytest.fail("nested scope entered")
        assert (controller.directory / "request").exists()


def test_started_deadline_is_used_without_caller_override(fuzzer):
    controller, _ = fuzzer
    controller.started("deadline-trial", deadline=time.time() - 1)
    for override in (None, time.time() + 60):
        with pytest.raises(PauseError, match="deadline already reached"):
            with controller.paused(deadline=override):
                pytest.fail("operation outlived the trial budget")


def test_container_exit_invalidates_even_an_existing_acknowledgement(fuzzer):
    controller, _ = fuzzer
    with pytest.raises(PauseError, match="container exited"):
        with controller.paused():
            controller._is_running = lambda cid: False


def test_online_monitor_stops_paused_trial_at_wall_clock_deadline(fuzzer, monkeypatch, tmp_path):
    import phase3_online
    from types import SimpleNamespace
    controller, _ = fuzzer
    trial = SimpleNamespace(container_id="container-one", pause_controller=controller, trial_id=0)
    state = phase3_online.OnlineState()
    state.trials[0] = {"overall_start": time.time() - 100, "crash_times": [],
                       "seen_crashes": set(), "state": "running"}
    monkeypatch.setattr(phase3_online.phase3_runner, "get_trial_dirs",
                        lambda *args: {"base": str(tmp_path)})
    monkeypatch.setattr(docker_util, "container_is_running", lambda cid: True)
    calls = []

    def stop(command, **kwargs):
        assert not (controller.directory / "request").exists()
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(docker_util.subprocess, "run", stop)
    monkeypatch.setattr(phase3_online, "_finalize_online_trial", lambda *args: None)
    with pytest.raises(PauseError):
        with controller.paused():
            phase3_online._monitor_online_trial(trial, "probe", 1, state)
    assert calls == [["docker", "stop", "-t", "10", "container-one"]]
    assert state.trials[0]["state"] == "budget_done"
