import subprocess

from lib import docker_util


def test_get_container_duration_seconds_parses_docker_timestamps(monkeypatch):
    inspect_output = (
        "2026-03-23T01:02:03.123456789Z\n"
        "2026-03-23T01:02:13.623456789Z\n"
    )

    def fake_run(cmd, capture_output, text):
        assert cmd[:3] == ["docker", "inspect", "-f"]
        return subprocess.CompletedProcess(cmd, 0, stdout=inspect_output, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    duration_s = docker_util.get_container_duration_seconds("abc123")

    assert duration_s == 10.5


def _fake_docker_logs(monkeypatch, returncode, output=b"log\n"):
    def fake_run(cmd, stdout, stderr):
        assert cmd[:2] == ["docker", "logs"]
        stdout.write(output)
        return subprocess.CompletedProcess(cmd, returncode)
    monkeypatch.setattr(subprocess, "run", fake_run)


def test_write_container_logs_returns_bytes_written(monkeypatch, tmp_path):
    _fake_docker_logs(monkeypatch, 0)
    assert docker_util.write_container_logs("c", str(tmp_path / "l"), check=True) == 4


def test_write_container_logs_check_raises_on_a_failed_docker_logs(monkeypatch, tmp_path):
    """check=True is what lets a caller decide whether removing the container
    would destroy the only copy of its log."""
    import pytest
    _fake_docker_logs(monkeypatch, 1, b"Error: No such container: c\n")
    dest = str(tmp_path / "l")
    with pytest.raises(RuntimeError, match="exited 1"):
        docker_util.write_container_logs("c", dest, check=True)
    # Unchecked callers (phase3_runner, recovery tool) keep the old contract.
    assert docker_util.write_container_logs("c", dest) > 0
