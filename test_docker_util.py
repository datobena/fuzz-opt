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
