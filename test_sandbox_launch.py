"""Tests for sandbox/launch.py — env scrubbing and container confinement."""
from sandbox.launch import (
    ENV_ALLOWLIST,
    build_agent_docker_command,
    build_agent_env,
)

# A realistic slice of what _agent_child_env currently hands the optimizer.
DIRTY = {
    "FUZZ_SOURCE_FOLDS_OUT_DIR": "/home/x/results/exp/libxml2-arvo-1972/optimized/out",
    "FUZZ_SOURCE_FOLDS_CORPUS_DIR": "/home/x/results/exp/libxml2-arvo-1972/seed_corpus",
    "FUZZ_SOURCE_FOLDS_MUTATION_IMAGE": "n132/arvo:1972-vul",
    "FUZZ_SOURCE_FOLDS_REPLAY_REPEATS": "3",
    "OSS_FUZZ_PROJECT": "libxml2",
    "HOME": "/home/sefcom",
    "AWS_SECRET_ACCESS_KEY": "nope",
    "ANTHROPIC_API_KEY": "sk-secret",
}


def test_env_drops_everything_not_allowlisted():
    env = build_agent_env(DIRTY)
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "OSS_FUZZ_PROJECT" not in env
    assert set(env) <= set(ENV_ALLOWLIST)


def test_env_contains_no_identifying_strings():
    """Leak inventory item 5: CVE and ARVO ids live in env var PATH STRINGS."""
    blob = " ".join(f"{k}={v}" for k, v in build_agent_env(DIRTY).items())
    for leak in ("arvo", "1972", "n132", "results", "libxml2-arvo", "CVE"):
        assert leak not in blob, f"{leak!r} leaked via env"


def test_env_rewrites_paths_into_the_sandbox():
    env = build_agent_env(DIRTY)
    assert env["FUZZ_SOURCE_FOLDS_OUT_DIR"].startswith("/work/")
    assert env["FUZZ_SOURCE_FOLDS_CORPUS_DIR"].startswith("/work/")


def test_env_keeps_non_path_scalars():
    assert build_agent_env(DIRTY)["FUZZ_SOURCE_FOLDS_REPLAY_REPEATS"] == "3"


def test_mutation_image_is_never_forwarded():
    """The image name carries the ARVO id and a '-vul' marker."""
    assert "FUZZ_SOURCE_FOLDS_MUTATION_IMAGE" not in build_agent_env(DIRTY)


def test_docker_command_has_no_docker_socket():
    cmd = build_agent_docker_command(
        image="bench-sandbox/agent", src="/host/src", profile="/host/prof",
        tools="/host/tools", sock="/host/broker.sock", network="agent-egress",
        env={},
    )
    joined = " ".join(cmd)
    assert "/var/run/docker.sock" not in joined
    assert "docker.sock" not in joined


def test_docker_command_pins_the_network():
    cmd = build_agent_docker_command(
        image="bench-sandbox/agent", src="/s", profile="/p", tools="/t",
        sock="/k", network="agent-egress", env={},
    )
    assert "--network" in cmd
    assert cmd[cmd.index("--network") + 1] == "agent-egress"


def test_docker_command_mounts_source_at_a_neutral_root():
    """Leak inventory item 5 again: the MOUNT TARGET must not name the target."""
    cmd = build_agent_docker_command(
        image="bench-sandbox/agent", src="/host/results/libxml2-arvo-1972/src",
        profile="/p", tools="/t", sock="/k", network="n", env={},
    )
    targets = [a.split(":")[1] for a in cmd if a.count(":") >= 1 and a.startswith("/")]
    assert targets, "expected mount specs"
    for t in targets:
        assert "arvo" not in t and "1972" not in t


def test_profile_and_tools_are_read_only():
    cmd = build_agent_docker_command(
        image="bench-sandbox/agent", src="/s", profile="/p", tools="/t",
        sock="/k", network="n", env={},
    )
    joined = " ".join(cmd)
    assert "/work/profile:ro" in joined
    assert "/work/bin:ro" in joined
    assert "/work/src:ro" not in joined, "source must stay writable"


def test_docker_command_drops_privileges_and_capabilities():
    cmd = build_agent_docker_command(
        image="bench-sandbox/agent", src="/s", profile="/p", tools="/t",
        sock="/k", network="n", env={},
    )
    joined = " ".join(cmd)
    assert "--privileged" not in joined, "the agent needs no privileges"
    assert "--cap-drop" in joined


def test_agent_tools_speak_the_broker_protocol(tmp_path, monkeypatch):
    """Run the REAL fold-replay-time script as a subprocess against a live broker.

    Proves the client/server contract end to end -- the scripts are the agent's
    entire interface, so a mismatch here would strand it with no way to build.
    """
    import json
    import subprocess
    import threading
    from pathlib import Path

    import sandbox.broker as b

    monkeypatch.setattr(b, "_run_replay", lambda ctx, repeats: 7.5)
    sock = tmp_path / "broker.sock"
    ctx = b.BrokerContext(
        image="i", source_dir=str(tmp_path), out_dir=str(tmp_path),
        corpus_dir=str(tmp_path), fuzz_target="t", project="p", cpu=0,
    )
    threading.Thread(target=b.serve, args=(str(sock), ctx), daemon=True).start()
    for _ in range(50):
        if sock.exists():
            break
        __import__("time").sleep(0.02)

    tool = Path("sandbox/agent_tools/fold-replay-time").absolute()
    client = tool.read_text().replace('"/run/broker.sock"', f'"{sock}"')
    patched = tmp_path / "fold-replay-time"
    patched.write_text(client)
    # _client.py resolves SOCK; point it at the test socket too.
    src = Path("sandbox/agent_tools/_client.py").read_text().replace(
        'SOCK = "/run/broker.sock"', f'SOCK = "{sock}"')
    (tmp_path / "_client.py").write_text(src)

    r = subprocess.run(
        ["python3", str(patched), "3"], capture_output=True, text=True, cwd=tmp_path,
    )
    assert r.returncode == 0, r.stderr
    assert "replay_seconds=7.5000" in r.stdout
    assert "repeats=3" in r.stdout
