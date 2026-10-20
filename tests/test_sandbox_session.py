"""Tests for sandbox/session.py — the piece that makes the sandbox non-inert.

Until this lands, phase 2 invokes the optimizer with
`--dangerously-skip-permissions` and the full host environment; every other
sandbox component exists but nothing routes through it.
"""
import pytest

from sandbox.session import (
    SANDBOX_BUILD_CMD,
    SANDBOX_SMOKE_CMD,
    SANDBOX_VALIDATE_CMD,
    build_sandbox_validation_env,
)


def test_validation_commands_are_broker_clients_not_docker():
    """The agent has no docker socket; a docker command here would just fail,
    and a docker command that WORKED would defeat the whole sandbox."""
    env = build_sandbox_validation_env()
    for key in ("FUZZ_SOURCE_FOLDS_BUILD_COMMAND",
                "FUZZ_SOURCE_FOLDS_SMOKE_COMMAND",
                "FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND"):
        assert "docker" not in env[key], f"{key} still shells out to docker"
        assert env[key].startswith("/work/bin/")


def test_validate_runs_build_then_smoke_sequentially():
    """Smoke depends on build artifacts; running them in parallel races."""
    assert SANDBOX_VALIDATE_CMD == f"{SANDBOX_BUILD_CMD} && {SANDBOX_SMOKE_CMD}"


def test_validation_env_declares_wrapper_mode():
    env = build_sandbox_validation_env()
    assert env["FUZZ_SOURCE_FOLDS_VALIDATION_MODE"] == "wrapper"


def test_validation_env_leaks_no_host_paths():
    env = build_sandbox_validation_env()
    for key, value in env.items():
        assert "/home/" not in value, f"{key} leaks a host path"
        assert "results/" not in value, f"{key} leaks the experiment dir"


def test_command_env_keys_are_allowlisted_for_the_agent():
    """build_agent_env drops anything not on the allowlist, so a validation
    command that is not allowlisted never reaches the agent at all."""
    from sandbox.launch import ENV_ALLOWLIST

    for key in build_sandbox_validation_env():
        assert key in ENV_ALLOWLIST, f"{key} would be dropped before the agent sees it"


def test_session_refuses_to_run_unsandboxed(monkeypatch):
    """A missing agent image must fail loudly rather than silently falling back
    to the old unconfined invocation."""
    import sandbox.session as s

    monkeypatch.setattr(s, "_image_exists", lambda _img: False)
    with pytest.raises(RuntimeError, match="agent image"):
        s.assert_sandbox_available()


# --- phase-2 integration -----------------------------------------------------

def test_phase2_uses_the_sandbox_by_default(monkeypatch):
    import phase2_setup

    calls = {}

    def fake_sandboxed(source_dir, prompt, *, timeout, project, extra_env):
        calls["used"] = "sandbox"
        return {"ok": True, "stdout": "", "stderr": "", "timed_out": False}

    def fail(*_a, **_k):
        raise AssertionError("unconfined path must not run when PHASE2_SANDBOX is on")

    monkeypatch.setattr(phase2_setup, "_invoke_agent_sandboxed", fake_sandboxed)
    monkeypatch.setattr(phase2_setup, "_invoke_claude_capture", fail)
    monkeypatch.setattr(phase2_setup, "_invoke_codex_capture", fail)
    monkeypatch.setattr(phase2_setup.config, "PHASE2_SANDBOX", True)

    phase2_setup._invoke_agent_capture("/src", "do the thing", project="p")
    assert calls["used"] == "sandbox"


def test_phase2_opt_out_is_explicit_and_warns(monkeypatch, caplog):
    """Running unconfined must be a loud, deliberate choice."""
    import logging

    import phase2_setup

    monkeypatch.setattr(phase2_setup.config, "PHASE2_SANDBOX", False)
    monkeypatch.setattr(phase2_setup, "_invoke_claude_capture",
                        lambda *a, **k: {"ok": True})
    monkeypatch.setattr(phase2_setup, "_optimizer_backend", lambda: "claude")

    with caplog.at_level(logging.WARNING):
        phase2_setup._invoke_agent_capture("/src", "p", project="p")
    assert any("UNCONFINED" in r.message for r in caplog.records)


def test_sandboxed_invocation_refuses_incomplete_context(monkeypatch):
    """Missing wiring must raise, not quietly run with an empty image name."""
    import phase2_setup

    with pytest.raises(RuntimeError, match="missing required context"):
        phase2_setup._invoke_agent_sandboxed(
            "/src", "prompt", timeout=None, project="p", extra_env={},
        )


# --- agent container cpuset ---------------------------------------------------
#
# The broker pins the agent's builds/replays to its profile core, but the agent
# CONTAINER (Claude CLI + whatever it runs; the image has gcc) was unpinned and
# could land on a trial core or on a profile core mid-replay.

# This host: 80 logical cpus, the HT sibling of c is c+40.
HT80 = {c: frozenset({c % 40, c % 40 + 40}) for c in range(80)}


@pytest.fixture
def pertrial_layout(monkeypatch):
    """run_online_pertrial.sh's layout: trials 12-31, optimizer profile 2-11."""
    import config
    monkeypatch.setattr(config, "ONLINE_TRIAL_CORES", "12-31")
    monkeypatch.setattr(config, "ONLINE_OPTIMIZER_CORES", "2-11")
    monkeypatch.setattr(config, "ONLINE_AGENT_CPUS", "")
    return config


def test_agent_cpus_derive_to_the_free_physical_cores(pertrial_layout):
    from sandbox.session import resolve_agent_cpus
    assert resolve_agent_cpus(siblings=HT80) == "0-1,32-39"


def test_agent_cpus_exclude_hyperthread_siblings_of_trial_cores(pertrial_layout):
    """A trial given as its HT sibling (52 = 12+40) still takes physical core 12;
    and the derived set never uses the idle 40-79 half."""
    from sandbox.session import resolve_agent_cpus
    pertrial_layout.ONLINE_TRIAL_CORES = "52-71"
    assert resolve_agent_cpus(siblings=HT80) == "0-1,32-39"


def test_agent_cpus_on_the_real_topology_avoid_trial_and_profile_cores(pertrial_layout):
    from lib.core_lock import parse_cpuset, thread_siblings
    from sandbox.session import resolve_agent_cpus
    sib = thread_siblings()
    if not sib or max(sib) < 39:
        pytest.skip("needs the 40-core host topology")
    got = set(parse_cpuset(resolve_agent_cpus()))
    banned = set()
    for c in parse_cpuset("2-31"):
        banned |= sib[c]
    assert got and not (got & banned)
    if sib == HT80:
        assert resolve_agent_cpus() == "0-1,32-39"


def test_agent_cpus_fail_loudly_when_nothing_is_free(pertrial_layout):
    from sandbox.session import resolve_agent_cpus
    pertrial_layout.ONLINE_TRIAL_CORES = "0-31"
    pertrial_layout.ONLINE_OPTIMIZER_CORES = "32-39"
    with pytest.raises(RuntimeError, match="unpinned"):
        resolve_agent_cpus(siblings=HT80)


def test_explicit_agent_cpus_are_used_as_given(pertrial_layout):
    from sandbox.session import resolve_agent_cpus
    pertrial_layout.ONLINE_AGENT_CPUS = "32-35,0"
    assert resolve_agent_cpus(siblings=HT80) == "0,32-35"


@pytest.mark.parametrize("bad", ["12", "30-33", "52"])     # 52 = HT sibling of 12
def test_explicit_agent_cpus_on_a_trial_core_are_refused(pertrial_layout, bad):
    from sandbox.session import resolve_agent_cpus
    pertrial_layout.ONLINE_AGENT_CPUS = bad
    with pytest.raises(RuntimeError, match="trial"):
        resolve_agent_cpus(siblings=HT80)


def test_explicit_agent_cpus_on_a_profile_core_warn(pertrial_layout, caplog):
    import logging
    from sandbox.session import resolve_agent_cpus
    pertrial_layout.ONLINE_AGENT_CPUS = "5"
    with caplog.at_level(logging.WARNING):
        assert resolve_agent_cpus(siblings=HT80) == "5"
    assert any("profile" in r.message for r in caplog.records)


def _stub_session(monkeypatch, tmp_path):
    """Everything around the agent `docker run`, stubbed; returns the captured argv."""
    import sandbox.session as s
    seen = {}

    class R:
        returncode, stdout, stderr = 0, "done", ""

    def run(cmd, **_k):
        seen["cmd"] = cmd
        return R()
    monkeypatch.setattr(s, "assert_sandbox_available", lambda: None)
    monkeypatch.setattr(s, "ensure_network", lambda: "net")
    monkeypatch.setattr(s.broker_mod, "serve", lambda *a, **k: None)
    monkeypatch.setattr(s.egress, "start_proxy", lambda **k: "http://proxy:1")
    monkeypatch.setattr(s.egress, "api_key", lambda: "k")
    monkeypatch.setattr(s.subprocess, "run", run)
    monkeypatch.setattr(s.tempfile, "mkdtemp",
                        lambda prefix="": str(tmp_path / "sock"), raising=True)
    (tmp_path / "sock").mkdir()
    return s, seen


def _run_session(s, tmp_path, **kw):
    out = tmp_path / "exp" / "out"
    out.mkdir(parents=True)
    return s.run_sandboxed_optimizer(
        source_dir=str(tmp_path), profile_dir=str(tmp_path), out_dir=str(out),
        corpus_dir=str(tmp_path), image="bench-aflpp/x-arvo-1", fuzz_target="t",
        project="x", prompt="p", cpu=3, **kw)


def test_session_pins_the_agent_container(monkeypatch, tmp_path, pertrial_layout):
    import lib.core_lock as cl
    monkeypatch.setattr(cl, "thread_siblings", lambda *a: HT80)
    s, seen = _stub_session(monkeypatch, tmp_path)
    res = _run_session(s, tmp_path)
    cmd = seen["cmd"]
    assert cmd[cmd.index("--cpuset-cpus") + 1] == "0-1,32-39"
    assert res["agent_cpus"] == "0-1,32-39"
    # The broker's core is NOT the agent's cpuset.
    assert cmd.count("--cpuset-cpus") == 1


def test_session_uses_the_cpuset_it_is_given(monkeypatch, tmp_path, pertrial_layout):
    s, seen = _stub_session(monkeypatch, tmp_path)
    _run_session(s, tmp_path, agent_cpus="36-39")
    cmd = seen["cmd"]
    assert cmd[cmd.index("--cpuset-cpus") + 1] == "36-39"


def test_session_refuses_to_launch_unpinned(monkeypatch, tmp_path, pertrial_layout):
    import lib.core_lock as cl
    monkeypatch.setattr(cl, "thread_siblings", lambda *a: HT80)
    pertrial_layout.ONLINE_TRIAL_CORES = "0-39"
    s, seen = _stub_session(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="unpinned"):
        _run_session(s, tmp_path)
    assert "cmd" not in seen, "the agent container must not start"
