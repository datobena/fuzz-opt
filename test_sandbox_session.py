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
