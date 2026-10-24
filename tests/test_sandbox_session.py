"""Tests for sandbox/session.py — the piece that makes the sandbox non-inert.

Until this lands, phase 2 invokes the optimizer with
`--dangerously-skip-permissions` and the full host environment; every other
sandbox component exists but nothing routes through it.
"""
import pytest
from pathlib import Path

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
        import json
        seen["cmd"] = cmd
        # What the container would be handed, read while it still exists.
        if "--env-file" in cmd:
            seen["env_file"] = Path(cmd[cmd.index("--env-file") + 1]).read_text()
        for i, a in enumerate(cmd[:-1]):
            if a == "-v" and cmd[i + 1].endswith(":/home/agent/.claude/.credentials.json"):
                src = cmd[i + 1].rsplit(":", 1)[0]
                seen["cred_src"] = src
                try:
                    seen["cred"] = json.loads(Path(src).read_text())
                    seen["cred_mode"] = Path(src).stat().st_mode & 0o777
                except (OSError, ValueError):
                    pass
        return R()
    monkeypatch.setattr(s, "assert_sandbox_available", lambda: None)
    monkeypatch.setattr(s, "ensure_network", lambda: "net")
    monkeypatch.setattr(s.broker_mod, "serve", lambda *a, **k: None)
    monkeypatch.setattr(s.egress, "start_proxy", lambda **k: "http://proxy:1")
    monkeypatch.setattr(s.egress, "api_key", lambda: "k")
    # Hermetic: never read this machine's real account->token map or login.
    monkeypatch.setattr(s.egress, "ACCOUNT_TOKENS_PATH", tmp_path / "no_tokens.json")
    monkeypatch.setattr(s.egress, "CLAUDE_CONFIG_PATH", tmp_path / "no_claude.json")
    monkeypatch.setattr(s.subprocess, "run", run)
    real_mkdtemp = s.tempfile.mkdtemp
    monkeypatch.setattr(
        s.tempfile, "mkdtemp",
        lambda prefix="", **k: (str(tmp_path / "sock") if prefix == "bs-"
                                else real_mkdtemp(prefix=prefix, dir=str(tmp_path / "private"))),
        raising=True)
    (tmp_path / "private").mkdir()
    (tmp_path / "sock").mkdir()
    return s, seen


def _given_token(seen):
    """The long-lived token the container was handed -- via a 0600 credential
    file, never on the docker command line."""
    token = seen["cred"]["claudeAiOauth"]["accessToken"]
    assert not any(token in a for a in seen["cmd"]), "token leaked into argv"
    assert seen["cred_mode"] == 0o600
    return token


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


def _no_staging(monkeypatch, s):
    """Fail the test if the session touches the shared OAuth credential file."""
    called = []
    monkeypatch.setattr(s.egress, "stage_credentials",
                        lambda *a, **k: called.append("stage") or [])
    monkeypatch.setattr(s.egress, "harvest_credentials",
                        lambda *a, **k: called.append("harvest"))
    return called


def test_session_passes_the_long_lived_oauth_token(monkeypatch, tmp_path, pertrial_layout):
    s, seen = _stub_session(monkeypatch, tmp_path)
    monkeypatch.setattr(s.egress, "api_key", lambda: "")
    monkeypatch.setenv(s.egress.OAUTH_TOKEN_ENV, "sk-ant-oat01-test")
    called = _no_staging(monkeypatch, s)
    res = _run_session(s, tmp_path, agent_cpus="36-39")
    cmd = seen["cmd"]
    assert _given_token(seen) == "sk-ant-oat01-test"
    assert "--env-file" not in cmd
    # No staged credential file, so no forced refresh can revoke this session.
    assert called == []
    assert res["credential"] == "oauth_token"


def test_session_prefers_the_api_key_over_the_oauth_token(monkeypatch, tmp_path, pertrial_layout):
    s, seen = _stub_session(monkeypatch, tmp_path)          # api_key -> "k"
    monkeypatch.setenv(s.egress.OAUTH_TOKEN_ENV, "sk-ant-oat01-test")
    called = _no_staging(monkeypatch, s)
    res = _run_session(s, tmp_path, agent_cpus="36-39")
    cmd = seen["cmd"]
    assert seen["env_file"] == f"{s.egress.API_KEY_ENV}=k\n"
    assert not any("k" == a.split("=", 1)[-1] for a in cmd)
    assert "cred" not in seen
    assert not any(a.startswith(f"{s.egress.OAUTH_TOKEN_ENV}=") for a in cmd)
    assert called == []
    assert res["credential"] == "api_key"


def _host_credential(monkeypatch, s, tmp_path, holder):
    """Point the host credential file at a temp file holding `holder`."""
    import json
    path = tmp_path / "host_credentials.json"
    path.write_text(json.dumps({"claudeAiOauth": holder}))
    monkeypatch.setitem(s.egress.CREDENTIAL_FILES, "claude",
                        (path, "/home/agent/.claude/.credentials.json"))
    return path


ROTATING = {"accessToken": "sk-ant-oat01-short", "refreshToken": "sk-ant-ort01-r",
            "expiresAt": 9999999999999, "scopes": ["user:inference"]}
CSWAP_TOKEN = {"accessToken": "sk-ant-oat01-year", "scopes": ["user:inference"]}


def test_session_without_a_long_lived_credential_stages_the_file(monkeypatch, tmp_path, pertrial_layout):
    s, seen = _stub_session(monkeypatch, tmp_path)
    monkeypatch.setattr(s.egress, "api_key", lambda: "")
    monkeypatch.delenv(s.egress.OAUTH_TOKEN_ENV, raising=False)
    _host_credential(monkeypatch, s, tmp_path, ROTATING)
    called = _no_staging(monkeypatch, s)
    res = _run_session(s, tmp_path, agent_cpus="36-39")
    assert not any(a.startswith(f"{s.egress.OAUTH_TOKEN_ENV}=") for a in seen["cmd"])
    assert called == ["stage", "harvest"]
    assert res["credential"] == "oauth_file"


def test_long_lived_auth_failure_is_not_retried_by_reseeding(monkeypatch, tmp_path):
    import phase2_setup
    from sandbox import egress
    monkeypatch.setattr(egress, "api_key", lambda: "")
    monkeypatch.setattr(egress, "ACCOUNT_TOKENS_PATH", tmp_path / "no_tokens.json")
    monkeypatch.setitem(egress.CREDENTIAL_FILES, "claude",
                        (tmp_path / "no_host.json", "/x"))
    monkeypatch.setenv(egress.OAUTH_TOKEN_ENV, "sk-ant-oat01-test")
    assert phase2_setup._sandbox_credential_mode() == "oauth_token"
    monkeypatch.delenv(egress.OAUTH_TOKEN_ENV)
    assert phase2_setup._sandbox_credential_mode() == "oauth_file"


def test_session_follows_the_cswap_token_on_the_host(monkeypatch, tmp_path, pertrial_layout):
    import hashlib
    s, seen = _stub_session(monkeypatch, tmp_path)
    monkeypatch.setattr(s.egress, "api_key", lambda: "")
    monkeypatch.delenv(s.egress.OAUTH_TOKEN_ENV, raising=False)
    _host_credential(monkeypatch, s, tmp_path, CSWAP_TOKEN)
    called = _no_staging(monkeypatch, s)
    res = _run_session(s, tmp_path, agent_cpus="36-39")
    assert _given_token(seen) == "sk-ant-oat01-year"
    assert called == []
    assert res["credential"] == "host_token"
    assert res["credential_id"] == hashlib.sha256(b"sk-ant-oat01-year").hexdigest()[:12]
    assert "sk-ant-oat01-year" not in res["credential_id"]


def test_explicit_token_beats_the_host_token(monkeypatch, tmp_path, pertrial_layout):
    s, seen = _stub_session(monkeypatch, tmp_path)
    monkeypatch.setattr(s.egress, "api_key", lambda: "")
    monkeypatch.setenv(s.egress.OAUTH_TOKEN_ENV, "sk-ant-oat01-env")
    _host_credential(monkeypatch, s, tmp_path, CSWAP_TOKEN)
    _no_staging(monkeypatch, s)
    res = _run_session(s, tmp_path, agent_cpus="36-39")
    assert _given_token(seen) == "sk-ant-oat01-env"
    assert res["credential"] == "oauth_token"


def test_a_blanked_rotating_credential_is_not_mistaken_for_a_token(monkeypatch, tmp_path):
    """A failed refresh blanks accessToken but keeps refreshToken: still oauth_file."""
    from sandbox import egress
    import sandbox.session as s
    monkeypatch.setattr(egress, "api_key", lambda: "")
    monkeypatch.setattr(egress, "ACCOUNT_TOKENS_PATH", tmp_path / "no_tokens.json")
    monkeypatch.delenv(egress.OAUTH_TOKEN_ENV, raising=False)
    _host_credential(monkeypatch, s, tmp_path, {**ROTATING, "accessToken": ""})
    assert egress.host_long_lived_token() == ""
    assert egress.credential_mode() == "oauth_file"
    _host_credential(monkeypatch, s, tmp_path, {"accessToken": "", "scopes": []})
    assert egress.credential_mode() == "oauth_file"


def test_credential_recorded_is_the_one_used_even_if_cswap_switches_mid_session(
        monkeypatch, tmp_path, pertrial_layout):
    import json
    s, seen = _stub_session(monkeypatch, tmp_path)
    monkeypatch.setattr(s.egress, "api_key", lambda: "")
    monkeypatch.delenv(s.egress.OAUTH_TOKEN_ENV, raising=False)
    path = _host_credential(monkeypatch, s, tmp_path, CSWAP_TOKEN)
    _no_staging(monkeypatch, s)
    inner = s.subprocess.run

    def run_and_switch(cmd, **k):
        path.write_text(json.dumps({"claudeAiOauth": ROTATING}))   # cswap switches
        return inner(cmd, **k)
    monkeypatch.setattr(s.subprocess, "run", run_and_switch)
    res = _run_session(s, tmp_path, agent_cpus="36-39")
    assert res["credential"] == "host_token"
    assert _given_token(seen) == "sk-ant-oat01-year"


def _account_map(monkeypatch, s, tmp_path, mapping, mode=0o600, email="Acct2@Example.com",
                 uuid="uuid-2"):
    """An account->token map plus a ~/.claude.json naming the active account."""
    import json
    tokens = tmp_path / "account_tokens.json"
    tokens.write_text(json.dumps(mapping))
    tokens.chmod(mode)
    config = tmp_path / "claude.json"
    config.write_text(json.dumps({"oauthAccount": {"emailAddress": email,
                                                   "accountUuid": uuid}}))
    monkeypatch.setattr(s.egress, "ACCOUNT_TOKENS_PATH", tokens)
    monkeypatch.setattr(s.egress, "CLAUDE_CONFIG_PATH", config)
    return tokens, config


def test_session_uses_the_active_accounts_year_token(monkeypatch, tmp_path, pertrial_layout):
    s, seen = _stub_session(monkeypatch, tmp_path)
    monkeypatch.setattr(s.egress, "api_key", lambda: "")
    monkeypatch.delenv(s.egress.OAUTH_TOKEN_ENV, raising=False)
    _host_credential(monkeypatch, s, tmp_path, ROTATING)      # cswap's normal login
    _account_map(monkeypatch, s, tmp_path, {"acct1@example.com": "sk-ant-oat01-one",
                                            "acct2@example.com": "sk-ant-oat01-two"})
    called = _no_staging(monkeypatch, s)
    res = _run_session(s, tmp_path, agent_cpus="36-39")
    assert _given_token(seen) == "sk-ant-oat01-two"
    assert called == [], "the rotating login must not be staged or refreshed"
    assert res["credential"] == "account_token"


def test_account_token_follows_a_cswap_switch_for_new_rounds(monkeypatch, tmp_path):
    import json
    from sandbox import egress
    import sandbox.session as s
    monkeypatch.setattr(egress, "api_key", lambda: "")
    monkeypatch.delenv(egress.OAUTH_TOKEN_ENV, raising=False)
    _, config = _account_map(monkeypatch, s, tmp_path,
                             {"acct1@example.com": "one", "uuid-2": "two"},
                             email="acct1@example.com", uuid="uuid-1")
    assert egress.resolve_session_credential() == ("account_token", "one")
    config.write_text(json.dumps({"oauthAccount": {"emailAddress": "x@example.com",
                                                   "accountUuid": "uuid-2"}}))
    assert egress.resolve_session_credential() == ("account_token", "two")   # by uuid


def test_unmapped_account_falls_back_to_the_rotating_login(monkeypatch, tmp_path):
    from sandbox import egress
    import sandbox.session as s
    monkeypatch.setattr(egress, "api_key", lambda: "")
    monkeypatch.delenv(egress.OAUTH_TOKEN_ENV, raising=False)
    _host_credential(monkeypatch, s, tmp_path, ROTATING)
    _account_map(monkeypatch, s, tmp_path, {"someone-else@example.com": "t"})
    assert egress.resolve_session_credential() == ("oauth_file", "")


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_a_token_map_readable_by_others_is_refused(monkeypatch, tmp_path, mode, caplog):
    import logging
    from sandbox import egress
    import sandbox.session as s
    monkeypatch.setattr(egress, "api_key", lambda: "")
    monkeypatch.delenv(egress.OAUTH_TOKEN_ENV, raising=False)
    _host_credential(monkeypatch, s, tmp_path, ROTATING)
    _account_map(monkeypatch, s, tmp_path, {"acct2@example.com": "t"}, mode=mode)
    with caplog.at_level(logging.WARNING):
        assert egress.account_token() == ""
    assert any("chmod 600" in r.message for r in caplog.records)


def test_a_malformed_token_map_is_ignored(monkeypatch, tmp_path):
    from sandbox import egress
    import sandbox.session as s
    monkeypatch.setattr(egress, "api_key", lambda: "")
    tokens, _ = _account_map(monkeypatch, s, tmp_path, {})
    tokens.write_text("{not json")
    assert egress.account_token() == ""
    tokens.write_text('["a list"]')
    assert egress.account_token() == ""


def test_credential_precedence(monkeypatch, tmp_path):
    from sandbox import egress
    import sandbox.session as s
    _host_credential(monkeypatch, s, tmp_path, CSWAP_TOKEN)
    _account_map(monkeypatch, s, tmp_path, {"acct2@example.com": "mapped"})
    monkeypatch.setenv(egress.OAUTH_TOKEN_ENV, "env")
    monkeypatch.setattr(egress, "api_key", lambda: "key")
    assert egress.resolve_session_credential() == ("api_key", "key")
    monkeypatch.setattr(egress, "api_key", lambda: "")
    assert egress.resolve_session_credential() == ("oauth_token", "env")
    monkeypatch.delenv(egress.OAUTH_TOKEN_ENV)
    assert egress.resolve_session_credential() == ("account_token", "mapped")
    monkeypatch.setattr(egress, "ACCOUNT_TOKENS_PATH", tmp_path / "none.json")
    assert egress.resolve_session_credential() == ("host_token", "sk-ant-oat01-year")


def test_credential_dir_is_private_outside_results_and_removed(monkeypatch, tmp_path, pertrial_layout):
    s, seen = _stub_session(monkeypatch, tmp_path)
    monkeypatch.setattr(s.egress, "api_key", lambda: "")
    monkeypatch.setenv(s.egress.OAUTH_TOKEN_ENV, "sk-ant-oat01-secret")
    _no_staging(monkeypatch, s)
    _run_session(s, tmp_path, agent_cpus="36-39")
    src = Path(seen["cred_src"])
    assert (tmp_path / "exp") not in src.parents, "credential written under results"
    assert not src.exists() and not src.parent.exists(), "credential left behind"


def test_a_credential_the_agent_printed_is_redacted_everywhere(monkeypatch, tmp_path, pertrial_layout, caplog):
    import logging
    s, seen = _stub_session(monkeypatch, tmp_path)
    monkeypatch.setattr(s.egress, "api_key", lambda: "")
    monkeypatch.setenv(s.egress.OAUTH_TOKEN_ENV, "sk-ant-oat01-secret")
    _no_staging(monkeypatch, s)
    src_file = tmp_path / "leaky.c"
    inner = s.subprocess.run

    class Leaky:
        returncode, stdout, stderr = 0, "token=sk-ant-oat01-secret", ""

    wrote = []

    def run_and_leak(cmd, **k):
        inner(cmd, **k)
        for i, a in enumerate(cmd[:-1]):
            host = cmd[i + 1].split(":")[0]
            if a == "-v" and host.endswith("transcripts"):
                Path(host, "t.jsonl").write_text('{"text":"sk-ant-oat01-secret"}')
                wrote.append(Path(host, "t.jsonl"))
        src_file.write_text("// sk-ant-oat01-secret\n")
        return Leaky()
    monkeypatch.setattr(s.subprocess, "run", run_and_leak)
    with caplog.at_level(logging.ERROR):
        res = _run_session(s, tmp_path, agent_cpus="36-39")
    assert "sk-ant-oat01-secret" not in res["stdout"]
    assert "sk-ant-oat01-secret" not in src_file.read_text()
    assert wrote, "the transcripts mount was not found"
    for t in wrote:
        assert "sk-ant-oat01-secret" not in t.read_text()
    assert any("redacted in place" in r.message for r in caplog.records)
    assert not any("sk-ant-oat01-secret" in r.getMessage() for r in caplog.records)


def test_redact_tree_skips_git_and_symlinks(tmp_path):
    from sandbox import egress
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "obj").write_text("SECRET")
    (tmp_path / "a.txt").write_text("x SECRET y")
    (tmp_path / "link").symlink_to(tmp_path / "a.txt")
    hits = egress.redact_tree(tmp_path, "SECRET")
    assert hits == [str(tmp_path / "a.txt")]
    assert (tmp_path / "a.txt").read_text() == f"x {egress.REDACTED} y"
    assert (tmp_path / ".git" / "obj").read_text() == "SECRET"
