"""Tests for sandbox/session.py — the piece that makes the sandbox non-inert.

Until this lands, phase 2 invokes the optimizer with
`--dangerously-skip-permissions` and the full host environment; every other
sandbox component exists but nothing routes through it.
"""
import pytest
from pathlib import Path

from sandbox.broker import serve as _REAL_SERVE
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


class _Gone:
    """`docker inspect` of a container that no longer exists."""
    returncode, stdout = 1, "[]"
    stderr = "Error response from daemon: No such container: x"


def _stub_session(monkeypatch, tmp_path):
    """Everything around the agent `docker run`, stubbed; returns the captured argv.

    ``seen["cmd"]`` is the agent `docker run`; ``seen["docker"]`` every docker
    call in order, teardown included (`rm -f`, then an `inspect` saying gone)."""
    import sandbox.session as s
    seen = {"docker": []}

    class R:
        returncode, stdout, stderr = 0, "done", ""

    def run(cmd, **_k):
        import json
        seen["docker"].append(cmd)
        if cmd[:2] == ["docker", "inspect"]:
            return _Gone()
        if cmd[:2] != ["docker", "run"]:
            return R()
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
        r = inner(cmd, **k)
        if cmd[:2] != ["docker", "run"]:
            return r                                  # teardown's rm -f / inspect
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


# --- the agent container never outlives its session ---------------------------
#
# subprocess.run(timeout=...) kills only the docker CLIENT. In 56 of 56 timed-out
# rounds the container ran on, 7-193 min, still editing the tree and building
# through the broker; once it re-applied its edits after the harness reset the
# tree, and the next round committed them as its baseline.

def _ordered_teardown(monkeypatch, s, seen):
    """Record teardown events in order: agent removal, broker stop, redaction,
    and whether the credential file still existed when the agent was removed."""
    events = []
    inner = s.subprocess.run

    def run(cmd, **k):
        if cmd[:3] == ["docker", "rm", "-f"]:
            events.append(("rm", cmd[3]))
            seen["cred_at_rm"] = Path(seen["cred_src"]).exists()
        return inner(cmd, **k)
    monkeypatch.setattr(s.subprocess, "run", run)
    real_stop = s.broker_mod.stop_session

    def stop(ctx, **k):
        events.append(("broker_stop", None))
        seen["ctx"] = ctx
        return real_stop(ctx, **k)
    monkeypatch.setattr(s.broker_mod, "stop_session", stop)
    real_redact = s.egress.redact_tree
    monkeypatch.setattr(s.egress, "redact_tree", lambda root, secret: (
        events.append(("redact", str(root))) or real_redact(root, secret)))
    return events


def _agent_raises(monkeypatch, s, make_exc):
    """The agent's `docker run` raises make_exc(cmd) -- with the container
    still up, as subprocess.run leaves it."""
    inner = s.subprocess.run

    def run(cmd, **k):
        r = inner(cmd, **k)
        if cmd[:2] == ["docker", "run"]:
            raise make_exc(cmd)
        return r
    monkeypatch.setattr(s.subprocess, "run", run)


def _timeout(cmd):
    import subprocess
    return subprocess.TimeoutExpired(cmd, 5)


@pytest.fixture
def token_session(monkeypatch, tmp_path, pertrial_layout):
    s, seen = _stub_session(monkeypatch, tmp_path)
    monkeypatch.setattr(s.egress, "api_key", lambda: "")
    monkeypatch.setenv(s.egress.OAUTH_TOKEN_ENV, "sk-ant-oat01-secret")
    _no_staging(monkeypatch, s)
    return s, seen


def _assert_removed_before_cleanup(s, seen, events):
    name = seen["cmd"][seen["cmd"].index("--name") + 1]
    assert events[0] == ("rm", name), events
    assert seen["cred_at_rm"], "the credential was removed while the agent ran"
    kinds = [e[0] for e in events]
    assert kinds.index("broker_stop") < kinds.index("redact")
    assert seen["ctx"].stop.is_set()
    # Confirmed gone: an inspect after the rm, before anything else.
    after_rm = seen["docker"][seen["docker"].index(["docker", "rm", "-f", name]) + 1]
    assert after_rm[:2] == ["docker", "inspect"] and after_rm[-1] == name
    assert not Path(seen["cred_src"]).exists()


def test_a_timed_out_agent_is_removed_before_cleanup(token_session, monkeypatch, tmp_path):
    import threading
    s, seen = token_session
    # The real serve(), which _stub_session replaced: it must return at the end.
    monkeypatch.setattr(s.broker_mod, "serve", _REAL_SERVE)
    events = _ordered_teardown(monkeypatch, s, seen)
    _agent_raises(monkeypatch, s, _timeout)
    res = _run_session(s, tmp_path, agent_cpus="36-39", timeout=5)
    _assert_removed_before_cleanup(s, seen, events)
    assert res["timed_out"] is True and res["ok"] is False
    assert {"stdout", "stderr", "transcripts", "model_requested", "effort_requested",
            "agent_cpus", "credential", "credential_id"} <= set(res)
    assert res["credential"] == "oauth_token"
    # The real broker thread was started and has returned.
    assert not [t for t in threading.enumerate() if "_serve" in t.name]


def test_an_interrupted_session_removes_the_agent_then_reraises(token_session, monkeypatch, tmp_path):
    s, seen = token_session
    events = _ordered_teardown(monkeypatch, s, seen)
    _agent_raises(monkeypatch, s, lambda cmd: KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        _run_session(s, tmp_path, agent_cpus="36-39")
    _assert_removed_before_cleanup(s, seen, events)


def test_a_normal_exit_also_confirms_the_agent_is_gone(token_session, tmp_path):
    from sandbox import launch
    s, seen = token_session
    res = _run_session(s, tmp_path, agent_cpus="36-39")
    cmd = seen["cmd"]
    name = cmd[cmd.index("--name") + 1]
    labels = dict(cmd[i + 1].split("=", 1) for i, a in enumerate(cmd) if a == "--label")
    assert labels[launch.LABEL_ROLE] == "agent"
    assert labels[launch.LABEL_LAUNCHER] == launch.launcher_token()
    assert labels[launch.LABEL_SESSION] in name and labels[launch.LABEL_PROJECT] == "x"
    rm_at = seen["docker"].index(["docker", "rm", "-f", name])
    confirm = seen["docker"][rm_at + 1]
    assert confirm[:2] == ["docker", "inspect"] and confirm[-1] == name
    assert res["timed_out"] is False and res["ok"] is True and res["stdout"] == "done"
    assert (res["agent_container"], res["agent_removed"], res["broker_leftovers"]) == (
        name, True, [])


def test_a_failed_setup_still_stops_the_broker(token_session, monkeypatch, tmp_path):
    s, seen = token_session
    stopped = []
    monkeypatch.setattr(s.broker_mod, "stop_session", lambda ctx, **k: stopped.append(ctx))

    def no_proxy(**k):
        raise RuntimeError("could not start egress proxy")
    monkeypatch.setattr(s.egress, "start_proxy", no_proxy)
    with pytest.raises(RuntimeError, match="egress proxy"):
        _run_session(s, tmp_path, agent_cpus="36-39")
    assert stopped and "cmd" not in seen
    assert not any(c[:3] == ["docker", "rm", "-f"] for c in seen["docker"])


def test_an_agent_that_will_not_die_is_reported_loudly(monkeypatch, caplog):
    import logging
    import sandbox.session as s

    class Alive:
        returncode, stdout, stderr = 0, "running", ""
    calls = []
    monkeypatch.setattr(s.subprocess, "run", lambda cmd, **k: calls.append(cmd) or Alive())
    monkeypatch.setattr(s.time, "sleep", lambda _s: None)
    with caplog.at_level(logging.ERROR):
        assert s.remove_container("agent-1-x", attempts=3) is False
    assert calls.count(["docker", "rm", "-f", "agent-1-x"]) == 3
    assert any("STILL PRESENT" in r.message for r in caplog.records)


def test_no_session_starts_once_the_launcher_is_shutting_down(token_session, monkeypatch, tmp_path):
    from sandbox import launch
    s, seen = token_session
    monkeypatch.setattr(launch, "SHUTTING_DOWN", __import__("threading").Event())
    launch.SHUTTING_DOWN.set()
    with pytest.raises(RuntimeError, match="shutting down"):
        _run_session(s, tmp_path, agent_cpus="36-39")
    assert "cmd" not in seen


# --- launcher-level sweep -------------------------------------------------------

def _own(launch):
    import os
    return os.getpid(), launch.process_start_time(os.getpid()), launch.boot_id()


def test_launcher_state_tells_live_dead_and_unknown(monkeypatch):
    import os
    import sandbox.session as s
    from sandbox import launch
    pid, start, boot = _own(launch)
    if not (start and boot):
        pytest.skip("needs /proc")
    assert s.launcher_state(launch.launcher_token()) == "alive"
    ppid = os.getppid()
    assert s.launcher_state(f"{ppid}:{launch.process_start_time(ppid)}:{boot}") == "alive"
    # Same pid, another process (pid reused) -> dead.
    assert s.launcher_state(f"{pid}:{int(start) + 1}:{boot}") == "dead"
    # Started before this boot -> dead, whatever the pid is now.
    assert s.launcher_state(f"{pid}:{start}:not-this-boot") == "dead"
    # Can't tell -> never 'dead'.
    for bad in ("", "garbage", "0:1:x", "-1:1:x", f"{pid}::{boot}"):
        assert s.launcher_state(bad) == "unknown", bad

    def no_such(p, sig):
        raise ProcessLookupError
    monkeypatch.setattr(s.os, "kill", no_such)
    assert s.launcher_state(f"424242:{start}:{boot}") == "dead"


def _fake_ps(monkeypatch, s, rows):
    """docker ps returns ``rows`` (id, name, launcher, role) for any filter;
    records every docker call."""
    calls = []

    class R:
        def __init__(self, out=""):
            self.returncode, self.stdout, self.stderr = 0, out, ""

    def run(cmd, **k):
        calls.append(cmd)
        if cmd[:2] == ["docker", "ps"]:
            flt = cmd[cmd.index("--filter") + 1]
            want = flt.split("=", 2)[2] if flt.count("=") >= 2 else None
            out = "\n".join("\t".join(r) for r in rows if want in (None, r[2]))
            return R(out + "\n")
        return R()
    monkeypatch.setattr(s.subprocess, "run", run)
    return calls


def test_sweep_removes_only_containers_of_dead_launchers(monkeypatch):
    import os
    import sandbox.session as s
    from sandbox import launch
    pid, start, boot = _own(launch)
    if not (start and boot):
        pytest.skip("needs /proc")
    ppid = os.getppid()
    live_other = f"{ppid}:{launch.process_start_time(ppid)}:{boot}"
    rows = [
        ("id-mine", "agent-me", launch.launcher_token(), "agent"),
        ("id-live", "agent-other", live_other, "agent"),          # another campaign
        ("id-reused", "broker-1-2", f"{pid}:{int(start) + 1}:{boot}", "broker"),
        ("id-reboot", "agent-old", f"{pid}:{start}:previous-boot", "agent"),
        ("id-odd", "agent-odd", "not-a-token", "agent"),
    ]
    calls = _fake_ps(monkeypatch, s, rows)
    removed = s.sweep_orphaned_containers()
    assert sorted(removed) == ["agent-old", "broker-1-2"]
    rm = [c for c in calls if c[:3] == ["docker", "rm", "-f"]]
    assert rm == [["docker", "rm", "-f", "id-reused", "id-reboot"]]
    # Listed by label key alone -- never by image or name.
    ps = [c for c in calls if c[:2] == ["docker", "ps"]]
    assert ps and all(c[c.index("--filter") + 1] == f"label={launch.LABEL_LAUNCHER}"
                      for c in ps)


def test_launcher_exit_removes_only_its_own_containers(monkeypatch):
    import sandbox.session as s
    from sandbox import launch
    rows = [("id-mine", "agent-me", launch.launcher_token(), "agent"),
            ("id-b", "broker-me", launch.launcher_token(), "broker"),
            ("id-other", "agent-other", "1:2:3", "agent")]
    calls = _fake_ps(monkeypatch, s, rows)
    assert s.remove_launcher_containers() == ["agent-me", "broker-me"]
    assert [c for c in calls if c[:3] == ["docker", "rm", "-f"]] == [
        ["docker", "rm", "-f", "id-mine", "id-b"]]
    assert calls[0][calls[0].index("--filter") + 1] == (
        f"label={launch.LABEL_LAUNCHER}={launch.launcher_token()}")


@pytest.fixture
def launcher_signal(monkeypatch, tmp_path):
    """A fresh shutdown flag and secret registry; no real sleep between sweeps."""
    import threading
    import sandbox.session as s
    from sandbox import launch
    monkeypatch.setattr(launch, "SHUTTING_DOWN", threading.Event())
    monkeypatch.setattr(s, "_LIVE_SECRET_DIRS", set())
    order = []
    monkeypatch.setattr(s.time, "sleep", lambda secs: order.append(("sleep", secs)))
    return s, launch, order


def test_signal_cleans_up_then_hands_over(monkeypatch, launcher_signal):
    import signal
    s, launch, order = launcher_signal
    monkeypatch.setattr(s, "remove_launcher_containers",
                        lambda: order.append("cleanup") or ["agent-1"])
    # A Python handler (SIGINT's KeyboardInterrupt) still runs, after cleanup --
    # which sweeps twice, for a container a racing call started in between.
    s._on_launcher_signal(signal.SIGINT, None,
                          prev=lambda n, f: order.append(("prev", n)))
    assert order == ["cleanup", ("sleep", s.SIGNAL_RESWEEP_SECS), "cleanup",
                     ("prev", signal.SIGINT)]
    assert launch.SHUTTING_DOWN.is_set()
    # SIG_DFL: restore it and re-deliver, so the process dies as it would have.
    sent = []
    monkeypatch.setattr(s.signal, "signal", lambda n, h: sent.append(("set", n, h)))
    monkeypatch.setattr(s.os, "kill", lambda p, n: sent.append(("kill", p, n)))
    s._on_launcher_signal(signal.SIGTERM, None, prev=signal.SIG_DFL)
    assert sent == [("set", signal.SIGTERM, signal.SIG_DFL),
                    ("kill", s.os.getpid(), signal.SIGTERM)]


@pytest.mark.real_launcher_cleanup
def test_install_sweeps_registers_exit_and_leaves_ignored_signals_alone(monkeypatch):
    import signal
    import sandbox.session as s
    from sandbox import launch
    monkeypatch.setattr(s, "_launcher_cleanup_installed", False)
    monkeypatch.setattr(launch, "_LAUNCHER_EXPERIMENT", "")
    swept, exits, handlers = [], [], {}
    monkeypatch.setattr(s, "sweep_orphaned_containers", lambda: swept.append(1) or [])
    monkeypatch.setattr(s.atexit, "register", exits.append)
    # Under `nohup ... &` SIGINT is ignored; it must stay ignored.
    monkeypatch.setattr(s.signal, "getsignal", lambda n: (
        signal.SIG_IGN if n == signal.SIGINT else signal.SIG_DFL))
    monkeypatch.setattr(s.signal, "signal", lambda n, h: handlers.__setitem__(n, h))
    s.install_launcher_cleanup("exp-7")
    s.install_launcher_cleanup("exp-7")                        # idempotent
    assert swept == [1] and exits == [s._cleanup_at_exit]
    assert set(handlers) == {signal.SIGTERM}
    assert launch.launcher_labels()[launch.LABEL_EXPERIMENT] == "exp-7"


def test_the_signal_is_handed_on_even_if_cleanup_is_interrupted(monkeypatch, launcher_signal):
    """A second Ctrl-C during a slow docker call raises inside the handler; the
    signal must still reach the previous handler, or kill us."""
    import signal
    s, launch, order = launcher_signal

    def interrupted():
        raise KeyboardInterrupt
    monkeypatch.setattr(s, "remove_launcher_containers", interrupted)
    with pytest.raises(KeyboardInterrupt):
        s._on_launcher_signal(signal.SIGINT, None,
                              prev=lambda n, f: order.append(("prev", n)))
    assert ("prev", signal.SIGINT) in order
    sent = []
    monkeypatch.setattr(s.signal, "signal", lambda n, h: sent.append(("set", n, h)))
    monkeypatch.setattr(s.os, "kill", lambda p, n: sent.append(("kill", p, n)))
    with pytest.raises(KeyboardInterrupt):
        s._on_launcher_signal(signal.SIGTERM, None, prev=signal.SIG_DFL)
    assert sent[-1] == ("kill", s.os.getpid(), signal.SIGTERM)


def test_signal_and_exit_delete_live_session_secrets(monkeypatch, launcher_signal, tmp_path):
    """SIGTERM ends the process before any session's finally runs: the handler
    deletes the credential dirs of sessions still running, after the containers
    and even when removing those fails."""
    import signal
    s, launch, order = launcher_signal
    for name in ("sbx-cred-a", "sbx-cred-b"):
        d = tmp_path / name
        d.mkdir()
        (d / "claude.json").write_text("secret")
        s._LIVE_SECRET_DIRS.add(str(d))

    def docker_down():
        raise OSError("docker daemon unreachable")
    monkeypatch.setattr(s, "remove_launcher_containers", docker_down)
    monkeypatch.setattr(s.signal, "signal", lambda n, h: None)
    monkeypatch.setattr(s.os, "kill", lambda p, n: order.append("killed"))
    s._on_launcher_signal(signal.SIGTERM, None, prev=signal.SIG_DFL)
    assert not list(tmp_path.glob("sbx-cred-*")) and not s._LIVE_SECRET_DIRS
    assert order[-1] == "killed"
    # atexit does the same.
    d = tmp_path / "sbx-cred-c"
    d.mkdir()
    s._LIVE_SECRET_DIRS.add(str(d))
    monkeypatch.setattr(s, "remove_launcher_containers", lambda: [])
    s._cleanup_at_exit()
    assert not d.exists()


def test_a_session_registers_its_secret_dir_only_while_it_runs(token_session, monkeypatch, tmp_path):
    s, seen = token_session
    monkeypatch.setattr(s, "_LIVE_SECRET_DIRS", set())
    inner = s.subprocess.run

    def run(cmd, **k):
        if cmd[:2] == ["docker", "run"]:
            seen["live"] = set(s._LIVE_SECRET_DIRS)
        return inner(cmd, **k)
    monkeypatch.setattr(s.subprocess, "run", run)
    _run_session(s, tmp_path, agent_cpus="36-39")
    assert seen["live"] == {str(Path(seen["cred_src"]).parent)}
    assert not s._LIVE_SECRET_DIRS


def test_an_unremovable_agent_reaches_the_caller(token_session, monkeypatch, tmp_path, caplog):
    """docker cannot confirm the agent gone: the result says so, the log does
    not claim it was removed, and broker leftovers are reported too."""
    import logging
    import subprocess
    s, seen = token_session

    class Alive:
        returncode, stdout, stderr = 0, "running", ""
    inner = s.subprocess.run

    def run(cmd, **k):
        r = inner(cmd, **k)
        if cmd[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(cmd, 5)
        if cmd[:2] == ["docker", "inspect"]:
            return Alive()
        return r
    monkeypatch.setattr(s.subprocess, "run", run)
    monkeypatch.setattr(s.time, "sleep", lambda _x: None)
    monkeypatch.setattr(s.broker_mod, "stop_session", lambda ctx, **k: ["broker-1-2"])
    with caplog.at_level(logging.WARNING):
        res = _run_session(s, tmp_path, agent_cpus="36-39", timeout=5)
    name = seen["cmd"][seen["cmd"].index("--name") + 1]
    assert res["timed_out"] is True
    assert (res["agent_container"], res["agent_removed"], res["broker_leftovers"]) == (
        name, False, ["broker-1-2"])
    msgs = [r.getMessage() for r in caplog.records]
    assert any("could NOT be confirmed removed" in m for m in msgs)
    assert not any(m.endswith(f"container {name} removed") for m in msgs)


def test_an_interrupted_teardown_still_removes_the_secret(token_session, monkeypatch, tmp_path):
    """Ctrl-C during a slow stop_session: the year-long token must not stay in
    TMPDIR, the tree must still be redacted."""
    import subprocess
    s, seen = token_session
    _agent_raises(monkeypatch, s, lambda cmd: subprocess.TimeoutExpired(cmd, 5))
    redacted = []
    real_redact = s.egress.redact_tree
    monkeypatch.setattr(s.egress, "redact_tree", lambda root, secret: (
        redacted.append(str(root)) or real_redact(root, secret)))

    def interrupted(ctx, **k):
        ctx.stop.set()
        raise KeyboardInterrupt
    monkeypatch.setattr(s.broker_mod, "stop_session", interrupted)
    with pytest.raises(KeyboardInterrupt):
        _run_session(s, tmp_path, agent_cpus="36-39", timeout=5)
    assert not list((tmp_path / "private").glob("sbx-cred-*/*")), "secret left behind"
    assert str(tmp_path) in redacted
    assert not (tmp_path / "sock" / "b.sock").exists()


def test_the_sessions_labels_reach_its_broker_containers(token_session, monkeypatch, tmp_path):
    """A request the agent sends mid-session starts a container carrying the
    same session, trial and round as the agent's own."""
    from lib import cpu_ledger
    from sandbox import launch
    s, seen = token_session
    broker_cmds = []

    def serve(sock_path, ctx):                  # one agent request, then idle
        s.broker_mod._run(["docker", "run", "--rm", "img", "make"], 5, ctx)
    monkeypatch.setattr(s.broker_mod, "serve", serve)
    inner = s.subprocess.run
    monkeypatch.setattr(s.subprocess, "run", lambda cmd, **k: (
        broker_cmds.append(cmd) if cmd[3:4] and cmd[3].startswith("broker-") else None)
        or inner(cmd, **k))
    cpu_ledger.set_thread_round(project="x", iter_n=5, trial_id=7)
    try:
        _run_session(s, tmp_path, agent_cpus="36-39")
    finally:
        cpu_ledger.clear_thread_round()

    def labels(cmd):
        return dict(cmd[i + 1].split("=", 1) for i, a in enumerate(cmd) if a == "--label")
    agent = next(c for c in seen["docker"] if c[:2] == ["docker", "run"] and "--init" in c)
    assert broker_cmds, "the broker's container never started"
    a, b = labels(agent), labels(broker_cmds[0])
    for key in (launch.LABEL_SESSION, launch.LABEL_TRIAL, launch.LABEL_ITER,
                launch.LABEL_PROJECT, launch.LABEL_LAUNCHER):
        assert b[key] == a[key], key
    assert (b[launch.LABEL_TRIAL], b[launch.LABEL_ITER]) == ("7", "5")
    assert (a[launch.LABEL_ROLE], b[launch.LABEL_ROLE]) == ("agent", "broker")


# --- a stopped container is not a writer --------------------------------------
#
# docker can leave a container it could not remove in `removing`, or `dead`
# after a device-busy error. Counting that as "still present" threw a finished
# round away, and a trial whose leftover stayed `dead` waited on it forever.

def _inspect_says(monkeypatch, s, *outputs):
    """`docker inspect` answers with each of ``outputs`` in turn (the last one
    repeats); an output of None is "No such container". Returns the calls."""
    calls, answers = [], list(outputs)

    class R:
        def __init__(self, rc, out, err=""):
            self.returncode, self.stdout, self.stderr = rc, out, err

    def run(cmd, **k):
        calls.append(cmd)
        if cmd[:2] == ["docker", "inspect"]:
            out = answers.pop(0) if len(answers) > 1 else answers[0]
            return (R(1, "", "Error response from daemon: No such container: x")
                    if out is None else R(0, out))
        return R(0, "")
    monkeypatch.setattr(s.subprocess, "run", run)
    monkeypatch.setattr(s.time, "sleep", lambda _x: None)
    return calls


@pytest.mark.parametrize("state", ["dead", "exited", "removing", "created"])
def test_a_container_stopped_for_good_counts_as_no_writer(monkeypatch, caplog, state):
    import logging
    import sandbox.session as s
    calls = _inspect_says(monkeypatch, s, f"{state} false false false")
    with caplog.at_level(logging.WARNING):
        assert s.remove_container("agent-1-x", attempts=3) is True
    # Still tried every time, and said so.
    assert calls.count(["docker", "rm", "-f", "agent-1-x"]) == 3
    assert any(f"stopped ({state})" in r.getMessage() for r in caplog.records)
    assert not any(r.levelno >= logging.ERROR for r in caplog.records)


@pytest.mark.parametrize("out", ["running true false false", "paused false true false",
                                 "restarting false false true", "exited false false true"])
def test_a_container_that_can_still_run_is_not_removed(monkeypatch, out):
    import sandbox.session as s
    _inspect_says(monkeypatch, s, out)
    assert s.remove_container("agent-1-x", attempts=2) is False


def test_a_created_container_that_starts_meanwhile_is_live(monkeypatch):
    """A start the dying client had already sent shows within the retries."""
    import sandbox.session as s
    _inspect_says(monkeypatch, s, "created false false false", "running true false false")
    assert s.remove_container("agent-1-x", attempts=3) is False


def test_docker_unreachable_is_not_gone(monkeypatch):
    import sandbox.session as s

    class Down:
        returncode, stdout = 1, ""
        stderr = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock"
    monkeypatch.setattr(s.subprocess, "run", lambda cmd, **k: Down())
    monkeypatch.setattr(s.time, "sleep", lambda _x: None)
    assert s._container_state("agent-1-x") == "unknown"
    assert s.remove_container("agent-1-x", attempts=2) is False


def test_an_agent_stuck_dead_after_a_good_run_keeps_its_round(token_session, monkeypatch, tmp_path):
    """The CLI exited 0; docker could not finish removing its stopped container.
    Nothing can write the tree, so phase 2 must go on with the round."""
    import phase2_setup
    s, seen = token_session
    inner = s.subprocess.run

    class Dead:
        returncode, stdout, stderr = 0, "dead false false false\n", ""

    def run(cmd, **k):
        return Dead() if cmd[:2] == ["docker", "inspect"] else inner(cmd, **k)
    monkeypatch.setattr(s.subprocess, "run", run)
    monkeypatch.setattr(s.time, "sleep", lambda _x: None)
    res = _run_session(s, tmp_path, agent_cpus="36-39")
    assert res["ok"] is True and res["agent_removed"] is True
    assert phase2_setup._containers_left(res) == []
