"""An expired or rotated credential must cost a retry, not a whole round.

The benchmark and the operator's CLI share one OAuth identity whose tokens
expire (~8h) and rotate on refresh. A round landing in that gap loses its entire
optimizer session: the agent never starts, so there is no diff and nothing for
the gates to judge. Observed live -- the store's token expired at 10:13:41, the
session failed at 10:13:46, the host refreshed at 10:13:47.
"""
from __future__ import annotations

import phase2_setup as ps


def test_recognises_the_failures_actually_seen():
    assert ps._is_auth_failure("", "API Error: 401 OAuth access token has expired.")
    assert ps._is_auth_failure("", "401 OAuth access token has been revoked.")
    assert ps._is_auth_failure("Not logged in · Please run /login", "")
    assert ps._is_auth_failure("", "Failed to authenticate. API Error: 401")


def test_does_not_misread_ordinary_output_as_an_auth_failure():
    """A fold mentioning tokens or login must not trigger a credential reseed."""
    assert not ps._is_auth_failure("BLOCKED_LOW_CONFIDENCE", "")
    assert not ps._is_auth_failure("refactored token parser", "")
    assert not ps._is_auth_failure("", "build failed: undefined reference")
    assert not ps._is_auth_failure("", "")


def test_reseed_reports_change(tmp_path, monkeypatch):
    import sandbox.egress as e
    store = tmp_path / "store"
    store.mkdir()
    (store / "claude.json").write_text("old")
    monkeypatch.setattr(e, "CREDENTIAL_STORE", store)
    monkeypatch.setattr(e, "CREDENTIAL_FILES", {"claude": (tmp_path / "h", "/c")})
    monkeypatch.setattr(e, "seed_store",
                        lambda *a, **k: (store / "claude.json").write_text("new"))
    assert ps._reseed_credentials_after_auth_failure() is True


def test_reseed_reports_no_change_so_a_bad_login_cannot_spin(tmp_path, monkeypatch):
    """Without this the retry loop would burn all its attempts re-running an
    agent that cannot authenticate at all."""
    import sandbox.egress as e
    store = tmp_path / "store"
    store.mkdir()
    (store / "claude.json").write_text("same")
    monkeypatch.setattr(e, "CREDENTIAL_STORE", store)
    monkeypatch.setattr(e, "CREDENTIAL_FILES", {"claude": (tmp_path / "h", "/c")})
    monkeypatch.setattr(e, "seed_store", lambda *a, **k: None)
    assert ps._reseed_credentials_after_auth_failure() is False


def test_reseed_survives_a_broken_store(tmp_path, monkeypatch):
    import sandbox.egress as e
    monkeypatch.setattr(e, "CREDENTIAL_FILES", {"claude": (tmp_path / "h", "/c")})
    monkeypatch.setattr(e, "seed_store", lambda *a, **k: (_ for _ in ()).throw(OSError("nope")))
    assert ps._reseed_credentials_after_auth_failure() is False


# --- the retry CONDITION: a usable credential, not merely a changed one -----
def test_a_valid_store_is_usable(tmp_path, monkeypatch):
    import json, time
    import sandbox.egress as e
    store = tmp_path / "s"; store.mkdir()
    (store / "claude.json").write_text(json.dumps(
        {"claudeAiOauth": {"expiresAt": int((time.time() + 3600) * 1000)}}))
    monkeypatch.setattr(e, "CREDENTIAL_STORE", store)
    monkeypatch.setattr(e, "CREDENTIAL_FILES", {"claude": (tmp_path / "h", "/c")})
    assert ps._store_credential_is_usable() is True


def test_an_expired_store_is_not_usable(tmp_path, monkeypatch):
    """Retrying against an expired credential would just fail again."""
    import json, time
    import sandbox.egress as e
    store = tmp_path / "s"; store.mkdir()
    (store / "claude.json").write_text(json.dumps(
        {"claudeAiOauth": {"expiresAt": int((time.time() - 10) * 1000)}}))
    monkeypatch.setattr(e, "CREDENTIAL_STORE", store)
    monkeypatch.setattr(e, "CREDENTIAL_FILES", {"claude": (tmp_path / "h", "/c")})
    assert ps._store_credential_is_usable() is False


def test_a_credential_about_to_expire_is_not_usable(tmp_path, monkeypatch):
    """A 60s margin: a token expiring mid-retry is not worth a round."""
    import json, time
    import sandbox.egress as e
    store = tmp_path / "s"; store.mkdir()
    (store / "claude.json").write_text(json.dumps(
        {"claudeAiOauth": {"expiresAt": int((time.time() + 30) * 1000)}}))
    monkeypatch.setattr(e, "CREDENTIAL_STORE", store)
    monkeypatch.setattr(e, "CREDENTIAL_FILES", {"claude": (tmp_path / "h", "/c")})
    assert ps._store_credential_is_usable() is False


def test_a_missing_store_is_not_usable(tmp_path, monkeypatch):
    import sandbox.egress as e
    monkeypatch.setattr(e, "CREDENTIAL_STORE", tmp_path / "nope")
    monkeypatch.setattr(e, "CREDENTIAL_FILES", {"claude": (tmp_path / "h", "/c")})
    assert ps._store_credential_is_usable() is False


def test_the_auth_retry_is_bounded_to_one():
    """A dead login must not burn all ten attempts."""
    import inspect
    src = inspect.getsource(ps._optimize_and_build)
    assert "_auth_retried = False" in src
    assert "and not _auth_retried" in src
    assert "_auth_retried = True" in src


# --- a rejected long-lived token falls back to the normal login, once -------
def _token_world(tmp_path, monkeypatch):
    """An account->token map naming the active account, plus a rotating login."""
    import json
    import sandbox.egress as e
    tokens = tmp_path / "account_tokens.json"
    tokens.write_text(json.dumps({"a@example.com": "sk-ant-oat01-year"}))
    tokens.chmod(0o600)
    config = tmp_path / "claude.json"
    config.write_text(json.dumps({"oauthAccount": {"emailAddress": "a@example.com"}}))
    host = tmp_path / "host.json"
    host.write_text(json.dumps({"claudeAiOauth": {"accessToken": "x",
                                                  "refreshToken": "r"}}))
    monkeypatch.setattr(e, "ACCOUNT_TOKENS_PATH", tokens)
    monkeypatch.setattr(e, "CLAUDE_CONFIG_PATH", config)
    monkeypatch.setattr(e, "CREDENTIAL_FILES", {"claude": (host, "/c")})
    monkeypatch.setattr(e, "api_key", lambda: "")
    monkeypatch.delenv(e.OAUTH_TOKEN_ENV, raising=False)
    return e


def test_rotating_login_only_skips_long_lived_tokens(tmp_path, monkeypatch):
    e = _token_world(tmp_path, monkeypatch)
    assert e.resolve_session_credential() == ("account_token", "sk-ant-oat01-year")
    with e.rotating_login_only():
        assert e.resolve_session_credential() == ("oauth_file", "")
        monkeypatch.setenv(e.OAUTH_TOKEN_ENV, "sk-ant-oat01-env")
        assert e.resolve_session_credential() == ("oauth_file", "")
        monkeypatch.setattr(e, "api_key", lambda: "key")      # not a subscription token
        assert e.resolve_session_credential() == ("api_key", "key")
    monkeypatch.setattr(e, "api_key", lambda: "")
    monkeypatch.delenv(e.OAUTH_TOKEN_ENV)
    assert e.resolve_session_credential() == ("account_token", "sk-ant-oat01-year")


def test_rotating_login_only_is_per_thread(tmp_path, monkeypatch):
    """Ten optimizers share the process; one round's fallback must not move the
    other nine off their year tokens."""
    import threading
    e = _token_world(tmp_path, monkeypatch)
    seen = {}
    inside, done = threading.Event(), threading.Event()

    def falling_back():
        with e.rotating_login_only():
            seen["fallback"] = e.resolve_session_credential()[0]
            inside.set()
            done.wait(5)

    t = threading.Thread(target=falling_back)
    t.start()
    inside.wait(5)
    seen["other"] = e.resolve_session_credential()[0]
    done.set()
    t.join(5)
    assert seen == {"fallback": "oauth_file", "other": "account_token"}


def test_the_rotating_fallback_is_wired_and_bounded():
    import inspect
    src = inspect.getsource(ps._optimize_and_build)
    assert "_rotating_login_context(_rotating_fallback)" in src
    i = src.index("if used in _LONG_LIVED_TOKEN_MODES and not _auth_retried:")
    branch = src[i:src.index("continue", i)]
    assert "_auth_retried = True" in branch and "_rotating_fallback = True" in branch
    assert 'reset", "--hard"' in branch, "the retry must start from the profiled tree"
