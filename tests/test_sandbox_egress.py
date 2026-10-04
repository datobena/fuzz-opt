"""Tests for the allowlisting egress proxy.

Network access is one of the few remaining ways the agent can learn where the
bug is: the CVE is public, ARVO-Meta is keyed by the image id, and the upstream
repo contains the fix commit. A leak here is silent -- the run completes and the
bug-survival number is simply meaningless.
"""
import json
import os

import pytest

from sandbox import egress
from sandbox.egress_proxy import DEFAULT_ALLOWLIST, host_allowed


@pytest.fixture(autouse=True)
def _isolate_credential_store(tmp_path, monkeypatch):
    """Never let a test write the REAL credential store.

    stage_credentials() calls seed_store(), and seed_store is seed-only by
    design: once a file exists it is the authority and is never re-seeded from
    the host. So a test that stages a fake credential without redirecting the
    store leaves `{"accessToken": "secret"}` in .sandbox-creds/claude.json
    permanently -- and every sandboxed optimizer session afterwards dies with
    "Not logged in", reported only as "No changes made by <skill>". Running the
    test suite bricked the benchmark, which is exactly the kind of coupling an
    autouse fixture exists to make impossible rather than remembered.
    """
    import sandbox.egress as e
    monkeypatch.setattr(e, "CREDENTIAL_STORE", tmp_path / "_store")


def test_allows_the_backends_the_optimizer_actually_uses():
    for host in ("api.anthropic.com", "api.openai.com", "chatgpt.com"):
        assert host_allowed(host, DEFAULT_ALLOWLIST)


def test_allows_token_refresh_endpoints():
    """A run outlives its access token; a refresh that cannot reach its endpoint
    fails partway through instead of at startup."""
    assert host_allowed("console.anthropic.com", DEFAULT_ALLOWLIST)
    assert host_allowed("auth.openai.com", DEFAULT_ALLOWLIST)


def test_blocks_the_lookup_routes_to_the_bug():
    for host in ("github.com", "raw.githubusercontent.com", "storage.googleapis.com",
                 "nvd.nist.gov", "gitlab.gnome.org", "hub.docker.com"):
        assert not host_allowed(host, DEFAULT_ALLOWLIST), host


def test_subdomains_of_allowed_hosts_are_allowed():
    assert host_allowed("foo.api.anthropic.com", DEFAULT_ALLOWLIST)


def test_lookalike_suffixes_are_rejected():
    """'api.anthropic.com.attacker.net' must not match: the dot boundary is what
    stops a suffix check from being a hole."""
    for host in ("api.anthropic.com.attacker.net",
                 "notapi.anthropic.com.evil.io",
                 "evilapi.openai.com.example.org"):
        assert not host_allowed(host, DEFAULT_ALLOWLIST), host


def test_prefix_lookalikes_are_rejected():
    assert not host_allowed("xapi.anthropic.com".replace("x", "evil"), DEFAULT_ALLOWLIST)


def test_case_and_trailing_dot_are_normalized():
    assert host_allowed("API.Anthropic.COM.", DEFAULT_ALLOWLIST)


def test_empty_or_missing_host_is_denied():
    assert not host_allowed("", DEFAULT_ALLOWLIST)
    assert not host_allowed(None, DEFAULT_ALLOWLIST)


# --- credential staging ------------------------------------------------------

def test_only_the_credential_file_is_mounted_never_its_parent(tmp_path, monkeypatch):
    """~/.claude holds projects/ with transcripts from prior runs on these very
    targets. Mounting the parent to get the credential would hand the agent the
    ASAN traces and CVE ids directly (leak-inventory item 10)."""
    import sandbox.egress as e

    home = tmp_path / "home"
    (home / ".claude" / "projects" / "old-run").mkdir(parents=True)
    (home / ".claude" / "projects" / "old-run" / "transcript.jsonl").write_text(
        "AddressSanitizer: stack-buffer-overflow /src/libxml2/valid.c:1279\n")
    cred = home / ".claude" / ".credentials.json"
    cred.write_text('{"claudeAiOauth": {"accessToken": "secret"}}')

    monkeypatch.setattr(e, "CREDENTIAL_FILES", {
        "claude": (cred, "/home/agent/.claude/.credentials.json")})
    mounts = e.stage_credentials(tmp_path / "session")

    assert len(mounts) == 1
    host_src = mounts[0].split(":")[0]
    assert host_src.endswith(".json")
    assert "projects" not in host_src
    # The staged copy must not be the parent dir under any spelling.
    from pathlib import Path
    assert Path(host_src).is_file()


def test_credential_is_a_writable_copy_not_the_host_file(tmp_path, monkeypatch):
    """Access tokens expire in hours and runs last far longer, so the CLI must be
    able to refresh -- which needs a writable file. Refreshing must not touch the
    operator's real credential."""
    import sandbox.egress as e

    cred = tmp_path / "real.json"
    cred.write_text('{"token": "original"}')
    monkeypatch.setattr(e, "CREDENTIAL_FILES", {"claude": (cred, "/c.json")})

    mounts = e.stage_credentials(tmp_path / "s")
    staged = mounts[0].split(":")[0]

    assert staged != str(cred)
    assert ":ro" not in mounts[0], "a read-only mount breaks token refresh"
    from pathlib import Path
    Path(staged).write_text('{"token": "refreshed"}')
    assert cred.read_text() == '{"token": "original"}'


def test_missing_credential_is_skipped_not_fatal(tmp_path, monkeypatch):
    import sandbox.egress as e

    monkeypatch.setattr(e, "CREDENTIAL_FILES",
                        {"codex": (tmp_path / "absent.json", "/c.json")})
    assert e.stage_credentials(tmp_path / "s") == []


def test_proxy_starts_on_the_internal_network(tmp_path):
    import sandbox.egress as e

    cmd = e.build_proxy_run_command(
        internal_network="bench-agent-egress", log_dir=str(tmp_path))
    assert cmd[cmd.index("--network") + 1] == "bench-agent-egress"


def test_extra_allowed_hosts_are_passed_through(tmp_path):
    import sandbox.egress as e

    cmd = e.build_proxy_run_command(
        internal_network="n", log_dir=str(tmp_path), extra_allow=["example.com"])
    assert "--allow" in cmd and "example.com" in cmd


# --- credential lifetime across sessions -------------------------------------
#
# Access tokens last hours; runs last days. OAuth refresh tokens typically
# ROTATE, so a refresh performed inside the sandbox can revoke the credential the
# next session would otherwise re-seed from.

def _store(tmp_path, monkeypatch):
    import sandbox.egress as e
    monkeypatch.setattr(e, "CREDENTIAL_STORE", tmp_path / "store")
    return e


def test_refreshed_credential_survives_into_the_next_session(tmp_path, monkeypatch):
    """The bug this replaced: a per-session copy discarded every refresh, so the
    next session re-seeded from a host token that rotation had just revoked."""
    import time

    e = _store(tmp_path, monkeypatch)
    host = tmp_path / "host.json"
    host.write_text('{"token": "v1"}')
    monkeypatch.setattr(e, "CREDENTIAL_FILES", {"claude": (host, "/c.json")})

    s1 = tmp_path / "s1"
    staged = e.stage_credentials(s1)[0].split(":")[0]
    from pathlib import Path
    Path(staged).write_text('{"token": "v2-refreshed"}')
    import os
    os.utime(staged, (time.time() + 10, time.time() + 10))
    assert e.harvest_credentials(s1) == ["claude"]

    s2 = tmp_path / "s2"
    staged2 = e.stage_credentials(s2)[0].split(":")[0]
    assert Path(staged2).read_text() == '{"token": "v2-refreshed"}'


def test_store_is_not_re_seeded_from_a_stale_host_credential(tmp_path, monkeypatch):
    """Re-seeding would overwrite a current token with a possibly revoked one."""
    e = _store(tmp_path, monkeypatch)
    host = tmp_path / "host.json"
    host.write_text('{"token": "stale-host"}')
    monkeypatch.setattr(e, "CREDENTIAL_FILES", {"claude": (host, "/c.json")})

    e.seed_store()
    (e.CREDENTIAL_STORE / "claude.json").write_text('{"token": "fresh"}')
    e.seed_store()

    assert (e.CREDENTIAL_STORE / "claude.json").read_text() == '{"token": "fresh"}'


def test_harvest_never_writes_the_host_credential(tmp_path, monkeypatch):
    """The operator's own CLI login must not be rewritten by the sandbox."""
    import os
    import time

    e = _store(tmp_path, monkeypatch)
    host = tmp_path / "host.json"
    host.write_text('{"token": "host-original"}')
    monkeypatch.setattr(e, "CREDENTIAL_FILES", {"claude": (host, "/c.json")})

    s = tmp_path / "s"
    staged = e.stage_credentials(s)[0].split(":")[0]
    from pathlib import Path
    Path(staged).write_text('{"token": "sandbox-refreshed"}')
    os.utime(staged, (time.time() + 10, time.time() + 10))
    e.harvest_credentials(s)

    assert host.read_text() == '{"token": "host-original"}'


def test_harvest_ignores_an_older_session_copy(tmp_path, monkeypatch):
    """Parallel sessions must converge on the newest refresh, not the last to finish."""
    import os
    import time

    e = _store(tmp_path, monkeypatch)
    host = tmp_path / "host.json"
    host.write_text('{"token": "v1"}')
    monkeypatch.setattr(e, "CREDENTIAL_FILES", {"claude": (host, "/c.json")})

    s = tmp_path / "s"
    staged = e.stage_credentials(s)[0].split(":")[0]
    (e.CREDENTIAL_STORE / "claude.json").write_text('{"token": "newer"}')
    os.utime(e.CREDENTIAL_STORE / "claude.json", (time.time() + 60, time.time() + 60))
    from pathlib import Path
    Path(staged).write_text('{"token": "older"}')

    assert e.harvest_credentials(s) == []
    assert (e.CREDENTIAL_STORE / "claude.json").read_text() == '{"token": "newer"}'


# --- a failed refresh must not poison the store -----------------------------
# b3r2 lost 7 optimizer rounds to exactly this: a session whose refresh failed
# wrote expiresAt=0, harvest folded it back on mtime alone, and _credential_expiry
# then ranked the dead copy by mtime -- i.e. as the FRESHEST thing on disk -- so
# seed_store would not heal from the host and every later round reported "no
# fresher credential is available" while the refresh token was still valid.
def _oauth(expires_at):
    return json.dumps({"claudeAiOauth": {
        "accessToken": "a", "refreshToken": "r", "expiresAt": expires_at}})


def test_failed_refresh_sorts_as_oldest_not_newest(tmp_path):
    dead = tmp_path / "dead.json"
    dead.write_text(_oauth(0))
    live = tmp_path / "live.json"
    live.write_text(_oauth(1900000000000))
    assert egress._credential_expiry(dead) == 0
    assert egress._credential_expiry(live) == 1900000000000
    assert egress._credential_expiry(dead) < egress._credential_expiry(live)


def test_harvest_refuses_credential_with_no_valid_expiry(tmp_path, monkeypatch):
    store = tmp_path / "store"
    store.mkdir()
    (store / "claude.json").write_text(_oauth(1900000000000))
    monkeypatch.setattr(egress, "CREDENTIAL_STORE", store)

    session = tmp_path / "session"
    (session / "creds").mkdir(parents=True)
    staged = session / "creds" / "claude.json"
    staged.write_text(_oauth(0))
    os.utime(staged, (2_000_000_000, 2_000_000_000))   # newer by mtime

    assert egress.harvest_credentials(session, backends=["claude"]) == []
    kept = json.loads((store / "claude.json").read_text())["claudeAiOauth"]
    assert kept["expiresAt"] == 1900000000000
