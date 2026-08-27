"""The sandbox store must hold the CURRENTLY VALID credential, either direction.

Refresh tokens rotate: whoever refreshes last revokes the other side's token.
The store has to survive a sandbox-side refresh (its original reason for being
seed-only) AND a host-side one -- the host runs a live CLI, and when it refreshed
mid-campaign the store kept a revoked token and every optimizer session died with
"401 OAuth access token has been revoked".
"""
from __future__ import annotations

import json

import sandbox.egress as e


def _write(path, expires):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"claudeAiOauth": {
        "accessToken": f"tok-{expires}", "expiresAt": expires}}))


def _setup(tmp_path, monkeypatch, host_exp, store_exp):
    host = tmp_path / "host" / ".credentials.json"
    _write(host, host_exp)
    monkeypatch.setattr(e, "CREDENTIAL_FILES",
                        {"claude": (host, "/home/agent/.claude/.credentials.json")})
    monkeypatch.setattr(e, "CREDENTIAL_STORE", tmp_path / "store")
    if store_exp is not None:
        _write(e.CREDENTIAL_STORE / "claude.json", store_exp)
    return host, e.CREDENTIAL_STORE / "claude.json"


def _exp(path):
    return json.loads(path.read_text())["claudeAiOauth"]["expiresAt"]


def test_host_refresh_is_picked_up(tmp_path, monkeypatch):
    """The observed failure: host refreshed at 02:13, store still held the token
    that refresh revoked."""
    _, stored = _setup(tmp_path, monkeypatch, host_exp=2000, store_exp=1000)
    e.seed_store()
    assert _exp(stored) == 2000


def test_sandbox_refresh_is_not_clobbered(tmp_path, monkeypatch):
    """The original invariant: a newer store copy must survive."""
    _, stored = _setup(tmp_path, monkeypatch, host_exp=1000, store_exp=2000)
    e.seed_store()
    assert _exp(stored) == 2000


def test_equal_expiry_leaves_the_store_alone(tmp_path, monkeypatch):
    _, stored = _setup(tmp_path, monkeypatch, host_exp=1500, store_exp=1500)
    before = stored.read_text()
    e.seed_store()
    assert stored.read_text() == before


def test_empty_store_is_seeded(tmp_path, monkeypatch):
    _, stored = _setup(tmp_path, monkeypatch, host_exp=1234, store_exp=None)
    e.seed_store()
    assert _exp(stored) == 1234


def test_a_store_with_no_host_credential_is_kept(tmp_path, monkeypatch):
    """Losing the host copy must not wipe a working sandbox credential."""
    host, stored = _setup(tmp_path, monkeypatch, host_exp=1, store_exp=999)
    host.unlink()
    e.seed_store()
    assert _exp(stored) == 999


def test_unparseable_files_fall_back_to_mtime(tmp_path, monkeypatch):
    """A backend whose file is not OAuth-shaped must still order sensibly."""
    host, stored = _setup(tmp_path, monkeypatch, host_exp=1, store_exp=1)
    host.write_text("not json")
    stored.write_text("not json either")
    import os, time
    os.utime(host, (time.time() + 60, time.time() + 60))
    e.seed_store()
    assert stored.read_text() == "not json"
