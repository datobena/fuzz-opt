"""Broker wiring of the per-trial ccache for upstream images (Task 6)."""
from contextlib import nullcontext
from types import SimpleNamespace

import sandbox.broker as b
from sandbox.broker import BrokerContext

UP = "bench-upstream/libssh-x"


def _ctx(tmp_path, image=UP, ccache_dir=""):
    return BrokerContext(
        image=image, source_dir=str(tmp_path), out_dir=str(tmp_path / "out"),
        corpus_dir=str(tmp_path), fuzz_target="t", project="libssh", cpu=3,
        ccache_dir=ccache_dir,
        source_guard=SimpleNamespace(snapshot=lambda: nullcontext(tmp_path)))


def test_build_command_upstream_uses_cache_when_env_set(tmp_path):
    cache = tmp_path / "cache"
    cmd = b._build_command(_ctx(tmp_path, ccache_dir=str(cache)))
    joined = " ".join(cmd)
    assert f"{cache}:" in joined
    assert "CCACHE_DISABLE=1" not in joined


def test_build_command_upstream_uncached_without_env(tmp_path):
    joined = " ".join(b._build_command(_ctx(tmp_path)))
    assert "CCACHE_DISABLE=1" in joined
    assert "cache" not in joined.replace("CCACHE_DISABLE", "")


def test_run_build_snapshot_upstream_branch(tmp_path, monkeypatch):
    cache = tmp_path / "newcache"
    seen = {}
    monkeypatch.setattr(b, "_run", lambda cmd, *a, **k: (seen.setdefault("cmd", cmd), (0, ""))[1])
    monkeypatch.setattr(b, "_audit", lambda *a, **k: None)
    monkeypatch.setattr(b, "_capture_reference", lambda ctx: None)
    owned = []
    monkeypatch.setattr(b, "_restore_ownership",
                        lambda ctx, **k: owned.append(ctx.ccache_dir) or True)
    ctx = _ctx(tmp_path, ccache_dir=str(cache))
    ok, _ = b._run_build_snapshot(ctx)
    assert ok and cache.is_dir()
    assert f"{cache}:" in " ".join(seen["cmd"])
    assert owned == [str(cache)]

