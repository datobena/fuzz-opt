"""Task 5: upstream ccache wiring in phase3_online (fakes only, no docker)."""
from pathlib import Path

import phase3_online as p3
import prework.prework_build as pb
from prework import upstream_ccache as uc

UP = {"kind": "upstream", "project": "libfoo", "ossfuzz_project": "libfoo"}
FB = {"kind": "fuzzbench", "project": "libfoo", "fuzzbench_dir": "libfoo"}


def _bin(d, content=b"ELF"):
    Path(d).mkdir(parents=True, exist_ok=True)
    (Path(d) / "t").write_bytes(content)


def _prep(tmp_path, entry, verified, build_fn):
    base = tmp_path / "base"
    _bin(base)
    online = tmp_path / "online"
    online.mkdir(exist_ok=True)
    return uc.prepare_upstream_ccache_template(
        entry=entry, online_dir=online, baseline_bin_dir=base, fuzz_target="t",
        build_fn=build_fn, verified=verified)


def _good_build(calls, statslog="1 cache_miss\n"):
    def fn(out, cache, stage):
        calls.append((stage, cache))
        _bin(out)
        if cache:
            (Path(cache) / "statslog").write_text(statslog)
        return True, ""
    return fn


def test_unverified_target_runs_uncached(tmp_path):
    calls = []
    rec = _prep(tmp_path, UP, {}, _good_build(calls))
    assert rec["enabled"] is False and rec["template"] is None
    assert calls == []          # not even a template build
    # and the strategy sets no broker key / passes no cache dir
    rebuilds = []
    import prework.prework_build as pbm
    orig = pbm.rebuild_with_prework_image
    pbm.rebuild_with_prework_image = lambda **kw: rebuilds.append(kw) or (True, "")
    try:
        rf, wf = p3._online_target_strategy(UP, "t", ccache_dir=None)
        wenv = wf("/x", "/y")
    finally:
        pbm.rebuild_with_prework_image = orig
    assert uc.BROKER_ENV_KEY not in wenv


def test_verified_template_ok(tmp_path):
    calls = []
    rec = _prep(tmp_path, UP, {"libfoo": "pass"}, _good_build(calls))
    assert rec["enabled"] and rec["template"]
    assert [c[0] for c in calls] == ["upstream_ccache_template_build"]


def test_template_failure_disables_campaign_ccache(tmp_path):
    def bad(out, cache, stage):
        return False, "boom"
    rec = _prep(tmp_path, UP, {"libfoo": "pass"}, bad)
    assert rec["enabled"] is False and rec["template"] is None

    def raises(out, cache, stage):
        raise RuntimeError("docker died")
    rec = _prep(tmp_path, UP, {"libfoo": "pass"}, raises)
    assert rec["enabled"] is False and rec["template"] is None
    assert not (tmp_path / "online" / uc.TEMPLATE_DIRNAME).exists()

    # cached build differs from baseline -> off
    def differs(out, cache, stage):
        _bin(out, b"XYZ")
        (Path(cache) / "statslog").write_text("1 cache_miss\n")
        return True, ""
    assert _prep(tmp_path, UP, {"libfoo": "pass"}, differs)["enabled"] is False
    # cache unused -> off
    assert _prep(tmp_path, UP, {"libfoo": "pass"},
                 _good_build([], statslog=""))["enabled"] is False


def test_fuzzbench_entry_is_not_handled(tmp_path):
    calls = []
    assert _prep(tmp_path, FB, {"libfoo": "pass"}, _good_build(calls))["enabled"] is False
    assert calls == []


def test_noise_masked_does_one_extra_uncached_build(tmp_path):
    calls = []
    rec = _prep(tmp_path, UP, {"libfoo": "pass_noise_masked"}, _good_build(calls))
    # identical binaries -> deterministic noise model, identical compare -> ok
    assert rec["enabled"]
    assert [c[0] for c in calls] == ["upstream_ccache_template_build",
                                     "upstream_ccache_template_noise_build"]
    assert calls[1][1] is None


def test_broker_env_key_set_only_for_verified_optimized(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(pb, "rebuild_with_prework_image",
                        lambda **kw: seen.append(kw) or (True, "log"))
    monkeypatch.setattr(p3.phase2_setup, "_find_project_source",
                        lambda root, proj: Path(root))
    cache = tmp_path / "trialcache"
    # optimized trial of a verified target
    rf, wf = p3._online_target_strategy(UP, "t", ccache_dir=str(cache))
    rf("/src", "/out")
    env = wf("/src", "/st")
    assert env[uc.BROKER_ENV_KEY] == str(cache)
    assert uc.BROKER_ENV_KEY != p3.fb_ccache.BROKER_ENV_KEY
    assert p3.fb_ccache.BROKER_ENV_KEY not in env
    assert seen[-1]["ccache_dir"] == str(cache)
    # baseline / reference style strategy: no cache
    rf, wf = p3._online_target_strategy(UP, "t")
    rf("/src", "/out")
    assert "ccache_dir" not in seen[-1]
    assert uc.BROKER_ENV_KEY not in wf("/src", "/st")


def test_stats_read_from_statslog_and_missing_is_unused(tmp_path, monkeypatch):
    monkeypatch.setattr(pb, "rebuild_with_prework_image", lambda **kw: (True, "log"))
    monkeypatch.setattr(p3.phase2_setup, "_find_project_source",
                        lambda root, proj: Path(root))
    cache = tmp_path / "c"
    cache.mkdir()
    rf, _wf = p3._online_target_strategy(UP, "t", ccache_dir=str(cache))
    # missing statslog: no crash, used False
    rf("/src", "/out")
    assert rf.ccache_stats["used"] is False
    (cache / "statslog").write_text("1 direct_cache_hit\n2 direct_cache_hit\n3 cache_miss\n")
    rf("/src", "/out")
    assert rf.ccache_stats == {"hits": 2, "misses": 1, "other": 0, "used": True}
    assert uc.read_trial_stats(tmp_path / "nonexistent")["used"] is False


def test_seed_cache_is_a_copy(tmp_path):
    t = tmp_path / "t"
    (t / "a").mkdir(parents=True)
    (t / "a" / "o").write_text("x")
    dest = uc.seed_cache(t, uc.trial_cache_dir(tmp_path / "trial"))
    assert (Path(dest) / "a" / "o").read_text() == "x" and Path(dest) != t
