"""Preflight result naming and the parallel upstream driver (no docker)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import preflight_online  # noqa: E402
import preflight_upstream_batch as pub  # noqa: E402


def _e(proj, san, tgt, lid=1, kind="upstream"):
    return {"project": proj, "ossfuzz_project": proj, "kind": kind, "sanitizer": san,
            "fuzz_target": tgt, "local_id": lid, "cve": f"upstream-{lid}"}


M = [_e("a", "undefined", "a_u", 1), _e("a", "address", "a1", 2),
     _e("b", "memory", "b_m", 3), _e("a", "address", "a2", 4),
     _e("b", "address", "b1", 5), _e("c", "address", "c1", 6, kind="arvo"),
     _e("b", "address", "b2", 7)]


def test_result_path():
    f = preflight_online.result_path
    assert f("/x/preflight-p/exp", "p", None) == Path("/x/preflight-p/preflight_p.json")
    assert f("/x/preflight-p/exp", "p", 970001) == Path("/x/preflight-p/preflight_p_970001.json")
    assert f("/x/preflight-p/exp", "p", "7").name == "preflight_p_7.json"


def test_container_name():
    f = preflight_online.container_name
    assert f({"project": "p"}, 5) == "preflight_p_5"
    assert f({"project": "p", "kind": "upstream", "local_id": 9}, 5) == "preflight_p_9_5"
    # ARVO/FuzzBench entries carry a local_id too but keep their historical name
    assert f({"project": "p", "local_id": 9}, 5) == "preflight_p_5"


def test_order_entries_passes():
    es = pub.select(M)
    assert [e["fuzz_target"] for e in pub.order_entries(es)] == \
        ["a1", "b1", "a2", "b2", "a_u", "b_m"]
    assert [e["fuzz_target"] for e in pub.first_pass(es)] == ["a1", "b1"]


def test_order_entries_builders_first_in_every_pass():
    es = [_e("a", "undefined", "au1", 1), _e("b", "undefined", "bu1", 2),
          _e("a", "undefined", "au2", 3), _e("b", "address", "b1", 4),
          _e("b", "undefined", "bu2", 5), _e("a", "memory", "am1", 6),
          _e("a", "address", "a1", 7), _e("a", "memory", "am2", 8)]
    assert [e["fuzz_target"] for e in pub.order_entries(es)] == \
        ["b1", "a1", "au1", "bu1", "au2", "bu2", "am1", "am2"]
    b = pub.builders(es)
    assert b[("a", "undefined")]["fuzz_target"] == "au1"
    assert b[("a", "memory")]["fuzz_target"] == "am1"
    assert set(b) == {("a", "undefined"), ("b", "undefined"), ("b", "address"),
                      ("a", "memory"), ("a", "address")}


def test_filters():
    assert [e["fuzz_target"] for e in pub.select(M, projects=["b"])] == ["b_m", "b1", "b2"]
    assert [e["fuzz_target"] for e in pub.select(M, sanitizers=["memory"])] == ["b_m"]
    assert all(e["kind"] == "upstream" for e in pub.select(M))


def test_result_path_for_and_skip(tmp_path):
    e = _e("a", "address", "a1")
    p = pub.result_path_for(tmp_path, e)
    assert p == tmp_path / "a" / "address" / "a1.json"
    es = [e, _e("b", "address", "b1", 5)]
    assert pub.pending(es, tmp_path, False) == es
    p.parent.mkdir(parents=True)
    p.write_text("{}")
    assert pub.pending(es, tmp_path, False) == es[1:]
    assert pub.pending(es, tmp_path, True) == es


def test_summarize():
    s = pub.summarize([(_e("a", "address", "x"), True), (_e("a", "address", "y"), False),
                       (_e("b", "address", "z"), False), (_e("b", "memory", "w"), True)])
    assert "a: 1" in s and "b: 0" in s and s.endswith(": 1")


class _A:
    def __init__(self, tmp, **kw):
        self.out_dir = str(tmp / "out")
        self.manifest = str(tmp / "m.json")
        self.build_cpus, self.smoke_secs, self.smoke_cpus = "1", 1, "0,1"
        self.__dict__.update(kw)


def test_stale_verdict_not_reused(tmp_path, monkeypatch):
    monkeypatch.setattr(pub, "ROOT", tmp_path)
    e = _e("a", "address", "a1", 5)
    stale = tmp_path / "results" / "preflight-a" / "preflight_a_5.json"
    stale.parent.mkdir(parents=True)
    stale.write_text('{"ok": true}')
    monkeypatch.setattr(pub.subprocess, "run",
                        lambda cmd, **k: pub.subprocess.CompletedProcess(cmd, 3))
    v = pub.run_one(e, 0, _A(tmp_path))
    assert v["ok"] is False and v["stages"]["driver"]["exit_code"] == 3


def test_cleanup_containers_filter(monkeypatch):
    calls = []

    def fake(cmd, **k):
        calls.append(cmd)
        return pub.subprocess.CompletedProcess(cmd, 0, "abc\ndef\n", "")
    monkeypatch.setattr(pub.subprocess, "run", fake)
    pub.cleanup_containers("a", 5)
    assert calls[0] == ["docker", "ps", "-q", "--filter", "name=^preflight_a_5_"]
    assert calls[1] == ["docker", "rm", "-f", "abc", "def"]


def test_cleanup_containers_no_docker(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(pub.subprocess, "run", boom)
    pub.cleanup_containers("a", 5)


def test_timeout_cleans_up(tmp_path, monkeypatch):
    monkeypatch.setattr(pub, "ROOT", tmp_path)
    seen = []
    monkeypatch.setattr(pub, "cleanup_containers", lambda p, l: seen.append((p, l)))

    def fake(cmd, **k):
        raise pub.subprocess.TimeoutExpired(cmd, 1)
    monkeypatch.setattr(pub.subprocess, "run", fake)
    v = pub.run_one(_e("a", "address", "a1", 5), 0, _A(tmp_path))
    assert v["stages"]["driver"]["error"] == "timeout" and seen == [("a", 5)]


def test_summary_counts_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(pub, "ROOT", tmp_path)
    a = _A(tmp_path)
    old, new = _e("a", "address", "a1", 1), _e("b", "address", "b1", 2)
    p = pub.result_path_for(a.out_dir, old)
    p.parent.mkdir(parents=True)
    p.write_text('{"ok": true}')
    done = pub.collect([old, new], pub.pending([old, new], a.out_dir, False), a,
                       runner=lambda e, c, a, **k: {"ok": True})
    s = pub.summarize(done)
    assert "a: 1" in s and "b: 1" in s and s.endswith(": 2")


# --------------------------------------------------------------------------- #
# clean reruns, baseline reuse, cleanup, scheduling
# --------------------------------------------------------------------------- #
def _exp(tmp, e, built=True):
    """A fake experiment dir + preflight verdict for ``e`` under tmp/results."""
    d = pub.exp_dir_for(e, tmp / "results")
    (d / "baseline" / "bin").mkdir(parents=True, exist_ok=True)
    if built:
        (d / "baseline" / "bin" / e["fuzz_target"]).write_bytes(b"x")
    pub.verdict_src_for(e, tmp / "results").write_text("{}")
    return d


def test_exp_dir_matches_preflight_online(tmp_path):
    e = _e("a", "address", "a1", 970005)
    d = pub.exp_dir_for(e, tmp_path)
    assert d == tmp_path / "preflight-a" / "a-upstream-970005"
    assert pub.verdict_src_for(e, tmp_path) == \
        preflight_online.result_path(str(d), "a", 970005)


def test_wipe_entry_dirs(tmp_path):
    e = _e("a", "address", "a1", 5)
    d = _exp(tmp_path, e)
    keep = pub.exp_dir_for(_e("a", "address", "a2", 6), tmp_path / "results")
    keep.mkdir(parents=True)
    assert pub.wipe_entry_dirs(e, tmp_path / "results") is True
    assert not d.exists() and not pub.verdict_src_for(e, tmp_path / "results").exists()
    assert keep.is_dir()                       # only this entry's dir
    assert pub.wipe_entry_dirs(e, tmp_path / "results") is False


def test_wipe_restores_ownership_and_retries_once(tmp_path, monkeypatch):
    e = dict(_e("a", "address", "a1", 5), image="bench-upstream/a")
    d = _exp(tmp_path, e)
    real, calls, fixed = pub.shutil.rmtree, [], []

    def rmtree(p, *a, **k):
        calls.append(p)
        if not fixed:
            raise PermissionError(13, "Permission denied")
        real(p, *a, **k)
    monkeypatch.setattr(pub.shutil, "rmtree", rmtree)
    monkeypatch.setattr(pub, "_restore_ownership",
                        lambda img, paths: fixed.append((img, paths)))
    pub.wipe_entry_dirs(e, tmp_path / "results")
    assert fixed == [("bench-upstream/a", [str(d)])] and len(calls) == 2
    assert not d.exists()

    # Still failing after the chown: raised, not looped.
    d = _exp(tmp_path, e)
    monkeypatch.setattr(pub, "_restore_ownership", lambda img, paths: None)
    monkeypatch.setattr(pub.shutil, "rmtree",
                        lambda p, *a, **k: (_ for _ in ()).throw(PermissionError(13, "x")))
    with pytest.raises(PermissionError):
        pub.wipe_entry_dirs(e, tmp_path / "results")


def test_run_one_starts_clean_and_passes_reuse_and_build_cpus(tmp_path, monkeypatch):
    monkeypatch.setattr(pub, "ROOT", tmp_path)
    e = _e("a", "address", "a2", 6)
    d = _exp(tmp_path, e)
    (d / "optimized" / "online" / "source_tree").mkdir(parents=True)
    seen = {}

    def fake(cmd, **k):
        seen["cmd"], seen["stale"] = cmd, d.exists()
        return pub.subprocess.CompletedProcess(cmd, 1)
    monkeypatch.setattr(pub.subprocess, "run", fake)
    pub.run_one(e, 4, _A(tmp_path), build_cpus="20-29", baseline_from="/x/builder")
    assert seen["stale"] is False             # wiped before the launch
    cmd = seen["cmd"]
    assert cmd[cmd.index("--build-cpus") + 1] == "20-29"
    assert cmd[cmd.index("--baseline-from") + 1] == "/x/builder"
    pub.run_one(e, 4, _A(tmp_path, build_cpus="1-3"))
    assert "--baseline-from" not in seen["cmd"]
    assert seen["cmd"][seen["cmd"].index("--build-cpus") + 1] == "1-3"


def test_run_one_wipe_failure_is_a_verdict(tmp_path, monkeypatch):
    monkeypatch.setattr(pub, "ROOT", tmp_path)
    monkeypatch.setattr(pub, "wipe_entry_dirs",
                        lambda e, r: (_ for _ in ()).throw(PermissionError(13, "x")))
    monkeypatch.setattr(pub.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("launched")))
    v = pub.run_one(_e("a", "address", "a1", 5), 0, _A(tmp_path))
    assert v["ok"] is False and "could not wipe" in v["stages"]["driver"]["error"]


def test_build_ok():
    assert pub.build_ok({"stages": {"extract": {"ok": True}, "aflbuild": {"ok": True}}})
    assert not pub.build_ok({"stages": {"extract": {"ok": True}, "aflbuild": {"ok": False}}})
    assert not pub.build_ok({"stages": {"extract": {"ok": False}}})
    assert pub.build_ok({"stages": {"extract": {"ok": True, "reused_from": "/b"}}})
    assert not pub.build_ok({"stages": {"driver": {"ok": False, "error": "timeout"}}})
    assert not pub.build_ok({})


def test_build_cpusets():
    assert pub.build_cpusets("10-19,30-39") == ["10-19,30-39"]
    assert pub.build_cpusets("10-14;15-19; 30-34") == ["10-14", "15-19", "30-34"]
    assert pub.build_cpusets("") == [""]


class _Runner:
    """Fake run_one: records start/end order and arguments; builds a fake
    experiment dir for entries whose verdict says the build passed."""

    def __init__(self, tmp, fail=(), delay=0.05):
        self.tmp, self.fail, self.delay = tmp, set(fail), delay
        self.events, self.args = [], {}
        self.lock = pub.threading.Lock()

    def __call__(self, e, core, a, build_cpus=None, baseline_from=None):
        t = e["fuzz_target"]
        with self.lock:
            self.events.append(("start", t))
            self.args[t] = (core, build_cpus, baseline_from)
        pub.time.sleep(self.delay)
        built = t not in self.fail
        _exp(self.tmp, e, built=built)
        ex = {"ok": built, **({"reused_from": str(baseline_from)} if baseline_from else {})}
        v = {"ok": built, "stages": {"extract": ex, "aflbuild": {"ok": built}}}
        pub.result_path_for(a.out_dir, e).parent.mkdir(parents=True, exist_ok=True)
        pub.result_path_for(a.out_dir, e).write_text(pub.json.dumps(v))
        with self.lock:
            self.events.append(("end", t))
        return v


def _run(tmp, es, monkeypatch, a=None, runner=None, first=False):
    monkeypatch.setattr(pub, "ROOT", tmp)
    a = a or _A(tmp, smoke_cpus="0,1,2")
    ordered = pub.first_pass(es) if first else pub.order_entries(es)
    runner = runner or _Runner(tmp)
    done = pub.collect(ordered, pub.pending(ordered, a.out_dir, False), a, runner=runner)
    return runner, done, a


G = [_e("a", "address", "a1", 1), _e("a", "address", "a2", 2),
     _e("a", "address", "a3", 3), _e("b", "address", "b1", 4),
     _e("b", "address", "b2", 5), _e("a", "undefined", "au1", 6),
     _e("a", "undefined", "au2", 7)]


def test_dependents_run_after_their_builder_with_its_baseline(tmp_path, monkeypatch):
    r, done, a = _run(tmp_path, G, monkeypatch)
    ev = r.events
    for builder, deps in (("a1", ["a2", "a3"]), ("b1", ["b2"]), ("au1", ["au2"])):
        assert r.args[builder][2] is None
        src = pub.exp_dir_for(next(e for e in G if e["fuzz_target"] == builder),
                              tmp_path / "results")
        for d in deps:
            assert ev.index(("end", builder)) < ev.index(("start", d))
            assert r.args[d][2] == src
    assert len(done) == len(G) and all(ok for _, ok in done)
    # Default cleanup: every dir deleted, dependents' as soon as their verdict
    # was copied, builders' at the end.
    assert not any(pub.exp_dir_for(e, tmp_path / "results").exists() for e in G)


def test_builders_are_eligible_at_once(tmp_path, monkeypatch):
    # Three workers, three builders (one in a later pass): all three run at the
    # same time -- each waits for the other two before it finishes.
    barrier = pub.threading.Barrier(3, timeout=10)
    inner = _Runner(tmp_path, delay=0)

    def runner(e, core, a, **k):
        if e["fuzz_target"] in ("a1", "b1", "au1"):
            barrier.wait()
        return inner(e, core, a, **k)
    _, done, _ = _run(tmp_path, G, monkeypatch, runner=runner)
    assert all(ok for _, ok in done)


def test_builder_failed_dependents_written_without_running(tmp_path, monkeypatch):
    r, done, a = _run(tmp_path, G, monkeypatch, runner=_Runner(tmp_path, fail={"a1"}))
    started = {t for k, t in r.events if k == "start"}
    assert "a2" not in started and "a3" not in started
    for t in ("a2", "a3"):
        e = next(e for e in G if e["fuzz_target"] == t)
        v = pub.json.loads(pub.result_path_for(a.out_dir, e).read_text())
        assert v["ok"] is False
        assert v["stages"]["driver"] == {"ok": False, "error": "group baseline build failed"}
    assert dict((e["fuzz_target"], ok) for e, ok in done)["b2"] is True


def test_first_pass_only_runs_address_builders(tmp_path, monkeypatch):
    r, done, _ = _run(tmp_path, G, monkeypatch, first=True)
    assert {t for k, t in r.events if k == "start"} == {"a1", "b1"}
    assert {e["fuzz_target"] for e, _ in done} == {"a1", "b1"}


def test_keep_exp_dirs(tmp_path, monkeypatch):
    a = _A(tmp_path, smoke_cpus="0,1", keep_exp_dirs=True)
    _run(tmp_path, G, monkeypatch, a=a)
    assert all(pub.exp_dir_for(e, tmp_path / "results").is_dir() for e in G)


def test_dependent_dirs_deleted_before_builders(tmp_path, monkeypatch, capsys):
    es = G[:3]
    r, _, _ = _run(tmp_path, es, monkeypatch, a=_A(tmp_path, smoke_cpus="0"))
    lines = [l for l in capsys.readouterr().out.splitlines() if l.startswith("deleted ")]
    names = [Path(l.split()[1]).name for l in lines]
    assert names == ["a-upstream-2", "a-upstream-3", "a-upstream-1"]


def test_skipped_builder_with_dir_is_the_source(tmp_path, monkeypatch):
    a = _A(tmp_path, smoke_cpus="0,1")
    b = G[0]
    d = _exp(tmp_path, b)
    p = pub.result_path_for(a.out_dir, b)
    p.parent.mkdir(parents=True)
    p.write_text('{"ok": true, "stages": {"extract": {"ok": true}, "aflbuild": {"ok": true}}}')
    r, done, _ = _run(tmp_path, G[:3], monkeypatch, a=a)
    assert {t for k, t in r.events if k == "start"} == {"a2", "a3"}
    assert r.args["a2"][2] == d and r.args["a3"][2] == d
    assert len(done) == 3 and not d.exists()   # a builder: deleted at the end


def test_skipped_builder_without_dir_next_entry_builds(tmp_path, monkeypatch):
    a = _A(tmp_path, smoke_cpus="0,1")
    p = pub.result_path_for(a.out_dir, G[0])
    p.parent.mkdir(parents=True)
    p.write_text('{"ok": true, "stages": {"extract": {"ok": true}, "aflbuild": {"ok": true}}}')
    r, _, _ = _run(tmp_path, G[:3], monkeypatch, a=a)
    assert r.args["a2"][2] is None             # rebuilt: a2 is the builder now
    assert r.args["a3"][2] == pub.exp_dir_for(G[1], tmp_path / "results")
    assert r.events.index(("end", "a2")) < r.events.index(("start", "a3"))


def test_skipped_builder_failed_dependents_not_run(tmp_path, monkeypatch):
    a = _A(tmp_path, smoke_cpus="0")
    p = pub.result_path_for(a.out_dir, G[0])
    p.parent.mkdir(parents=True)
    p.write_text('{"ok": false, "stages": {"extract": {"ok": false}}}')
    r, done, _ = _run(tmp_path, G[:3], monkeypatch, a=a)
    assert r.events == []
    assert [ok for _, ok in done] == [False, False, False]


def test_build_cpus_round_robin_per_worker(tmp_path, monkeypatch):
    es = [_e(p, "address", p + "1", i) for i, p in enumerate("abcd")]
    a = _A(tmp_path, smoke_cpus="0,1,2,3", build_cpus="10-14;15-19")
    r, _, _ = _run(tmp_path, es, monkeypatch, a=a, runner=_Runner(tmp_path, delay=0.2))
    # Worker i owns smoke core i and build cpuset i % 2.
    assert len(r.args) == 4
    assert all(bc == ["10-14", "15-19"][core % 2] for core, bc, _ in r.args.values())


def test_runner_exception_is_one_not_ready_entry(tmp_path, monkeypatch):
    def boom(e, core, a, **k):
        raise RuntimeError("bad")
    _, done, a = _run(tmp_path, G[3:5], monkeypatch, runner=boom)
    v = pub.json.loads(pub.result_path_for(a.out_dir, G[3]).read_text())
    assert "RuntimeError: bad" in v["stages"]["driver"]["error"]
    # b1's build "failed" (no verdict stages): b2 written without running.
    assert [ok for _, ok in done] == [False, False]
