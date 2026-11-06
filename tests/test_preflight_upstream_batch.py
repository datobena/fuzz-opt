"""Preflight result naming and the parallel upstream driver (no docker)."""
from __future__ import annotations

import sys
from pathlib import Path

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


def test_summary_counts_skipped(tmp_path):
    a = _A(tmp_path)
    old, new = _e("a", "address", "a1", 1), _e("b", "address", "b1", 2)
    p = pub.result_path_for(a.out_dir, old)
    p.parent.mkdir(parents=True)
    p.write_text('{"ok": true}')
    done = pub.collect([old, new], pub.pending([old, new], a.out_dir, False), a,
                       runner=lambda e, c, a: {"ok": True})
    s = pub.summarize(done)
    assert "a: 1" in s and "b: 1" in s and s.endswith(": 2")
