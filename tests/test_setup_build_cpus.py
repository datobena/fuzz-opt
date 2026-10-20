"""Campaign-setup builds run multi-core on ONLINE_SETUP_BUILD_CPUS (phase3_online
._setup_build), retry once on the profile core, and lock every core they use."""
import json
from pathlib import Path

import pytest

import phase3_online
import prework.prework_build as pb
from lib import core_lock as cl
from lib import cpu_ledger
from prework import fb_ccache

FB_ENTRY = {"project": "mruby", "cve": "fuzzbench-900026", "local_id": 900026,
            "fuzz_target": "mruby_fuzzer", "kind": "fuzzbench", "type": "bug",
            "fuzzbench_dir": "mruby_mruby_fuzzer_8c8bbd"}


def test_parse_cpuset():
    assert cl.parse_cpuset("2-4,9,3") == [2, 3, 4, 9]
    assert cl.parse_cpuset(7) == [7]
    assert cl.parse_cpuset(None) == [] and cl.parse_cpuset("") == []


def test_cpuset_lock_takes_every_core(tmp_path, monkeypatch):
    monkeypatch.setattr(cl, "LOCK_DIR", str(tmp_path))
    with cl.cpuset_lock("3-5"):
        assert sorted(p.name for p in tmp_path.iterdir()) == [
            "fold-core-3.lock", "fold-core-4.lock", "fold-core-5.lock"]
        # Core 4 is held: a bounded wait gives up (and proceeds unlocked).
        import fcntl, os
        fd = os.open(tmp_path / "fold-core-4.lock", os.O_RDWR)
        with pytest.raises(BlockingIOError):
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.close(fd)
    with cl.cpuset_lock(None):
        pass


def test_setup_cpus_env_overrides_profile(monkeypatch):
    monkeypatch.delenv("ONLINE_SETUP_BUILD_CPUS", raising=False)
    monkeypatch.setattr(phase3_online.config, "ONLINE_SETUP_BUILD_CPUS", "", raising=False)
    assert phase3_online._setup_cpus(2) == 2
    monkeypatch.setenv("ONLINE_SETUP_BUILD_CPUS", " 2-39 ")
    assert phase3_online._setup_cpus(2) == "2-39"


def _ledger(tmp_path, monkeypatch):
    path = tmp_path / "ledger.jsonl"
    monkeypatch.setenv(cpu_ledger.LEDGER_ENV, str(path))   # not set_ledger_path: no leak
    return path


def test_setup_build_multicore_then_one_core_retry(tmp_path, monkeypatch):
    ledger = _ledger(tmp_path, monkeypatch)
    calls = []

    def fake(*, cpu, **k):
        calls.append(cpu)
        return (cpu == 2), "make: *** race"
    monkeypatch.setattr(pb, "rebuild_with_prework_image", fake)
    ok, _ = phase3_online._setup_build(entry=FB_ENTRY, source_dir="/s", out_dir="/o",
                                       setup_cpus="2-39", profile_cpu=2,
                                       stage="baseline_afl_build", counts=False)
    assert ok and calls == ["2-39", 2]
    rows = [json.loads(l) for l in ledger.read_text().splitlines()]
    assert [(r["cores"], r["retry"], r["ok"]) for r in rows] == [
        (38, False, False), (1, True, True)]


def test_setup_build_no_retry_on_success_timeout_or_same_core(monkeypatch):
    calls = []

    def ok(*, cpu, **k):
        calls.append(cpu)
        return True, ""
    monkeypatch.setattr(pb, "rebuild_with_prework_image", ok)
    assert phase3_online._setup_build(entry=FB_ENTRY, source_dir="/s", out_dir="/o",
                                      setup_cpus="2-39", profile_cpu=2)[0]
    assert calls == ["2-39"]

    calls.clear()

    def timeout(*, cpu, **k):
        calls.append(cpu)
        return False, "build timed out after 5400s"
    monkeypatch.setattr(pb, "rebuild_with_prework_image", timeout)
    assert not phase3_online._setup_build(entry=FB_ENTRY, source_dir="/s", out_dir="/o",
                                          setup_cpus="2-39", profile_cpu=2)[0]
    assert calls == ["2-39"]

    calls.clear()

    def fail(*, cpu, **k):
        calls.append(cpu)
        return False, "error"
    monkeypatch.setattr(pb, "rebuild_with_prework_image", fail)
    assert not phase3_online._setup_build(entry=FB_ENTRY, source_dir="/s", out_dir="/o",
                                          setup_cpus=2, profile_cpu=2)[0]
    assert calls == [2]


def test_template_builds_use_setup_cpus(tmp_path, monkeypatch):
    v = tmp_path / "v.txt"
    v.write_text("mruby_mruby_fuzzer_8c8bbd pass_noise_masked\n")
    monkeypatch.setattr(fb_ccache, "VERIFIED_LIST", v)
    monkeypatch.delenv("FB_CCACHE", raising=False)
    base = tmp_path / "base"
    (base / "cmplog").mkdir(parents=True)
    (base / "t").write_bytes(b"M")
    (base / "cmplog" / "t").write_bytes(b"C")
    (base / "afl++.dict").write_text('"a"\n')
    seen = []

    def fake(*, out_dir, cpu, ccache_dir=None, **k):
        seen.append((cpu, bool(ccache_dir)))
        (Path(out_dir) / "cmplog").mkdir(parents=True, exist_ok=True)
        (Path(out_dir) / "t").write_bytes(b"M")
        (Path(out_dir) / "cmplog" / "t").write_bytes(b"C")
        (Path(out_dir) / "afl++.dict").write_text('"a"\n')
        return True, ('FB_CCACHE_STATS {"build": "main", "enabled": true, "misses": 3}\n'
                      'FB_CCACHE_STATS {"build": "cmplog", "enabled": true, "misses": 3}\n')
    monkeypatch.setattr(pb, "rebuild_with_prework_image", fake)
    rec = phase3_online._prepare_fb_ccache_template(
        entry=FB_ENTRY, project_src_dir="/x", online_dir=str(tmp_path),
        baseline_bin_dir=str(base), fuzz_target="t", profile_cpu=2, setup_cpus="2-39")
    assert rec["enabled"]
    assert seen == [("2-39", True), ("2-39", False)]   # template, then noise build


def test_fuzzbench_extract_builds_baseline_from_stripped_tree(tmp_path, monkeypatch):
    """The extraction build IS the FuzzBench baseline (run_online no longer builds
    it twice), so it must see the same .git-free tree every later rebuild sees."""
    import phase2_setup
    monkeypatch.setattr(phase3_online, "prework_image_for", lambda e: "fb-aflpp/x")

    def fake_extract(image, dest):
        (Path(dest) / "src" / "mruby" / ".git").mkdir(parents=True)
        (Path(dest) / "src" / "mruby" / "a.c").write_text("x")
        return True
    monkeypatch.setattr(phase2_setup, "extract_source_from_image", fake_extract)
    monkeypatch.setattr(phase2_setup, "_find_project_source",
                        lambda root, p: Path(root) / "src" / "mruby")
    seen = {}

    def fake_build(*, source_dir, cpu, **k):
        seen["git"] = (Path(source_dir) / ".git").exists()
        seen["cpu"] = cpu
        return True, ""
    monkeypatch.setattr(pb, "rebuild_with_prework_image", fake_build)
    phase3_online._extract_online_target(
        FB_ENTRY, str(tmp_path / "tree"), str(tmp_path / "bin"), str(tmp_path / "poc"),
        "mruby_fuzzer", "mruby", cpu=2, setup_cpus="2-39")
    assert seen == {"git": False, "cpu": "2-39"}


def test_inter_round_wait_stops_at_the_last_round_start():
    w = phase3_online._inter_round_wait
    assert w(7200, None, 3600, now=0) == 7200
    assert w(7200, 86400, 3600, now=0) == 7200            # plenty of budget
    assert w(7200, 86400, 3600, now=80000) == 2800         # capped at deadline - lead
    assert w(7200, 86400, 3600, now=85000) == 0            # already inside the lead
