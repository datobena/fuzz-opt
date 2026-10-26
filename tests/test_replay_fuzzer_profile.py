import importlib.util
import json
import re
import subprocess
import types
from pathlib import Path

import pytest


# The skill is vendored in this repo under skills/, where config.py points.
SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "skills" / "profile-once-fuzz-folds" / "scripts"


def _load_module(name):
    path = SCRIPTS_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _fake_hotspots(**kw):
    return {"total_samples": 1000, "target_source_samples": 900,
            "target_source_pct": 90.0, "outside_target_samples": 100,
            "target_source_functions": 3, "source_root": "/src/demo",
            "harness_files": [], "perf_script_seconds": 1.5, "host_seconds": 2.0,
            "seconds_total": 3.5, "host_timings": {}}


def _no_target_libs(profile, monkeypatch):
    """These tests fake the perf container only; the shared-library probe that
    runs before it has its own tests (test_profile_target_libs.py)."""
    monkeypatch.setattr(profile, "prepare_target_libs", lambda **kw: None)


def test_replay_profile_command_perf_records_a_readonly_replay_loop(tmp_path):
    profile = _load_module("replay_fuzzer_profile")

    cmd = profile.build_replay_profile_docker_command(
        out_dir=tmp_path / "out",
        corpus_dir=tmp_path / "fixed",
        artifact_dir=tmp_path / "artifacts",
        fuzz_target="demo_fuzzer",
        min_sample_seconds=60,
        seed=1337,
        cpu=3,
        memory="4g",
        shm_size="2g",
    )

    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "--cpuset-cpus" in cmd
    assert cmd[cmd.index("--cpuset-cpus") + 1] == "3"
    # The live script records in a kernel-matched profiler image (perf must match
    # `uname -r`), configurable via FUZZ_SOURCE_FOLDS_PROFILER_IMAGE.
    assert profile.PROFILER_IMAGE in cmd

    joined = " ".join(str(part) for part in cmd)
    # Corpus and binary are read-only: a profile pass must never mutate the
    # frozen evaluation set.
    assert f"{tmp_path / 'fixed'}:/corpus:ro" in joined
    assert f"{tmp_path / 'out'}:/out:ro" in joined
    assert f"{tmp_path / 'artifacts'}:/artifacts" in joined

    script = cmd[-1]
    assert "apt-get install -y linux-tools-generic" in script
    # Call graph records with LBR where available, falling back to FP -- never
    # dwarf (empty under the -gline-tables-only OSS-Fuzz build). See the comment
    # in replay_fuzzer_profile.py.
    assert "--call-graph dwarf" not in script
    assert "CG=fp" in script
    assert "--call-graph lbr" in script
    assert 'record -g --call-graph "$CG" -F 997' in script
    assert "-o /artifacts/perf.data --" in script
    # Replay loop: -runs=0, fixed seed, looped until the sample floor elapses.
    assert "/bin/bash -c '" in script
    assert "-runs=0" in script
    assert "-seed=1337" in script
    assert "while [" in script and "$(date +%s)" in script
    assert "+ 60 ))" in script
    # Reports are generated in-container (symbol resolution).
    assert "report --stdio --no-children -g none --percent-limit 0.5" in script
    assert "report --stdio -g callee,0.5 --percent-limit 0.5" in script
    # Inclusive (self + descendants) report so allocation cost is credited to the
    # target functions that drive it, not just the uneditable __asan/libc leaves.
    assert "report --stdio -g caller --children --percent-limit 0.5" in script
    assert "/artifacts/flat.txt" in script
    assert "/artifacts/callgraph.txt" in script
    assert "/artifacts/children.txt" in script
    assert "chmod a+r /artifacts/perf.data /artifacts/fuzzer.log" in script
    # Every sample's call chain, symbol-resolved in the SAME container run, for
    # the hotspot table (no percent floor).
    assert ("script -i /artifacts/perf.data --no-inline "
            "-F comm,pid,period,ip,sym,symoff,dso,dsoff") in script
    assert "| gzip -1 > /artifacts/perf_script.txt.gz" in script
    # ... plus each sample's own IP (-G), both pipelines' exit codes, dsoff
    # support and perf report's exact sample count, for the host to verify.
    assert ("script -i /artifacts/perf.data --no-inline -G "
            "-F comm,pid,period,ip,sym,symoff,dso,dsoff") in script
    assert "| gzip -1 > /artifacts/perf_script_ip.txt.gz" in script
    assert 'cg_rc="${PIPESTATUS[0]} ${PIPESTATUS[1]}"' in script
    assert 'ip_rc="${PIPESTATUS[0]} ${PIPESTATUS[1]}"' in script
    assert 'case "$ph" in *dsoff*)' in script and "dsoff=no" in script
    assert "report -i /artifacts/perf.data --stats" in script
    assert "> /artifacts/perf_script.status" in script


def test_replay_profile_command_resolves_relative_paths_to_absolute():
    profile = _load_module("replay_fuzzer_profile")
    cmd = profile.build_replay_profile_docker_command(
        out_dir="rel/out", corpus_dir="rel/corpus", artifact_dir="rel/art",
        fuzz_target="t", min_sample_seconds=60, seed=1337, cpu=3,
        memory="4g", shm_size="2g",
    )
    # Every bind-mount source must be absolute, else docker treats it as a named
    # volume ("invalid characters for a local volume name").
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    assert mounts, "expected -v mounts"
    for m in mounts:
        assert m.startswith("/"), f"mount source not absolute: {m}"
    assert any(m.endswith(":/out:ro") for m in mounts)
    assert any(m.endswith(":/corpus:ro") for m in mounts)


def test_replay_profile_reuses_real_fuzzer_profile_helpers():
    profile = _load_module("replay_fuzzer_profile")
    # It imports the sibling module rather than duplicating its helpers.
    assert profile.rfp.__name__ == "real_fuzzer_profile"
    assert profile.RUNNER_IMAGE == profile.rfp.RUNNER_IMAGE
    assert hasattr(profile.rfp, "_write_perf_reports")


def test_run_replay_profile_writes_reports_and_metadata(tmp_path, monkeypatch):
    profile = _load_module("replay_fuzzer_profile")

    corpus = tmp_path / "fixed"
    corpus.mkdir()
    (corpus / "unit_00000000").write_text("aaa")
    artifact_dir = tmp_path / "artifacts"

    def fake_run(cmd, *, timeout=None):
        # Simulate the container producing perf.data + the in-container reports
        # (symbol-resolved flat.txt / callgraph.txt).
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "perf.data").write_bytes(b"PERF")
        # Real perf flat format; DSO must be the target so the live script's
        # target-DSO-share validation sees a non-trivial share.
        (artifact_dir / "flat.txt").write_text(
            "    13.00%  demo_fuzzer  demo_fuzzer  [.] hashtab_map\n"
        )
        (artifact_dir / "callgraph.txt").write_text("callgraph")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(profile, "_run", fake_run)
    _no_target_libs(profile, monkeypatch)
    monkeypatch.setattr(profile, "build_hotspots", _fake_hotspots)

    args = types.SimpleNamespace(
        out_dir=tmp_path / "out",
        corpus_dir=corpus,
        artifact_dir=artifact_dir,
        fuzz_target="demo_fuzzer",
        min_sample_seconds=60,
        loop_timeout=1800,
        seed=1337,
        cpu=3,
        memory="4g",
        shm_size="2g",
    )

    rc = profile.run_replay_profile(args)
    assert rc == 0
    assert "hashtab_map" in (artifact_dir / "flat.txt").read_text()
    assert (artifact_dir / "callgraph.txt").read_text() == "callgraph"

    metadata = json.loads((artifact_dir / "metadata.json").read_text())
    assert metadata["mode"] == "replay"
    assert metadata["corpus_file_count"] == 1
    assert metadata["min_sample_seconds"] == 60


def test_run_replay_profile_retries_once_on_transient_failure(tmp_path, monkeypatch):
    profile = _load_module("replay_fuzzer_profile")
    corpus = tmp_path / "fixed"
    corpus.mkdir()
    (corpus / "u0").write_text("a")
    artifact_dir = tmp_path / "artifacts"
    calls = {"n": 0}

    def fake_run(cmd, *, timeout=None):
        calls["n"] += 1
        artifact_dir.mkdir(parents=True, exist_ok=True)
        if calls["n"] == 1:
            # Transient failure: container produced nothing.
            return subprocess.CompletedProcess(cmd, 1, "", "transient docker error")
        (artifact_dir / "perf.data").write_bytes(b"PERF")
        (artifact_dir / "flat.txt").write_text("    10.00%  t  t  [.] foo\n")
        (artifact_dir / "callgraph.txt").write_text("cg")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(profile, "_run", fake_run)
    _no_target_libs(profile, monkeypatch)
    monkeypatch.setattr(profile, "build_hotspots", _fake_hotspots)
    args = types.SimpleNamespace(
        out_dir=tmp_path / "out", corpus_dir=corpus, artifact_dir=artifact_dir,
        fuzz_target="t", min_sample_seconds=60, loop_timeout=1800, seed=1337,
        cpu=3, memory="4g", shm_size="2g",
    )
    assert profile.run_replay_profile(args) == 0
    assert calls["n"] == 2  # retried once


def test_run_replay_profile_raises_with_docker_output(tmp_path, monkeypatch):
    profile = _load_module("replay_fuzzer_profile")
    corpus = tmp_path / "fixed"
    corpus.mkdir()
    (corpus / "u0").write_text("a")

    def fake_run(cmd, *, timeout=None):
        return subprocess.CompletedProcess(cmd, 1, "", "perf: cannot open perf.data")

    monkeypatch.setattr(profile, "_run", fake_run)
    _no_target_libs(profile, monkeypatch)
    args = types.SimpleNamespace(
        out_dir=tmp_path / "out", corpus_dir=corpus, artifact_dir=tmp_path / "a",
        fuzz_target="t", min_sample_seconds=60, loop_timeout=1800, seed=1337,
        cpu=3, memory="4g", shm_size="2g",
    )
    try:
        profile.run_replay_profile(args)
    except RuntimeError as exc:
        assert "perf: cannot open" in str(exc)  # docker output surfaced
    else:
        raise AssertionError("expected RuntimeError after 2 failed attempts")


def test_run_replay_profile_rejects_empty_corpus(tmp_path):
    profile = _load_module("replay_fuzzer_profile")
    empty = tmp_path / "empty"
    empty.mkdir()
    args = types.SimpleNamespace(
        out_dir=tmp_path / "out",
        corpus_dir=empty,
        artifact_dir=tmp_path / "artifacts",
        fuzz_target="demo_fuzzer",
        min_sample_seconds=60,
        loop_timeout=1800,
        seed=1337,
        cpu=3,
        memory="4g",
        shm_size="2g",
    )
    try:
        profile.run_replay_profile(args)
    except RuntimeError as exc:
        assert "empty" in str(exc)
    else:
        raise AssertionError("expected RuntimeError on empty corpus")


def test_profile_has_no_target_dso_share_gate(tmp_path, monkeypatch):
    """The 8% floor is gone: a profile whose flat.txt shows no target rows still
    succeeds here. Whether perf sampled the target is the harness's call, made
    from hotspots.json's target-source sample count."""
    profile = _load_module("replay_fuzzer_profile")
    assert not hasattr(profile, "MIN_TARGET_DSO_SHARE")
    corpus = tmp_path / "fixed"
    corpus.mkdir()
    (corpus / "u0").write_text("a")
    art = tmp_path / "a"

    def fake_run(cmd, *, timeout=None):
        art.mkdir(parents=True, exist_ok=True)
        (art / "perf.data").write_bytes(b"PERF")
        (art / "flat.txt").write_text("    75.00%  afl-showmap  afl-showmap  [.] main\n")
        (art / "dso.txt").write_text("    75.00%  afl-showmap\n     2.00%  t\n")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(profile, "_run", fake_run)
    _no_target_libs(profile, monkeypatch)
    monkeypatch.setattr(profile, "build_hotspots", _fake_hotspots)
    args = types.SimpleNamespace(
        out_dir=tmp_path / "out", corpus_dir=corpus, artifact_dir=art,
        fuzz_target="t", min_sample_seconds=60, loop_timeout=1800, seed=1337,
        cpu=3, memory="4g", shm_size="2g")
    assert profile.run_replay_profile(args) == 0
    meta = json.loads((art / "metadata.json").read_text())
    # Shares stay recorded, as information.
    assert meta["target_dso_share_pct"] == 2.0
    assert meta["hotspots"]["target_source_samples"] == 900


def test_hotspot_table_failure_fails_the_profile_loudly(tmp_path, monkeypatch, capsys):
    profile = _load_module("replay_fuzzer_profile")
    corpus = tmp_path / "fixed"
    corpus.mkdir()
    (corpus / "u0").write_text("a")
    art = tmp_path / "a"

    def fake_run(cmd, *, timeout=None):
        art.mkdir(parents=True, exist_ok=True)
        (art / "perf.data").write_bytes(b"PERF")
        (art / "flat.txt").write_text("    10.00%  t  t  [.] foo\n")
        (art / "hotspots.json").write_text("{}")      # stale, must be removed
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(profile, "_run", fake_run)
    _no_target_libs(profile, monkeypatch)
    # The real build: no perf_script.txt.gz was produced.
    args = types.SimpleNamespace(
        out_dir=tmp_path / "out", corpus_dir=corpus, artifact_dir=art,
        fuzz_target="t", min_sample_seconds=60, loop_timeout=1800, seed=1337,
        cpu=3, memory="4g", shm_size="2g")
    try:
        profile.run_replay_profile(args)
    except RuntimeError as exc:
        assert "hotspots.json" in str(exc)
    else:
        raise AssertionError("a missing hotspot table must fail the profile")
    assert "HOTSPOT TABLE FAILED" in capsys.readouterr().err
    meta = json.loads((art / "metadata.json").read_text())
    assert "perf script step never ran" in meta["hotspots_error"]
    assert not (art / "hotspots.json").exists()


@pytest.mark.parametrize("status,needle", [
    ("dsoff=no\ncg_rc=na\nip_rc=na\nreport_samples=10\nperf=perf version 5.4\n",
     "-F dsoff"),
    ("dsoff=yes\ncg_rc=1 0\nip_rc=0 0\nreport_samples=10\n", "cg_rc"),
    ("dsoff=yes\ncg_rc=0 0\nip_rc=0 141\nreport_samples=10\n", "ip_rc"),
    ("dsoff=yes\ncg_rc=0 0\nip_rc=0 0\nreport_samples=\n", "sample count"),
])
def test_a_failed_or_unsupported_perf_script_is_refused(tmp_path, status, needle):
    profile = _load_module("replay_fuzzer_profile")
    p = tmp_path / "perf_script.status"
    p.write_text(status)
    with pytest.raises(profile.hotspot_table.HotspotError, match=re.escape(needle)):
        profile.read_perf_script_status(p)


def test_good_status_parses(tmp_path):
    profile = _load_module("replay_fuzzer_profile")
    p = tmp_path / "perf_script.status"
    p.write_text("dsoff=yes\ncg_rc=0 0\nip_rc=0 0\nreport_samples=137144\n"
                 "perf=perf version 6.8.12\nms=1949\n")
    st = profile.read_perf_script_status(p)
    assert st["report_samples"] == 137144 and st["ms"] == 1949


def test_stale_reports_never_survive_into_a_new_attempt(tmp_path, monkeypatch):
    """A retry or a resumed run must not pick up children.txt / hotspots.* from
    an earlier attempt: they are removed before each attempt and after a failed
    one."""
    profile = _load_module("replay_fuzzer_profile")
    corpus = tmp_path / "fixed"
    corpus.mkdir()
    (corpus / "u0").write_text("a")
    art = tmp_path / "a"
    art.mkdir()
    for n in ("children.txt", "hotspots.json", "hotspots.txt", "perf_script.status"):
        (art / n).write_text("stale")
    seen = []

    def fake_run(cmd, *, timeout=None):
        seen.append(sorted(p.name for p in art.iterdir()))
        return subprocess.CompletedProcess(cmd, 1, "", "perf died")

    monkeypatch.setattr(profile, "_run", fake_run)
    _no_target_libs(profile, monkeypatch)
    args = types.SimpleNamespace(
        out_dir=tmp_path / "out", corpus_dir=corpus, artifact_dir=art,
        fuzz_target="t", min_sample_seconds=60, loop_timeout=1800, seed=1337,
        cpu=3, memory="4g", shm_size="2g")
    with pytest.raises(RuntimeError):
        profile.run_replay_profile(args)
    assert seen and all(not names for names in seen)
