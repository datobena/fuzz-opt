import importlib.util
import json
import subprocess
import types
from pathlib import Path


SCRIPTS_DIR = Path(
    "/home/sefcom/.codex/skills/profile-once-fuzz-folds/scripts"
)


def _load_module(name):
    path = SCRIPTS_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _args(tmp_path, grow, snap, art, **over):
    base = dict(
        out_dir=tmp_path / "out", corpus_dir=tmp_path / "merged",
        evolving_corpus_dir=grow, snapshot_dir=snap, artifact_dir=art,
        fuzz_target="demo_fuzzer", duration=3600, seed=1337, cpu=3,
        memory="4g", shm_size="2g", per_unit_timeout=10, filter_timeout=1800,
    )
    base.update(over)
    return types.SimpleNamespace(**base)


def test_grow_command_mounts_corpus_readwrite_with_no_perf(tmp_path):
    bc = _load_module("build_corpus")
    cmd = bc.build_grow_docker_command(
        out_dir=tmp_path / "out", corpus_dir=tmp_path / "grow",
        artifact_dir=tmp_path / "artifacts", fuzz_target="demo_fuzzer",
        duration=3600, seed=1337, cpu=3, memory="4g", shm_size="2g",
    )
    joined = " ".join(str(p) for p in cmd)
    assert f"{(tmp_path / 'grow').resolve()}:/corpus " in joined + " "
    assert f"{(tmp_path / 'grow').resolve()}:/corpus:ro" not in joined
    assert f"{(tmp_path / 'out').resolve()}:/out:ro" in joined
    assert "--cpuset-cpus" in cmd and cmd[cmd.index("--cpuset-cpus") + 1] == "3"
    script = cmd[-1]
    assert "/out/demo_fuzzer /corpus" in script
    assert "-max_total_time=3600" in script and "-seed=1337" in script
    assert "perf" not in script  # grow does NOT profile


def test_grow_command_is_crash_tolerant(tmp_path):
    # Policy: the replay corpus is a timed fuzz of the BASELINE; on a vulnerable
    # baseline the grow must continue past the easy crash, else it yields an
    # empty/tiny corpus and a meaningless replay measurement.
    bc = _load_module("build_corpus")
    cmd = bc.build_grow_docker_command(
        out_dir=tmp_path / "out", corpus_dir=tmp_path / "grow",
        artifact_dir=tmp_path / "artifacts", fuzz_target="demo_fuzzer",
        duration=3600, seed=1337, cpu=3, memory="4g", shm_size="2g",
    )
    script = cmd[-1]
    for flag in ("-fork=1", "-ignore_crashes=1", "-ignore_timeouts=1",
                 "-ignore_ooms=1"):
        assert flag in script, f"missing crash-tolerance flag: {flag}"


def test_grow_command_resolves_relative_paths_to_absolute():
    bc = _load_module("build_corpus")
    cmd = bc.build_grow_docker_command(
        out_dir="rel/out", corpus_dir="rel/grow", artifact_dir="rel/art",
        fuzz_target="t", duration=60, seed=1337, cpu=3, memory="4g", shm_size="2g",
    )
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    assert mounts
    for m in mounts:
        assert m.startswith("/"), f"mount source not absolute: {m}"


def test_bulk_replay_command_is_readonly_runs0(tmp_path):
    bc = _load_module("build_corpus")
    cmd = bc.build_bulk_replay_command(
        out_dir="rel/out", corpus_dir="rel/corpus", fuzz_target="t",
        seed=1337, cpu=3, memory="4g", shm_size="2g",
    )
    joined = " ".join(cmd)
    assert ":/corpus:ro" in joined and ":/out:ro" in joined
    for m in [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]:
        assert m.startswith("/")
    assert "-runs=0" in cmd[-1]


def test_crash_filter_command_is_readwrite_and_removes(tmp_path):
    bc = _load_module("build_corpus")
    cmd = bc.build_crash_filter_command(
        out_dir="rel/out", corpus_dir="rel/corpus", fuzz_target="t",
        per_unit_timeout=10, cpu=3, memory="4g", shm_size="2g",
    )
    joined = " ".join(cmd)
    # corpus is writable (no :ro) so the filter can delete crashers
    assert ":/corpus:ro" not in joined
    assert any(m.endswith(":/corpus") for m in [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"])
    script = cmd[-1]
    assert "for f in /corpus/*" in script
    assert "rm -f" in script
    assert "REMOVED=" in script
    assert "timeout 10" in script


def test_run_build_corpus_freezes_snapshot_after_growing(tmp_path, monkeypatch):
    bc = _load_module("build_corpus")
    merged = tmp_path / "merged"; merged.mkdir()
    (merged / "s0").write_text("seed")
    grow = tmp_path / "grow"; snap = tmp_path / "fixed"; art = tmp_path / "art"

    def fake_run(cmd, *, timeout=None):
        script = cmd[-1]
        if "-runs=0" in script:                       # bulk replay -> clean
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if "-max_total_time" in script:               # grow -> discover a unit
            (grow / "disc_0").write_text("new")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(bc, "_run", fake_run)
    assert bc.run_build_corpus(_args(tmp_path, grow, snap, art)) == 0

    # Snapshot frozen AFTER grow: seed + discovered unit.
    assert sorted(p.name for p in snap.iterdir()) == ["unit_00000000", "unit_00000001"]
    md = json.loads((art / "corpus_build_metadata.json").read_text())
    assert md["seeded_from_merged"] == 1
    assert md["crash_filter_ran"] is False
    assert md["removed_crashers"] == 0
    assert md["corpus_files_before"] == 1
    assert md["corpus_files_after"] == 2
    assert md["snapshot_file_count"] == 2


def test_run_build_corpus_filters_crashers_only_when_bulk_crashes(tmp_path, monkeypatch):
    bc = _load_module("build_corpus")
    merged = tmp_path / "merged"; merged.mkdir()
    (merged / "good").write_text("ok")
    (merged / "bad").write_text("boom")
    grow = tmp_path / "grow"; snap = tmp_path / "fixed"; art = tmp_path / "art"

    def fake_run(cmd, *, timeout=None):
        script = cmd[-1]
        if "REMOVED=" in script:                      # per-unit filter
            # remove the second copied unit to simulate dropping a crasher
            (grow / "unit_00000001").unlink(missing_ok=True)
            return subprocess.CompletedProcess(cmd, 0, "REMOVED=1 KEPT=1", "")
        if "-runs=0" in script:                       # bulk replay -> crash
            return subprocess.CompletedProcess(cmd, 1, "", "AddressSanitizer: heap-use-after-free")
        if "-max_total_time" in script:               # grow -> discover a unit
            (grow / "disc_0").write_text("new")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(bc, "_run", fake_run)
    assert bc.run_build_corpus(_args(tmp_path, grow, snap, art)) == 0

    md = json.loads((art / "corpus_build_metadata.json").read_text())
    assert md["crash_filter_ran"] is True
    assert md["bulk_replay_exit"] == 1
    assert md["removed_crashers"] == 1
    assert md["seeded_from_merged"] == 2
    assert md["corpus_files_before"] == 1   # one crasher removed before grow
    assert md["snapshot_file_count"] == 2   # 1 survivor + 1 discovered


def test_run_build_corpus_raises_on_empty_snapshot(tmp_path, monkeypatch):
    bc = _load_module("build_corpus")
    merged = tmp_path / "merged"; merged.mkdir()  # empty
    grow = tmp_path / "grow"; snap = tmp_path / "fixed"; art = tmp_path / "art"

    def fake_run(cmd, *, timeout=None):
        # grow discovers nothing; bulk is skipped (empty corpus)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(bc, "_run", fake_run)
    try:
        bc.run_build_corpus(_args(tmp_path, grow, snap, art, duration=60))
    except RuntimeError as exc:
        assert "empty" in str(exc)
    else:
        raise AssertionError("expected RuntimeError on empty snapshot")
