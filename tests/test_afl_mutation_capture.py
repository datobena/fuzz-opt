"""Tests for lib/afl_mutation_capture.py."""
from lib.afl_mutation_capture import build_capture_command, capture_mutations


def test_capture_loads_the_shim_at_runtime_not_by_relinking(tmp_path):
    """The libFuzzer version needed a diagnostic REBUILD with the shim on the
    link line; AFL dlopens it, so the target is untouched."""
    cmd = build_capture_command(
        image="i", out_dir=str(tmp_path), seeds_dir=str(tmp_path),
        work_dir=str(tmp_path), fuzz_target="t",
    )
    script = cmd[-1]
    assert "AFL_CUSTOM_MUTATOR_LIBRARY=" in script
    assert "compile" not in script, "must not rebuild the target"
    assert "/out/t" in script and ":/out:ro" in " ".join(cmd)


def test_capture_sets_the_dump_controls(tmp_path):
    cmd = build_capture_command(
        image="i", out_dir=str(tmp_path), seeds_dir=str(tmp_path),
        work_dir=str(tmp_path), fuzz_target="t", cap=777, every=3, seed=99,
    )
    s = cmd[-1]
    assert "MUTATION_DUMP_CAP=777" in s
    assert "MUTATION_DUMP_EVERY=3" in s
    assert "MUTATION_DUMP_SEED=99" in s


def test_capture_seeds_are_mounted_read_only(tmp_path):
    """AFL treats -i as read-only; mounting rw would let a capture mutate the
    seed corpus that later rounds depend on."""
    joined = " ".join(build_capture_command(
        image="i", out_dir=str(tmp_path), seeds_dir=str(tmp_path),
        work_dir=str(tmp_path), fuzz_target="t"))
    assert ":/seeds:ro" in joined


def test_zero_captured_is_reported_as_failure(tmp_path, monkeypatch):
    """Seeds-only profiling measures the wrong workload, so an empty capture
    must surface rather than pass quietly."""
    import lib.afl_mutation_capture as m

    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: None)
    r = capture_mutations(
        image="i", out_dir=str(tmp_path), seeds_dir=str(tmp_path),
        work_dir=str(tmp_path / "w"), fuzz_target="t", duration=1,
    )
    assert r["ok"] is False
    assert r["captured"] == 0


def test_captured_files_are_counted(tmp_path, monkeypatch):
    import lib.afl_mutation_capture as m

    work = tmp_path / "w"
    (work / "dump").mkdir(parents=True)
    for i in range(7):
        (work / "dump" / f"mut_1_{i:08d}").write_bytes(b"x")
    monkeypatch.setattr(m.subprocess, "run", lambda *a, **k: None)
    r = capture_mutations(
        image="i", out_dir=str(tmp_path), seeds_dir=str(tmp_path),
        work_dir=str(work), fuzz_target="t", duration=1,
    )
    assert r["captured"] == 7 and r["ok"] is True


def test_phase2_mutation_builder_uses_the_prework_image_under_afl(monkeypatch):
    """Returning an ARVO builder would capture libFuzzer mutations and profile
    an AFL experiment against them -- the wrong workload, with no error."""
    import phase2_setup

    monkeypatch.setattr(phase2_setup.config, "PHASE2_SANDBOX", True)
    entry = {"project": "libavc", "cve": "arvo-16505", "local_id": 16505,
             "image": "n132/arvo:16505-vul"}
    image, mode = phase2_setup._phase2_mutation_builder(entry)
    assert image == "bench-aflpp/libavc-arvo-16505"
    assert mode == "afl-custom-mutator"
    assert "n132" not in image


def test_phase2_mutation_builder_keeps_the_legacy_path_when_unsandboxed(monkeypatch):
    import phase2_setup

    monkeypatch.setattr(phase2_setup.config, "PHASE2_SANDBOX", False)
    entry = {"project": "libavc", "cve": "arvo-16505", "local_id": 16505,
             "image": "n132/arvo:16505-vul"}
    assert phase2_setup._phase2_mutation_builder(entry) == (
        "n132/arvo:16505-vul", "arvo compile")
