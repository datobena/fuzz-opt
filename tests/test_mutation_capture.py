import importlib.util
import subprocess
from pathlib import Path


def _load(name="mutation_capture"):
    path = Path(__file__).resolve().parent.parent / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _mount_map(cmd):
    """dst -> host for every -v host:dst[:ro] in a docker command."""
    out = {}
    for i, a in enumerate(cmd):
        if a == "-v":
            parts = str(cmd[i + 1]).split(":")
            out[parts[1]] = parts[0]
    return out


def test_shim_build_command_injects_shim_and_compiles(tmp_path):
    m = _load()
    cmd = m.build_shim_build_docker_command(
        image="gcr.io/oss-fuzz/42493454",
        shim_src=tmp_path / "shim.c",
        out_dir=tmp_path / "out",
        sanitizer="address",
    )
    assert cmd[:4] == ["docker", "run", "--rm", "--privileged"]
    assert "gcr.io/oss-fuzz/42493454" in cmd
    assert cmd[cmd.index("--entrypoint") + 1] == "/bin/bash"
    joined = " ".join(str(p) for p in cmd)
    assert f"{tmp_path / 'shim.c'}:/mutation_shim.c:ro" in joined
    assert f"{tmp_path / 'out'}:/out" in joined
    assert "SANITIZER=address" in joined
    script = cmd[-1]
    assert "$CC $CFLAGS -c /mutation_shim.c -o /tmp/mutation_shim.o" in script
    # sed-inject the shim object for BOTH link conventions (exactly one branch)
    assert "-lFuzzingEngine" in script and "/tmp/mutation_shim.o -lFuzzingEngine" in script
    assert "/tmp/mutation_shim.o \\$LIB_FUZZING_ENGINE" in script
    assert '"$SRC/build.sh"' in script
    # + nested FUZZERS_LIBS Makefiles (wolfssl's triple-nested build)
    assert "FUZZERS_LIBS" in script and "*fuzzers/Makefile" in script
    assert script.rstrip().endswith("compile")


def test_shim_build_command_uses_custom_compile_cmd(tmp_path):
    m = _load()
    cmd = m.build_shim_build_docker_command(
        image="n132/arvo:10222-vul", shim_src=tmp_path / "s.c",
        out_dir=tmp_path / "o", compile_cmd="arvo compile",
    )
    assert cmd[-1].rstrip().endswith("arvo compile")
    assert "n132/arvo:10222-vul" in cmd


def test_generation_command_dumps_all_mutations(tmp_path):
    m = _load()
    cmd = m.build_generation_docker_command(
        gen_out_dir=tmp_path / "gen", seed_corpus_dir=tmp_path / "seeds",
        work_corpus_dir=tmp_path / "work", mut_dir=tmp_path / "muts",
        fuzz_target="demo_fuzzer", duration=120, seed=1337, cap=50000, every=1, cpu=3,
    )
    assert cmd[:3] == ["docker", "run", "--rm"]
    joined = " ".join(str(p) for p in cmd)
    assert "MUTATION_DUMP_DIR=/muts" in joined
    assert "MUTATION_DUMP_CAP=50000" in joined
    assert "MUTATION_DUMP_EVERY=1" in joined
    # reservoir sampling on by default, PRNG seeded from the fuzzer seed
    assert "MUTATION_DUMP_RESERVOIR=1" in joined
    assert "MUTATION_DUMP_SEED=1337" in joined
    # guaranteed one-pass over the seed queue on by default (5 mutations/seed)
    assert "MUTATION_QUEUE_DIR=/seeds" in joined
    assert "MUTATION_QUEUE_DEPTH=5" in joined
    assert f"{tmp_path / 'gen'}:/out:ro" in joined
    assert f"{tmp_path / 'seeds'}:/seeds:ro" in joined
    assert f"{tmp_path / 'work'}:/corpus" in joined
    assert f"{tmp_path / 'muts'}:/muts" in joined
    script = cmd[-1]
    assert "/out/demo_fuzzer /corpus /seeds" in script
    assert "-max_total_time=120" in script
    assert "-seed=1337" in script
    assert "gen_rc=" in script and "exit 0" in script


def test_generation_command_reservoir_toggle_and_sample_seed(tmp_path):
    m = _load()
    # legacy prefix mode + explicit reservoir PRNG seed
    cmd = m.build_generation_docker_command(
        gen_out_dir=tmp_path / "gen", seed_corpus_dir=tmp_path / "seeds",
        work_corpus_dir=tmp_path / "work", mut_dir=tmp_path / "muts",
        fuzz_target="t", duration=60, seed=1337, reservoir=False, sample_seed=99,
    )
    joined = " ".join(str(p) for p in cmd)
    assert "MUTATION_DUMP_RESERVOIR=0" in joined
    assert "MUTATION_DUMP_SEED=99" in joined     # sample_seed overrides fuzzer seed


def test_generation_command_can_disable_queue_pass(tmp_path):
    m = _load()
    cmd = m.build_generation_docker_command(
        gen_out_dir=tmp_path / "gen", seed_corpus_dir=tmp_path / "seeds",
        work_corpus_dir=tmp_path / "work", mut_dir=tmp_path / "muts",
        fuzz_target="t", duration=60, seed=1, guarantee_queue=False,
    )
    joined = " ".join(str(p) for p in cmd)
    assert "MUTATION_QUEUE_DIR" not in joined
    assert "MUTATION_QUEUE_DEPTH" not in joined


def test_replay_timing_command_runs_seed_queue_once(tmp_path):
    m = _load()
    cmd = m.build_replay_timing_docker_command(
        gen_out_dir=tmp_path / "gen", seed_corpus_dir=tmp_path / "seeds",
        fuzz_target="demo_fuzzer", cpu=2,
    )
    joined = " ".join(str(p) for p in cmd)
    assert "/out/demo_fuzzer /seeds -runs=0" in joined      # one pass, no fuzzing
    assert "MUTATION_DUMP_DIR" not in joined                # not a capture run
    assert f"{tmp_path / 'seeds'}:/seeds:ro" in joined
    assert "--cpuset-cpus 2" in joined


def test_generation_command_resolves_relative_paths_to_absolute():
    m = _load()
    cmd = m.build_generation_docker_command(
        gen_out_dir="rel/gen", seed_corpus_dir="rel/seeds", work_corpus_dir="rel/work",
        mut_dir="rel/muts", fuzz_target="t", duration=60, seed=1,
    )
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    for mnt in mounts:
        assert mnt.startswith("/"), f"mount source not absolute: {mnt}"


def test_parse_final_stats_reads_libfuzzer_and_cap_marker():
    m = _load()
    # libFuzzer DONE line (time-bound run, target didn't hit the file cap)
    s = m._parse_final_stats(
        "#999 DONE cov: 42 ft: 9\nstat::number_of_executed_units: 777\ngen_rc=0\n")
    assert s["executed_units"] == 777 and s["cov"] == 42 and s["gen_rc"] == 0
    # shim cap-exit marker (fast target hit the file cap, libFuzzer DONE not printed)
    s2 = m._parse_final_stats("MUTATION_DUMP_DONE saved=50000 seen=51234\ngen_rc=0\n")
    assert s2["dumped_saved"] == 50000 and s2["dumped_seen"] == 51234


def test_freeze_flat_corpus(tmp_path):
    m = _load()
    src = tmp_path / "raw"
    (src / "a").mkdir(parents=True)
    (src / "mut_1_0").write_text("x")
    (src / "a" / "mut_1_1").write_text("y")
    dst = tmp_path / "frozen"
    n = m._freeze_flat_corpus(src, dst)
    assert n == 2
    assert sorted(p.name for p in dst.iterdir()) == ["unit_00000000", "unit_00000001"]


def test_run_mutation_capture_builds_generates_freezes(tmp_path, monkeypatch):
    m = _load()
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "s0").write_text("seed")

    def fake_run(cmd, *, timeout=None):
        mounts = _mount_map(cmd)
        joined = " ".join(str(p) for p in cmd)
        if "-runs=0" in joined:                          # one-queue-pass timing replay
            return subprocess.CompletedProcess(cmd, 0, "stat::number_of_executed_units: 1\n", "")
        if "MUTATION_DUMP_DIR=/muts" in joined:          # generation run
            muts = Path(mounts["/muts"])
            for i in range(5):
                (muts / f"mut_7_{i}").write_text(f"m{i}")
            return subprocess.CompletedProcess(
                cmd, 0, "#500 DONE cov: 42 ft: 99\nstat::number_of_executed_units: 500\n", "")
        out = Path(mounts["/out"])                        # build run
        out.mkdir(parents=True, exist_ok=True)
        (out / "demo_fuzzer").write_text("ELF")
        return subprocess.CompletedProcess(cmd, 0, "built", "")

    monkeypatch.setattr(m, "_run", fake_run)
    frozen, meta = m.run_mutation_capture(
        image="gcr.io/oss-fuzz/1", shim_src=tmp_path / "shim.c",
        gen_out_dir=tmp_path / "mutgen", seed_corpus_dir=seeds,
        work_corpus_dir=tmp_path / "work", mut_raw_dir=tmp_path / "raw",
        frozen_dir=tmp_path / "mutations", fuzz_target="demo_fuzzer",
        duration=120, seed=1337, cap=50000,
    )
    assert meta["mode"] == "mutation-capture"
    assert meta["raw_count"] == 5 and meta["frozen_count"] == 5
    assert meta["built_shim"] is True
    assert meta["final_stats"]["executed_units"] == 500
    assert m._count_files(frozen) == 5
    assert sorted(p.name for p in frozen.iterdir())[0] == "unit_00000000"
    assert not (tmp_path / "raw").exists()                # raw dropped after freeze


def test_run_mutation_capture_reuses_existing_build(tmp_path, monkeypatch):
    m = _load()
    seeds = tmp_path / "seeds"; seeds.mkdir(); (seeds / "s0").write_text("x")
    gen = tmp_path / "mutgen"; gen.mkdir()
    (gen / "demo_fuzzer").write_text("ELF")               # pre-existing shim binary
    calls = []

    def fake_run(cmd, *, timeout=None):
        joined = " ".join(str(p) for p in cmd)
        calls.append(joined)
        if "-runs=0" in joined:                       # one-queue-pass timing replay
            return subprocess.CompletedProcess(cmd, 0, "", "")
        muts = Path(_mount_map(cmd)["/muts"])
        (muts / "mut_1_0").write_text("m")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(m, "_run", fake_run)
    _, meta = m.run_mutation_capture(
        image="img", shim_src=tmp_path / "shim.c", gen_out_dir=gen,
        seed_corpus_dir=seeds, work_corpus_dir=tmp_path / "w",
        mut_raw_dir=tmp_path / "r", frozen_dir=tmp_path / "f",
        fuzz_target="demo_fuzzer", duration=10, seed=1, reuse_build=True,
    )
    # no build (reused): a one-queue-pass timing replay + the generation run
    gen_calls = [c for c in calls if "MUTATION_DUMP_DIR=/muts" in c]
    assert len(gen_calls) == 1
    assert any("-runs=0" in c for c in calls)          # queue-pass timing measured
    assert meta["built_shim"] is False
    assert meta["effective_duration"] >= 10            # max(duration, queue time)


def test_run_mutation_capture_rejects_empty_seed_corpus(tmp_path, monkeypatch):
    m = _load()
    gen = tmp_path / "mutgen"; gen.mkdir(); (gen / "t").write_text("ELF")
    monkeypatch.setattr(m, "_run", lambda cmd, *, timeout=None:
                        subprocess.CompletedProcess(cmd, 0, "", ""))
    empty = tmp_path / "seeds"; empty.mkdir()
    try:
        m.run_mutation_capture(image="i", shim_src=tmp_path / "s.c", gen_out_dir=gen,
                               seed_corpus_dir=empty, work_corpus_dir=tmp_path / "w",
                               mut_raw_dir=tmp_path / "r", frozen_dir=tmp_path / "f",
                               fuzz_target="t", duration=10, seed=1)
    except RuntimeError as exc:
        assert "empty" in str(exc)
    else:
        raise AssertionError("expected RuntimeError on empty seed corpus")
