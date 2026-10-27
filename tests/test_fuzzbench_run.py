"""FuzzBench run parity (manifest entries with "kind": "fuzzbench").

FuzzBench targets must be fuzzed exactly as FuzzBench's aflplusplus runner
fuzzes them (fuzzers/afl/fuzzer.py + fuzzers/aflplusplus/fuzzer.py +
experiment/runner.py at 3234e151), and ARVO targets must launch byte-for-byte
as before. Both halves are pinned here.
"""
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

import config
import phase3_online
import phase3_runner
from lib import afl_launch
from lib import corpus as corpus_util
from lib.afl_mutation_capture import build_capture_command

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import preflight_online  # noqa: E402


BUG = {"project": "mruby", "cve": "fuzzbench-900025", "local_id": 900025,
       "fuzz_target": "mruby_fuzzer", "kind": "fuzzbench", "type": "bug",
       "fuzzbench_dir": "mruby_mruby_fuzzer_8c8bbd"}
COV = {"project": "zlib", "cve": "fuzzbench-900030", "local_id": 900030,
       "fuzz_target": "zlib_uncompress_fuzzer", "kind": "fuzzbench",
       "type": "coverage", "fuzzbench_dir": "zlib_zlib_uncompress_fuzzer"}
ARVO = {"project": "libxml2", "cve": "arvo-1", "local_id": 1, "fuzz_target": "xml"}


def _fb_bin(tmp_path, target, *, cmplog=True, aflpp_dict=True, options=None,
            target_dict=False):
    b = tmp_path / "bin"
    b.mkdir(parents=True, exist_ok=True)
    (b / target).write_bytes(b"\x7fELF")
    (b / "afl-fuzz").write_bytes(b"")
    if cmplog:
        (b / "cmplog").mkdir(exist_ok=True)
        (b / "cmplog" / target).write_bytes(b"\x7fELF-cmplog")
    if aflpp_dict:
        (b / "afl++.dict").write_text('"tok"\n')
    if options is not None:
        (b / f"{target}.options").write_text(options)
    if target_dict:
        (b / f"{target}.dict").write_text('"own"\n')
    return b


# --------------------------------------------------------------------------- #
# argv / env / cwd
# --------------------------------------------------------------------------- #
def test_bug_target_with_cmplog_dicts_and_options_dict(tmp_path):
    b = _fb_bin(tmp_path, "mruby_fuzzer",
                options="[libfuzzer]\ndict = mruby.dict\nmax_len = 4096\n")
    (b / "mruby.dict").write_text('"def"\n')
    L = afl_launch.build_afl_launch(
        entry=BUG, host_bin_dir=str(b), fuzz_target="mruby_fuzzer",
        input_dir="/corpus", output_dir="/afl_out", duration=600, seed=7)
    assert L.argv == [
        "/out/afl-fuzz", "-i", "/corpus", "-o", "/afl_out", "-m", "none",
        "-t", config.AFL_TIMEOUT_FLAG, "-d",
        "-x", "/out/afl++.dict", "-c", "/out/cmplog/mruby_fuzzer",
        "-x", "/out/mruby.dict",
        "-s", "7", "-V", "600",
        "--", "/out/mruby_fuzzer", "2147483647"]
    assert L.workdir == "/out"
    env = dict(L.env)
    for k in ("AFL_NO_UI", "AFL_SKIP_CPUFREQ", "AFL_NO_AFFINITY",
              "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "AFL_SKIP_CRASHES",
              "AFL_SHUFFLE_QUEUE", "AFL_IGNORE_UNKNOWN_ENVS", "AFL_FAST_CAL",
              "AFL_NO_WARN_INSTABILITY", "AFL_DISABLE_TRIM", "AFL_CMPLOG_ONLY_NEW",
              "AFL_AUTORESUME"):
        assert env[k] == "1", k
    # Deliberately not FuzzBench's "2": a 2 MB cache can hang afl-fuzz (config.py).
    assert env["AFL_TESTCACHE_SIZE"] == "50"
    assert env["LD_LIBRARY_PATH"] == ":/out"
    assert env["PATH"].endswith(":/out")
    assert env["ASAN_OPTIONS"] == config.FUZZ_ASAN_OPTIONS
    assert env["UBSAN_OPTIONS"] == config.FUZZ_UBSAN_OPTIONS
    assert "LSAN_OPTIONS" not in env, "afl-fuzz sets it itself, as under FuzzBench"
    rec = L.record()
    assert rec["flags"]["cmplog"] == "/out/cmplog/mruby_fuzzer"
    assert rec["flags"]["options_dict"] == "/out/mruby.dict"
    assert rec["flags"]["benchmark_type"] == "bug"


def test_target_dict_beats_options_dict(tmp_path):
    b = _fb_bin(tmp_path, "t", options="[libfuzzer]\ndict = other.dict\n",
                target_dict=True)
    L = afl_launch.build_afl_launch(entry=BUG, host_bin_dir=str(b), fuzz_target="t",
                                    input_dir="/i", output_dir="/o")
    assert L.argv[-5:] == ["-x", "/out/t.dict", "--", "/out/t", "2147483647"]


def test_coverage_target_without_optional_files(tmp_path):
    b = _fb_bin(tmp_path, "zlib_uncompress_fuzzer", cmplog=False, aflpp_dict=False)
    L = afl_launch.build_afl_launch(
        entry=COV, host_bin_dir=str(b), fuzz_target="zlib_uncompress_fuzzer",
        input_dir="/corpus", output_dir="/afl_out", duration=60, seed=1)
    assert "-x" not in L.argv and "-c" not in L.argv
    assert L.argv[L.argv.index("-t") + 2] == "-d"
    assert L.argv[-3:] == ["--", "/out/zlib_uncompress_fuzzer", "2147483647"]


def test_options_without_dict_key_adds_nothing(tmp_path):
    b = _fb_bin(tmp_path, "t", options="[libfuzzer]\nmax_len = 10\n")
    assert afl_launch.fuzzbench_options_dict(str(b), "t") is None


def test_options_dict_naming_a_missing_file_is_fatal(tmp_path):
    """FuzzBench's get_dictionary_path raises; the trial must not silently
    fuzz without the dictionary."""
    b = _fb_bin(tmp_path, "t", options="[libfuzzer]\ndict = gone.dict\n")
    with pytest.raises(ValueError):
        afl_launch.fuzzbench_options_dict(str(b), "t")


def _fb_trial(tmp_path, entry=BUG, capture=False):
    t = phase3_runner.Trial(project=entry["project"], cve=entry["cve"],
                            local_id=entry["local_id"], entry=entry,
                            variant="optimized", trial_id=1, seed=1337, cpu=21)
    t.capture_mutations = capture
    t._docker_image = "fb-aflpp/" + entry["fuzzbench_dir"]
    t._bin_dir = str(tmp_path / "bin")
    t._fuzz_target_name = entry["fuzz_target"]
    t._dirs = {"corpus": str(tmp_path / "corpus"), "crashes": str(tmp_path / "cr"),
               "afl_out": str(tmp_path / "afl_out"), "base": str(tmp_path),
               "mutations": str(tmp_path / "mut")}
    return t


def _launch(monkeypatch, trial, duration=321):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="cid\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    ok = phase3_runner._launch_container(trial, "exp", duration)
    runs = [c for c in calls if len(c) > 1 and c[1] == "run"]
    return ok, (runs[-1] if runs else None)


def test_runner_launches_fuzzbench_trial_with_fuzzbench_launch(monkeypatch, tmp_path):
    _fb_bin(tmp_path, "mruby_fuzzer")
    ok, cmd = _launch(monkeypatch, _fb_trial(tmp_path))
    assert ok
    shell = cmd[-1]
    # existing substrings the ARVO tests also rely on
    assert "-t 1000 " in shell and "-- /out/mruby_fuzzer" in shell
    assert shell.split(" 2>&1")[0].strip().endswith("-- /out/mruby_fuzzer 2147483647")
    assert " -d " in shell
    assert "-x /out/afl++.dict -c /out/cmplog/mruby_fuzzer" in shell
    assert "-s 1337 -V 321 --" in shell
    assert cmd[cmd.index("-w") + 1] == "/out"
    joined = " ".join(cmd)
    assert "AFL_CMPLOG_ONLY_NEW=1" in joined and "LD_LIBRARY_PATH=:/out" in joined
    assert ":/out:ro" in joined


def test_runner_records_full_launch_in_provenance(monkeypatch, tmp_path):
    _fb_bin(tmp_path, "mruby_fuzzer")
    t = _fb_trial(tmp_path)
    _launch(monkeypatch, t)
    rec = phase3_runner._trial_env_record(t)
    assert rec["launch"]["argv"][-1] == "2147483647"
    assert rec["launch"]["workdir"] == "/out"
    assert rec["AFL_ENV"]["AFL_FAST_CAL"] == "1"
    assert rec["afl_flags"]["cmplog"] == "/out/cmplog/mruby_fuzzer"


def test_runner_fails_trial_on_broken_options_dict(monkeypatch, tmp_path):
    _fb_bin(tmp_path, "mruby_fuzzer", options="[libfuzzer]\ndict = nope.dict\n")
    t = _fb_trial(tmp_path)
    ok, cmd = _launch(monkeypatch, t)
    assert ok is False and t.status == "failed" and cmd is None


def test_fuzzbench_shim_uses_a_compiler_the_builder_image_has(monkeypatch, tmp_path):
    _fb_bin(tmp_path, "mruby_fuzzer")
    _, cmd = _launch(monkeypatch, _fb_trial(tmp_path, capture=True))
    shell = cmd[-1]
    assert "clang-18" not in shell
    assert shell.startswith(f"{config.FUZZBENCH_SHIM_CC} -O2 -shared -fPIC")
    assert shell.index("continuing without capture") < shell.index("afl-fuzz")


def test_fuzzbench_trial_resolves_its_fb_aflpp_image(monkeypatch):
    import prework.prework_build as pb
    monkeypatch.setattr(pb, "prework_image_for", lambda e: "fb-aflpp/" + e["fuzzbench_dir"])
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd[-1])
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    t = phase3_runner.Trial(project="mruby", cve=BUG["cve"], local_id=900025,
                            entry=BUG, variant="baseline", trial_id=0, seed=1)
    assert phase3_runner._resolve_trial_image(t) == "fb-aflpp/mruby_mruby_fuzzer_8c8bbd"
    assert seen == ["fb-aflpp/mruby_mruby_fuzzer_8c8bbd"], "no bench-aflpp fallback"


def test_trial_without_entry_finds_it_in_the_manifest(monkeypatch, tmp_path):
    import json
    m = tmp_path / "m.json"
    m.write_text(json.dumps([ARVO, BUG]))
    monkeypatch.setattr(config, "MANIFEST_PATH", str(m))
    t = phase3_runner.Trial(project="mruby", cve=BUG["cve"], variant="baseline",
                            trial_id=0, seed=1)
    assert phase3_runner._trial_entry(t)["kind"] == "fuzzbench"


def test_online_trials_carry_their_entry(monkeypatch):
    monkeypatch.setattr(config, "ONLINE_PER_TRIAL_OPTIMIZER", False, raising=False)
    base, online = phase3_online._build_online_trials(BUG)
    assert all(t.entry is BUG for t in base + online)


def test_capture_command_for_fuzzbench(tmp_path):
    b = _fb_bin(tmp_path, "mruby_fuzzer")
    s = build_capture_command(image="i", out_dir=str(b), seeds_dir=str(tmp_path),
                              work_dir=str(tmp_path), fuzz_target="mruby_fuzzer",
                              entry=BUG)[-1]
    assert "clang-18" not in s and s.startswith("set -e; clang ")
    assert "cd /out; /out/afl-fuzz -i /seeds -o /work/aflout" in s
    assert "-c /out/cmplog/mruby_fuzzer" in s
    assert "-- /out/mruby_fuzzer 2147483647 >" in s
    assert "AFL_AUTORESUME" not in s


def test_preflight_smoke_uses_the_shared_builder(monkeypatch, tmp_path):
    exp = tmp_path / "exp"
    b = exp / "baseline" / "bin"
    b.mkdir(parents=True)
    (b / "mruby_fuzzer").write_bytes(b"x")
    (b / "afl++.dict").write_text("")
    calls = []
    monkeypatch.setattr(preflight_online, "prework_image_for", lambda e: "fb-aflpp/x")
    monkeypatch.setattr(preflight_online.subprocess, "run",
                        lambda cmd, **k: calls.append(cmd) or
                        subprocess.CompletedProcess(cmd, 0, "", ""))
    preflight_online.smoke(BUG, str(exp), "mruby_fuzzer", 22, 5)
    cmd = calls[-1]
    i = cmd.index("fb-aflpp/x")
    assert cmd[i + 1:] == ["/out/afl-fuzz", "-i", "/corpus", "-o", "/afl_out",
                           "-m", "none", "-t", config.AFL_TIMEOUT_FLAG, "-d",
                           "-x", "/out/afl++.dict", "-V", "5",
                           "--", "/out/mruby_fuzzer", "2147483647"]
    assert cmd[cmd.index("-w") + 1] == "/out"


def test_preflight_poc_stage_is_skipped_for_fuzzbench(monkeypatch, tmp_path):
    exp = tmp_path / "exp"
    monkeypatch.setattr(preflight_online, "_entry", lambda p: BUG)
    monkeypatch.setattr(preflight_online.phase2_setup, "get_experiment_dir",
                        lambda i, e: str(exp))
    monkeypatch.setattr(preflight_online, "prework_image_for", lambda e: "fb-aflpp/x")
    monkeypatch.setattr(preflight_online.subprocess, "run",
                        lambda cmd, **k: subprocess.CompletedProcess(cmd, 0))
    got = {}

    def fake_extract(*a, **k):
        got["cpu"] = k.get("cpu")
        return False, None, None, str(tmp_path / "src")

    monkeypatch.setattr(preflight_online.phase3_online, "_extract_online_target",
                        fake_extract)
    monkeypatch.setattr(preflight_online.phase3_online, "_src_subtree_has_files",
                        lambda p: True)
    monkeypatch.setattr(preflight_online.phase3_online, "_stage_online_seed_corpus",
                        lambda *a, **k: 0)
    monkeypatch.setattr(preflight_online.phase2_setup, "_find_project_source",
                        lambda r, p: str(tmp_path / "src"))
    monkeypatch.setattr(preflight_online.tracked_git, "strip_vcs_metadata", lambda r: None)
    monkeypatch.setattr(preflight_online.phase3_online, "_build_afl_baseline",
                        lambda **k: False)
    res = preflight_online.preflight("mruby", 23, 5, False)
    assert res["stages"]["poc"]["ok"] is True
    assert res["stages"]["poc"]["skipped"]
    assert got["cpu"] == 23, "extract-time build must be pinned"


# --------------------------------------------------------------------------- #
# ARVO stays byte-identical (literal copies of the pre-parity commands)
# --------------------------------------------------------------------------- #
def _old_runner_cmd(t, duration, capture, shim_src):
    cmd = [
        "docker", "run", "-d", "--name", t.container_name, "--privileged",
        "--cpuset-cpus", str(t.cpu), "--memory", config.MEMORY_LIMIT,
        "--shm-size", config.DOCKER_SHM_SIZE, "--ulimit", "core=0",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-e", "HOME=/tmp", "-e", "AFL_NO_AFFINITY=1", "-e", "AFL_SKIP_CPUFREQ=1",
        "-e", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1", "-e", "AFL_AUTORESUME=1",
        "-e", f"ASAN_OPTIONS={config.FUZZ_ASAN_OPTIONS}",
        "-e", f"UBSAN_OPTIONS={config.FUZZ_UBSAN_OPTIONS}",
        "-v", f"{t._bin_dir}:/out:ro", "-v", f"{t._dirs['corpus']}:/corpus",
        "-v", f"{t._dirs['afl_out']}:/afl_out",
    ]
    if capture:
        cmd += [
            "-e", "MUTATION_DUMP_DIR=/mutations",
            "-e", f"MUTATION_DUMP_CAP={int(getattr(config, 'PHASE2_MUTATION_CAP', 30000))}",
            "-e", f"MUTATION_DUMP_MODE={getattr(config, 'ONLINE_MUTATION_MODE', 'reservoir')}",
            "-e", f"MUTATION_DUMP_SEED={t.seed}",
            "-v", f"{t._dirs['mutations']}:/mutations",
            "-v", f"{shim_src}:/tmp/mutation_dump_afl.c:ro",
        ]
    cmd += [t._docker_image, "/bin/bash", "-c", (
        (f"clang-{getattr(config, 'PREWORK_LLVM_VERSION', 18)} -O2 -shared -fPIC "
         f"-o /tmp/mutdump.so /tmp/mutation_dump_afl.c 2>/tmp/shim_build.log "
         f"&& export AFL_CUSTOM_MUTATOR_LIBRARY=/tmp/mutdump.so "
         f"|| echo 'mutation shim build FAILED; continuing without capture';"
         if capture else "")
        + f" /out/afl-fuzz -i /corpus -o /afl_out -V {duration} -s {t.seed} -m none"
        f" -t {config.AFL_TIMEOUT_FLAG} -- /out/{t._fuzz_target_name}"
        f" 2>&1 | tee /tmp/fuzzer.log; cp /tmp/fuzzer.log /afl_out/fuzzer.log 2>/dev/null || true")]
    return cmd


@pytest.mark.parametrize("capture", [False, True])
def test_arvo_runner_launch_is_byte_identical(monkeypatch, tmp_path, capture):
    t = phase3_runner.Trial(project="libxml2", cve="arvo-1", local_id=1, entry=ARVO,
                            variant="optimized", trial_id=3, seed=99, cpu=7)
    t.capture_mutations = capture
    t._docker_image = "bench-aflpp/libxml2-arvo-1"
    t._bin_dir = str(tmp_path / "bin")
    t._fuzz_target_name = "xml"
    t._dirs = {"corpus": str(tmp_path / "c"), "crashes": str(tmp_path / "cr"),
               "afl_out": str(tmp_path / "ao"), "base": str(tmp_path),
               "mutations": str(tmp_path / "m")}
    _, cmd = _launch(monkeypatch, t, duration=600)
    shim = os.path.join(os.path.dirname(os.path.abspath(phase3_runner.__file__)),
                        "mutation_dump_afl.c")
    assert cmd == _old_runner_cmd(t, 600, capture, shim)


def test_arvo_preflight_smoke_is_byte_identical(monkeypatch, tmp_path):
    exp = tmp_path / "exp"
    calls = []
    monkeypatch.setattr(preflight_online, "prework_image_for", lambda e: "img")
    monkeypatch.setattr(preflight_online.time, "time", lambda: 1000)
    monkeypatch.setattr(preflight_online.subprocess, "run",
                        lambda cmd, **k: calls.append(cmd) or
                        subprocess.CompletedProcess(cmd, 0, "", ""))
    preflight_online.smoke(ARVO, str(exp), "xml", 5, 120)
    assert calls[-1] == [
        "docker", "run", "--rm", "--name", "preflight_libxml2_1000", "--privileged",
        "--cpuset-cpus", "5", "--ulimit", "core=0", "--user", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{exp}/baseline/bin:/out:ro", "-v", f"{exp}/seed_corpus/merged:/corpus",
        "-v", f"{exp}/preflight_afl_out:/afl_out", "-e", "HOME=/tmp",
        "-e", "AFL_NO_AFFINITY=1", "-e", "AFL_SKIP_CPUFREQ=1",
        "-e", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1", "-e", "AFL_AUTORESUME=1",
        "-e", f"ASAN_OPTIONS={config.FUZZ_ASAN_OPTIONS}",
        "-e", f"UBSAN_OPTIONS={config.FUZZ_UBSAN_OPTIONS}", "img",
        "/out/afl-fuzz", "-i", "/corpus", "-o", "/afl_out", "-V", "120",
        "-m", "none", "-t", config.AFL_TIMEOUT_FLAG, "--", "/out/xml"]


def test_arvo_capture_command_is_byte_identical(tmp_path):
    cmd = build_capture_command(image="img", out_dir=str(tmp_path / "o"),
                                seeds_dir=str(tmp_path / "s"), work_dir=str(tmp_path / "w"),
                                fuzz_target="xml", cpu=4, seed=7, duration=33)
    assert cmd[-1] == (
        "set -e; clang-18 -O2 -shared -fPIC -o /work/mutdump.so /work/shim.c; "
        "export AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; "
        f"export ASAN_OPTIONS={config.FUZZ_ASAN_OPTIONS} UBSAN_OPTIONS={config.FUZZ_UBSAN_OPTIONS}; "
        "export AFL_CUSTOM_MUTATOR_LIBRARY=/work/mutdump.so; "
        "export MUTATION_DUMP_DIR=/work/dump MUTATION_DUMP_CAP=30000 "
        "MUTATION_DUMP_EVERY=1 MUTATION_DUMP_SEED=7; "
        "mkdir -p /work/dump /work/aflout; "
        f"/out/afl-fuzz -V 33 -s 7 -m none -t {config.AFL_TIMEOUT_FLAG} "
        "-i /seeds -o /work/aflout -- /out/xml > /work/capture.log 2>&1 || true; "
        "chmod -R a+rX /work")
    assert cmd[:6] == ["docker", "run", "--rm", "--privileged", "--cpuset-cpus", "4"]


def test_arvo_shim_compiler_unchanged():
    assert afl_launch.shim_compiler(ARVO) == "clang-18"
    assert afl_launch.shim_compiler(None) == "clang-18"
    assert afl_launch.shim_compiler(BUG) == config.FUZZBENCH_SHIM_CC


def test_opt_level_is_per_type_for_fuzzbench():
    assert afl_launch.fuzzbench_opt_level(BUG) == "-O1"
    assert afl_launch.fuzzbench_opt_level(COV) == "-O3"
    assert afl_launch.fuzzbench_opt_level(ARVO) is None


# --------------------------------------------------------------------------- #
# Seeds (experiment/runner.py rules)
# --------------------------------------------------------------------------- #
import hashlib  # noqa: E402

BIG = 1024 * 1024 + 1


def _sha1(b):
    return hashlib.sha1(b).hexdigest()


def test_seed_staging_follows_fuzzbench_runner(tmp_path):
    b = tmp_path / "bin"
    (b / "seeds" / "sub").mkdir(parents=True)
    (b / "seeds" / "a").write_bytes(b"from-out-seeds")
    (b / "seeds" / "sub" / "big").write_bytes(b"x" * BIG)       # removed by clean
    with zipfile.ZipFile(b / "t_seed_corpus.zip", "w") as z:
        z.writestr("dir/", "")
        z.writestr("dir/one", b"one")
        z.writestr("two", b"two")
        z.writestr("dup", b"one")                                # collapses by sha1
        z.writestr("huge", b"y" * BIG)                            # skipped at unpack
        z.writestr("exactly_limit", b"z" * (1024 * 1024))         # kept (<= limit)
    dst = tmp_path / "merged"
    st = corpus_util.stage_fuzzbench_seed_corpus(str(b), "t", str(dst))
    names = sorted(p.name for p in dst.iterdir())
    want = sorted(_sha1(x) for x in (b"from-out-seeds", b"one", b"two", b"z" * (1024 * 1024)))
    assert names == want
    assert all(p.is_file() for p in dst.iterdir()), "flattened, no subdirs"
    assert st["zip_skipped_oversize"] == 1 and st["removed_oversize"] == 1
    assert st["from_zip"] == 4 and st["default_seed"] is False


def test_only_target_named_zip_is_used(tmp_path):
    """zlib ships a misnamed seed_corpus.zip; FuzzBench fuzzes it unseeded."""
    b = tmp_path / "bin"
    b.mkdir()
    with zipfile.ZipFile(b / "seed_corpus.zip", "w") as z:
        z.writestr("s", b"seed")
    dst = tmp_path / "merged"
    st = corpus_util.stage_fuzzbench_seed_corpus(str(b), "zlib_uncompress_fuzzer", str(dst))
    assert [p.name for p in dst.iterdir()] == ["default_seed"]
    assert (dst / "default_seed").read_bytes() == b"hi"
    assert st["default_seed"] is True and st["staged"] == 0


def test_all_oversize_gives_default_seed(tmp_path):
    b = tmp_path / "bin"
    (b / "seeds").mkdir(parents=True)
    (b / "seeds" / "big").write_bytes(b"x" * BIG)
    dst = tmp_path / "merged"
    corpus_util.stage_fuzzbench_seed_corpus(str(b), "t", str(dst))
    assert [p.name for p in dst.iterdir()] == ["default_seed"]


def test_online_staging_routes_fuzzbench_to_runner_rules(tmp_path):
    exp = tmp_path / "exp"
    b = tmp_path / "bin"
    b.mkdir()
    with zipfile.ZipFile(b / "t_seed_corpus.zip", "w") as z:
        z.writestr("x/a", b"aaa")
    n = phase3_online._stage_online_seed_corpus(str(exp), str(b), "t", entry=BUG)
    merged = exp / "seed_corpus" / "merged"
    build = exp / "seed_corpus" / "build"
    assert n == 1
    assert [p.name for p in merged.iterdir()] == [_sha1(b"aaa")]
    assert [p.name for p in build.iterdir()] == [_sha1(b"aaa")]


def test_online_staging_empty_fuzzbench_corpus(tmp_path):
    exp = tmp_path / "exp"
    b = tmp_path / "bin"
    b.mkdir()
    assert phase3_online._stage_online_seed_corpus(str(exp), str(b), "t", entry=COV) == 0
    merged = exp / "seed_corpus" / "merged"
    assert (merged / "default_seed").read_bytes() == b"hi"
    assert list((exp / "seed_corpus" / "build").iterdir()) == []
    prov = phase3_online._seed_corpus_provenance(str(exp))
    assert prov["fallback_only"] is True


def test_online_staging_arvo_unchanged(tmp_path):
    """ARVO keeps the seed_corpus.zip fallback, corpus_NNNNNN names and the
    1-byte seed_fallback_00."""
    exp = tmp_path / "exp"
    b = tmp_path / "bin"
    b.mkdir()
    with zipfile.ZipFile(b / "seed_corpus.zip", "w") as z:
        z.writestr("d/a", b"aaa")
    assert phase3_online._stage_online_seed_corpus(str(exp), str(b), "t") == 1
    assert [p.name for p in (exp / "seed_corpus" / "merged").iterdir()] == ["corpus_000000"]
    exp2 = tmp_path / "exp2"
    b2 = tmp_path / "bin2"
    b2.mkdir()
    assert phase3_online._stage_online_seed_corpus(str(exp2), str(b2), "t", entry=ARVO) == 0
    assert (exp2 / "seed_corpus" / "merged" / "seed_fallback_00").read_bytes() == b"\x00"


# --------------------------------------------------------------------------- #
# Hot swap replaces the whole FuzzBench /out set
# --------------------------------------------------------------------------- #
def _set(d, tag, cmplog=True):
    d.mkdir(parents=True, exist_ok=True)
    (d / "t").write_bytes(f"target-{tag}".encode())
    if cmplog:
        (d / "cmplog").mkdir(exist_ok=True)
        (d / "cmplog" / "t").write_bytes(f"cmplog-{tag}".encode())
    (d / "afl++.dict").write_text(f"dict-{tag}")


def test_swap_extra_files():
    assert phase3_online._swap_extra_files(ARVO, "t") == ()
    assert phase3_online._swap_extra_files(BUG, "t") == ("cmplog/t", "afl++.dict")


def test_overwrite_replaces_whole_fuzzbench_set(tmp_path):
    live, new = tmp_path / "live", tmp_path / "new"
    _set(live, "old")
    _set(new, "new")
    phase3_online._overwrite_binary(str(live / "t"), str(new / "t"),
                                    extra_files=("cmplog/t", "afl++.dict"))
    assert (live / "t").read_bytes() == b"target-new"
    assert (live / "cmplog" / "t").read_bytes() == b"cmplog-new"
    assert (live / "afl++.dict").read_text() == "dict-new"
    assert os.access(live / "t", os.X_OK)
    assert not [p for p in live.rglob(".swap-*")]


def test_overwrite_drops_companions_the_new_build_lacks(tmp_path):
    live, new = tmp_path / "live", tmp_path / "new"
    _set(live, "old")
    _set(new, "new", cmplog=False)
    phase3_online._overwrite_binary(str(live / "t"), str(new / "t"),
                                    extra_files=("cmplog/t", "afl++.dict"))
    assert not (live / "cmplog" / "t").exists(), "-c must not point at a stale cmplog"
    assert (live / "t").read_bytes() == b"target-new"


def test_failed_swap_leaves_the_old_set_intact(tmp_path, monkeypatch):
    live, new = tmp_path / "live", tmp_path / "new"
    _set(live, "old")
    _set(new, "new")
    real = phase3_online.shutil.copy2

    def flaky(src, dst, *a, **k):
        if src.endswith("afl++.dict"):
            raise OSError("disk full")
        return real(src, dst, *a, **k)

    monkeypatch.setattr(phase3_online.shutil, "copy2", flaky)
    with pytest.raises(OSError):
        phase3_online._overwrite_binary(str(live / "t"), str(new / "t"),
                                        extra_files=("cmplog/t", "afl++.dict"))
    assert (live / "t").read_bytes() == b"target-old"
    assert (live / "cmplog" / "t").read_bytes() == b"cmplog-old"
    assert not [p for p in live.rglob(".swap-*")]


def test_hot_swap_one_swaps_the_whole_set(monkeypatch, tmp_path):
    import threading
    import types
    live, new = tmp_path / "bin_01", tmp_path / "iter_01"
    _set(live, "old")
    _set(new, "new")
    trial = types.SimpleNamespace(trial_id=1, container_id="c", bin_dir_override=str(live))
    ctx = types.SimpleNamespace(trial=trial, iter_n=1, fuzz_target="t", entry=BUG,
                                experiment_id="e",
                                swap_timeline_path=str(tmp_path / "tl.json"))
    rel, ready = threading.Event(), threading.Event()
    # Stand-in for the trial's monitor: relaunch once the swap says ready.
    threading.Thread(target=lambda: ready.wait(10) and rel.set(), daemon=True).start()
    state = types.SimpleNamespace(
        trials={1: {"state": "running", "relaunched": rel, "relaunch_ready": ready}},
        swap_timeline=[])
    monkeypatch.setattr(phase3_online.docker_util, "stop_container", lambda c, **k: None)
    monkeypatch.setattr(phase3_online.docker_util, "container_is_running", lambda c: False)
    monkeypatch.setattr(phase3_online, "_fuzzer_state", lambda e, t: {})
    monkeypatch.setattr(phase3_online.swap_signal.SIGNAL, "record_swap", lambda *a: 1)
    phase3_online.hot_swap_one(ctx, state, str(new))
    assert (live / "cmplog" / "t").read_bytes() == b"cmplog-new"
    assert (live / "afl++.dict").read_text() == "dict-new"


def test_preflight_tool_runs_the_setup_profile_check(monkeypatch, tmp_path):
    """A target that passes the tool must not then be refused by run_online's
    setup profile check: the tool runs the same function, before the smoke."""
    exp = tmp_path / "exp"
    (exp / "baseline" / "bin").mkdir(parents=True)
    (exp / "baseline" / "bin" / BUG["fuzz_target"]).write_bytes(b"x")
    monkeypatch.setattr(preflight_online, "_entry", lambda p: BUG)
    monkeypatch.setattr(preflight_online.phase2_setup, "get_experiment_dir",
                        lambda i, e: str(exp))
    monkeypatch.setattr(preflight_online, "prework_image_for", lambda e: "fb-aflpp/x")
    monkeypatch.setattr(preflight_online.subprocess, "run",
                        lambda cmd, **k: subprocess.CompletedProcess(cmd, 0))
    monkeypatch.setattr(preflight_online.phase3_online, "_extract_online_target",
                        lambda *a, **k: (False, None, None, str(tmp_path / "src")))
    monkeypatch.setattr(preflight_online.phase3_online, "_src_subtree_has_files",
                        lambda p: True)
    monkeypatch.setattr(preflight_online.phase3_online, "_stage_online_seed_corpus",
                        lambda *a, **k: 0)
    monkeypatch.setattr(preflight_online.phase2_setup, "_find_project_source",
                        lambda r, p: str(tmp_path / "src"))
    monkeypatch.setattr(preflight_online.tracked_git, "strip_vcs_metadata", lambda r: None)
    seen = {}
    monkeypatch.setattr(preflight_online.phase3_online, "_preflight_profile",
                        lambda **k: seen.update(k) or (False, "hotspots: mismatch"))
    monkeypatch.setattr(preflight_online, "smoke",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("smoke ran")))
    res = preflight_online.preflight("mruby", 23, 5, False)
    assert res["stages"]["profile"]["ok"] is False
    assert "mismatch" in res["stages"]["profile"]["reason"]
    assert seen["project_src_dir"] == str(tmp_path / "src") and seen["profile_cpu"] == 23
    assert res["ok"] is False
