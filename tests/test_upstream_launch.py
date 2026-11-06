"""Upstream OSS-Fuzz launch parity (manifest entries with "kind": "upstream").

Upstream targets are fuzzed exactly as OSS-Fuzz's base-runner run_fuzzer
script (afl branch) fuzzes them, with two user-decided deviations:
``-t config.AFL_TIMEOUT_FLAG`` in place of ``5000+`` and ``detect_leaks=0``
appended to ASAN_OPTIONS. ARVO and FuzzBench launches stay as they were.
"""
import config
from lib import afl_launch


UP = {"project": "libssh", "ossfuzz_project": "libssh", "cve": "upstream-970001", "local_id": 970001,
      "fuzz_target": "ssh_server_fuzzer", "kind": "upstream", "sanitizer": "address", "language": "c"}
BUG = {"project": "mruby", "cve": "fuzzbench-900025", "local_id": 900025,
       "fuzz_target": "mruby_fuzzer", "kind": "fuzzbench", "type": "bug",
       "fuzzbench_dir": "mruby_mruby_fuzzer_8c8bbd"}
ARVO = {"project": "libxml2", "cve": "arvo-1", "local_id": 1, "fuzz_target": "xml"}

# base-runner image ENV (image of 2026-07-09), literal so a constant edit shows here.
RUNNER_ASAN = (
    "alloc_dealloc_mismatch=0:allocator_may_return_null=1:allocator_release_to_os_interval_ms=500:"
    "check_malloc_usable_size=0:detect_container_overflow=1:detect_odr_violation=0:detect_leaks=1:"
    "detect_stack_use_after_return=1:fast_unwind_on_fatal=0:handle_abort=1:handle_segv=1:"
    "handle_sigill=1:max_uar_stack_size_log=16:print_scariness=1:quarantine_size_mb=10:"
    "strict_memcmp=1:strip_path_prefix=/workspace/:symbolize=1:use_sigaltstack=1:dedup_token_length=3")
RUNNER_MSAN = "print_stats=1:strip_path_prefix=/workspace/:symbolize=1:dedup_token_length=3"
RUNNER_UBSAN = ("print_stacktrace=1:print_summary=1:silence_unsigned_overflow=1:"
                "strip_path_prefix=/workspace/:symbolize=1:dedup_token_length=3")


def _bin(tmp_path, target, *, cmplog_marker=False, aflpp_dict=False, options=None,
         target_dict=False):
    """An upstream $OUT: the target, afl-fuzz, and the optional files
    run_fuzzer looks for (afl_cmplog.txt, afl++.dict, <t>.options, <t>.dict)."""
    b = tmp_path / "bin"
    b.mkdir(parents=True, exist_ok=True)
    (b / target).write_bytes(b"\x7fELF")
    (b / "afl-fuzz").write_bytes(b"")
    if cmplog_marker:
        (b / "afl_cmplog.txt").write_text("")
    if aflpp_dict:
        (b / "afl++.dict").write_text('"tok"\n')
    if options is not None:
        (b / f"{target}.options").write_text(options)
    if target_dict:
        (b / f"{target}.dict").write_text('"own"\n')
    return b


def test_upstream_argv_matches_run_fuzzer_with_the_two_deviations(tmp_path):
    b = _bin(tmp_path, "ssh_server_fuzzer", cmplog_marker=True, aflpp_dict=True,
             options="[libfuzzer]\nmax_len = 4096\ndict = ssh.dict\n[asan]\nmax_malloc_fill_size = 100\n")
    (b / "ssh.dict").write_text('"x"\n')
    L = afl_launch.build_afl_launch(entry=UP, host_bin_dir=str(b), fuzz_target="ssh_server_fuzzer",
                                    input_dir="/corpus", output_dir="/afl_out", duration=600, seed=7)
    assert L.argv == ["/out/afl-fuzz", "-m", "none", "-c", "/out/ssh_server_fuzzer", "-x", "/out/afl++.dict",
                      "-t", config.AFL_TIMEOUT_FLAG, "-i", "/corpus", "-o", "/afl_out",
                      "-x", "/out/ssh.dict", "-s", "7", "-V", "600", "--", "/out/ssh_server_fuzzer"]
    env = dict(L.env)
    assert env["ASAN_OPTIONS"] == (RUNNER_ASAN + ":max_malloc_fill_size=100:abort_on_error=1:"
                                   "symbolize=0:detect_odr_violation=0:detect_leaks=0")
    assert env["UBSAN_OPTIONS"] == RUNNER_UBSAN + ":symbolize=0"
    assert env["MSAN_OPTIONS"] == RUNNER_MSAN + ":exit_code=86:symbolize=0"
    assert L.flags["-m"] == "none"
    assert [k for k, _ in L.afl_env] == ["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "AFL_SKIP_CPUFREQ",
        "AFL_TRY_AFFINITY", "AFL_FAST_CAL", "AFL_CMPLOG_ONLY_NEW", "AFL_FORKSRV_INIT_TMOUT",
        "AFL_IGNORE_PROBLEMS", "AFL_IGNORE_UNKNOWN_ENVS", "AFL_AUTORESUME"]
    assert env["AFL_FORKSRV_INIT_TMOUT"] == "30000" and "AFL_NO_AFFINITY" not in env
    assert L.workdir == "/out" and L.shell().startswith("export PATH=/out:$PATH; /out/afl-fuzz ")
    assert L.flags["deviations"] == [f"-t {config.AFL_TIMEOUT_FLAG} not 5000+", "detect_leaks=0"]


def test_optional_flags_appear_only_when_their_files_exist(tmp_path):
    # no afl_cmplog.txt, no afl++.dict, no .options, a <t>.dict present
    b = _bin(tmp_path, "t", target_dict=True)
    L = afl_launch.build_afl_launch(entry=UP, host_bin_dir=str(b), fuzz_target="t",
                                    input_dir="/corpus", output_dir="/afl_out", duration=600, seed=7)
    assert L.argv == ["/out/afl-fuzz", "-m", "none", "-t", config.AFL_TIMEOUT_FLAG, "-i", "/corpus", "-o", "/afl_out",
                      "-x", "/out/t.dict", "-s", "7", "-V", "600", "--", "/out/t"]
    assert L.flags["cmplog"] is None and L.flags["aflpp_dict"] is None
    assert L.flags["options_dict"] == "/out/t.dict"


def test_options_sections_join_like_parse_options(tmp_path):
    # values with '=' and spaces; libfuzzer keys ignored; msan section honoured
    b = _bin(tmp_path, "t", options=(
        "[libfuzzer]\nmax_len = 10\ndict = a.dict\n"
        "[asan]\nallocator_may_return_null = 1\nstrip_path_prefix = /a=b c\n"
        "[msan]\npoison_in_dtor = 1\n"))
    p = str(b / "t.options")
    assert afl_launch.parse_options_section(p, "asan") == "allocator_may_return_null=1:strip_path_prefix=/a=b c"
    assert afl_launch.parse_options_section(p, "ubsan") is None
    assert afl_launch.parse_options_section(str(b / "missing.options"), "asan") is None
    env = dict(afl_launch.upstream_sanitizer_env(str(b), "t", "memory"))
    assert env["ASAN_OPTIONS"] == (RUNNER_ASAN + ":allocator_may_return_null=1:strip_path_prefix=/a=b c:"
                                   "abort_on_error=1:symbolize=0:detect_odr_violation=0:detect_leaks=0")
    assert env["MSAN_OPTIONS"] == RUNNER_MSAN + ":poison_in_dtor=1:exit_code=86:symbolize=0"
    assert env["UBSAN_OPTIONS"] == RUNNER_UBSAN + ":symbolize=0"


def test_arvo_and_fuzzbench_launches_are_unchanged(tmp_path):
    # ARVO: the preflight and capture argv from tests/test_fuzzbench_run.py.
    L = afl_launch.build_afl_launch(entry=ARVO, host_bin_dir=None, fuzz_target="xml",
                                    input_dir="/corpus", output_dir="/afl_out", duration=120,
                                    arvo_order=afl_launch.ARVO_ORDER_PREFLIGHT)
    assert L.argv == [
        "/out/afl-fuzz", "-i", "/corpus", "-o", "/afl_out", "-V", "120",
        "-m", "none", "-t", config.AFL_TIMEOUT_FLAG, "--", "/out/xml"]
    assert L.docker_env_args() == [
        "-e", "AFL_NO_AFFINITY=1", "-e", "AFL_SKIP_CPUFREQ=1",
        "-e", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1", "-e", "AFL_AUTORESUME=1",
        "-e", f"ASAN_OPTIONS={config.FUZZ_ASAN_OPTIONS}",
        "-e", f"UBSAN_OPTIONS={config.FUZZ_UBSAN_OPTIONS}"]
    assert L.workdir is None and L.kind == "arvo"
    L = afl_launch.build_afl_launch(entry=ARVO, host_bin_dir=None, fuzz_target="xml",
                                    input_dir="/seeds", output_dir="/work/aflout", duration=33,
                                    seed=7, autoresume=False,
                                    arvo_order=afl_launch.ARVO_ORDER_CAPTURE)
    assert L.shell() == (f"/out/afl-fuzz -V 33 -s 7 -m none -t {config.AFL_TIMEOUT_FLAG} "
                         "-i /seeds -o /work/aflout -- /out/xml")

    # BUG: the expectations of test_bug_target_with_cmplog_dicts_and_options_dict.
    b = tmp_path / "bin"
    b.mkdir()
    (b / "mruby_fuzzer").write_bytes(b"\x7fELF")
    (b / "afl-fuzz").write_bytes(b"")
    (b / "cmplog").mkdir()
    (b / "cmplog" / "mruby_fuzzer").write_bytes(b"\x7fELF-cmplog")
    (b / "afl++.dict").write_text('"tok"\n')
    (b / "mruby_fuzzer.options").write_text("[libfuzzer]\ndict = mruby.dict\nmax_len = 4096\n")
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
    assert L.shell() == " ".join(L.argv)


def test_shim_compiler_for_upstream_is_the_image_clang():
    assert afl_launch.shim_compiler(UP) == "clang"
