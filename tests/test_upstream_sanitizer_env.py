"""An upstream target's gate, smoke, profile and trials run under ONE set of
sanitizer options -- the kind's own (afl_launch.upstream_sanitizer_env) -- while
every ARVO and FuzzBench command string stays byte-identical."""
import importlib.util
import json
import types
from pathlib import Path

import config
import phase2_setup
import sandbox.broker as broker
from sandbox.broker import BrokerContext
from prework.prework_build import upstream_compile_args

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "skills" / "profile-once-fuzz-folds" / "scripts"

# Today's export text, pinned byte-for-byte (copied from the pre-change source).
DEFAULT_EXPORTS = (f"ASAN_OPTIONS={config.REPLAY_ASAN_OPTIONS} "
                   f"UBSAN_OPTIONS={config.REPLAY_UBSAN_OPTIONS} MSAN_OPTIONS=symbolize=0; ")
DEFAULT_SMOKE_EXPORTS = (f"export ASAN_OPTIONS={config.REPLAY_ASAN_OPTIONS} "
                         f"UBSAN_OPTIONS={config.REPLAY_UBSAN_OPTIONS}; ")
CUSTOM = {"ASAN_OPTIONS": "a=1", "MSAN_OPTIONS": "m=1", "UBSAN_OPTIONS": "u=1"}
CUSTOM_EXPORTS = "ASAN_OPTIONS=a=1 UBSAN_OPTIONS=u=1 MSAN_OPTIONS=m=1; "


def _ctx(tmp_path, **kw):
    kw.setdefault("image", "bench-aflpp/x-arvo-1")
    smoke = tmp_path / "smoke"
    smoke.mkdir(exist_ok=True)
    return BrokerContext(source_dir=str(tmp_path / "s"), out_dir=str(tmp_path / "o"),
                         corpus_dir=str(tmp_path / "c"), fuzz_target="t", project="x",
                         cpu=3, smoke_corpus_dir=str(smoke), **kw)


def _smoke_cmd(ctx, monkeypatch):
    seen = []
    monkeypatch.setattr(broker, "_run", lambda cmd, t, c=None, **k: (seen.append(cmd) or (0, "")))
    monkeypatch.setattr(broker, "_audit", lambda *a: None)
    broker._run_smoke(ctx)
    return seen[0][-1]


def _load_profile():
    spec = importlib.util.spec_from_file_location(
        "replay_fuzzer_profile", SCRIPTS_DIR / "replay_fuzzer_profile.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# (a) ------------------------------------------------------------------------
def test_default_context_keeps_todays_export_strings(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    assert (ctx.sanitizer, ctx.language, ctx.sanitizer_env) == ("address", "c++", {})
    replay = broker._replay_command(ctx)[-1]
    assert replay.startswith(
        "export AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 "
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 " + DEFAULT_EXPORTS + "/out/afl-showmap -C ")
    scan = broker._crash_scan_command(ctx, ctx.out_dir, ctx.corpus_dir)[-1]
    assert ("AFL_CMIN_CRASHES_ONLY=1 " + DEFAULT_EXPORTS + "/out/afl-showmap -q -Z") in scan
    assert _smoke_cmd(ctx, monkeypatch).startswith(
        DEFAULT_SMOKE_EXPORTS + "printf '' > /tmp/e; ")
    report = broker._crash_report_command(ctx, ctx.out_dir, ctx.corpus_dir, ["a"])[-1]
    asan = config.REPLAY_ASAN_OPTIONS.replace("symbolize=0", "symbolize=1")
    ubsan = (config.REPLAY_UBSAN_OPTIONS.replace("symbolize=0", "symbolize=1")
             .replace("print_stacktrace=0", "print_stacktrace=1"))
    assert report.startswith(f"export ASAN_OPTIONS={asan} UBSAN_OPTIONS={ubsan}; [ -x ")
    assert broker._sanitizer_exports(ctx) == "export " + DEFAULT_EXPORTS
    assert broker._sanitizer_exports(ctx, msan=False) == DEFAULT_SMOKE_EXPORTS


# (b) ------------------------------------------------------------------------
def test_sanitizer_env_reaches_every_command(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path, image="bench-upstream/x", sanitizer_env=dict(CUSTOM))
    assert broker._sanitizer_exports(ctx) == "export " + CUSTOM_EXPORTS
    assert broker._sanitizer_exports(ctx, msan=False) == "export " + CUSTOM_EXPORTS
    cmds = {
        "replay": broker._replay_command(ctx)[-1],
        "scan": broker._crash_scan_command(ctx, ctx.out_dir, ctx.corpus_dir)[-1],
        "smoke": _smoke_cmd(ctx, monkeypatch),
    }
    for name, script in cmds.items():
        assert CUSTOM_EXPORTS in script, name
        assert script.count("ASAN_OPTIONS=") == 1, name
        assert config.REPLAY_ASAN_OPTIONS not in script, name
    # The upstream gate also exports the target's map size, like FuzzBench's.
    assert "AFL_DUMP_MAP_SIZE=1 /out/t" in cmds["replay"]
    assert "AFL_DUMP_MAP_SIZE=1 /out/t" in cmds["scan"]
    report = broker._crash_report_command(ctx, ctx.out_dir, ctx.corpus_dir, ["a"])[-1]
    assert report.startswith("export ASAN_OPTIONS=a=1 UBSAN_OPTIONS=u=1 MSAN_OPTIONS=m=1; ")


def test_symbolized_report_flips_symbolize_in_the_kinds_values(tmp_path):
    ctx = _ctx(tmp_path, image="bench-upstream/x", sanitizer_env={
        "ASAN_OPTIONS": "x=1:symbolize=0", "MSAN_OPTIONS": "symbolize=0",
        "UBSAN_OPTIONS": "print_stacktrace=0:symbolize=0"})
    report = broker._crash_report_command(ctx, ctx.out_dir, ctx.corpus_dir, ["a"])[-1]
    assert report.startswith(
        "export ASAN_OPTIONS=x=1:symbolize=1 UBSAN_OPTIONS=print_stacktrace=1:symbolize=1 "
        "MSAN_OPTIONS=symbolize=1; ")


def test_values_are_shell_quoted(tmp_path):
    ctx = _ctx(tmp_path, sanitizer_env={"ASAN_OPTIONS": "a b", "UBSAN_OPTIONS": "u",
                                        "MSAN_OPTIONS": "m"})
    assert broker._sanitizer_exports(ctx) == \
        "export ASAN_OPTIONS='a b' UBSAN_OPTIONS=u MSAN_OPTIONS=m; "


# (c) ------------------------------------------------------------------------
def test_upstream_build_uses_upstream_compile_args(tmp_path):
    ctx = _ctx(tmp_path, image="bench-upstream/x", sanitizer="memory", language="c")
    ctx.build_source_dir = str(tmp_path / "snap")
    cmd = broker._build_command(ctx)
    assert cmd == ["docker", "run", "--rm", "--privileged", "--cpuset-cpus", "3",
                   "--ulimit", "core=0",
                   *upstream_compile_args(image="bench-upstream/x",
                                          source_dir=str(tmp_path / "snap"),
                                          out_dir=ctx.out_dir, project="x",
                                          sanitizer="memory", language="c")]
    assert cmd[cmd.index("--network") + 1] == "none"
    assert "SANITIZER=memory" in cmd and "FUZZING_LANGUAGE=c" in cmd


# (d) ------------------------------------------------------------------------
_PROFILE_DEFAULT_E = [
    "ASAN_OPTIONS=abort_on_error=1:alloc_dealloc_mismatch=0:"
    "allocator_may_return_null=1:allocator_release_to_os_interval_ms=500:"
    "allow_user_segv_handler=0:check_malloc_usable_size=0:detect_leaks=0:"
    "detect_odr_violation=0:detect_stack_use_after_return=1:"
    "fast_unwind_on_fatal=0:handle_abort=2:handle_segv=2:handle_sigbus=2:"
    "handle_sigfpe=2:handle_sigill=2:max_uar_stack_size_log=16:"
    "quarantine_size_mb=64:strict_memcmp=1:symbolize=0:"
    "symbolize_inline_frames=0",
    "UBSAN_OPTIONS=abort_on_error=1:allocator_release_to_os_interval_ms=500:"
    "handle_abort=2:handle_segv=2:handle_sigbus=2:handle_sigfpe=2:"
    "handle_sigill=2:print_stacktrace=0:symbolize=0:"
    "symbolize_inline_frames=0",
    "MSAN_OPTIONS=symbolize=0",
]


def _profile_cmd(mod, tmp_path, **kw):
    return mod.build_replay_profile_docker_command(
        out_dir=tmp_path / "o", corpus_dir=tmp_path / "c", artifact_dir=tmp_path / "a",
        fuzz_target="t", min_sample_seconds=60, seed=1337, cpu=3, memory="4g",
        shm_size="2g", **kw)


def _env_pairs(cmd):
    return [cmd[i + 1] for i, a in enumerate(cmd) if a == "-e"]


def test_profiler_default_env_unchanged_and_override_replaces(tmp_path):
    mod = _load_profile()
    default = _profile_cmd(mod, tmp_path)
    assert _env_pairs(default)[:3] == _PROFILE_DEFAULT_E
    assert _profile_cmd(mod, tmp_path, sanitizer_env=None) == default
    assert _profile_cmd(mod, tmp_path, sanitizer_env=[]) == default

    over = _profile_cmd(mod, tmp_path, sanitizer_env=[("ASAN_OPTIONS", "a=1")])
    pairs = _env_pairs(over)
    assert pairs[:3] == ["ASAN_OPTIONS=a=1", *_PROFILE_DEFAULT_E[1:]]
    assert sum(p.startswith("ASAN_OPTIONS=") for p in pairs) == 1
    assert len(over) == len(default)

    extra = _profile_cmd(mod, tmp_path, sanitizer_env=[("MSAN_OPTIONS", "m=1"),
                                                       ("LSAN_OPTIONS", "l=1")])
    assert _env_pairs(extra)[:4] == [*_PROFILE_DEFAULT_E[:2], "MSAN_OPTIONS=m=1",
                                     "LSAN_OPTIONS=l=1"]


def test_profiler_cli_parses_repeatable_sanitizer_env(monkeypatch):
    mod = _load_profile()
    monkeypatch.setattr("sys.argv", ["p", "--out-dir", "o", "--corpus-dir", "c",
                                     "--artifact-dir", "a", "--fuzz-target", "t",
                                     "--sanitizer-env", "ASAN_OPTIONS=a=1:b=2",
                                     "--sanitizer-env", "UBSAN_OPTIONS=u=1"])
    args = mod.parse_args()
    assert mod.parse_sanitizer_env(args.sanitizer_env) == [
        ("ASAN_OPTIONS", "a=1:b=2"), ("UBSAN_OPTIONS", "u=1")]
    monkeypatch.setattr("sys.argv", ["p", "--out-dir", "o", "--corpus-dir", "c",
                                     "--artifact-dir", "a", "--fuzz-target", "t"])
    assert mod.parse_sanitizer_env(mod.parse_args().sanitizer_env) == []


# (e) ------------------------------------------------------------------------
def _profile_argv(monkeypatch, tmp_path, env):
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        return types.SimpleNamespace(returncode=1, stdout="", stderr="x")
    monkeypatch.setattr(phase2_setup.subprocess, "run", fake_run)
    phase2_setup.run_baseline_profile(
        replay_profile="r.py", out_dir="o", corpus_dir="c", profile_dir=str(tmp_path),
        fuzz_target="t", min_sample_seconds=1, cpu=0, env=env)
    return seen[0]


def test_phase2_profiler_call_passes_the_kinds_sanitizer_env(monkeypatch, tmp_path):
    plain = _profile_argv(monkeypatch, tmp_path, {})
    assert "--sanitizer-env" not in plain
    cmd = _profile_argv(monkeypatch, tmp_path, {"PHASE2_SANITIZER_ENV": json.dumps(
        {"UBSAN_OPTIONS": "u=1", "ASAN_OPTIONS": "a=1", "MSAN_OPTIONS": "m=1"})})
    assert cmd[:len(plain)] == plain
    assert cmd[len(plain):] == ["--sanitizer-env", "ASAN_OPTIONS=a=1",
                                "--sanitizer-env", "MSAN_OPTIONS=m=1",
                                "--sanitizer-env", "UBSAN_OPTIONS=u=1"]


def test_phase2_sandboxed_call_passes_sanitizer_context(monkeypatch):
    import sandbox.session as s
    seen = {}
    monkeypatch.setattr(s, "run_sandboxed_optimizer", lambda **kw: seen.update(kw) or {"ok": True})
    monkeypatch.setattr(s, "resolve_agent_cpus", lambda: "0")
    base = {"FUZZ_SOURCE_FOLDS_OUT_DIR": "/o", "FUZZ_SOURCE_FOLDS_CORPUS_DIR": "/c",
            "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR": "/p",
            "PHASE2_PREWORK_IMAGE": "bench-upstream/x", "FUZZ_TARGET": "t",
            "FUZZ_SOURCE_FOLDS_PROFILE_CPU": "4"}
    phase2_setup._invoke_agent_sandboxed("/src", "p", timeout=None, project="x",
                                         extra_env=dict(base))
    assert (seen["sanitizer"], seen["language"], seen["sanitizer_env"]) == \
        ("address", "c++", None)
    phase2_setup._invoke_agent_sandboxed(
        "/src", "p", timeout=None, project="x",
        extra_env={**base, "PHASE2_SANITIZER": "memory", "PHASE2_FUZZING_LANGUAGE": "c",
                   "PHASE2_SANITIZER_ENV": json.dumps(CUSTOM)})
    assert (seen["sanitizer"], seen["language"], seen["sanitizer_env"]) == \
        ("memory", "c", CUSTOM)


def test_session_signature_defaults():
    import inspect
    import sandbox.session as s
    p = inspect.signature(s.run_sandboxed_optimizer).parameters
    assert p["sanitizer"].default == "address"
    assert p["language"].default == "c++"
    assert p["sanitizer_env"].default is None


def test_phase3_round_env_only_for_upstream(tmp_path):
    import phase3_online
    from lib import afl_launch
    assert phase3_online.upstream_round_env({"kind": "fuzzbench"}, "t", str(tmp_path)) == {}
    assert phase3_online.upstream_round_env({"project": "x"}, "t", str(tmp_path)) == {}
    (tmp_path / "t.options").write_text("[asan]\nfoo=1\n")
    entry = {"kind": "upstream", "sanitizer": "memory", "language": "c"}
    env = phase3_online.upstream_round_env(entry, "t", str(tmp_path))
    assert env["PHASE2_SANITIZER"] == "memory"
    assert env["PHASE2_FUZZING_LANGUAGE"] == "c"
    assert json.loads(env["PHASE2_SANITIZER_ENV"]) == dict(
        afl_launch.upstream_sanitizer_env(str(tmp_path), "t", "memory"))
    assert "foo=1" in json.loads(env["PHASE2_SANITIZER_ENV"])["ASAN_OPTIONS"]
