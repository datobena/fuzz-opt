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
    assert "--sanitizer" not in plain and "--language" not in plain
    cmd = _profile_argv(monkeypatch, tmp_path, {
        "PHASE2_SANITIZER": "memory", "PHASE2_FUZZING_LANGUAGE": "c",
        "PHASE2_SANITIZER_ENV": json.dumps({"ASAN_OPTIONS": "a=1"})})
    assert cmd[len(plain):] == ["--sanitizer-env", "ASAN_OPTIONS=a=1",
                                "--sanitizer", "memory", "--language", "c"]


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


# (f) ------------------------------------------------------------------------
def _measured_cmds(monkeypatch, tmp_path, **kw):
    from lib import afl_replay
    seen = []

    def fake_run(cmd, **k):
        seen.append(cmd)
        return types.SimpleNamespace(returncode=0, stdout="Captured 1 tuples", stderr="")
    monkeypatch.setattr(afl_replay.subprocess, "run", fake_run)
    (tmp_path / "c").mkdir(exist_ok=True)
    afl_replay.measure_binary(out_dir=tmp_path / "o", corpus_dir=tmp_path / "c",
                              fuzz_target="t", cpu=3, repeats=1, memory="4g",
                              shm_size="2g", run_timeout=10, image=kw.pop("image"), **kw)
    return seen[0]


def test_host_gate_measure_binary_carries_the_kinds_set(monkeypatch, tmp_path):
    cmd = _measured_cmds(monkeypatch, tmp_path, image="bench-upstream/x",
                         sanitizer_env=dict(CUSTOM))
    assert CUSTOM_EXPORTS in cmd[-1] and cmd[-1].count("ASAN_OPTIONS=") == 1
    assert config.REPLAY_ASAN_OPTIONS not in cmd[-1]


def test_host_gate_and_crash_checks_default_byte_identical(monkeypatch, tmp_path):
    from lib import afl_replay
    for image in ("bench-aflpp/x-arvo-1", "fb-aflpp/x"):
        ctx = BrokerContext(image=image, source_dir="", out_dir=str(tmp_path / "o"),
                            corpus_dir=str(tmp_path / "c"), fuzz_target="t", project="",
                            cpu=3)
        assert _measured_cmds(monkeypatch, tmp_path, image=image) == broker._replay_command(ctx)
        assert _measured_cmds(monkeypatch, tmp_path, image=image, sanitizer_env=None) == \
            broker._replay_command(ctx)
        seen = []
        monkeypatch.setattr(broker, "scan_for_crashers",
                            lambda c, o, d: seen.append(broker._crash_scan_command(c, o, d)) or {})
        monkeypatch.setattr(broker, "crash_report",
                            lambda c, o, d, n: seen.append(broker._crash_report_command(c, o, d, n)) or "")
        afl_replay.find_crashers(out_dir=tmp_path / "o", corpus_dir=tmp_path / "c",
                                 fuzz_target="t", cpu=3, image=image)
        afl_replay.crash_report(out_dir=tmp_path / "o", corpus_dir=tmp_path / "c",
                                fuzz_target="t", cpu=3, image=image, names=["a"])
        assert seen == [broker._crash_scan_command(ctx, ctx.out_dir, ctx.corpus_dir),
                        broker._crash_report_command(ctx, ctx.out_dir, ctx.corpus_dir, ["a"])]
        seen.clear()
        afl_replay.find_crashers(out_dir=tmp_path / "o", corpus_dir=tmp_path / "c",
                                 fuzz_target="t", cpu=3, image=image, sanitizer_env=dict(CUSTOM))
        assert CUSTOM_EXPORTS in seen[0][-1]


# (g) ------------------------------------------------------------------------
import pytest  # noqa: E402


@pytest.mark.parametrize("kind", ["upstream", "arvo"])
@pytest.mark.parametrize("gate_result", ["clean", "crash"])
def test_run_round_threads_the_kinds_set_into_host_checks(monkeypatch, tmp_path, kind,
                                                          gate_result):
    import phase3_online
    from lib import afl_launch
    entry = {"cve": "x", "project": "libxml2"}
    if kind == "upstream":
        entry.update(kind="upstream", sanitizer="memory", language="c")
    live = tmp_path / "live"
    live.mkdir()
    online = tmp_path / "trial_02"
    ctx = phase3_online.RoundContext(
        entry=entry, experiment_id="e", experiment_dir=str(tmp_path),
        online_dir=str(online), source_tree=str(tmp_path / "src"),
        source_root=str(tmp_path / "src"), project="libxml2", image="", fuzz_target="xml",
        poc_path=None, previous_best_bin=str(tmp_path / "iter_00_bin"), prev_tag="iter_00",
        optimized_bin_dir=str(live), ledger_path=str(online / "ledger.json"),
        swap_timeline_path="", profile_cpu=1, wrapper_env_fn=lambda root, state: {})
    ctx.trial = types.SimpleNamespace(trial_id=2, project="libxml2", cve="x",
                                      variant="optimized")
    ctx.fixed_mutations = str(tmp_path / "fixed_mutations")
    ctx.fixed_mutation_count = 10
    expected = (dict(afl_launch.upstream_sanitizer_env(str(live), "xml", "memory"))
                if kind == "upstream" else None)

    calls = {}
    rc = {k: 1 for k in ("harvested", "checked_count", "crashers_removed",
                         "tuning_count", "units_per_s", "budget_secs", "smoke_count")}
    rc.update(tuning="tuning", smoke="smoke", checked="checked", gate="gate")
    monkeypatch.setattr(phase3_online.config, "ONLINE_FIXED_MUTATION_CORPUS", True)
    monkeypatch.setattr(phase3_online, "prepare_round_corpus",
                        lambda **kw: calls.setdefault("prepare", kw) and rc)
    monkeypatch.setattr(phase3_online, "prework_image_for", lambda e: "img")
    monkeypatch.setattr(phase3_online, "_gate_replay_rate", lambda d: None)
    monkeypatch.setattr(phase3_online, "build_round_env", lambda **k: {})
    monkeypatch.setattr(phase3_online, "_reassert_edit_mtimes", lambda t: None)
    monkeypatch.setattr(phase3_online, "_carry_forward_agent_memory", lambda *a: False)
    monkeypatch.setattr(phase3_online, "_write_cpu_cost_summary", lambda c: None)
    monkeypatch.setattr(phase3_online, "_write_cumulative_diff", lambda *a: None)
    monkeypatch.setattr(phase2_setup, "optimizer_provenance", lambda: {})
    monkeypatch.setattr(phase3_online, "apply_round_outcome",
                        lambda ready, **kw: kw["previous_best_bin"])

    def optimize(source, target, diff_dir, **kwargs):
        calls["env"] = kwargs["codex_extra_env"]
        (Path(diff_dir) / "optimization.diff").write_text("diff --git a/x b/x\n")
        return True
    monkeypatch.setattr(phase2_setup, "optimize_and_build", optimize)
    monkeypatch.setattr(phase2_setup, "_reject_if_optimization_removed_bug",
                        lambda **kw: (kw["optimization_ready"], None))
    monkeypatch.setattr(phase3_online.afl_replay, "find_crashers",
                        lambda **kw: calls.setdefault("find", kw) and {
                            "ok": True, "scanned": 1, "expected": 1,
                            "crashers": ["c"] if gate_result == "crash" else []})
    monkeypatch.setattr(phase3_online.afl_replay, "crash_report",
                        lambda **kw: calls.setdefault("report", kw) and "r")
    monkeypatch.setattr(phase2_setup, "run_replay_speedup",
                        lambda **kw: calls.setdefault("replay", kw) and {
                            "replay_speedup": 1.0, "partial": False,
                            "baseline": {"median_time_s": 1}, "optimized": {"median_time_s": 1}})
    monkeypatch.setattr(phase2_setup, "_reject_if_no_replay_speedup",
                        lambda **kw: (kw["optimization_ready"], None))

    phase3_online.run_round(ctx, phase3_online.OnlineState(), 1)

    assert calls["prepare"]["sanitizer_env"] == expected
    assert calls["find"].get("sanitizer_env") == expected
    if gate_result == "crash":
        assert calls["report"].get("sanitizer_env") == expected
        assert "replay" not in calls
    else:
        assert calls["replay"]["sanitizer_env"] == expected
    if expected is None:
        # ARVO keeps the exact argument lists it had.
        assert "sanitizer_env" not in calls["find"]
        assert not any(k.startswith("PHASE2_SANITIZER") for k in calls["env"])
    else:
        assert json.loads(calls["env"]["PHASE2_SANITIZER_ENV"]) == expected
        assert calls["env"]["PHASE2_SANITIZER"] == "memory"


def test_noise_floor_measure_gets_the_kinds_set(monkeypatch, tmp_path):
    import phase3_online
    from lib import afl_replay, provenance
    seen = {}
    monkeypatch.setattr(afl_replay, "measure_binary", lambda **kw: seen.update(kw) or {})
    monkeypatch.setattr(phase3_online, "_setup_build", lambda **kw: (True, ""))
    monkeypatch.setattr(provenance, "noise_floor",
                        lambda rebuild, measure, rounds: measure("/d") or {})
    online = tmp_path / "exp" / "optimized" / "online"
    online.mkdir(parents=True)
    for san in (dict(CUSTOM), None):
        seen.clear()
        phase3_online._measure_noise_floor(
            ctx_entry={"project": "x", "local_id": 1},
            source_root=str(tmp_path), fuzz_target="t", online_dir=str(online),
            profile_cpu=1, rounds=2, sanitizer_env=san)
        assert seen.get("sanitizer_env") == san
