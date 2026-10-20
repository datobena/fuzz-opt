import subprocess
from pathlib import Path

import phase3_runner


def test_start_trial_clears_existing_trial_corpus(monkeypatch, tmp_path):
    experiment_id = "exp"
    trial = phase3_runner.Trial(
        project="demo",
        cve="CVE-0000-0001",
        variant="baseline",
        trial_id=0,
        seed=1337,
    )

    monkeypatch.setattr(phase3_runner.config, "RESULTS_DIR", str(tmp_path))

    trial_dirs = phase3_runner.get_trial_dirs(experiment_id, trial)
    corpus_dir = Path(trial_dirs["corpus"])
    corpus_dir.mkdir(parents=True, exist_ok=True)
    stale_file = corpus_dir / "stale_seed"
    stale_file.write_text("old-seed")

    empty_seed_dir = tmp_path / "empty-seed"
    empty_seed_dir.mkdir()
    monkeypatch.setattr(
        phase3_runner, "get_seed_corpus_dir", lambda _exp, _trial: str(empty_seed_dir)
    )

    fuzzer_binary = tmp_path / "demo_fuzzer"
    fuzzer_binary.write_text("#!/bin/sh\nexit 0\n")
    monkeypatch.setattr(
        phase3_runner, "get_fuzzer_binary", lambda _exp, _trial: str(fuzzer_binary)
    )

    def fake_run(cmd, capture_output=True, text=False, timeout=None):
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(phase3_runner, "_launch_container", lambda *args, **kwargs: True)

    assert phase3_runner.start_trial(trial, experiment_id, duration=123) is True
    assert not stale_file.exists()
    assert list(corpus_dir.iterdir()) == []


# --------------------------------------------------------------------------- #
# AFL++ launch. The engine change is the point of the migration: libFuzzer
# stopped at the first crash, so every trial was truncated at exactly the event
# being measured.
# --------------------------------------------------------------------------- #
def _afl_trial(tmp_path):
    trial = phase3_runner.Trial(
        project="demo", cve="CVE-0000-0001", variant="baseline",
        trial_id=0, seed=1337, cpu=2,
    )
    trial._docker_image = "bench-aflpp/demo-arvo-1"
    trial._bin_dir = str(tmp_path / "bin")
    trial._fuzz_target_name = "demo_fuzzer"
    trial._dirs = {
        "corpus": str(tmp_path / "corpus"),
        "crashes": str(tmp_path / "crashes"),
        "afl_out": str(tmp_path / "afl_out"),
        "base": str(tmp_path),
    }
    return trial


def _capture_launch(monkeypatch, trial, duration=321):
    captured = {}

    def fake_run(cmd, capture_output=True, text=False, timeout=None):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="container-id\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert phase3_runner._launch_container(trial, "exp", duration) is True
    return captured["cmd"]


def test_launch_runs_afl_fuzz_not_libfuzzer(monkeypatch, tmp_path):
    shell = _capture_launch(monkeypatch, _afl_trial(tmp_path))[-1]
    assert "afl-fuzz" in shell
    assert "-max_total_time" not in shell, "libFuzzer flag must be gone"
    assert "-artifact_prefix" not in shell


def test_launch_passes_duration_seed_and_memory_flags(monkeypatch, tmp_path):
    shell = _capture_launch(monkeypatch, _afl_trial(tmp_path), duration=321)[-1]
    assert "-V 321" in shell          # time-limited campaign
    assert "-s 1337" in shell         # deterministic RNG seed
    assert "-m none" in shell         # ASAN needs an unlimited memory cap
    assert "-t 1000 " in shell        # fixed 1 s per-exec timeout, no auto-scaling


def test_launch_target_comes_last_after_the_separator(monkeypatch, tmp_path):
    shell = _capture_launch(monkeypatch, _afl_trial(tmp_path))[-1]
    assert "-- /out/demo_fuzzer" in shell


def test_launch_disables_afl_cpu_affinity(monkeypatch, tmp_path):
    """The container is already pinned with --cpuset-cpus; AFL binding on top of
    that makes it fail to find a free core and abort."""
    cmd = _capture_launch(monkeypatch, _afl_trial(tmp_path))
    joined = " ".join(cmd)
    assert "AFL_NO_AFFINITY=1" in joined
    assert "--cpuset-cpus" in cmd


def test_launch_mounts_a_writable_afl_output_dir(monkeypatch, tmp_path):
    """/out is read-only, so AFL needs a separate writable output directory."""
    cmd = _capture_launch(monkeypatch, _afl_trial(tmp_path))
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    out_mounts = [m for m in mounts if m.endswith(":/out:ro")]
    afl_mounts = [m for m in mounts if m.endswith(":/afl_out")]
    assert out_mounts, "binary mount should stay read-only"
    assert afl_mounts, "AFL needs a writable output mount"


def test_launch_sets_asan_options_for_afl(monkeypatch, tmp_path):
    """AFL cannot see a crash unless the sanitizer aborts on error."""
    joined = " ".join(_capture_launch(monkeypatch, _afl_trial(tmp_path)))
    assert "abort_on_error=1" in joined
    # FuzzBench's fuzz-run set: dynamically linked libc++ otherwise turns every
    # caught C++ exception into an ASan abort. Leaks are NOT crashes (deviation).
    assert "alloc_dealloc_mismatch=0" in joined
    assert "detect_leaks=0" in joined and "detect_leaks=1" not in joined
    assert "UBSAN_OPTIONS=" in joined


# --------------------------------------------------------------------------- #
# Container names carry the experiment id. _launch_container starts with
# `docker rm -f <name>`; named by trial alone, a second campaign on the same
# project force-removed the first campaign's live trials.
# --------------------------------------------------------------------------- #
import json
import re

import pytest

from lib import swap_signal

_DOCKER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")


def test_container_name_includes_the_experiment_id():
    name = phase3_runner.trial_container_name(
        "online-24h-c1-libxml2-20261019-1430", "libxml2-arvo-1972-baseline-trial_00")
    assert name == ("bench_online-24h-c1-libxml2-20261019-1430_"
                    "libxml2-arvo-1972-baseline-trial_00")
    assert _DOCKER_NAME_RE.match(name)


def test_two_experiments_never_share_a_container_name():
    t = phase3_runner.Trial(project="demo", cve="CVE-0000-0001", variant="baseline",
                            trial_id=0, seed=1)
    a = phase3_runner.trial_container_name("smoke-demo-20261019-1430", t.name)
    b = phase3_runner.trial_container_name("online-24h-c1-demo-20261019-1430", t.name)
    assert a != b


def test_container_name_is_always_a_valid_docker_name():
    name = phase3_runner.trial_container_name("weird id/with:chars", "p-c-baseline-trial_01")
    assert _DOCKER_NAME_RE.match(name), name
    # Empty id = the legacy name (the recovery tool's fallback for old campaigns).
    assert phase3_runner.trial_container_name("", "p-c-baseline-trial_01") == \
        "bench_p-c-baseline-trial_01"


def test_launch_removes_and_names_only_this_experiments_container(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="cid\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    trial = _afl_trial(tmp_path)
    assert phase3_runner._launch_container(trial, "exp-A", 60) is True
    want = phase3_runner.trial_container_name("exp-A", trial.name)
    rm = [c for c in calls if c[:3] == ["docker", "rm", "-f"]]
    assert rm == [["docker", "rm", "-f", want]]
    run = [c for c in calls if c[:2] == ["docker", "run"]][0]
    assert run[run.index("--name") + 1] == want
    assert trial.container_name == want


# --------------------------------------------------------------------------- #
# A fresh campaign must never resume a previous campaign's AFL state. Every
# launch sets AFL_AUTORESUME=1 and start_trial never wiped afl_out, so a reused
# experiment id silently resumed the old queues.
# --------------------------------------------------------------------------- #
def _stale_trial(monkeypatch, tmp_path, marker="fuzzer_stats"):
    monkeypatch.setattr(phase3_runner.config, "RESULTS_DIR", str(tmp_path))
    trial = phase3_runner.Trial(project="demo", cve="CVE-0000-0001",
                                variant="baseline", trial_id=0, seed=1)
    afl_default = Path(phase3_runner.get_trial_dirs("exp", trial)["afl_out"]) / "default"
    afl_default.mkdir(parents=True)
    if marker == "queue":
        (afl_default / "queue").mkdir()
    else:
        (afl_default / marker).write_text("execs_done : 5\n")
    return trial, afl_default / marker


@pytest.mark.parametrize("marker", ["fuzzer_stats", "queue"])
def test_start_trial_refuses_existing_afl_state(monkeypatch, tmp_path, caplog, marker):
    trial, path = _stale_trial(monkeypatch, tmp_path, marker)
    launched = []
    monkeypatch.setattr(phase3_runner, "_launch_container",
                        lambda *a, **k: launched.append(a) or True)
    assert phase3_runner.start_trial(trial, "exp", duration=60) is False
    assert trial.status == "failed"
    assert launched == [], "must refuse before launching"
    assert str(path) in caplog.text, "the error must name the offending path"


def test_start_trial_on_a_clean_afl_out_is_not_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(phase3_runner.config, "RESULTS_DIR", str(tmp_path))
    trial = phase3_runner.Trial(project="demo", cve="CVE-0000-0001",
                                variant="baseline", trial_id=0, seed=1)
    # afl_out exists (a previous fuzzer.log copy, say) but holds no AFL instance.
    afl_out = Path(phase3_runner.get_trial_dirs("exp", trial)["afl_out"])
    afl_out.mkdir(parents=True)
    (afl_out / "fuzzer.log").write_text("x")
    assert phase3_runner.existing_afl_state("exp", trial) is None


def test_start_trial_resume_flag_lets_existing_state_through(monkeypatch, tmp_path):
    trial, _ = _stale_trial(monkeypatch, tmp_path)
    fuzzer = tmp_path / "demo_fuzzer"
    fuzzer.write_text("#!/bin/sh\n")
    monkeypatch.setattr(phase3_runner, "get_seed_corpus_dir", lambda e, t: str(tmp_path / "none"))
    monkeypatch.setattr(phase3_runner, "get_fuzzer_binary", lambda e, t: str(fuzzer))
    monkeypatch.setattr(phase3_runner, "_resolve_trial_image", lambda t: "img")
    monkeypatch.setattr(phase3_runner, "_launch_container", lambda *a, **k: True)
    assert phase3_runner.start_trial(trial, "exp", duration=60,
                                     allow_existing_afl_state=True) is True


def test_relaunch_within_a_run_still_resumes(monkeypatch, tmp_path):
    """The guard is for FRESH starts only: a relaunch must keep its queue."""
    trial, _ = _stale_trial(monkeypatch, tmp_path)
    fuzzer = tmp_path / "demo_fuzzer"
    fuzzer.write_text("#!/bin/sh\n")
    monkeypatch.setattr(phase3_runner, "get_fuzzer_binary", lambda e, t: str(fuzzer))
    trial._docker_image = "img"
    launched = []
    monkeypatch.setattr(phase3_runner, "_launch_container",
                        lambda t, e, d: launched.append(d) or True)
    assert phase3_runner.relaunch_preserving_corpus(trial, "exp", 123) is True
    assert launched == [123]


def test_fresh_slot_campaign_refuses_before_starting_any_trial(monkeypatch, tmp_path):
    _stale_trial(monkeypatch, tmp_path)
    monkeypatch.setattr(phase3_runner.config, "NUM_TRIALS", 2)
    started = []
    monkeypatch.setattr(phase3_runner, "start_trial",
                        lambda *a, **k: started.append(a) or False)
    with pytest.raises(RuntimeError, match="already hold AFL state"):
        phase3_runner.run_all_trials_slot(
            [{"project": "demo", "cve": "CVE-0000-0001"}], "exp", 60, 2)
    assert started == []


# --------------------------------------------------------------------------- #
# monitor_trial: early death relaunches (as the online arm does), a crash loop
# gives up, every death is recorded, and swap mirroring is per trial pair.
# --------------------------------------------------------------------------- #
class _Clock:
    def __init__(self, t=10_000.0):
        self.t = t
        self.hooks = []          # [(at, fn)] fired once the clock passes `at`

    def time(self):
        return self.t

    def sleep(self, s):
        self.t += s
        for hook in [h for h in self.hooks if h[0] <= self.t]:
            self.hooks.remove(hook)
            hook[1]()
        assert self.t < 10_000.0 + 100_000, "monitor never finished"


_AFL_CRASH_0 = "id:000000,sig:06,src:000000,time:1000,execs:5,op:havoc,rep:2"
_AFL_CRASH_1 = "id:000001,sig:11,src:000003,time:400000,execs:9,op:havoc,rep:4"


def _monitor(monkeypatch, tmp_path, lifetimes, *, duration=1000, trial_id=0,
             variant="baseline", relaunch_ok=True, on_relaunch=None, clock=None):
    """Run monitor_trial against fake containers. lifetimes[k] = seconds the
    k-th container stays up (None = until the budget runs out)."""
    monkeypatch.setattr(phase3_runner.config, "RESULTS_DIR", str(tmp_path))
    clock = clock or _Clock()
    monkeypatch.setattr(phase3_runner, "time", clock)
    trial = phase3_runner.Trial(project="demo", cve="CVE-0000-0001", variant=variant,
                                trial_id=trial_id, seed=1)
    start = clock.t
    trial.start_time = start
    trial.container_id = "c0"
    budget_end = start + duration + 1
    ends = {"c0": start + lifetimes[0] if lifetimes[0] is not None else budget_end}
    relaunches, removed = [], []

    def fake_relaunch(t, exp, remaining):
        relaunches.append({"at": clock.t, "remaining": remaining})
        if not relaunch_ok:
            return False
        k = len(relaunches)
        t.container_id = f"c{k}"
        t.start_time = clock.t
        life = lifetimes[k] if k < len(lifetimes) else None
        ends[t.container_id] = clock.t + life if life is not None else budget_end
        if on_relaunch:
            on_relaunch(k)
        return True

    du = phase3_runner.docker_util
    monkeypatch.setattr(du, "container_is_running", lambda cid: clock.t < ends[cid])
    monkeypatch.setattr(du, "inspect_container_state",
                        lambda cid: {"ExitCode": 137, "OOMKilled": True, "Error": "",
                                     "StartedAt": "s", "FinishedAt": "f"})
    monkeypatch.setattr(du, "get_container_duration_seconds", lambda cid: 42.0)
    monkeypatch.setattr(du, "write_container_logs", lambda cid, path: 0)
    monkeypatch.setattr(du, "remove_container", lambda cid: removed.append(cid))
    monkeypatch.setattr(phase3_runner, "_save_log_tail", lambda cid, dest, lines=200: dest)
    monkeypatch.setattr(phase3_runner, "relaunch_preserving_corpus", fake_relaunch)
    result = phase3_runner.monitor_trial(trial, "exp", duration)
    meta = json.loads(Path(phase3_runner.get_trial_dirs("exp", trial)["metadata"]).read_text())
    return result, meta, relaunches, removed


def test_baseline_relaunches_after_an_early_death(monkeypatch, tmp_path):
    crashes = None

    def archive_and_find_more(k):
        # What AFL does on resume: archive crashes/ and start a fresh one.
        crashes.rename(crashes.parent / "crashes.2026-10-19-00:00:00")
        crashes.mkdir()
        (crashes / _AFL_CRASH_1).write_bytes(b"y")

    monkeypatch.setattr(phase3_runner.config, "RESULTS_DIR", str(tmp_path))
    probe = phase3_runner.Trial(project="demo", cve="CVE-0000-0001",
                                variant="baseline", trial_id=0, seed=1)
    crashes = Path(phase3_runner.get_trial_dirs("exp", probe)["afl_out"]) / "default" / "crashes"
    crashes.mkdir(parents=True)
    (crashes / _AFL_CRASH_0).write_bytes(b"x")

    result, meta, relaunches, _ = _monitor(monkeypatch, tmp_path, [300, None],
                                           on_relaunch=archive_and_find_more)
    assert len(relaunches) == 1, "one death, one relaunch"
    assert 650 <= relaunches[0]["remaining"] <= 700, "relaunched with the REMAINING budget"
    [death] = meta["early_deaths"]
    assert death["action"] == "relaunched"
    assert death["exit_code"] == 137 and death["oom_killed"] is True
    assert 300 <= death["at_s"] <= 310
    assert meta["end_reason"] == "budget"
    assert meta["death_relaunches"] == 1
    # Crash scanning spans the relaunch, archived dir included.
    assert {c["artifact"] for c in result["crash_times"]} == {_AFL_CRASH_0, _AFL_CRASH_1}
    # duration covers the whole trial, not just the last container (42s).
    assert meta["duration_source"] == "wall_since_first_launch"
    assert meta["duration_s"] >= 1000


def test_trial_that_runs_its_budget_is_not_relaunched(monkeypatch, tmp_path):
    _, meta, relaunches, _ = _monitor(monkeypatch, tmp_path, [None])
    assert relaunches == []
    assert meta["early_deaths"] == [] and meta["end_reason"] == "budget"
    assert meta["duration_source"] == "container" and meta["duration_s"] == 42.0


def test_exit_inside_the_last_minute_is_the_budget_not_a_death(monkeypatch, tmp_path):
    _, meta, relaunches, _ = _monitor(monkeypatch, tmp_path, [975])
    assert relaunches == [] and meta["early_deaths"] == []


def test_crash_loop_gives_up_and_says_why(monkeypatch, tmp_path, caplog):
    _, meta, relaunches, _ = _monitor(monkeypatch, tmp_path, [5, 5, 5, 5, 5])
    assert len(relaunches) == 2, "three quick deaths in a row: relaunch twice, then stop"
    assert [d["action"] for d in meta["early_deaths"]] == \
        ["relaunched", "relaunched", "gave_up"]
    assert meta["end_reason"] == "crash_loop"
    assert "crash loop" in caplog.text


def test_a_long_lived_relaunch_resets_the_crash_loop_count(monkeypatch, tmp_path):
    _, meta, relaunches, _ = _monitor(monkeypatch, tmp_path, [5, 5, 200, 5, 5, None])
    assert len(relaunches) == 5
    assert meta["end_reason"] == "budget"
    assert all(d["action"] == "relaunched" for d in meta["early_deaths"])


def test_failed_relaunch_finalizes_short(monkeypatch, tmp_path):
    _, meta, relaunches, _ = _monitor(monkeypatch, tmp_path, [300], relaunch_ok=False)
    assert len(relaunches) == 1
    assert meta["end_reason"] == "relaunch_failed"
    assert meta["early_deaths"][0]["action"] == "relaunch_failed"


def _mirror(monkeypatch, swaps, *, trial_id=3):
    """Run a mirroring baseline monitor while `swaps` [(t_offset, trial_id|None)]
    are recorded; return how many restarts it made."""
    sig = swap_signal.SwapSignal()
    monkeypatch.setattr(phase3_runner.swap_signal, "SIGNAL", sig)
    monkeypatch.setattr(phase3_runner.config, "BASELINE_RESTART_MIRROR_SWAPS", True,
                        raising=False)
    clock = _Clock()
    for off, tid in swaps:
        clock.hooks.append((clock.t + off, (lambda tid=tid: sig.record_swap(1, 1, tid)
                                            if tid is not None
                                            else sig.record_swap(1, 10))))
    return clock


def test_baseline_mirrors_only_its_paired_optimized_trials_swaps(monkeypatch, tmp_path):
    clock = _mirror(monkeypatch, [(100, 7), (200, 3), (300, 1), (400, 3)])
    _, meta, relaunches, removed = _monitor(monkeypatch, tmp_path, [None, None, None],
                                            trial_id=3, clock=clock)
    assert len(relaunches) == 2, "trial 3 swapped twice; 7 and 1 are not its pair"
    assert meta["scheduled_restarts"] == 2 and meta["early_deaths"] == []


def test_legacy_shared_swap_still_restarts_every_baseline(monkeypatch, tmp_path):
    clock = _mirror(monkeypatch, [(100, None)])
    _, meta, relaunches, _ = _monitor(monkeypatch, tmp_path, [None, None],
                                      trial_id=5, clock=clock)
    assert len(relaunches) == 1
