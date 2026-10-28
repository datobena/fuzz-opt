from contextlib import contextmanager
from types import SimpleNamespace
import os
import threading
import time

import pytest

from lib import cpu_ledger, online_resources as R
from sandbox import broker


class Pause:
    deadline = time.time() + 3600

    def __init__(self):
        self.active = False
        self.calls = 0

    @contextmanager
    def paused(self, **kwargs):
        assert not self.active
        self.active = True
        self.calls += 1
        try:
            yield "trial"
        finally:
            self.active = False


def policy():
    trial = SimpleNamespace(cpu=min(os.sched_getaffinity(0)), pause_controller=Pause())
    return R.TrialResources(trial, deadline=trial.pause_controller.deadline)


def test_shared_operations_do_not_read_cost_clock_or_write_ledger(tmp_path, monkeypatch):
    p = policy()
    monkeypatch.setenv(cpu_ledger.LEDGER_ENV, str(tmp_path / "cost.jsonl"))
    def forbidden():
        raise AssertionError("CPU accounting clock was read")
    monkeypatch.setattr(cpu_ledger.time, "time", forbidden)
    with R.bind(p):
        for stage in ("rebuild", "broker_smoke", "profile_prebuild", "broker_replay", "replay_gate"):
            with cpu_ledger.timed(stage) as info:
                info["ok"] = True
                assert p.trial.pause_controller.active == (stage in R.EXCLUSIVE_STAGES)
            assert cpu_ledger.record(stage, wall_s=99, cores=1) is None
    assert not (tmp_path / "cost.jsonl").exists()


def test_profile_and_replay_quiesce_fuzzer_and_agent_and_resume_on_error(monkeypatch):
    p = policy()
    p.agent_container = "agent-one"
    events = []
    @contextmanager
    def agent(container, deadline):
        assert p.trial.pause_controller.active
        events.append(("pause", container))
        try:
            yield
        finally:
            events.append(("resume", container))
    monkeypatch.setattr(R, "freeze_agent", agent)
    with R.bind(p):
        with pytest.raises(ValueError):
            with cpu_ledger.timed("profile_prebuild"):
                with R.operation("baseline_profile"):
                    assert os.sched_getaffinity(0) == {p.cpu}
                    raise ValueError("profile failed")
    assert events == [("pause", "agent-one"), ("resume", "agent-one")]
    assert p.trial.pause_controller.calls == 1
    assert not p.trial.pause_controller.active


def test_broker_thread_receives_owning_trial_policy(monkeypatch):
    p = policy()
    ctx = broker.BrokerContext(image="img", source_dir="src", out_dir="out", corpus_dir="tune",
                              fuzz_target="target", project="p", cpu=p.cpu, resource_policy=p)
    seen = []
    def check(stage, result):
        def op(*args):
            assert R.current() is p
            assert os.sched_getaffinity(0) == {p.cpu}
            seen.append((stage, p.trial.pause_controller.active))
            return result
        return op
    monkeypatch.setattr(broker, "_run_build", check("build", (True, "built")))
    monkeypatch.setattr(broker, "_run_smoke", check("smoke", (True, "ok")))
    monkeypatch.setattr(broker, "_run_replay", check("replay", {"seconds": 1}))
    replies = []
    def worker():
        for op in ("build", "smoke", "replay_time"):
            replies.append(broker.handle_request({"op": op}, ctx))
        assert R.current() is None
    t = threading.Thread(target=worker)
    t.start(); t.join()
    assert all(r["ok"] for r in replies) and len(replies) == 3
    assert seen == [("build", False), ("smoke", False), ("replay", True)]


def test_round_host_affinity_matches_trial_and_is_restored(monkeypatch):
    import phase3_online as P
    p = policy()
    p.trial.resource_policy = p
    old = os.sched_getaffinity(0)
    ctx = SimpleNamespace(shared_cpu=True, profile_cpu=p.cpu, trial=p.trial)
    def run(*args):
        assert R.current() is p and os.sched_getaffinity(0) == {p.cpu}
        raise ValueError("failed round")
    monkeypatch.setattr(P, "_run_round", run)
    with pytest.raises(ValueError):
        P.run_round(ctx, None, 1)
    assert os.sched_getaffinity(0) == old and R.current() is None
    ctx.profile_cpu = p.cpu + 1
    with pytest.raises(RuntimeError, match="differs"):
        P.run_round(ctx, None, 1)


def test_shared_mode_does_not_require_a_spare_agent_core(tmp_path, monkeypatch):
    import phase3_online as P
    import config
    import sandbox.session as S
    monkeypatch.setattr(config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(config, "ONLINE_SHARED_TRIAL_CPU", True)
    monkeypatch.setattr(config, "ONLINE_PER_TRIAL_OPTIMIZER", True)
    monkeypatch.setattr(config, "PHASE2_SANDBOX", True)
    monkeypatch.setattr(R, "validate_trial_cpus", lambda trials: None)
    monkeypatch.setenv(cpu_ledger.LEDGER_ENV, "")
    monkeypatch.setattr(S, "resolve_agent_cpus", lambda: pytest.fail("used dedicated agent pool"))
    class SetupReached(Exception): pass
    monkeypatch.setattr(P, "_extract_online_target", lambda *a, **k: (_ for _ in ()).throw(SetupReached()))
    with pytest.raises(SetupReached):
        P.run_online({"project": "p", "cve": "c", "fuzz_target": "t"}, "shared-probe", 60)
    assert cpu_ledger.ledger_path() == ""


def test_physical_siblings_cannot_be_assigned_to_two_trials(monkeypatch):
    from lib import core_lock
    monkeypatch.setattr(core_lock, "thread_siblings", lambda: {0: {0, 2}, 2: {0, 2}})
    monkeypatch.setattr(R.os, "sched_getaffinity", lambda tid: {0, 1, 2, 3})
    with pytest.raises(RuntimeError, match="physical"):
        R.validate_trial_cpus([SimpleNamespace(cpu=0), SimpleNamespace(cpu=2)])


def test_phase2_pins_agent_and_broker_to_trial_cpu(monkeypatch):
    import phase2_setup as P
    import sandbox.session as S
    p = policy()
    seen = []
    monkeypatch.setattr(S, "resolve_agent_cpus", lambda: pytest.fail("dedicated pool was used"))
    monkeypatch.setattr(S, "run_sandboxed_optimizer", lambda **kwargs: seen.append(kwargs) or {"ok": True})
    env = {"FUZZ_SOURCE_FOLDS_OUT_DIR": "/out", "FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR": "/tune",
           "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR": "/profile", "PHASE2_PREWORK_IMAGE": "image",
           "FUZZ_TARGET": "target", "FUZZ_SOURCE_FOLDS_PROFILE_CPU": str(p.cpu)}
    with R.bind(p):
        assert P._invoke_agent_sandboxed("src", "prompt", timeout=10, project="p", extra_env=env)["ok"]
        assert P._agent_cpus_provenance() == str(p.cpu)
    assert seen[0]["cpu"] == p.cpu and seen[0]["agent_cpus"] == str(p.cpu)


def test_session_rejects_agent_or_broker_on_another_cpu(monkeypatch):
    import sandbox.session as S
    p = policy()
    monkeypatch.setattr(S, "assert_sandbox_available", lambda: None)
    with R.bind(p):
        with pytest.raises(RuntimeError, match="owning trial CPU"):
            S.run_sandboxed_optimizer(source_dir="src", profile_dir="profile", out_dir="out",
                corpus_dir="tune", image="image", fuzz_target="target", project="p", prompt="prompt",
                cpu=p.cpu + 1)
