import json
import sys
import threading
import time
import types
from pathlib import Path

import run_benchmark


def _write_setup_metadata(
    root: Path,
    experiment_id: str,
    entry: dict,
    *,
    baseline: bool,
    optimized: bool,
    optimization_applied: bool,
    failure: dict | None = None,
):
    exp_dir = root / experiment_id / f"{entry['project']}-{entry['cve']}"
    exp_dir.mkdir(parents=True, exist_ok=True)
    metadata = {
        "entry": entry,
        "verification": {
            "baseline": baseline,
            "optimized": optimized,
            "optimization_applied": optimization_applied,
        },
        "experiment_id": experiment_id,
    }
    if failure:
        metadata["failure"] = failure
    (exp_dir / "setup_metadata.json").write_text(json.dumps(metadata))


def test_mark_phase_completed_is_idempotent():
    state = {"phases_completed": [2, 4, 4]}

    run_benchmark.mark_phase_completed(state, 4)
    run_benchmark.mark_phase_completed(state, 3)

    assert state["phases_completed"] == [2, 4, 3]


def test_run_phase_setup_allows_single_cve_manifest(monkeypatch, tmp_path):
    manifest = [
        {"project": "demo", "cve": "CVE-0000-0001", "fuzz_target": "demo_fuzzer"},
    ]

    fake_phase2 = types.SimpleNamespace(
        load_manifest=lambda: manifest,
        save_manifest=lambda data: None,
        setup_cve=lambda entry, experiment_id: True,
        get_experiment_dir=lambda experiment_id, entry: str(
            tmp_path / experiment_id / f"{entry['project']}-{entry['cve']}"
        ),
    )

    monkeypatch.setitem(sys.modules, "phase2_setup", fake_phase2)
    monkeypatch.setattr(run_benchmark.config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(run_benchmark.config, "MIN_CVE_COUNT", 3)

    state = {
        "experiment_id": "single-cve",
        "phases_completed": [],
        "current_phase": None,
        "started_at": None,
        "updated_at": None,
        "errors": [],
    }

    ok = run_benchmark.run_phase_setup("single-cve", state)

    assert ok is True
    assert 2 in state["phases_completed"]


def test_run_phase_setup_uses_bounded_parallel_pool_and_profile_args(
    monkeypatch, tmp_path
):
    manifest = [
        {
            "project": f"demo{i}",
            "cve": f"CVE-0000-000{i}",
            "fuzz_target": "fuzzer",
            "local_id": 42000000 + i,
        }
        for i in range(3)
    ]
    lock = threading.Lock()
    active = 0
    max_active = 0
    seen = []

    def fake_setup_cve(
        entry, experiment_id, *,
        profile_cpu=None,
        baseline_profile_duration=None,
        refresh_profile_duration=None,
    ):
        nonlocal active, max_active
        with lock:
            active += 1
            max_active = max(max_active, active)
            seen.append(
                (
                    entry["project"],
                    experiment_id,
                    profile_cpu,
                    baseline_profile_duration,
                    refresh_profile_duration,
                )
            )
        time.sleep(0.05)
        with lock:
            active -= 1
        return True

    fake_phase2 = types.SimpleNamespace(
        load_manifest=lambda: manifest,
        save_manifest=lambda data: None,
        setup_cve=fake_setup_cve,
        get_experiment_dir=lambda experiment_id, entry: str(
            tmp_path / experiment_id / f"{entry['project']}-{entry['cve']}"
        ),
    )

    monkeypatch.setitem(sys.modules, "phase2_setup", fake_phase2)
    monkeypatch.setattr(run_benchmark.config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(run_benchmark.config, "MIN_CVE_COUNT", 3)
    monkeypatch.setattr(run_benchmark.config, "RESERVED_CORES", 4)
    monkeypatch.setattr(
        run_benchmark.config, "PHASE2_BASELINE_PROFILE_DURATION_SECS", 1200
    )
    monkeypatch.setattr(
        run_benchmark.config, "PHASE2_REFRESH_PROFILE_DURATION_SECS", 300
    )
    monkeypatch.setattr(run_benchmark.config, "PHASE2_MAX_PARALLEL", 2)

    state = {
        "experiment_id": "parallel-phase2",
        "phases_completed": [],
        "current_phase": None,
        "started_at": None,
        "updated_at": None,
        "errors": [],
    }

    ok = run_benchmark.run_phase_setup(
        "parallel-phase2",
        state,
        phase2_max_parallel=2,
        baseline_profile_duration=1200,
        refresh_profile_duration=300,
    )

    assert ok is True
    assert max_active == 2
    assert len(seen) == 3
    assert {item[2] for item in seen} <= {0, 1, 2, 3}
    assert all(item[3] == 1200 for item in seen)
    assert all(item[4] == 300 for item in seen)


def test_run_phase_setup_serializes_shared_arvo_local_ids(
    monkeypatch, tmp_path
):
    manifest = [
        {"project": "wolfmqtt", "cve": "CVE-1", "local_id": 42500940},
        {"project": "wolfmqtt", "cve": "CVE-2", "local_id": 42500940},
        {"project": "selinux", "cve": "CVE-3", "local_id": 42493388},
    ]
    lock = threading.Lock()
    active_by_local_id = {}
    saw_overlap = False

    def fake_setup_cve(
        entry, experiment_id, *,
        profile_cpu=None,
        baseline_profile_duration=None,
        refresh_profile_duration=None,
    ):
        nonlocal saw_overlap
        local_id = entry["local_id"]
        with lock:
            active_by_local_id[local_id] = active_by_local_id.get(local_id, 0) + 1
            if active_by_local_id[local_id] > 1:
                saw_overlap = True
        time.sleep(0.05)
        with lock:
            active_by_local_id[local_id] -= 1
        return True

    fake_phase2 = types.SimpleNamespace(
        load_manifest=lambda: manifest,
        save_manifest=lambda data: None,
        setup_cve=fake_setup_cve,
        get_experiment_dir=lambda experiment_id, entry: str(
            tmp_path / experiment_id / f"{entry['project']}-{entry['cve']}"
        ),
    )

    monkeypatch.setitem(sys.modules, "phase2_setup", fake_phase2)
    monkeypatch.setattr(run_benchmark.config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(run_benchmark.config, "MIN_CVE_COUNT", 3)
    monkeypatch.setattr(run_benchmark.config, "RESERVED_CORES", 4)

    state = {
        "experiment_id": "arvo-locks",
        "phases_completed": [],
        "current_phase": None,
        "started_at": None,
        "updated_at": None,
        "errors": [],
    }

    ok = run_benchmark.run_phase_setup(
        "arvo-locks", state, phase2_max_parallel=3
    )

    assert ok is True
    assert saw_overlap is False


def test_run_phase_setup_samples_distinct_projects_when_sampling(
    monkeypatch, tmp_path
):
    manifest = [
        {"project": "wolfmqtt", "cve": "CVE-1", "local_id": 42500940},
        {"project": "wolfmqtt", "cve": "CVE-2", "local_id": 42500941},
        {"project": "file", "cve": "CVE-3", "local_id": 42477517},
        {"project": "gpac", "cve": "CVE-4", "local_id": 42494318},
    ]
    attempted = []
    saved_manifests = []

    def fake_setup_cve(entry, experiment_id, **_kwargs):
        attempted.append(entry["project"])
        _write_setup_metadata(
            tmp_path,
            experiment_id,
            entry,
            baseline=True,
            optimized=True,
            optimization_applied=True,
        )
        return True

    fake_phase2 = types.SimpleNamespace(
        load_manifest=lambda: manifest,
        save_manifest=lambda data: saved_manifests.append(list(data)),
        setup_cve=fake_setup_cve,
        get_experiment_dir=lambda experiment_id, entry: str(
            tmp_path / experiment_id / f"{entry['project']}-{entry['cve']}"
        ),
    )

    monkeypatch.setitem(sys.modules, "phase2_setup", fake_phase2)
    monkeypatch.setattr(run_benchmark.config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(run_benchmark.config, "MIN_CVE_COUNT", 2)
    monkeypatch.setattr(run_benchmark.config, "RESERVED_CORES", 2)
    monkeypatch.setattr(
        run_benchmark.config,
        "ARVO_BASELINE_DENYLIST_PATH",
        str(tmp_path / "arvo_baseline_denylist.json"),
        raising=False,
    )

    state = {
        "experiment_id": "distinct-projects",
        "phases_completed": [],
        "current_phase": None,
        "started_at": None,
        "updated_at": None,
        "errors": [],
    }

    ok = run_benchmark.run_phase_setup(
        "distinct-projects",
        state,
        sample_cves=2,
        sample_seed=6,
        phase2_max_parallel=2,
    )

    assert ok is True
    assert len(attempted) == 2
    assert len(set(attempted)) == 2
    assert len(saved_manifests[-1]) == 2
    assert len({entry["project"] for entry in saved_manifests[-1]}) == 2


def test_run_phase_setup_refills_failed_baseline_build_and_updates_denylist(
    monkeypatch, tmp_path
):
    manifest = [
        {"project": "badproj", "cve": "CVE-1", "local_id": 42000001},
        {"project": "good1", "cve": "CVE-2", "local_id": 42000002},
        {"project": "good2", "cve": "CVE-3", "local_id": 42000003},
    ]
    attempted = []
    saved_manifests = []
    denylist_path = tmp_path / "arvo_baseline_denylist.json"

    def fake_setup_cve(entry, experiment_id, **_kwargs):
        attempted.append(entry["project"])
        if entry["project"] == "badproj":
            _write_setup_metadata(
                tmp_path,
                experiment_id,
                entry,
                baseline=False,
                optimized=False,
                optimization_applied=False,
                failure={
                    "stage": "baseline_build",
                    "reason": "ARVO build failed for CVE-1",
                },
            )
            return False

        _write_setup_metadata(
            tmp_path,
            experiment_id,
            entry,
            baseline=True,
            optimized=True,
            optimization_applied=True,
        )
        return True

    fake_phase2 = types.SimpleNamespace(
        load_manifest=lambda: manifest,
        save_manifest=lambda data: saved_manifests.append(list(data)),
        setup_cve=fake_setup_cve,
        get_experiment_dir=lambda experiment_id, entry: str(
            tmp_path / experiment_id / f"{entry['project']}-{entry['cve']}"
        ),
    )

    monkeypatch.setitem(sys.modules, "phase2_setup", fake_phase2)
    monkeypatch.setattr(run_benchmark.config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(run_benchmark.config, "MIN_CVE_COUNT", 2)
    monkeypatch.setattr(run_benchmark.config, "RESERVED_CORES", 2)
    monkeypatch.setattr(
        run_benchmark.config,
        "ARVO_BASELINE_DENYLIST_PATH",
        str(denylist_path),
        raising=False,
    )

    state = {
        "experiment_id": "refill-phase2",
        "phases_completed": [],
        "current_phase": None,
        "started_at": None,
        "updated_at": None,
        "errors": [],
    }

    ok = run_benchmark.run_phase_setup(
        "refill-phase2",
        state,
        sample_cves=2,
        sample_seed=1,
        phase2_max_parallel=2,
    )

    assert ok is True
    assert attempted == ["badproj", "good2", "good1"]
    assert denylist_path.exists()
    denylist = json.loads(denylist_path.read_text())
    assert {record["project"] for record in denylist} == {"badproj"}
    assert saved_manifests[-1] == [
        manifest[1],
        manifest[2],
    ]


def test_run_phase_setup_denylists_baseline_poc_verify_failures(
    monkeypatch, tmp_path
):
    manifest = [
        {"project": "nonrepro", "cve": "CVE-1", "local_id": 42000010},
        {"project": "good1", "cve": "CVE-2", "local_id": 42000011},
        {"project": "good2", "cve": "CVE-3", "local_id": 42000012},
    ]
    attempted = []
    saved_manifests = []
    denylist_path = tmp_path / "arvo_baseline_denylist.json"

    def fake_setup_cve(entry, experiment_id, **_kwargs):
        attempted.append(entry["project"])
        if entry["project"] == "nonrepro":
            _write_setup_metadata(
                tmp_path,
                experiment_id,
                entry,
                baseline=False,
                optimized=False,
                optimization_applied=False,
                failure={
                    "stage": "baseline_poc_verify",
                    "reason": "Baseline did not reproduce PoC for CVE-1",
                },
            )
            return False

        _write_setup_metadata(
            tmp_path,
            experiment_id,
            entry,
            baseline=True,
            optimized=True,
            optimization_applied=True,
        )
        return True

    fake_phase2 = types.SimpleNamespace(
        load_manifest=lambda: manifest,
        save_manifest=lambda data: saved_manifests.append(list(data)),
        setup_cve=fake_setup_cve,
        get_experiment_dir=lambda experiment_id, entry: str(
            tmp_path / experiment_id / f"{entry['project']}-{entry['cve']}"
        ),
    )

    monkeypatch.setitem(sys.modules, "phase2_setup", fake_phase2)
    monkeypatch.setattr(run_benchmark.config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(run_benchmark.config, "MIN_CVE_COUNT", 2)
    monkeypatch.setattr(run_benchmark.config, "RESERVED_CORES", 2)
    monkeypatch.setattr(
        run_benchmark.config,
        "ARVO_BASELINE_DENYLIST_PATH",
        str(denylist_path),
        raising=False,
    )

    state = {
        "experiment_id": "refill-poc",
        "phases_completed": [],
        "current_phase": None,
        "started_at": None,
        "updated_at": None,
        "errors": [],
    }

    ok = run_benchmark.run_phase_setup(
        "refill-poc",
        state,
        sample_cves=2,
        sample_seed=1,
        phase2_max_parallel=2,
    )

    assert ok is True
    assert "nonrepro" in attempted
    assert denylist_path.exists()
    denylist = json.loads(denylist_path.read_text())
    assert {record["project"] for record in denylist} == {"nonrepro"}
    assert denylist[0]["stage"] == "baseline_poc_verify"


def test_run_phase_setup_skips_persistently_denylisted_arvo_entries(
    monkeypatch, tmp_path
):
    manifest = [
        {"project": "badproj", "cve": "CVE-1", "local_id": 42000001},
        {"project": "good1", "cve": "CVE-2", "local_id": 42000002},
        {"project": "good2", "cve": "CVE-3", "local_id": 42000003},
    ]
    attempted = []
    saved_manifests = []
    denylist_path = tmp_path / "arvo_baseline_denylist.json"
    denylist_path.write_text(json.dumps([
        {
            "project": "badproj",
            "cve": "CVE-1",
            "local_id": 42000001,
            "stage": "baseline_build",
            "reason": "ARVO build failed for CVE-1",
        }
    ]))

    def fake_setup_cve(entry, experiment_id, **_kwargs):
        attempted.append(entry["project"])
        _write_setup_metadata(
            tmp_path,
            experiment_id,
            entry,
            baseline=True,
            optimized=True,
            optimization_applied=True,
        )
        return True

    fake_phase2 = types.SimpleNamespace(
        load_manifest=lambda: manifest,
        save_manifest=lambda data: saved_manifests.append(list(data)),
        setup_cve=fake_setup_cve,
        get_experiment_dir=lambda experiment_id, entry: str(
            tmp_path / experiment_id / f"{entry['project']}-{entry['cve']}"
        ),
    )

    monkeypatch.setitem(sys.modules, "phase2_setup", fake_phase2)
    monkeypatch.setattr(run_benchmark.config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(run_benchmark.config, "MIN_CVE_COUNT", 2)
    monkeypatch.setattr(run_benchmark.config, "RESERVED_CORES", 2)
    monkeypatch.setattr(
        run_benchmark.config,
        "ARVO_BASELINE_DENYLIST_PATH",
        str(denylist_path),
        raising=False,
    )

    state = {
        "experiment_id": "denylisted-phase2",
        "phases_completed": [],
        "current_phase": None,
        "started_at": None,
        "updated_at": None,
        "errors": [],
    }

    ok = run_benchmark.run_phase_setup(
        "denylisted-phase2",
        state,
        sample_cves=2,
        sample_seed=1,
        phase2_max_parallel=2,
    )

    assert ok is True
    assert attempted == ["good1", "good2"]
    assert saved_manifests[-1] == [manifest[1], manifest[2]]


def test_run_phase_setup_writes_failure_metadata_on_setup_exception(
    monkeypatch, tmp_path
):
    manifest = [
        {"project": "demo", "cve": "CVE-0000-0001", "fuzz_target": "demo_fuzzer"},
    ]

    def fake_setup_cve(entry, experiment_id, **_kwargs):
        raise RuntimeError("boom")

    fake_phase2 = types.SimpleNamespace(
        load_manifest=lambda: manifest,
        save_manifest=lambda data: None,
        setup_cve=fake_setup_cve,
        get_experiment_dir=lambda experiment_id, entry: str(
            tmp_path / experiment_id / f"{entry['project']}-{entry['cve']}"
        ),
    )

    monkeypatch.setitem(sys.modules, "phase2_setup", fake_phase2)
    monkeypatch.setattr(run_benchmark.config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(run_benchmark.config, "MIN_CVE_COUNT", 1)

    state = {
        "experiment_id": "failure-metadata",
        "phases_completed": [],
        "current_phase": None,
        "started_at": None,
        "updated_at": None,
        "errors": [],
    }

    ok = run_benchmark.run_phase_setup("failure-metadata", state)

    metadata_path = (
        tmp_path
        / "failure-metadata"
        / "demo-CVE-0000-0001"
        / "setup_metadata.json"
    )
    assert ok is False
    assert metadata_path.exists()
    metadata = __import__("json").loads(metadata_path.read_text())
    assert metadata["verification"]["baseline"] is False
    assert metadata["verification"]["optimized"] is False
    assert metadata["failure"]["stage"] == "setup_exception"
    assert "boom" in metadata["failure"]["reason"]


def test_prepare_experiment_dir_for_fresh_run_archives_existing_results(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(run_benchmark.config, "RESULTS_DIR", str(tmp_path))

    exp_dir = Path(tmp_path) / "codex-2"
    exp_dir.mkdir(parents=True)
    (exp_dir / "state.json").write_text('{"success": true}')
    (exp_dir / "artifact.txt").write_text("keep me")

    run_benchmark.prepare_experiment_dir_for_run(
        "codex-2",
        fresh_full_run=True,
    )

    archived_dirs = sorted(tmp_path.glob("codex-2.backup.*"))
    assert len(archived_dirs) == 1
    assert (archived_dirs[0] / "artifact.txt").read_text() == "keep me"
    assert not exp_dir.exists()


def test_run_phase_trials_dispatches_to_k8s(monkeypatch):
    import run_benchmark
    import config
    monkeypatch.delenv("PHASE3_BACKEND", raising=False)
    monkeypatch.setattr(config, "PHASE3_BACKEND", "k8s")
    assert run_benchmark._phase3_backend() == "k8s"
    monkeypatch.setattr(config, "PHASE3_BACKEND", "local")
    assert run_benchmark._phase3_backend() == "local"


def _online_phase3(monkeypatch, tmp_path, run_online):
    """run_phase_trials on the online path with run_online stubbed; returns
    (ok, state, results_path) for experiment "exp"."""
    import config
    import phase3_online
    import phase3_runner
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps([{"project": "mruby", "cve": "fb-mruby",
                                     "fuzz_target": "t"}]))
    monkeypatch.setattr(config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(config, "MANIFEST_PATH", str(manifest))
    monkeypatch.setattr(config, "ONLINE_ENABLED", True)
    monkeypatch.setenv("PHASE3_BACKEND", "local")
    monkeypatch.setattr(phase3_online, "run_online", run_online)
    monkeypatch.setattr(phase3_runner, "collect_all_trial_results",
                        lambda exp: [{"trial": "new"}])
    results = tmp_path / "exp" / "trial_results.json"
    results.parent.mkdir(parents=True)
    results.write_text('[{"trial": "old campaign"}]')
    state = {"phases_completed": [], "errors": []}
    ok = run_benchmark.run_phase_trials("exp", state, duration=60, max_parallel=1,
                                        project="mruby")
    return ok, state, results


def test_online_phase3_refusal_fails_the_phase(monkeypatch, tmp_path):
    """run_online's False (e.g. a reused experiment id) is a failure: the old
    campaign's trial_results.json survives, phase 3 is not marked complete, and
    main() exits non-zero on the False."""
    ok, state, results = _online_phase3(monkeypatch, tmp_path,
                                        lambda entry, exp, duration=None: False)
    assert ok is False
    assert 3 not in state["phases_completed"]
    assert json.loads(results.read_text()) == [{"trial": "old campaign"}]
    assert state["errors"] and state["errors"][-1]["phase"] == 3


def test_online_phase3_exception_fails_the_phase(monkeypatch, tmp_path):
    def boom(entry, exp, duration=None):
        raise RuntimeError("setup died")
    ok, state, results = _online_phase3(monkeypatch, tmp_path, boom)
    assert ok is False and 3 not in state["phases_completed"]
    assert json.loads(results.read_text()) == [{"trial": "old campaign"}]


def test_online_phase3_success_writes_results_and_completes(monkeypatch, tmp_path):
    ok, state, results = _online_phase3(monkeypatch, tmp_path,
                                        lambda entry, exp, duration=None: True)
    assert ok is True and 3 in state["phases_completed"]
    assert json.loads(results.read_text()) == [{"trial": "new"}]


# --------------------------------------------------------------------------- #
# --duration: phase 3 needs a run length (config default when not given);
# phase 4 must get it ONLY when given, else it overrides every trial's recorded
# length and cuts a 24h campaign at 6h.
# --------------------------------------------------------------------------- #

def _run_main(monkeypatch, tmp_path, argv, state=None):
    """main() with phases 3/4 stubbed; returns {phase: duration passed}."""
    import config
    monkeypatch.setattr(config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(config, "TRIAL_DURATION_SECS", 21600)
    monkeypatch.setattr(config, "ONLINE_ENABLED", False)
    monkeypatch.setenv("PHASE3_BACKEND", "local")
    if state is not None:
        (tmp_path / "exp").mkdir(parents=True, exist_ok=True)
        (tmp_path / "exp" / config.STATE_FILE).write_text(json.dumps(state))
    seen = {}

    def fake_trials(experiment_id, state, duration, max_parallel,
                    resume=False, project=None):
        seen[3] = duration
        return True

    def fake_analysis(experiment_id, state, duration=None, project=None):
        seen[4] = duration
        return True

    monkeypatch.setattr(run_benchmark, "run_phase_trials", fake_trials)
    monkeypatch.setattr(run_benchmark, "run_phase_analysis", fake_analysis)
    monkeypatch.setattr(sys, "argv",
                        ["run_benchmark.py", "--experiment-id", "exp", *argv])
    run_benchmark.main()
    return seen


def test_phase4_alone_gets_no_duration_override(monkeypatch, tmp_path):
    assert _run_main(monkeypatch, tmp_path, ["--phase", "4"]) == {4: None}


def test_skip_setup_keeps_phase3_default_and_phase4_uses_metadata(
    monkeypatch, tmp_path
):
    seen = _run_main(monkeypatch, tmp_path, ["--skip-setup"])
    assert seen == {3: 21600, 4: None}


def test_resume_into_phase4_gets_no_duration_override(monkeypatch, tmp_path):
    state = {"experiment_id": "exp", "phases_completed": [1, 2, 3],
             "current_phase": None, "started_at": "x", "errors": []}
    seen = _run_main(monkeypatch, tmp_path, ["--resume"], state=state)
    assert seen == {4: None}


def test_explicit_duration_reaches_both_phases(monkeypatch, tmp_path):
    seen = _run_main(monkeypatch, tmp_path,
                     ["--skip-setup", "--duration", "86400"])
    assert seen == {3: 86400, 4: 86400}


def test_online_pertrial_invocation_passes_duration_to_phase3(
    monkeypatch, tmp_path
):
    # What run_online_pertrial.sh runs: --online --phase 3 --duration $DURATION.
    seen = _run_main(monkeypatch, tmp_path, [
        "--online", "--phase", "3", "--project", "mruby",
        "--duration", "86400",
    ])
    assert seen == {3: 86400}


def test_phase3_without_duration_uses_config_default(monkeypatch, tmp_path):
    assert _run_main(monkeypatch, tmp_path, ["--phase", "3"]) == {3: 21600}


def test_non_positive_duration_is_rejected(monkeypatch, tmp_path):
    import pytest
    for bad in ("0", "-5"):
        with pytest.raises(SystemExit) as exc:
            _run_main(monkeypatch, tmp_path, ["--phase", "4", "--duration", bad])
        assert exc.value.code == 2


def test_phase4_on_24h_campaign_counts_late_finds(monkeypatch, tmp_path):
    """End to end: `run_benchmark.py --phase 4` on 24h trials cuts at 24h."""
    import config
    key = "demo-CVE-0000-0009"
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps([
        {"project": "demo", "cve": "CVE-0000-0009", "crash_type": "crash"},
    ]))
    monkeypatch.setattr(config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(config, "MANIFEST_PATH", str(manifest))
    monkeypatch.setattr(config, "TRIAL_DURATION_SECS", 21600)
    for variant, crash_ts in (("baseline", 36000.0), ("optimized", 600.0)):
        trial_dir = tmp_path / "exp" / key / variant / "trial_00"
        trial_dir.mkdir(parents=True)
        (trial_dir / "crash_times.json").write_text(json.dumps([{
            "timestamp_s": crash_ts, "artifact": "crash-" + "0" * 40,
            "crash_type": "crash",
        }]))
        (trial_dir / "metadata.json").write_text(json.dumps({
            "duration_s": 86400.5, "duration_seconds": 86400,
            "final_stats": {"total_execs": 100, "final_exec_s": 10},
        }))
    monkeypatch.setattr(sys, "argv",
                        ["run_benchmark.py", "--experiment-id", "exp",
                         "--phase", "4"])
    run_benchmark.main()

    results = json.loads(
        (tmp_path / "exp" / "report" / "results.json").read_text())
    assert results[0]["trial_duration"] == 86400
    assert results[0]["trial_duration_source"] == "trial metadata"
    assert results[0]["baseline_found_bug"] == 1
