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
