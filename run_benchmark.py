#!/usr/bin/env python3
"""Master orchestrator for the fold-deterministic-calls fuzzing benchmark.

Single entry point that runs all phases sequentially with state tracking,
progress monitoring, and resume support.

Usage:
    python run_benchmark.py --experiment-id eval_v1 --duration 21600
    python run_benchmark.py --resume --experiment-id eval_v1
    python run_benchmark.py --experiment-id eval_v1 --skip-setup --duration 21600
    python run_benchmark.py --experiment-id eval_v1 --phase 3
"""

import argparse
import inspect
import json
import logging
import os
import queue
import shutil
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


def _get_arvo_baseline_denylist_path() -> str:
    return str(
        getattr(
            config,
            "ARVO_BASELINE_DENYLIST_PATH",
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "arvo_baseline_denylist.json",
            ),
        )
    )


def _load_arvo_baseline_denylist() -> list[dict]:
    path = _get_arvo_baseline_denylist_path()
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception as e:
        logger.warning("Failed to read ARVO denylist %s: %s", path, e)
        return []


def _save_arvo_baseline_denylist(records: list[dict]):
    path = _get_arvo_baseline_denylist_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(records, f, indent=2)


def _is_denylisted_arvo_entry(entry: dict, records: list[dict]) -> bool:
    if "local_id" not in entry:
        return False
    entry_local_id = entry.get("local_id")
    entry_cve = entry.get("cve")
    for record in records:
        if record.get("local_id") == entry_local_id:
            return True
        if record.get("cve") == entry_cve:
            return True
    return False


def _filter_denylisted_arvo_entries(entries: list[dict]) -> tuple[list[dict], int]:
    records = _load_arvo_baseline_denylist()
    filtered = []
    skipped = 0
    for entry in entries:
        if _is_denylisted_arvo_entry(entry, records):
            skipped += 1
            continue
        filtered.append(entry)
    return filtered, skipped


_ARVO_DENYLIST_STAGES = {"baseline_build", "baseline_poc_verify"}


def _record_arvo_baseline_failure(entry: dict, metadata_path: str):
    if "local_id" not in entry or not os.path.exists(metadata_path):
        return
    try:
        with open(metadata_path) as f:
            metadata = json.load(f)
    except Exception as e:
        logger.warning(
            "Failed to inspect setup metadata for denylist update (%s): %s",
            metadata_path,
            e,
        )
        return

    failure = metadata.get("failure", {})
    stage = failure.get("stage")
    if stage not in _ARVO_DENYLIST_STAGES:
        return

    records = _load_arvo_baseline_denylist()
    if _is_denylisted_arvo_entry(entry, records):
        return

    records.append({
        "project": entry.get("project"),
        "cve": entry.get("cve"),
        "local_id": entry.get("local_id"),
        "stage": stage,
        "reason": failure.get("reason"),
        "timestamp": datetime.now().isoformat(),
    })
    _save_arvo_baseline_denylist(records)
    logger.warning(
        "Added ARVO baseline failure (%s) to denylist: %s / %s (local_id=%s)",
        stage,
        entry.get("project"),
        entry.get("cve"),
        entry.get("local_id"),
    )


def _sample_distinct_project_entries(
    entries: list[dict],
    sample_count: int,
    sample_seed: int | None,
) -> list[dict]:
    import random

    project_to_entries: dict[str, list[dict]] = {}
    for entry in entries:
        project_to_entries.setdefault(entry["project"], []).append(entry)

    if not project_to_entries:
        return []

    rng = random.Random(sample_seed)
    project_names = list(project_to_entries.keys())
    project_order = rng.sample(project_names, len(project_names))

    candidates = []
    for project_name in project_order:
        candidates.append(rng.choice(project_to_entries[project_name]))

    return candidates[: min(sample_count, len(candidates))]


def get_experiment_dir(experiment_id: str) -> str:
    """Get path to the experiment directory."""
    return os.path.join(config.RESULTS_DIR, experiment_id)


def prepare_experiment_dir_for_run(
    experiment_id: str,
    *,
    fresh_full_run: bool,
) -> str:
    """Prepare the experiment directory for a run.

    Fresh full runs archive any previous results tree to avoid mixing old and
    new artifacts under the same experiment id.
    """
    exp_dir = get_experiment_dir(experiment_id)
    if not fresh_full_run or not os.path.isdir(exp_dir):
        return exp_dir

    if not any(os.scandir(exp_dir)):
        return exp_dir

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = f"{exp_dir}.backup.{timestamp}"
    suffix = 1
    while os.path.exists(backup_dir):
        backup_dir = f"{exp_dir}.backup.{timestamp}_{suffix}"
        suffix += 1

    logger.warning(
        "Fresh run requested for existing experiment '%s'; archiving %s to %s",
        experiment_id,
        exp_dir,
        backup_dir,
    )
    shutil.move(exp_dir, backup_dir)
    return exp_dir


def get_state_path(experiment_id: str) -> str:
    """Get path to the state file for an experiment."""
    exp_dir = get_experiment_dir(experiment_id)
    os.makedirs(exp_dir, exist_ok=True)
    return os.path.join(exp_dir, config.STATE_FILE)


def load_state(experiment_id: str) -> dict:
    """Load experiment state from disk."""
    state_path = get_state_path(experiment_id)
    if os.path.exists(state_path):
        with open(state_path) as f:
            return json.load(f)
    return {
        "experiment_id": experiment_id,
        "phases_completed": [],
        "current_phase": None,
        "started_at": None,
        "updated_at": None,
        "errors": [],
    }


def save_state(state: dict, experiment_id: str):
    """Save experiment state to disk."""
    state["updated_at"] = datetime.now().isoformat()
    state_path = get_state_path(experiment_id)
    with open(state_path, "w") as f:
        json.dump(state, f, indent=2)


def mark_phase_completed(state: dict, phase: int):
    """Record completed phases once, preserving first-seen order."""
    completed = list(dict.fromkeys(state.get("phases_completed", [])))
    if phase not in completed:
        completed.append(phase)
    state["phases_completed"] = completed


def _write_setup_failure_metadata(
    *,
    phase2_module,
    experiment_id: str,
    entry: dict,
    stage: str,
    reason: str,
):
    """Persist a minimal setup metadata file for early phase-2 failures."""
    exp_dir = phase2_module.get_experiment_dir(experiment_id, entry)
    os.makedirs(exp_dir, exist_ok=True)
    metadata_path = os.path.join(exp_dir, "setup_metadata.json")
    if os.path.exists(metadata_path):
        return
    metadata = {
        "entry": entry,
        "verification": {
            "baseline": False,
            "optimized": False,
            "optimization_applied": False,
        },
        "failure": {
            "stage": stage,
            "reason": reason,
        },
        "experiment_id": experiment_id,
        "setup_timestamp": datetime.now().isoformat(),
    }
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)


def _phase2_resource_key(entry: dict) -> str:
    """Return the shared resource key that must not run concurrently."""
    if "local_id" in entry:
        return f"arvo:{entry['local_id']}"
    return f"osv:{entry['project']}"


def run_phase_manifest(experiment_id: str, state: dict) -> bool:
    """Phase 1: Generate ARVO manifest."""
    logger.info("=== Phase 1: Generate ARVO Manifest ===")
    state["current_phase"] = 1
    save_state(state, experiment_id)

    try:
        from generate_arvo_manifest import generate_manifest, parse_cves_file

        cves_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cves.txt")
        if not os.path.exists(cves_path):
            logger.error("cves.txt not found at %s", cves_path)
            return False

        entries = parse_cves_file(cves_path)
        logger.info("Parsed %d unique CVEs from %s", len(entries), cves_path)

        success = generate_manifest(config.MANIFEST_PATH, entries)
        if success:
            mark_phase_completed(state, 1)
            save_state(state, experiment_id)
        return success
    except Exception as e:
        logger.error("Phase 1 failed: %s", e)
        state["errors"].append({
            "phase": 1, "error": str(e),
            "timestamp": datetime.now().isoformat(),
        })
        save_state(state, experiment_id)
        return False


def run_phase_setup(
    experiment_id: str, state: dict, project: str = None,
    sample_cves: int = None, sample_seed: int = None,
    phase2_max_parallel: int | None = None,
    baseline_profile_duration: int | None = None,
    refresh_profile_duration: int | None = None,
) -> bool:
    """Phase 2: Build baseline and optimized fuzzers."""
    logger.info("=== Phase 2: Environment Setup ===")
    state["current_phase"] = 2
    save_state(state, experiment_id)

    try:
        from phase2_setup import load_manifest, save_manifest, setup_cve, get_experiment_dir

        manifest = load_manifest()
        logger.info("Loaded manifest with %d entries", len(manifest))

        manifest, denylisted = _filter_denylisted_arvo_entries(manifest)
        if denylisted:
            logger.info(
                "Filtered %d ARVO entries from baseline-build denylist",
                denylisted,
            )

        filtered_entries = [
            entry for entry in manifest
            if not project or entry["project"] == project
        ]
        if not filtered_entries:
            logger.error("No manifest entries selected for phase 2")
            state["errors"].append({
                "phase": 2, "error": "No manifest entries selected",
                "timestamp": datetime.now().isoformat(),
            })
            save_state(state, experiment_id)
            return False

        if phase2_max_parallel is None:
            phase2_max_parallel = int(
                getattr(config, "PHASE2_MAX_PARALLEL", 4)
            )
        if baseline_profile_duration is None:
            baseline_profile_duration = int(
                getattr(config, "PHASE2_BASELINE_PROFILE_DURATION_SECS", 1200)
            )
        if refresh_profile_duration is None:
            refresh_profile_duration = int(
                getattr(config, "PHASE2_REFRESH_PROFILE_DURATION_SECS", 300)
            )

        target_entries = filtered_entries
        sample_distinct_projects = bool(sample_cves)
        required_successes = min(config.MIN_CVE_COUNT, len(target_entries))
        manifest_to_save = manifest

        reserved_cores = max(int(getattr(config, "RESERVED_CORES", 1)), 1)
        profile_cpu_pool: queue.Queue[int] = queue.Queue()
        for cpu in range(reserved_cores):
            profile_cpu_pool.put(cpu)
        resource_locks: dict[str, threading.Lock] = {}
        resource_locks_guard = threading.Lock()

        results = []
        pending_entries = []
        for entry in target_entries:
            # Skip only if both baseline and optimized built successfully
            exp_dir = get_experiment_dir(experiment_id, entry)
            metadata_path = os.path.join(exp_dir, "setup_metadata.json")
            if os.path.exists(metadata_path):
                with open(metadata_path) as mf:
                    meta = json.load(mf)
                verification = meta.get("verification", {})
                if verification.get("baseline") and verification.get("optimized"):
                    logger.info("Skipping %s (already complete)", entry["project"])
                    results.append(True)
                    continue
                logger.info("Retrying %s (previous build: baseline=%s, optimized=%s)",
                            entry["project"],
                            verification.get("baseline"),
                            verification.get("optimized"))
            pending_entries.append(entry)

        def _setup_entry(entry: dict) -> bool:
            profile_cpu = profile_cpu_pool.get()
            try:
                resource_key = _phase2_resource_key(entry)
                with resource_locks_guard:
                    resource_lock = resource_locks.setdefault(
                        resource_key, threading.Lock()
                    )
                setup_sig = inspect.signature(setup_cve)
                setup_kwargs = {}
                if "profile_cpu" in setup_sig.parameters:
                    setup_kwargs["profile_cpu"] = profile_cpu
                if "baseline_profile_duration" in setup_sig.parameters:
                    setup_kwargs["baseline_profile_duration"] = (
                        baseline_profile_duration
                    )
                if "refresh_profile_duration" in setup_sig.parameters:
                    setup_kwargs["refresh_profile_duration"] = (
                        refresh_profile_duration
                    )
                with resource_lock:
                    return setup_cve(entry, experiment_id, **setup_kwargs)
            finally:
                profile_cpu_pool.put(profile_cpu)

        def _run_setup_batch(entries: list[dict]) -> list[tuple[dict, bool]]:
            outcomes: list[tuple[dict, bool]] = []
            if not entries:
                return outcomes

            max_workers = max(1, min(int(phase2_max_parallel), len(entries)))
            logger.info(
                "Phase 2 worker pool: %d projects in parallel, %d reserved profile CPUs, baseline_profile=%ss, refresh_profile=%ss",
                max_workers,
                reserved_cores,
                baseline_profile_duration,
                refresh_profile_duration,
            )
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(_setup_entry, entry): entry
                    for entry in entries
                }
                for future in as_completed(futures):
                    entry = futures[future]
                    try:
                        success = future.result()
                    except Exception as e:
                        logger.error(
                            "Phase 2 setup crashed for %s / %s: %s",
                            entry["project"], entry["cve"], e,
                        )
                        _write_setup_failure_metadata(
                            phase2_module=sys.modules["phase2_setup"],
                            experiment_id=experiment_id,
                            entry=entry,
                            stage="setup_exception",
                            reason=str(e),
                        )
                        success = False
                    if not success:
                        _write_setup_failure_metadata(
                            phase2_module=sys.modules["phase2_setup"],
                            experiment_id=experiment_id,
                            entry=entry,
                            stage="setup_failed",
                            reason="setup_cve returned False before writing metadata",
                        )
                    metadata_path = os.path.join(
                        get_experiment_dir(experiment_id, entry),
                        "setup_metadata.json",
                    )
                    _record_arvo_baseline_failure(entry, metadata_path)
                    outcomes.append((entry, success))
            return outcomes

        if sample_distinct_projects:
            distinct_project_count = len({e["project"] for e in filtered_entries})
            candidate_entries = _sample_distinct_project_entries(
                filtered_entries,
                distinct_project_count,
                sample_seed,
            )
            target_entries = candidate_entries
            required_successes = int(sample_cves)
            logger.info(
                "Sampled up to %d distinct projects (seed=%s): %s",
                sample_cves,
                sample_seed,
                [e["project"] for e in candidate_entries[:sample_cves]],
            )

            entry_order = {
                (entry["project"], entry["cve"]): idx
                for idx, entry in enumerate(filtered_entries)
            }
            successful_entries: list[dict] = []
            pending_candidates: list[dict] = []
            for entry in candidate_entries:
                exp_dir = get_experiment_dir(experiment_id, entry)
                metadata_path = os.path.join(exp_dir, "setup_metadata.json")
                if os.path.exists(metadata_path):
                    with open(metadata_path) as mf:
                        meta = json.load(mf)
                    verification = meta.get("verification", {})
                    if verification.get("baseline") and verification.get("optimized"):
                        logger.info(
                            "Skipping %s (already complete)",
                            entry["project"],
                        )
                        successful_entries.append(entry)
                        continue
                    logger.info(
                        "Retrying %s (previous build: baseline=%s, optimized=%s)",
                        entry["project"],
                        verification.get("baseline"),
                        verification.get("optimized"),
                    )
                pending_candidates.append(entry)

            results = [True] * len(successful_entries)
            next_candidate_idx = 0
            while (
                len(successful_entries) < required_successes
                and next_candidate_idx < len(pending_candidates)
            ):
                needed = required_successes - len(successful_entries)
                batch = pending_candidates[
                    next_candidate_idx: next_candidate_idx + needed
                ]
                next_candidate_idx += len(batch)
                for entry, success in _run_setup_batch(batch):
                    results.append(success)
                    if success:
                        successful_entries.append(entry)

            successful_entries = sorted(
                {
                    (entry["project"], entry["cve"]): entry
                    for entry in successful_entries
                }.values(),
                key=lambda entry: entry_order[(entry["project"], entry["cve"])],
            )
            manifest_to_save = successful_entries
            passed = len(successful_entries)
            total_considered = required_successes
        else:
            pending_entries = []
            results = []
            for entry in target_entries:
                # Skip only if both baseline and optimized built successfully
                exp_dir = get_experiment_dir(experiment_id, entry)
                metadata_path = os.path.join(exp_dir, "setup_metadata.json")
                if os.path.exists(metadata_path):
                    with open(metadata_path) as mf:
                        meta = json.load(mf)
                    verification = meta.get("verification", {})
                    if verification.get("baseline") and verification.get("optimized"):
                        logger.info("Skipping %s (already complete)", entry["project"])
                        results.append(True)
                        continue
                    logger.info("Retrying %s (previous build: baseline=%s, optimized=%s)",
                                entry["project"],
                                verification.get("baseline"),
                                verification.get("optimized"))
                pending_entries.append(entry)

            if pending_entries:
                results.extend(
                    success for _, success in _run_setup_batch(pending_entries)
                )

            passed = sum(1 for r in results if r)
            total_considered = len(results)

        # Save updated manifest
        save_manifest(manifest_to_save)

        logger.info(
            "Phase 2: %d/%d projects set up successfully",
            passed,
            total_considered,
        )

        if passed >= required_successes:
            mark_phase_completed(state, 2)
            save_state(state, experiment_id)
            return True

        logger.error("Insufficient projects built (%d < %d)",
                     passed, required_successes)
        state["errors"].append({
            "phase": 2,
            "error": f"Only {passed}/{total_considered} succeeded",
            "timestamp": datetime.now().isoformat(),
        })
        save_state(state, experiment_id)
        return False

    except Exception as e:
        logger.error("Phase 2 failed: %s", e)
        state["errors"].append({
            "phase": 2, "error": str(e),
            "timestamp": datetime.now().isoformat(),
        })
        save_state(state, experiment_id)
        return False


def run_phase_trials(
    experiment_id: str, state: dict,
    duration: int, max_parallel: int,
    resume: bool = False, project: str = None,
) -> bool:
    """Phase 3: Run fuzzing trials."""
    logger.info("=== Phase 3: Fuzzing Trials ===")
    state["current_phase"] = 3
    save_state(state, experiment_id)

    try:
        from phase3_runner import run_all_trials_slot, collect_all_trial_results

        with open(config.MANIFEST_PATH) as f:
            manifest = json.load(f)

        if project:
            manifest = [e for e in manifest if e["project"] == project]

        # Filter to only projects that were successfully set up
        setup_manifest = []
        for entry in manifest:
            cve_dir = f"{entry['project']}-{entry['cve']}"
            metadata_path = os.path.join(
                config.RESULTS_DIR, experiment_id, cve_dir,
                "setup_metadata.json",
            )
            if os.path.exists(metadata_path):
                with open(metadata_path) as mf:
                    meta = json.load(mf)
                verification = meta.get("verification", {})
                if verification.get("baseline") and verification.get("optimized"):
                    setup_manifest.append(entry)
                else:
                    logger.warning(
                        "Skipping %s (build failed: baseline=%s, optimized=%s)",
                        entry["project"],
                        verification.get("baseline"),
                        verification.get("optimized"),
                    )
            else:
                logger.warning(
                    "Skipping %s (no setup_metadata.json)", entry["project"]
                )

        if not setup_manifest:
            logger.error("No projects ready for trials")
            return False

        logger.info(
            "Running trials for %d projects, duration=%ds, max_parallel=%d",
            len(setup_manifest), duration, max_parallel,
        )

        results = run_all_trials_slot(
            setup_manifest, experiment_id, duration, max_parallel,
            resume=resume,
        )

        # Rebuild full results from disk for accuracy
        all_results = collect_all_trial_results(experiment_id)

        results_path = os.path.join(
            config.RESULTS_DIR, experiment_id, "trial_results.json"
        )
        with open(results_path, "w") as f:
            json.dump(all_results, f, indent=2)

        total = len(all_results)
        with_crashes = sum(1 for r in all_results if r.get("crash_times"))
        logger.info(
            "Phase 3 complete: %d trials, %d with crashes", total, with_crashes
        )

        mark_phase_completed(state, 3)
        state["trial_summary"] = {
            "total": total,
            "with_crashes": with_crashes,
        }
        save_state(state, experiment_id)
        return True

    except Exception as e:
        logger.error("Phase 3 failed: %s", e)
        state["errors"].append({
            "phase": 3, "error": str(e),
            "timestamp": datetime.now().isoformat(),
        })
        save_state(state, experiment_id)
        return False


def run_phase_analysis(
    experiment_id: str, state: dict,
    duration: int, project: str = None,
) -> bool:
    """Phase 4: Statistical analysis and report generation."""
    logger.info("=== Phase 4: Analysis ===")
    state["current_phase"] = 4
    save_state(state, experiment_id)

    try:
        from phase4_analysis import load_trial_data, analyze_cve, generate_report

        with open(config.MANIFEST_PATH) as f:
            manifest = json.load(f)

        if project:
            manifest = [e for e in manifest if e["project"] == project]

        report_dir = os.path.join(
            config.RESULTS_DIR, experiment_id, "report"
        )

        logger.info("Loading trial data...")
        all_data = load_trial_data(experiment_id, manifest, duration=duration)

        results = []
        for key, data in all_data.items():
            logger.info("Analyzing %s...", key)
            result = analyze_cve(key, data, report_dir, duration=duration)
            if result:
                results.append(result)

        if not results:
            logger.error("No results to analyze")
            return False

        generate_report(results, report_dir, experiment_id)

        logger.info("Phase 4 complete: analyzed %d CVEs", len(results))
        logger.info("Report: %s/report.md", report_dir)

        mark_phase_completed(state, 4)
        state["report_dir"] = report_dir
        save_state(state, experiment_id)
        return True

    except Exception as e:
        logger.error("Phase 4 failed: %s", e)
        state["errors"].append({
            "phase": 4, "error": str(e),
            "timestamp": datetime.now().isoformat(),
        })
        save_state(state, experiment_id)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Master orchestrator for fold-deterministic-calls benchmark",
    )
    parser.add_argument(
        "--experiment-id", required=True,
        help="Experiment identifier",
    )
    parser.add_argument(
        "--duration", type=int, default=config.TRIAL_DURATION_SECS,
        help=f"Trial duration in seconds (default: {config.TRIAL_DURATION_SECS})",
    )
    parser.add_argument(
        "--max-parallel", type=int, default=config.USABLE_CORES,
        help=f"Max parallel trials (default: {config.USABLE_CORES})",
    )
    parser.add_argument(
        "--phase2-max-parallel", type=int,
        default=config.PHASE2_MAX_PARALLEL,
        help=(
            f"Max parallel phase-2 setup workers "
            f"(default: {config.PHASE2_MAX_PARALLEL})"
        ),
    )
    parser.add_argument(
        "--phase2-baseline-profile-duration",
        type=int,
        default=config.PHASE2_BASELINE_PROFILE_DURATION_SECS,
        help=(
            "Phase-2 initial real-fuzzer baseline profile duration in seconds "
            f"(default: {config.PHASE2_BASELINE_PROFILE_DURATION_SECS})"
        ),
    )
    parser.add_argument(
        "--phase2-refresh-profile-duration",
        type=int,
        default=config.PHASE2_REFRESH_PROFILE_DURATION_SECS,
        help=(
            "Phase-2 refresh real-fuzzer profile duration in seconds "
            f"(default: {config.PHASE2_REFRESH_PROFILE_DURATION_SECS})"
        ),
    )
    parser.add_argument(
        "--skip-setup", action="store_true",
        help="Skip phases 1-2 (reuse existing builds)",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Resume from previous run",
    )
    parser.add_argument(
        "--phase", type=int, choices=[1, 2, 3, 4], default=None,
        help="Run a specific phase only",
    )
    parser.add_argument(
        "--project", default=None,
        help="Only process a specific project",
    )
    parser.add_argument(
        "--sample-cves", type=int, default=None,
        help="Randomly sample N CVEs from the manifest",
    )
    parser.add_argument(
        "--sample-seed", type=int, default=None,
        help="Random seed for --sample-cves (default: random)",
    )
    args = parser.parse_args()

    experiment_id = args.experiment_id
    prepare_experiment_dir_for_run(
        experiment_id,
        fresh_full_run=(
            not args.resume
            and not args.skip_setup
            and args.phase is None
        ),
    )
    state = load_state(experiment_id)

    if state["started_at"] is None:
        state["started_at"] = datetime.now().isoformat()

    logger.info("Experiment: %s", experiment_id)
    logger.info("Duration: %ds (%.1fh)", args.duration, args.duration / 3600)
    logger.info("Max parallel: %d", args.max_parallel)
    logger.info(
        "Phase 2 max parallel: %d (baseline profile=%ss, refresh profile=%ss)",
        args.phase2_max_parallel,
        args.phase2_baseline_profile_duration,
        args.phase2_refresh_profile_duration,
    )

    if args.resume:
        logger.info("Resuming from state: phases_completed=%s",
                     state["phases_completed"])

    # Determine which phases to run
    if args.phase:
        phases = [args.phase]
    elif args.skip_setup:
        phases = [3, 4]
    elif args.resume:
        # Resume from last incomplete phase
        all_phases = [1, 2, 3, 4]
        phases = [p for p in all_phases if p not in state["phases_completed"]]
    else:
        phases = [1, 2, 3, 4]

    logger.info("Phases to run: %s", phases)
    save_state(state, experiment_id)

    overall_success = True

    for phase in phases:
        if phase == 1:
            if not run_phase_manifest(experiment_id, state):
                logger.error("Phase 1 failed, continuing with existing manifest")
                # Don't abort — manifest.json may already exist
                if not os.path.exists(config.MANIFEST_PATH):
                    overall_success = False
                    break

        elif phase == 2:
            if not run_phase_setup(experiment_id, state, project=args.project,
                                  sample_cves=args.sample_cves,
                                  sample_seed=args.sample_seed,
                                  phase2_max_parallel=args.phase2_max_parallel,
                                  baseline_profile_duration=(
                                      args.phase2_baseline_profile_duration
                                  ),
                                  refresh_profile_duration=(
                                      args.phase2_refresh_profile_duration
                                  )):
                logger.error("Phase 2 failed")
                overall_success = False
                break

        elif phase == 3:
            if not run_phase_trials(
                experiment_id, state,
                duration=args.duration,
                max_parallel=args.max_parallel,
                resume=args.resume,
                project=args.project,
            ):
                logger.error("Phase 3 failed")
                overall_success = False
                break

        elif phase == 4:
            if not run_phase_analysis(
                experiment_id, state,
                duration=args.duration,
                project=args.project,
            ):
                logger.error("Phase 4 failed")
                overall_success = False
                break

    # Final state update
    state["current_phase"] = None
    state["finished_at"] = datetime.now().isoformat()
    state["success"] = overall_success
    save_state(state, experiment_id)

    if overall_success:
        print(f"\n=== Benchmark Complete ===")
        print(f"  Experiment: {experiment_id}")
        print(f"  State: {get_state_path(experiment_id)}")
        if state.get("report_dir"):
            print(f"  Report: {state['report_dir']}/report.md")
    else:
        print(f"\n=== Benchmark Failed ===")
        print(f"  Experiment: {experiment_id}")
        print(f"  State: {get_state_path(experiment_id)}")
        if state.get("errors"):
            print(f"  Last error: {state['errors'][-1]}")
        print(f"\n  Retry with: python run_benchmark.py --resume --experiment-id {experiment_id}")
        sys.exit(1)


if __name__ == "__main__":
    main()
