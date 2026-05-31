#!/usr/bin/env python3
"""Phase 3: Parallel Trial Execution (slot-based scheduler).

Runs fuzzing trials in Docker containers with CPU pinning,
monitors for crashes, and collects results.  Uses a slot-based
scheduler that fills freed CPU slots immediately instead of
waiting for entire waves to complete.
"""

import argparse
import json
import logging
import os
import random
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
from lib import docker_util

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class Trial:
    """Represents a single fuzzing trial."""
    project: str
    cve: str
    variant: str  # "baseline" or "optimized"
    trial_id: int
    seed: int
    cpu: int = -1
    container_id: str = ""
    status: str = "pending"  # pending, running, completed, failed
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def name(self) -> str:
        return f"{self.project}-{self.cve}-{self.variant}-trial_{self.trial_id:02d}"

    @property
    def container_name(self) -> str:
        return f"bench_{self.name}"


def generate_trials(manifest: list[dict]) -> list[Trial]:
    """Generate all trial objects from manifest."""
    trials = []

    for entry in manifest:
        project = entry["project"]
        cve = entry["cve"]

        for trial_id in range(config.NUM_TRIALS):
            # Baseline trial
            baseline_seed = (
                config.BASE_SEED
                + trial_id * config.SEED_MULTIPLIER
                + config.BASELINE_SEED_OFFSET
            )
            trials.append(Trial(
                project=project,
                cve=cve,
                variant="baseline",
                trial_id=trial_id,
                seed=baseline_seed,
            ))

            # Optimized trial
            optimized_seed = (
                config.BASE_SEED
                + trial_id * config.SEED_MULTIPLIER
                + config.OPTIMIZED_SEED_OFFSET
            )
            trials.append(Trial(
                project=project,
                cve=cve,
                variant="optimized",
                trial_id=trial_id,
                seed=optimized_seed,
            ))

    # Shuffle to interleave variants and avoid systematic bias
    rng = random.Random(config.SHUFFLE_SEED)
    rng.shuffle(trials)

    logger.info("Generated %d trials across %d CVEs", len(trials), len(manifest))
    return trials


def get_trial_dirs(experiment_id: str, trial: Trial) -> dict[str, str]:
    """Get directory paths for a trial."""
    cve_dir = f"{trial.project}-{trial.cve}"
    base = os.path.join(
        config.RESULTS_DIR, experiment_id, cve_dir,
        trial.variant, f"trial_{trial.trial_id:02d}",
    )
    return {
        "base": base,
        "corpus": os.path.join(base, "corpus"),
        "crashes": os.path.join(base, "crashes"),
        "log": os.path.join(base, "fuzzer.log"),
        "metadata": os.path.join(base, "metadata.json"),
        "crash_times": os.path.join(base, "crash_times.json"),
    }


def get_fuzzer_binary(experiment_id: str, trial: Trial) -> str:
    """Get path to the fuzzer binary for this trial."""
    cve_dir = f"{trial.project}-{trial.cve}"
    manifest_path = config.MANIFEST_PATH
    with open(manifest_path) as f:
        manifest = json.load(f)

    fuzz_target = ""
    for entry in manifest:
        if entry["project"] == trial.project and entry["cve"] == trial.cve:
            fuzz_target = entry["fuzz_target"]
            break

    if not fuzz_target:
        raise RuntimeError(f"No fuzz target found for {trial.project}/{trial.cve}")

    return os.path.join(
        config.RESULTS_DIR, experiment_id, cve_dir,
        trial.variant, "bin", fuzz_target,
    )


def get_seed_corpus_dir(experiment_id: str, trial: Trial) -> str:
    """Get path to the seed corpus directory."""
    cve_dir = f"{trial.project}-{trial.cve}"
    merged = os.path.join(
        config.RESULTS_DIR, experiment_id, cve_dir,
        "seed_corpus", "merged",
    )
    if os.path.isdir(merged):
        return merged
    return os.path.join(
        config.RESULTS_DIR, experiment_id, cve_dir, "seed_corpus",
    )


def is_trial_completed(experiment_id: str, trial: Trial) -> bool:
    """Check if a trial has already been completed (for --resume)."""
    dirs = get_trial_dirs(experiment_id, trial)
    metadata_path = dirs["metadata"]
    if not os.path.exists(metadata_path):
        return False
    try:
        with open(metadata_path) as f:
            meta = json.load(f)
        return meta.get("duration_s", 0) > 0
    except (json.JSONDecodeError, KeyError):
        return False


def start_trial(
    trial: Trial, experiment_id: str, duration: int = config.TRIAL_DURATION_SECS
) -> bool:
    """Start a single fuzzing trial in a Docker container."""
    dirs = get_trial_dirs(experiment_id, trial)

    # Clean trial input/output dirs from any previous run, then recreate them.
    for d in [dirs["corpus"], dirs["crashes"]]:
        if os.path.isdir(d):
            shutil.rmtree(d)
        os.makedirs(d, exist_ok=True)

    # Copy seed corpus to trial corpus dir
    seed_dir = get_seed_corpus_dir(experiment_id, trial)
    if os.path.isdir(seed_dir):
        for fname in os.listdir(seed_dir):
            src = os.path.join(seed_dir, fname)
            if os.path.isfile(src):
                shutil.copy2(src, dirs["corpus"])

    fuzzer_binary = get_fuzzer_binary(experiment_id, trial)
    if not os.path.isfile(fuzzer_binary):
        logger.error("Fuzzer binary not found: %s", fuzzer_binary)
        trial.status = "failed"
        return False

    os.chmod(fuzzer_binary, 0o755)

    bin_dir = os.path.dirname(fuzzer_binary)
    fuzz_target_name = os.path.basename(fuzzer_binary)

    # Determine the docker image
    candidate_images = []
    if trial.variant == "optimized":
        candidate_images.append(f"gcr.io/oss-fuzz/{trial.project}_opt")
    candidate_images.append(f"gcr.io/oss-fuzz/{trial.project}")
    candidate_images.append("gcr.io/oss-fuzz-base/base-runner")

    docker_image = None
    for img in candidate_images:
        check = subprocess.run(
            ["docker", "image", "inspect", img],
            capture_output=True,
        )
        if check.returncode == 0:
            docker_image = img
            break

    if docker_image is None:
        logger.error("No suitable Docker image found for trial %s", trial.name)
        trial.status = "failed"
        return False

    container_name = trial.container_name
    trial._docker_image = docker_image
    trial._bin_dir = bin_dir
    trial._fuzz_target_name = fuzz_target_name
    trial._dirs = dirs

    if not _launch_container(trial, experiment_id, duration):
        return False
    return True


def _launch_container(
    trial: Trial, experiment_id: str, duration: int,
) -> bool:
    """Launch the Docker container for a trial."""
    container_name = trial.container_name
    docker_image = trial._docker_image
    bin_dir = trial._bin_dir
    fuzz_target_name = trial._fuzz_target_name
    dirs = trial._dirs
    seed = trial.seed

    # Clean up any leftover container with same name
    subprocess.run(
        ["docker", "rm", "-f", container_name],
        capture_output=True,
    )

    cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "--privileged",
        "--cpuset-cpus", str(trial.cpu),
        "--memory", config.MEMORY_LIMIT,
        "--shm-size", config.DOCKER_SHM_SIZE,
        "-v", f"{bin_dir}:/out:ro",
        "-v", f"{dirs['corpus']}:/corpus",
        "-v", f"{dirs['crashes']}:/crashes",
        docker_image,
        "/bin/bash", "-c",
        (
            f"/out/{fuzz_target_name} /corpus"
            f" -seed={seed}"
            f" -detect_leaks=0"
            f" -max_total_time={duration}"
            f" -print_final_stats=1"
            f" -rss_limit_mb={config.RSS_LIMIT_MB}"
            f" -malloc_limit_mb={config.RSS_LIMIT_MB // 2}"
            f" -artifact_prefix=/crashes/"
            f" 2>&1 | tee /tmp/fuzzer.log;"
            f" cp /tmp/fuzzer.log /corpus/../fuzzer.log"
        ),
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            logger.error(
                "Failed to start trial %s: %s", trial.name, result.stderr
            )
            trial.status = "failed"
            return False

        trial.container_id = result.stdout.strip()
        trial.status = "running"
        trial.start_time = time.time()

        logger.info(
            "Started trial %s (container=%s, cpu=%d, seed=%d, duration=%ds)",
            trial.name, trial.container_id[:12], trial.cpu, seed, duration,
        )
        return True

    except subprocess.TimeoutExpired:
        logger.error("Timeout starting trial %s", trial.name)
        trial.status = "failed"
        return False


def monitor_trial(
    trial: Trial, experiment_id: str,
    duration: int = config.TRIAL_DURATION_SECS,
) -> dict:
    """Monitor a running trial until completion.

    If the trial exits early (before duration), restarts the container
    with the remaining time so the full budget is used.
    """
    dirs = get_trial_dirs(experiment_id, trial)
    crashes_dir = dirs["crashes"]
    crash_times = []
    seen_crashes = set()
    overall_start = trial.start_time

    def scan_crashes():
        """Scan crashes directory for new artifacts."""
        if not os.path.isdir(crashes_dir):
            return
        for fname in os.listdir(crashes_dir):
            if fname in seen_crashes:
                continue
            if not fname.startswith(("crash-", "oom-", "timeout-")):
                continue
            seen_crashes.add(fname)

            elapsed = time.time() - overall_start
            crash_type = classify_crash(os.path.join(crashes_dir, fname))

            crash_times.append({
                "timestamp_s": round(elapsed, 2),
                "artifact": fname,
                "crash_type": crash_type,
            })
            logger.info(
                "Trial %s: crash found at %.1fs (%s: %s)",
                trial.name, elapsed, crash_type, fname,
            )

    # Ramp the poll interval: short cadence during the first 30 seconds so
    # startup failures (ghost trials that die in <1s) are noticed promptly
    # and don't get their wall duration rounded up by a full 10s poll.
    while True:
        if not docker_util.container_is_running(trial.container_id):
            break
        scan_crashes()
        elapsed_since_start = time.time() - overall_start
        poll_interval = 2 if elapsed_since_start < 30 else 10
        time.sleep(poll_interval)

    # Final scan after container exits
    scan_crashes()

    actual_duration = docker_util.get_container_duration_seconds(trial.container_id)

    # Collect logs
    logs = docker_util.get_container_logs(trial.container_id)

    # Capture post-exit docker state BEFORE removing the container.
    # This is the only place ExitCode / OOMKilled / Error are recoverable;
    # docker rm -f destroys them. Needed to diagnose ghost trials (<1s exits
    # with empty fuzzer.log) where stdout/stderr capture yields nothing.
    inspect_state = docker_util.inspect_container_state(trial.container_id)

    # Clean up container
    docker_util.remove_container(trial.container_id)

    trial.end_time = time.time()
    trial.status = "completed"

    log_path = dirs["log"]
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "w") as f:
        f.write(logs)

    final_stats = parse_fuzzer_stats(logs)

    observed_duration = round(trial.end_time - overall_start, 2)
    if not actual_duration or actual_duration <= 0:
        actual_duration = observed_duration

    if actual_duration > 0 and final_stats.get("total_execs"):
        final_stats["final_exec_s"] = round(
            float(final_stats["total_execs"]) / float(actual_duration), 2
        )

    with open(dirs["crash_times"], "w") as f:
        json.dump(crash_times, f, indent=2)

    # Persist raw docker state for post-mortem diagnosis.
    state_path = os.path.join(dirs["base"], "docker_state.json")
    try:
        with open(state_path, "w") as f:
            json.dump(inspect_state, f, indent=2)
    except OSError as e:
        logger.warning(
            "Failed to write docker_state.json for %s: %s", trial.name, e
        )

    # Heuristic flag: a "ghost" startup failure produces no log output, no
    # stats, and exits in under 5 seconds. Helps downstream reporting skip
    # these so they don't pollute baseline/optimized success ratios.
    failed_start = (
        actual_duration is not None
        and actual_duration > 0
        and actual_duration < 5
        and not final_stats
        and not crash_times
        and not (logs or "").strip()
    )

    metadata = {
        "trial_name": trial.name,
        "variant": trial.variant,
        "trial_id": trial.trial_id,
        "seed": trial.seed,
        "cpu": trial.cpu,
        "start_time": overall_start,
        "end_time": trial.end_time,
        "duration_s": actual_duration,
        "wall_duration_s": observed_duration,
        "duration_seconds": duration,
        "num_crashes": len(crash_times),
        "final_stats": final_stats,
        "failed_start": failed_start,
        "docker_exit_code": (
            inspect_state.get("ExitCode")
            if isinstance(inspect_state, dict) else None
        ),
        "docker_oom_killed": (
            inspect_state.get("OOMKilled")
            if isinstance(inspect_state, dict) else None
        ),
    }
    with open(dirs["metadata"], "w") as f:
        json.dump(metadata, f, indent=2)

    logger.info(
        "Trial %s completed: %d crashes in %.1f seconds",
        trial.name, len(crash_times), actual_duration,
    )

    return {
        "trial": trial.name,
        "crash_times": crash_times,
        "final_stats": final_stats,
    }


def classify_crash(crash_path: str) -> str:
    """Try to classify a crash artifact type."""
    fname = os.path.basename(crash_path)
    if fname.startswith("crash-"):
        return "crash"
    if fname.startswith("oom-"):
        return "oom"
    if fname.startswith("timeout-"):
        return "timeout"
    return "unknown"


def parse_fuzzer_stats(log: str) -> dict:
    """Parse libFuzzer final statistics from log output."""
    stats = {}

    patterns = {
        "exec_s": r"exec/s:\s*(\d+)",
        "total_execs": r"stat::number_of_executed_units:\s*(\d+)",
        "new_units": r"stat::new_units_added:\s*(\d+)",
        "peak_rss": r"stat::peak_rss_mb:\s*(\d+)",
        "corpus_size": r"stat::corpus_num_features:\s*(\d+)",
        "stat_avg_exec_s": r"stat::average_exec_per_sec:\s*(\d+)",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, log)
        if match:
            stats[key] = int(match.group(1))

    # Get final exec/s from the last progress line
    exec_s_values = re.findall(r"exec/s:\s*(\d+)", log)
    if exec_s_values:
        stats["final_exec_s"] = int(exec_s_values[-1])

    # Use stat::average_exec_per_sec as authoritative source if available,
    # since progress lines may not appear when no new coverage is found
    if "stat_avg_exec_s" in stats:
        stats["final_exec_s"] = stats["stat_avg_exec_s"]

    return stats


def save_partial_results(completed: list[dict], experiment_id: str):
    """Write intermediate results to disk."""
    results_path = os.path.join(
        config.RESULTS_DIR, experiment_id, "trial_results.json"
    )
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, "w") as f:
        json.dump(completed, f, indent=2)


def collect_all_trial_results(experiment_id: str) -> list[dict]:
    """Rebuild results from trial directories on disk.

    Useful for --resume or when in-memory results are incomplete.
    """
    results = []
    exp_dir = os.path.join(config.RESULTS_DIR, experiment_id)

    if not os.path.isdir(exp_dir):
        return results

    for cve_dir_name in sorted(os.listdir(exp_dir)):
        cve_path = os.path.join(exp_dir, cve_dir_name)
        if not os.path.isdir(cve_path) or cve_dir_name in ("report",):
            continue

        for variant in ["baseline", "optimized"]:
            variant_dir = os.path.join(cve_path, variant)
            if not os.path.isdir(variant_dir):
                continue

            for trial_name in sorted(os.listdir(variant_dir)):
                if not trial_name.startswith("trial_"):
                    continue

                trial_dir = os.path.join(variant_dir, trial_name)
                metadata_path = os.path.join(trial_dir, "metadata.json")
                crash_times_path = os.path.join(trial_dir, "crash_times.json")

                if not os.path.exists(metadata_path):
                    continue

                try:
                    with open(metadata_path) as f:
                        metadata = json.load(f)
                except (json.JSONDecodeError, OSError):
                    continue

                crash_times = []
                if os.path.exists(crash_times_path):
                    try:
                        with open(crash_times_path) as f:
                            crash_times = json.load(f)
                    except (json.JSONDecodeError, OSError):
                        pass

                results.append({
                    "trial": metadata.get("trial_name", trial_name),
                    "crash_times": crash_times,
                    "final_stats": metadata.get("final_stats", {}),
                })

    return results


def log_progress(
    running: dict, completed: list[dict], pending: deque,
    manifest: list[dict], start_time: float,
):
    """Log progress summary."""
    elapsed = time.time() - start_time
    hours = int(elapsed // 3600)
    mins = int((elapsed % 3600) // 60)
    secs = int(elapsed % 60)

    total = len(running) + len(completed) + len(pending)
    logger.info(
        "[%02d:%02d:%02d] Progress: %d/%d complete, %d running, %d pending",
        hours, mins, secs,
        len(completed), total, len(running), len(pending),
    )

    # Per-project summary
    project_stats = {}
    for entry in manifest:
        key = entry["project"]
        if key not in project_stats:
            project_stats[key] = {
                "bl_found": 0, "bl_total": 0,
                "opt_found": 0, "opt_total": 0,
            }

    for result in completed:
        trial_name = result.get("trial", "")
        has_crash = bool(result.get("crash_times"))

        # Parse project and variant from trial name
        # Format: project-CVE-XXXX-XXXXX-variant-trial_NN
        parts = trial_name.rsplit("-", 2)
        if len(parts) >= 2:
            variant = parts[-2] if "trial" in parts[-1] else ""
            # Extract project name (everything before the CVE)
            for entry in manifest:
                if entry["project"] in trial_name and entry["cve"] in trial_name:
                    key = entry["project"]
                    if key in project_stats:
                        if "baseline" in trial_name:
                            project_stats[key]["bl_total"] += 1
                            if has_crash:
                                project_stats[key]["bl_found"] += 1
                        elif "optimized" in trial_name:
                            project_stats[key]["opt_total"] += 1
                            if has_crash:
                                project_stats[key]["opt_found"] += 1
                    break

    header = f"{'Project':<16} | {'BL found':>10} | {'OPT found':>10}"
    logger.info(header)
    logger.info("-" * len(header))
    for proj, stats in project_stats.items():
        bl = f"{stats['bl_found']}/{stats['bl_total']}" if stats['bl_total'] else "—"
        opt = f"{stats['opt_found']}/{stats['opt_total']}" if stats['opt_total'] else "—"
        logger.info(f"{proj:<16} | {bl:>10} | {opt:>10}")


def run_all_trials_slot(
    manifest: list[dict],
    experiment_id: str,
    duration: int = config.TRIAL_DURATION_SECS,
    max_parallel: int = config.USABLE_CORES,
    resume: bool = False,
) -> list[dict]:
    """Run all trials using slot-based scheduling.

    Instead of running in waves, immediately fills freed CPU slots
    with pending trials for better utilization.
    """
    all_trials = generate_trials(manifest)

    # Filter out already-completed trials if resuming
    if resume:
        remaining = []
        skipped = 0
        for trial in all_trials:
            if is_trial_completed(experiment_id, trial):
                skipped += 1
            else:
                remaining.append(trial)
        logger.info("Resume: skipping %d completed trials, %d remaining",
                     skipped, len(remaining))
        all_trials = remaining

    if not all_trials:
        logger.info("No trials to run")
        return collect_all_trial_results(experiment_id)

    pending = deque(all_trials)
    running = {}  # cpu -> (trial, future)
    completed_results = []
    available_cpus = deque(range(config.RESERVED_CORES, config.TOTAL_CORES))

    # Limit to max_parallel
    while len(available_cpus) > max_parallel:
        available_cpus.pop()

    total = len(all_trials)
    start_time = time.time()
    last_progress_time = 0

    logger.info(
        "Running %d trials with %d CPU slots (duration=%ds)",
        total, len(available_cpus), duration,
    )

    executor = ThreadPoolExecutor(max_workers=max_parallel)
    monitor_futures = {}  # future -> (cpu, trial)

    try:
        while pending or running:
            # Fill empty slots
            while pending and available_cpus:
                trial = pending.popleft()
                cpu = available_cpus.popleft()
                trial.cpu = cpu

                if start_trial(trial, experiment_id, duration):
                    future = executor.submit(monitor_trial, trial, experiment_id, duration)
                    running[cpu] = trial
                    monitor_futures[future] = (cpu, trial)
                else:
                    # Trial failed to start, return CPU
                    available_cpus.append(cpu)
                    completed_results.append({
                        "trial": trial.name,
                        "crash_times": [],
                        "final_stats": {},
                        "error": "failed_to_start",
                    })

            # Check for completed futures (non-blocking)
            done_futures = []
            for future in list(monitor_futures.keys()):
                if future.done():
                    done_futures.append(future)

            for future in done_futures:
                cpu, trial = monitor_futures.pop(future)
                try:
                    result = future.result()
                    completed_results.append(result)
                except Exception as e:
                    logger.error("Trial %s failed: %s", trial.name, e)
                    completed_results.append({
                        "trial": trial.name,
                        "crash_times": [],
                        "final_stats": {},
                        "error": str(e),
                    })
                    if trial.container_id:
                        docker_util.stop_container(trial.container_id)
                        docker_util.remove_container(trial.container_id)

                if cpu in running:
                    del running[cpu]
                available_cpus.append(cpu)

                # Write intermediate results
                save_partial_results(completed_results, experiment_id)

            # Log progress periodically
            now = time.time()
            if now - last_progress_time >= config.MONITOR_INTERVAL:
                log_progress(
                    running, completed_results, pending, manifest, start_time
                )
                last_progress_time = now

            if pending or running:
                time.sleep(10)

    finally:
        executor.shutdown(wait=False)

    # Final save
    save_partial_results(completed_results, experiment_id)
    return completed_results


def main():
    parser = argparse.ArgumentParser(description="Phase 3: Trial Execution")
    parser.add_argument(
        "--manifest", default=config.MANIFEST_PATH,
        help="Path to manifest.json",
    )
    parser.add_argument(
        "--experiment-id", required=True,
        help="Experiment ID (from Phase 2)",
    )
    parser.add_argument(
        "--duration", type=int, default=config.TRIAL_DURATION_SECS,
        help=f"Trial duration in seconds (default: {config.TRIAL_DURATION_SECS})",
    )
    parser.add_argument(
        "--max-parallel", type=int, default=config.USABLE_CORES,
        help="Max parallel trials",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Resume from previous run, skipping completed trials",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Run a quick dry-run (1 trial, 5 minutes)",
    )
    parser.add_argument(
        "--project", default=None,
        help="Only run trials for a specific project",
    )
    args = parser.parse_args()

    with open(args.manifest) as f:
        manifest = json.load(f)

    if args.project:
        manifest = [e for e in manifest if e["project"] == args.project]

    if args.dry_run:
        logger.info("=== DRY RUN MODE ===")
        original_trials = config.NUM_TRIALS
        config.NUM_TRIALS = 1
        duration = 300
        max_parallel = min(args.max_parallel, 4)

        results = run_all_trials_slot(
            manifest, args.experiment_id, duration, max_parallel,
            resume=args.resume,
        )

        config.NUM_TRIALS = original_trials
    else:
        results = run_all_trials_slot(
            manifest, args.experiment_id, args.duration, args.max_parallel,
            resume=args.resume,
        )

    # If resuming, rebuild full results from disk
    if args.resume:
        results = collect_all_trial_results(args.experiment_id)

    # Save overall results
    results_path = os.path.join(
        config.RESULTS_DIR, args.experiment_id, "trial_results.json"
    )
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)

    logger.info("All trials complete. Results saved to %s", results_path)

    total = len(results)
    with_crashes = sum(1 for r in results if r.get("crash_times"))
    print(f"\n=== Trial Summary ===")
    print(f"  Total completed: {total}")
    print(f"  Found crashes: {with_crashes}")
    print(f"  Results: {results_path}")
    print()


if __name__ == "__main__":
    main()
