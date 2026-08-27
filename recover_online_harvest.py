#!/usr/bin/env python3
"""Recover an online-arm trial harvest from containers that outlived the runner.

_finalize_online_trial() writes fuzzer.log, crash_times.json and metadata.json,
then removes the container. If the runner dies inside that function -- as it did
on 2026-08-10, when nine concurrent buffered `docker logs` reached 239 GiB and
were OOM-killed -- the trial dirs are left without metadata.json and the
containers are left in place, still holding their logs. This rebuilds the
missing artifacts from those containers plus AFL's own output tree, so the
experiment does not have to be re-fuzzed.

Everything written here is derived from surviving evidence:

  fuzzer.log        streamed out of the container (never buffered in memory)
  crash_times.json  rescanned from <afl_out>/default/crashes*, which is where
                    the live monitor read them too -- timestamps come from the
                    artifact filenames, so a rescan is exact, not approximate
  metadata.json     AFL's fuzzer_stats/plot_data for the counters, docker
                    inspect for seed/cpu/exit state, and run_time for duration

Duration deliberately comes from AFL's accumulated `run_time`, not the
container's wall clock: the online arm relaunches the container on every hot
swap, so the surviving container covers only the final incarnation, while
run_time and execs_done both carry across resumes. Pairing execs_done with
container wall time would overstate exec/s by the fraction of the trial that
ran before the last swap (27% for lcms-arvo-756).

Usage:
    python3 recover_online_harvest.py --experiment-id online-24h-b3-lcms \
        --project lcms --cve arvo-756 [--variant optimized] [--force] [--dry-run]
"""
import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
from lib import afl, crash_classify, docker_util

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("recover")

MIN_FREE_BYTES = 150 * 1024**3


def inspect_container(name: str) -> dict:
    """Full docker inspect for one container, or {} if it is gone."""
    r = subprocess.run(
        ["docker", "inspect", name], capture_output=True, text=True,
    )
    if r.returncode != 0:
        return {}
    try:
        return json.loads(r.stdout)[0]
    except (json.JSONDecodeError, IndexError, KeyError):
        return {}


def _epoch(ts: str):
    """Docker RFC3339 timestamp -> unix epoch. Docker gives 9 fractional
    digits; fromisoformat on 3.12 wants at most 6."""
    if not ts or ts.startswith("0001-01-01"):
        return None
    ts = ts.replace("Z", "+00:00")
    if "." in ts:
        head, _, tail = ts.partition(".")
        frac, sign, off = tail.partition("+")
        ts = f"{head}.{frac[:6]}{sign}{off}" if sign else f"{head}.{frac[:6]}"
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return None


def _flag(cmd: list, flag: str):
    """Value of `flag` in the container's afl-fuzz command line."""
    joined = " ".join(cmd or [])
    parts = joined.split()
    for i, tok in enumerate(parts):
        if tok == flag and i + 1 < len(parts):
            return parts[i + 1]
    return None


def recover_trial(exp_id, cve_key, variant, trial_id, configured_duration,
                  swap_count, force=False, dry_run=False) -> dict:
    trial_name = f"{cve_key}-{variant}-trial_{trial_id:02d}"
    container = f"bench_{trial_name}"
    base = os.path.join(
        config.RESULTS_DIR, exp_id, cve_key, variant, f"trial_{trial_id:02d}",
    )
    paths = {
        "log": os.path.join(base, "fuzzer.log"),
        "metadata": os.path.join(base, "metadata.json"),
        "crash_times": os.path.join(base, "crash_times.json"),
        "docker_state": os.path.join(base, "docker_state.json"),
        "afl_out": os.path.join(base, "afl_out"),
    }

    if not os.path.isdir(base):
        return {"trial": trial_name, "status": "no-trial-dir"}
    if os.path.exists(paths["metadata"]) and not force:
        return {"trial": trial_name, "status": "already-harvested"}

    info = inspect_container(container)
    if not info:
        return {"trial": trial_name, "status": "container-gone"}

    state = info.get("State", {})
    started, finished = _epoch(state.get("StartedAt")), _epoch(state.get("FinishedAt"))
    cmd = info.get("Config", {}).get("Cmd", [])
    seed = _flag(cmd, "-s")
    v_flag = _flag(cmd, "-V")
    cpuset = info.get("HostConfig", {}).get("CpusetCpus")

    # AFL's structured output: counters and coverage series, accumulated across
    # every resume rather than just the surviving container's run.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import phase3_runner
    final_stats = phase3_runner.parse_fuzzer_stats(paths["afl_out"])
    run_time = final_stats.get("run_time")

    crashes_dir = os.path.join(paths["afl_out"], "default", "crashes")
    crash_times = [
        {"timestamp_s": c["timestamp_s"], "artifact": c["artifact"],
         "crash_type": "crash"}
        for c in afl.collect_crashes(crashes_dir)
    ]

    # Prefer AFL's accumulated run_time; fall back to container wall clock only
    # if fuzzer_stats is unreadable, and say so in the metadata.
    if run_time:
        duration_s, duration_src = float(run_time), "afl_run_time"
    elif started and finished:
        duration_s, duration_src = round(finished - started, 2), "container_wall"
    else:
        duration_s, duration_src = None, "unavailable"

    # AFL stamps last_update at exit; run_time back from it is the effective
    # trial start across all incarnations.
    end_time = finished
    start_time = (end_time - duration_s) if (end_time and duration_s) else started

    metadata = {
        "trial_name": trial_name,
        "variant": variant,
        "trial_id": trial_id,
        "seed": int(seed) if seed and seed.isdigit() else None,
        "cpu": int(cpuset) if cpuset and cpuset.isdigit() else None,
        "start_time": start_time,
        "end_time": end_time,
        "duration_s": duration_s,
        "duration_seconds": configured_duration,
        "num_crashes": len(crash_times),
        "found_bug": crash_classify.trial_found_bug(
            crash_times, configured_duration),
        "time_to_bug_s": crash_classify.trial_time_to_bug(
            crash_times, configured_duration),
        "final_stats": final_stats,
        "failed_start": False,
        "docker_exit_code": state.get("ExitCode"),
        "docker_oom_killed": state.get("OOMKilled"),
        # Provenance. duration_s spans every incarnation of this trial, while
        # the container below is only the last one -- do not read them as the
        # same window.
        "recovered": True,
        "recovery": {
            "reason": "runner OOM-killed during _finalize_online_trial",
            "recovered_at": datetime.now().isoformat(),
            "from_container": container,
            "container_started_at": state.get("StartedAt"),
            "container_finished_at": state.get("FinishedAt"),
            "container_wall_s": (round(finished - started, 2)
                                 if started and finished else None),
            "container_v_flag_s": int(v_flag) if v_flag and v_flag.isdigit() else None,
            "duration_source": duration_src,
            "hot_swaps_before_this_container": swap_count,
        },
    }

    if dry_run:
        return {"trial": trial_name, "status": "dry-run",
                "duration_s": duration_s, "crashes": len(crash_times),
                "execs": final_stats.get("total_execs")}

    t0 = time.time()
    log_bytes = docker_util.write_container_logs(container, paths["log"])
    elapsed = time.time() - t0

    with open(paths["crash_times"], "w") as f:
        json.dump(crash_times, f, indent=2)
    with open(paths["docker_state"], "w") as f:
        json.dump(state, f, indent=2)
    with open(paths["metadata"], "w") as f:
        json.dump(metadata, f, indent=2)

    return {
        "trial": trial_name, "status": "recovered",
        "log_bytes": log_bytes, "log_secs": round(elapsed, 1),
        "duration_s": duration_s, "duration_source": duration_src,
        "crashes": len(crash_times), "execs": final_stats.get("total_execs"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--cve", required=True)
    ap.add_argument("--variant", default="optimized")
    ap.add_argument("--trials", type=int, default=9)
    ap.add_argument("--duration", type=int, default=None,
                    help="configured trial duration; defaults to the baseline "
                         "sibling's duration_seconds, else config")
    ap.add_argument("--force", action="store_true",
                    help="rewrite trials that already have metadata.json")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    cve_key = f"{args.project}-{args.cve}"
    exp_root = os.path.join(config.RESULTS_DIR, args.experiment_id, cve_key)

    st = os.statvfs(exp_root if os.path.isdir(exp_root) else "/")
    free = st.f_bavail * st.f_frsize
    logger.info("free space: %.1f GB", free / 1e9)
    if free < MIN_FREE_BYTES and not args.dry_run:
        logger.error("under %.0f GB free; the logs need roughly 80 GB. Aborting.",
                     MIN_FREE_BYTES / 1e9)
        return 1

    # Configured duration: mirror the baseline arm of the same experiment.
    duration = args.duration
    if duration is None:
        sibling = os.path.join(exp_root, "baseline", "trial_00", "metadata.json")
        if os.path.exists(sibling):
            with open(sibling) as f:
                duration = json.load(f).get("duration_seconds")
        duration = duration or config.TRIAL_DURATION_SECS
    logger.info("configured trial duration: %ss", duration)

    swap_path = os.path.join(exp_root, "optimized", "online", "swap_timeline.json")
    swap_count = 0
    if os.path.exists(swap_path):
        try:
            with open(swap_path) as f:
                swap_count = len(json.load(f))
        except (json.JSONDecodeError, OSError):
            pass
    logger.info("hot swaps recorded for this arm: %d", swap_count)

    results = []
    for trial_id in range(args.trials):
        r = recover_trial(args.experiment_id, cve_key, args.variant, trial_id,
                          duration, swap_count, args.force, args.dry_run)
        results.append(r)
        logger.info("trial_%02d: %s", trial_id, json.dumps(r))

    print("\n=== summary ===")
    for r in results:
        print(f"  {r['trial']}: {r['status']}"
              + (f"  execs={r.get('execs')} duration_s={r.get('duration_s')}"
                 f" crashes={r.get('crashes')}"
                 f" log={r.get('log_bytes', 0) / 1e9:.1f}GB"
                 if r["status"] == "recovered" else ""))
    ok = sum(1 for r in results if r["status"] in ("recovered", "already-harvested"))
    print(f"\n{ok}/{len(results)} trials have metadata")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
