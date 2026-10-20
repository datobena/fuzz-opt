#!/usr/bin/env python3
"""Phase 4: Statistical Analysis and Report Generation.

Analyzes trial results using Mann-Whitney U, Vargha-Delaney A12,
and survival analysis. Generates plots and summary tables.
"""

import argparse
import json
import logging
import os
import re
import sys
from collections import defaultdict
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
from lib import crash_classify, stats_util

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Bug survival
#
# The pipeline no longer reverts an optimization for removing the bug -- survival
# is MEASURED, not enforced (see the 2026-07-30 design spec). That makes an
# optimized arm with no finding ambiguous: it was either slower/unlucky, or the
# bug is not in the binary at all. The recorded poc_verdict is the discriminator,
# and pooling the two cases would make a removed bug look like a performance
# regression.
# --------------------------------------------------------------------------- #

# Verdicts written by phase 2 (prework.verify.classify_run). "other_crash" means
# the PoC now triggers a DIFFERENT bug, so the target bug is gone too.
_VERDICT_BUG_PRESENT = ("poc_crash",)
_VERDICT_BUG_REMOVED = ("no_crash", "other_crash")


def classify_trial_outcome(ttb, poc_verdict):
    """Classify one trial: found / not_found / bug_absent / unverified.

    A find always counts, even against a "bug removed" verdict -- that
    combination is a contradiction worth surfacing rather than resolving
    silently, because it means either the verdict or the triage is wrong.
    """
    if ttb is not None:
        return "found"
    if poc_verdict in _VERDICT_BUG_PRESENT:
        return "not_found"
    if poc_verdict in _VERDICT_BUG_REMOVED:
        return "bug_absent"
    return "unverified"


def summarize_bug_survival(arms):
    """Bug-survival rate over arms carrying a poc_verdict.

    Unverified arms are counted but EXCLUDED from the rate: a verdict we could
    not obtain is not evidence in either direction, and folding it in would
    silently bias the headline number.
    """
    survived = sum(1 for a in arms if a.get("poc_verdict") in _VERDICT_BUG_PRESENT)
    removed = sum(1 for a in arms if a.get("poc_verdict") in _VERDICT_BUG_REMOVED)
    verified = survived + removed
    return {
        "total": len(arms),
        "survived": survived,
        "removed": removed,
        "unverified": len(arms) - verified,
        "survival_rate": (survived / verified) if verified else None,
    }


_EXEC_S_RE = re.compile(r"exec/s:\s*(\d+)")
_AVG_EXEC_S_RE = re.compile(r"stat::average_exec_per_sec:\s*(\d+)")


def _scan_log_for_exec_rates(
    log_path: str, chunk_size: int = 1 << 20, overlap: int = 256,
) -> tuple[Optional[int], Optional[int]]:
    """Find the last `exec/s:` and the first average-exec rate in a fuzzer log.

    Returns (last_progress_exec_s, avg_exec_s), either of which may be None.

    Reads in fixed chunks rather than lines or one gulp. These logs reach
    12.5 GB, so lf.read() is an OOM waiting to happen -- and iterating by line
    is no safer, because AFL++ redraws its status screen with carriage
    returns, leaving gigabytes between two newlines. Consecutive chunks
    overlap so a marker split across a boundary is still matched; rescanning
    the overlap is harmless when all we keep is a first and a last hit.
    """
    last_progress = None
    avg = None
    tail = ""

    with open(log_path, errors="replace") as lf:
        while True:
            chunk = lf.read(chunk_size)
            if not chunk:
                break
            window = tail + chunk
            for m in _EXEC_S_RE.finditer(window):
                last_progress = int(m.group(1))
            if avg is None:
                m = _AVG_EXEC_S_RE.search(window)
                if m:
                    avg = int(m.group(1))
            tail = window[-overlap:]

    return last_progress, avg


def extract_execs_per_second(metadata: dict, trial_dir: str) -> float:
    """Extract a trustworthy executions/sec value for one trial."""
    final_stats = metadata.get("final_stats", {})
    total_execs = final_stats.get("total_execs", 0)
    duration_s = metadata.get("duration_s", 0)
    if total_execs and duration_s:
        return float(total_execs) / float(duration_s)

    exec_s = final_stats.get("final_exec_s", 0)
    if exec_s:
        return float(exec_s)

    log_path = os.path.join(trial_dir, "fuzzer.log")
    if os.path.exists(log_path):
        last_progress_exec_s, avg_exec_s = _scan_log_for_exec_rates(log_path)

        if last_progress_exec_s and last_progress_exec_s > 0:
            return float(last_progress_exec_s)

        if avg_exec_s and avg_exec_s > 0:
            return float(avg_exec_s)

    return 0.0


# --------------------------------------------------------------------------- #
# Trial duration (the time-to-bug censoring cutoff)
#
# The duration is not a timeout: crashes at or after it are ignored and a trial
# with no earlier crash is censored at it. Analysing a 24h campaign with a 6h
# cutoff silently reports every bug first found after hour 6 as "not found", so
# the cutoff comes from what each trial recorded, not from a config default.
# --------------------------------------------------------------------------- #

DURATION_SRC_OVERRIDE = "override"
DURATION_SRC_METADATA = "metadata"
DURATION_SRC_EXPERIMENT_MAX = "experiment_max"
DURATION_SRC_CONFIG = "config_default"

_DURATION_SRC_LABELS = {
    DURATION_SRC_OVERRIDE: "--duration override",
    DURATION_SRC_METADATA: "trial metadata",
    DURATION_SRC_EXPERIMENT_MAX: "max recorded in this experiment (trial recorded none)",
    DURATION_SRC_CONFIG: "config.TRIAL_DURATION_SECS default (no trial recorded one)",
}


def recorded_trial_duration(metadata: Optional[dict]) -> Optional[int]:
    """The configured run length a trial's metadata.json recorded, or None.

    Reads `duration_seconds` (the -max_total_time the trial ran under), not
    `duration_s`, which is the measured wall time and overshoots the cutoff.
    """
    if not isinstance(metadata, dict):
        return None
    value = metadata.get("duration_seconds")
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def check_duration_override(override: Optional[int]) -> None:
    """Reject a non-positive override instead of quietly replacing it.

    A 0 cutoff used to fall through `or config.TRIAL_DURATION_SECS` and become
    6h while the report still said "--duration override".
    """
    if override is not None and int(override) <= 0:
        raise ValueError(
            f"duration override must be a positive number of seconds, "
            f"got {override!r}"
        )


def resolve_trial_duration(
    recorded: Optional[int],
    override: Optional[int] = None,
    experiment_max: Optional[int] = None,
) -> tuple[int, str]:
    """Pick one trial's censoring cutoff and say where it came from.

    Order: explicit override, then the trial's own metadata, then the longest
    duration any trial of the experiment recorded, then the config default.
    """
    check_duration_override(override)
    if override is not None:
        return int(override), DURATION_SRC_OVERRIDE
    if recorded:
        return int(recorded), DURATION_SRC_METADATA
    if experiment_max:
        return int(experiment_max), DURATION_SRC_EXPERIMENT_MAX
    return int(config.TRIAL_DURATION_SECS), DURATION_SRC_CONFIG


def describe_duration_sources(sources: list[str]) -> str:
    """Human summary of where a set of trials' durations came from."""
    counts: dict[str, int] = {}
    for src in sources:
        counts[src] = counts.get(src, 0) + 1
    if not counts:
        return _DURATION_SRC_LABELS[DURATION_SRC_CONFIG]
    if len(counts) == 1:
        return _DURATION_SRC_LABELS.get(next(iter(counts)), next(iter(counts)))
    return ", ".join(
        f"{_DURATION_SRC_LABELS.get(src, src)} ({n} trials)"
        for src, n in counts.items()
    )


def format_duration(durations: list[int], source: str) -> str:
    """'24.0 hours (86400s, from trial metadata)', or a mixed range."""
    durations = sorted(set(durations))
    if not durations:
        return f"unknown ({source})"
    if len(durations) == 1:
        d = durations[0]
        return f"{d / 3600:.1f} hours ({d}s, from {source})"
    return (
        f"MIXED {durations[0] / 3600:.1f}-{durations[-1] / 3600:.1f} hours "
        f"({', '.join(str(d) for d in durations)}s, from {source})"
    )


def _assign_times_to_bug(pending: list[tuple], duration: Optional[int]) -> None:
    """Resolve every trial's cutoff, then compute its time-to-bug.

    Runs after all trials are loaded because the fallback for a trial with no
    recorded duration is the longest duration the rest of the experiment
    recorded.
    """
    recorded = [rec for *_, rec in pending if rec]
    experiment_max = max(recorded) if recorded else None

    counts: dict[str, int] = {}
    for variant_data, crash_times, crash_type, trial_dir, rec in pending:
        trial_duration, source = resolve_trial_duration(
            rec, override=duration, experiment_max=experiment_max,
        )
        counts[source] = counts.get(source, 0) + 1
        variant_data["durations"].append(trial_duration)
        variant_data["duration_sources"].append(source)
        variant_data["times"].append(find_time_to_target_bug(
            crash_times, crash_type, trial_dir, trial_duration=trial_duration,
        ))

    if not pending:
        return
    if duration is not None:
        disagree = sorted({rec for rec in recorded if rec != duration})
        if disagree:
            logger.warning(
                "--duration %ds overrides the %s s recorded by %d trial(s): "
                "crashes at/after %ds are ignored and those trials are "
                "censored there",
                duration, "/".join(str(d) for d in disagree),
                sum(1 for rec in recorded if rec != duration), duration,
            )
        return
    if len(set(recorded)) > 1:
        logger.warning(
            "Trials recorded DIFFERENT durations (%s s); each trial is censored "
            "at its own, so censored times are not comparable across trials",
            "/".join(str(d) for d in sorted(set(recorded))),
        )
    if counts.get(DURATION_SRC_EXPERIMENT_MAX):
        logger.warning(
            "%d trial(s) recorded no duration; censoring them at %ds, the "
            "longest duration recorded in this experiment",
            counts[DURATION_SRC_EXPERIMENT_MAX], experiment_max,
        )
    if counts.get(DURATION_SRC_CONFIG):
        logger.warning(
            "!!! NO trial metadata recorded a duration: censoring all %d "
            "trials at config.TRIAL_DURATION_SECS=%ds (%.1fh). Any bug first "
            "found after that is reported NOT FOUND. Pass --duration with the "
            "real run length. !!!",
            counts[DURATION_SRC_CONFIG], config.TRIAL_DURATION_SECS,
            config.TRIAL_DURATION_SECS / 3600,
        )


def load_trial_data(
    experiment_id: str, manifest: list[dict],
    duration: int = None,
) -> dict[str, dict]:
    """Load all trial data for an experiment.

    `duration` overrides every trial's censoring cutoff. Leave it None to use
    the duration each trial recorded in its metadata.json (see
    resolve_trial_duration for the fallbacks).

    Returns dict keyed by "{project}-{cve}" with structure:
    {
        "baseline": {"times": [...], "durations": [...],
                     "duration_sources": [...], "exec_s": [...],
                     "coverage": [...]},
        "optimized": {...same...},
    }
    `times`, `durations` and `duration_sources` are parallel, one per trial.
    """
    check_duration_override(duration)
    results = {}
    # One entry per trial, in load order: (variant data, crash_times,
    # crash_type, trial_dir, recorded duration). Times are filled in once
    # every trial's recorded duration is known.
    pending: list[tuple] = []

    for entry in manifest:
        project = entry["project"]
        cve = entry["cve"]
        key = f"{project}-{cve}"
        crash_type = entry.get("crash_type", "")

        data = {
            "baseline": {
                "times": [],
                "durations": [],
                "duration_sources": [],
                "exec_s": [],
                "coverage": [],
                "trial_data": [],
            },
            "optimized": {
                "times": [],
                "durations": [],
                "duration_sources": [],
                "exec_s": [],
                "coverage": [],
                "trial_data": [],
            },
        }

        for variant in ["baseline", "optimized"]:
            # Scan for actual trial directories rather than assuming fixed count
            variant_dir = os.path.join(
                config.RESULTS_DIR, experiment_id, key, variant,
            )
            trial_ids = []
            if os.path.isdir(variant_dir):
                for d in sorted(os.listdir(variant_dir)):
                    if d.startswith("trial_") and os.path.isdir(
                        os.path.join(variant_dir, d)
                    ):
                        trial_ids.append(d)

            if not trial_ids:
                logger.warning("No trial dirs found in %s", variant_dir)

            for trial_name in trial_ids:
                trial_dir = os.path.join(variant_dir, trial_name)

                if not os.path.isdir(trial_dir):
                    continue

                # Load crash times
                crash_times_path = os.path.join(trial_dir, "crash_times.json")
                if os.path.exists(crash_times_path):
                    with open(crash_times_path) as f:
                        crash_times = json.load(f)
                else:
                    crash_times = []

                # Load metadata for exec/s and the recorded run length
                metadata_path = os.path.join(trial_dir, "metadata.json")
                recorded = None
                if os.path.exists(metadata_path):
                    with open(metadata_path) as f:
                        metadata = json.load(f)
                    exec_s = extract_execs_per_second(metadata, trial_dir)
                    data[variant]["exec_s"].append(exec_s)
                    data[variant]["trial_data"].append(metadata)
                    recorded = recorded_trial_duration(metadata)

                # Time to the target bug needs the cutoff, which may fall back
                # to other trials' metadata -- resolved after the scan.
                pending.append(
                    (data[variant], crash_times, crash_type, trial_dir, recorded)
                )

                # Load coverage data if available
                coverage = load_coverage_data(trial_dir)
                if coverage:
                    data[variant]["coverage"].append(coverage)

        # Deterministic corpus-replay speedup recorded in phase 2 (headline
        # throughput metric; apples-to-apples, unlike live exec/s).
        setup_meta_path = os.path.join(
            config.RESULTS_DIR, experiment_id, key, "setup_metadata.json"
        )
        if os.path.exists(setup_meta_path):
            try:
                with open(setup_meta_path) as f:
                    data["replay"] = json.load(f).get("replay")
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Could not read replay metric for %s: %s", key, exc)

        results[key] = data

    _assign_times_to_bug(pending, duration)

    # Validate: log trial counts and the cutoff each CVE was censored at
    for key, data in results.items():
        for variant in ["baseline", "optimized"]:
            n = len(data[variant]["times"])
            if n == 0:
                logger.warning("%s: no trials for %s", key, variant)
            else:
                logger.info(
                    "%s: %d trials for %s, duration %s", key, n, variant,
                    format_duration(
                        data[variant]["durations"],
                        describe_duration_sources(data[variant]["duration_sources"]),
                    ),
                )

    return results


def find_time_to_target_bug(
    crash_times: list[dict],
    target_crash_type: str,
    trial_dir: str,
    trial_duration: int = None,
) -> float:
    """Time to the first genuine target-bug crash, or the censored value.

    Delegates the "is this a real target-bug crash?" decision to the canonical
    classifier (lib/crash_classify), which excludes slow-units (crash_type
    "unknown"), timeouts, OOMs, and the empty-input / end-of-run boundary
    artifact. `target_crash_type` is retained as documentation of the expected
    bug signature; the reproduction-based signature match lives in
    crash_classify.verify_crash_reproduces for when the binary is available.
    """
    if trial_duration is None:
        trial_duration = config.TRIAL_DURATION_SECS
    elif trial_duration <= 0:
        raise ValueError(
            f"trial_duration must be a positive number of seconds, "
            f"got {trial_duration!r}"
        )
    censored = float(trial_duration)
    ttb = crash_classify.trial_time_to_bug(crash_times, censored)
    return ttb if ttb is not None else censored


def matches_crash_type(actual: str, target: str) -> bool:
    """Check if an actual crash type matches the target."""
    if not actual or not target:
        return False
    # Normalize
    actual = actual.lower().replace("_", "-").replace(" ", "-")
    target = target.lower().replace("_", "-").replace(" ", "-")

    if actual == target:
        return True
    # Partial matches
    if target in actual or actual in target:
        return True
    # "crash" matches anything that isn't oom/timeout
    if actual == "crash" and target not in ("oom", "timeout"):
        return True
    return False


def analyze_crash_artifact(artifact_path: str, trial_dir: str) -> str:
    """Analyze a crash artifact to determine crash type.

    This would ideally re-run the fuzzer with the artifact to get ASAN output.
    For now, just return the file prefix.
    """
    fname = os.path.basename(artifact_path)
    if fname.startswith("crash-"):
        return "crash"
    if fname.startswith("oom-"):
        return "oom"
    if fname.startswith("timeout-"):
        return "timeout"
    return "unknown"


def load_coverage_data(
    trial_dir: str,
) -> Optional[list[tuple[float, int]]]:
    """Load coverage-over-time data from a trial directory.

    Returns list of (time_seconds, edge_count) tuples, or None.
    """
    coverage_path = os.path.join(trial_dir, "coverage_over_time.json")
    if not os.path.exists(coverage_path):
        return None

    with open(coverage_path) as f:
        data = json.load(f)

    return [(entry["time_s"], entry["edges"]) for entry in data]


def analyze_cve(
    key: str, data: dict, report_dir: str,
    duration: int = None,
) -> Optional[dict]:
    """Perform statistical analysis for a single CVE.

    Returns result dict or None if insufficient data.
    """
    baseline_times = data["baseline"]["times"]
    optimized_times = data["optimized"]["times"]

    if not baseline_times or not optimized_times:
        logger.warning("No trial data for %s", key)
        return None

    if len(baseline_times) < 1 or len(optimized_times) < 1:
        logger.warning(
            "Need at least 1 trial per variant for %s: baseline=%d, optimized=%d",
            key, len(baseline_times), len(optimized_times),
        )
        return None

    # Statistical tests
    u_stat, p_value_less = stats_util.mann_whitney_u(
        optimized_times, baseline_times, alternative="less"
    )
    _, p_value_two = stats_util.mann_whitney_u(
        optimized_times, baseline_times, alternative="two-sided"
    )

    a12 = stats_util.vargha_delaney_a12(optimized_times, baseline_times)
    a12_label = stats_util.a12_effect_label(a12)

    speedup = stats_util.compute_speedup(optimized_times, baseline_times)

    baseline_stats = stats_util.summary_stats(baseline_times)
    optimized_stats = stats_util.summary_stats(optimized_times)

    # Each trial's censoring cutoff, as load_trial_data resolved it. A trial
    # found the bug iff its time is below its OWN cutoff: comparing against
    # one shared value miscounts as soon as two trials ran different lengths.
    # `duration` is only the fallback for data that carries no per-trial
    # cutoffs (callers building `data` by hand).
    fallback_dur, fallback_src = resolve_trial_duration(None, override=duration)
    per_variant_durs = {}
    duration_sources = []
    for variant, times in (("baseline", baseline_times),
                           ("optimized", optimized_times)):
        durs = data[variant].get("durations") or []
        srcs = data[variant].get("duration_sources") or []
        if len(durs) != len(times):
            durs = [fallback_dur] * len(times)
            srcs = [fallback_src] * len(times)
        per_variant_durs[variant] = durs
        duration_sources.extend(srcs)
    all_durs = per_variant_durs["baseline"] + per_variant_durs["optimized"]
    trial_dur = max(all_durs)
    trial_durations = sorted(set(all_durs))
    duration_source = describe_duration_sources(duration_sources)

    # Parse project/cve from key like "json-c-OSV-2020-252" or "re2-CVE-2019-18224"
    # The CVE/OSV ID follows a known pattern; everything before it is the project name.
    m = re.match(r'^(.+?)-((?:CVE|OSV|GHSA)-\d{4}-\d+)$', key)
    if m:
        project_name = m.group(1)
        cve_name = m.group(2)
    else:
        # Fallback: last resort split
        project_name = key
        cve_name = key

    result = {
        "key": key,
        "project": project_name,
        "cve": cve_name,
        "baseline_median": baseline_stats["median"],
        "optimized_median": optimized_stats["median"],
        "speedup": round(speedup, 2) if speedup else None,
        "p_value": p_value_less,
        "p_value_two_sided": p_value_two,
        "u_stat": u_stat,
        "a12": round(a12, 3),
        "a12_label": a12_label,
        "baseline_stats": baseline_stats,
        "optimized_stats": optimized_stats,
        "baseline_found_bug": sum(
            1 for t, d in zip(baseline_times, per_variant_durs["baseline"])
            if t < d
        ),
        "optimized_found_bug": sum(
            1 for t, d in zip(optimized_times, per_variant_durs["optimized"])
            if t < d
        ),
        # Longest cutoff; `trial_durations` lists every distinct one.
        "trial_duration": trial_dur,
        "trial_durations": trial_durations,
        "trial_duration_source": duration_source,
    }

    # Generate plots
    project_report_dir = os.path.join(report_dir, key)
    os.makedirs(project_report_dir, exist_ok=True)

    # Time-to-bug box plot
    stats_util.plot_time_to_bug_boxplot(
        optimized_times, baseline_times,
        title=f"Time to Bug: {key}",
        output_path=os.path.join(project_report_dir, "time_to_bug_boxplot.png"),
        duration_secs=trial_dur,
    )

    # Survival curve. The plot takes one cutoff; with mixed durations the
    # shortest never marks a censored trial as a find (it can only under-count).
    stats_util.plot_survival_curve(
        optimized_times, baseline_times,
        title=f"Survival Curve: {key}",
        output_path=os.path.join(project_report_dir, "survival_curve.png"),
        duration_secs=trial_durations[0],
    )

    # Exec/s comparison
    baseline_eps = data["baseline"]["exec_s"]
    optimized_eps = data["optimized"]["exec_s"]
    if baseline_eps and optimized_eps:
        stats_util.plot_execs_per_sec(
            optimized_eps, baseline_eps,
            title=f"Executions/sec: {key}",
            output_path=os.path.join(project_report_dir, "exec_per_sec.png"),
        )

        import numpy as np
        result["baseline_exec_s_median"] = float(np.median(baseline_eps))
        result["optimized_exec_s_median"] = float(np.median(optimized_eps))
        if result["baseline_exec_s_median"] > 0:
            result["exec_s_speedup"] = round(
                result["optimized_exec_s_median"] / result["baseline_exec_s_median"],
                2,
            )

    # Deterministic corpus-replay speedup: the headline throughput metric.
    # Both binaries replay the SAME frozen corpus, so this is apples-to-apples
    # and immune to the coverage-gradient divergence that confounds live exec/s.
    replay = data.get("replay") or {}
    if replay.get("replay_speedup") is not None:
        result["replay_speedup"] = replay["replay_speedup"]
        baseline_t = (replay.get("baseline") or {}).get("median_time_s")
        optimized_t = (replay.get("optimized") or {}).get("median_time_s")
        if baseline_t is not None:
            result["replay_baseline_time_s"] = baseline_t
        if optimized_t is not None:
            result["replay_optimized_time_s"] = optimized_t
        result["replay_corpus_file_count"] = replay.get("corpus_file_count")

    # Coverage over time
    baseline_cov = data["baseline"]["coverage"]
    optimized_cov = data["optimized"]["coverage"]
    if baseline_cov and optimized_cov:
        stats_util.plot_coverage_over_time(
            optimized_cov, baseline_cov,
            title=f"Coverage Over Time: {key}",
            output_path=os.path.join(project_report_dir, "coverage_over_time.png"),
        )

        # Coverage Mann-Whitney U on final edge counts
        import numpy as np
        baseline_final_edges = [trial[-1][1] for trial in baseline_cov if trial]
        optimized_final_edges = [trial[-1][1] for trial in optimized_cov if trial]
        if baseline_final_edges and optimized_final_edges:
            _, cov_p = stats_util.mann_whitney_u(
                optimized_final_edges, baseline_final_edges, alternative="greater"
            )
            result["coverage_p_value"] = cov_p
            result["baseline_final_edges_median"] = float(
                np.median(baseline_final_edges)
            )
            result["optimized_final_edges_median"] = float(
                np.median(optimized_final_edges)
            )

    return result


def generate_report(
    results: list[dict], report_dir: str, experiment_id: str
):
    """Generate final report with summary tables and aggregated results."""
    os.makedirs(report_dir, exist_ok=True)

    # Summary table
    markdown_table, latex_table = stats_util.generate_summary_table(results)

    # Overall summary
    significant = [r for r in results if r["p_value"] < 0.05]
    large_effect = [r for r in results if r["a12"] >= 0.71]
    any_bugs = any(
        r.get("baseline_found_bug", 0) > 0 or r.get("optimized_found_bug", 0) > 0
        for r in results
    )

    # The censoring cutoff every CVE was analysed with, and where it came from.
    # Results predating per-trial durations carry only `trial_duration`.
    def _result_duration(r):
        durs = r.get("trial_durations") or [
            r.get("trial_duration", config.TRIAL_DURATION_SECS)
        ]
        src = r.get("trial_duration_source", "unrecorded source")
        return format_duration(durs, src)

    cve_durations = [_result_duration(r) for r in results]
    mixed_durations = len(set(cve_durations)) > 1
    duration_line = (
        "MIXED across CVEs -- see each CVE below" if mixed_durations
        else (cve_durations[0] if cve_durations
              else format_duration([config.TRIAL_DURATION_SECS],
                                   _DURATION_SRC_LABELS[DURATION_SRC_CONFIG]))
    )
    used_config_default = any(
        _DURATION_SRC_LABELS[DURATION_SRC_CONFIG] in r.get("trial_duration_source", "")
        for r in results
    )
    trial_count = results[0].get("baseline_stats", {}).get("n", config.NUM_TRIALS) if results else config.NUM_TRIALS

    # Compute aggregate exec/s stats (secondary diagnostic only)
    eps_results = [r for r in results if "exec_s_speedup" in r]
    avg_eps_speedup = (
        sum(r["exec_s_speedup"] for r in eps_results) / len(eps_results)
        if eps_results else None
    )

    # Headline throughput metric: deterministic corpus-replay speedup.
    replay_results = [r for r in results if "replay_speedup" in r]
    avg_replay_speedup = (
        sum(r["replay_speedup"] for r in replay_results) / len(replay_results)
        if replay_results else None
    )

    report_lines = [
        f"# Benchmark Report: fold-deterministic-calls",
        f"",
        f"**Experiment ID**: {experiment_id}",
        f"**Trials per variant**: {trial_count}",
        f"**Duration per trial**: {duration_line}",
        f"**Engine**: {config.ENGINE}",
        f"**Sanitizer**: {config.SANITIZER}",
        f"",
    ]
    if used_config_default:
        report_lines.extend([
            f"> **WARNING**: no trial metadata recorded a run length, so trials "
            f"were censored at the config default "
            f"({config.TRIAL_DURATION_SECS / 3600:.1f}h). Any bug first found "
            f"after that is counted as NOT FOUND. Re-run with --duration set "
            f"to the real trial length.",
            f"",
        ])
    report_lines.extend([
        f"## Summary",
        f"",
        f"- **CVEs tested**: {len(results)}",
    ])

    # Lead with the headline throughput metric: deterministic corpus replay.
    if replay_results:
        report_lines.append(
            f"- **Avg replay speedup**: {avg_replay_speedup:.2f}x across "
            f"{len(replay_results)} projects (same corpus replayed on both binaries)"
        )
        rimproved = [r for r in replay_results if r["replay_speedup"] > 1.05]
        rregressed = [r for r in replay_results if r["replay_speedup"] < 0.95]
        report_lines.append(
            f"- **Replay improved**: {len(rimproved)}/{len(replay_results)} projects (>5% faster)"
        )
        if rregressed:
            report_lines.append(
                f"- **Replay regressed**: {len(rregressed)}/{len(replay_results)} projects (>5% slower)"
            )

    # Secondary diagnostic: live exec/s (confounded by coverage divergence).
    if eps_results:
        report_lines.append(f"- _(diagnostic)_ Avg live exec/s ratio: {avg_eps_speedup:.2f}x across {len(eps_results)} projects")

    if any_bugs:
        report_lines.extend([
            f"- **Statistically significant (p < 0.05)**: {len(significant)}/{len(results)}",
            f"- **Large effect size (A12 >= 0.71)**: {len(large_effect)}/{len(results)}",
        ])
    else:
        report_lines.append(f"- **Bugs found**: 0/{len(results)} CVEs (neither baseline nor optimized found bugs within {duration_line})")

    report_lines.extend([
        f"",
        f"## Results",
        f"",
        markdown_table,
        f"",
        f"## Per-CVE Details",
        f"",
    ])

    for r, cve_duration in zip(results, cve_durations):
        found_bug = r.get("baseline_found_bug", 0) > 0 or r.get("optimized_found_bug", 0) > 0

        report_lines.extend([
            f"### {r['project']} ({r['cve']})",
            f"",
        ])
        if mixed_durations or len(r.get("trial_durations") or []) > 1:
            report_lines.append(f"- Trial duration: {cve_duration}")

        # Lead with the headline deterministic replay speedup.
        if "replay_speedup" in r:
            bt = r.get("replay_baseline_time_s")
            ot = r.get("replay_optimized_time_s")
            timing = (
                f" ({bt:.2f}s → {ot:.2f}s on {r.get('replay_corpus_file_count', 0)} inputs)"
                if bt is not None and ot is not None else ""
            )
            report_lines.append(
                f"- **Replay speedup**: **{r['replay_speedup']:.2f}x**{timing}"
            )

        # Secondary diagnostic: live exec/s throughput.
        if "exec_s_speedup" in r:
            report_lines.extend([
                f"- _(diagnostic)_ Live throughput: {r.get('baseline_exec_s_median', 0):.0f} → {r.get('optimized_exec_s_median', 0):.0f} exec/s "
                f"({r['exec_s_speedup']:.2f}x)",
            ])

        # Bug-finding results
        report_lines.extend([
            f"- Baseline: found bug in {r['baseline_found_bug']}/{r['baseline_stats']['n']} trials",
            f"- Optimized: found bug in {r['optimized_found_bug']}/{r['optimized_stats']['n']} trials",
        ])

        if found_bug:
            report_lines.extend([
                f"- Time-to-bug speedup: {r.get('speedup', 'N/A')}x",
                f"  - Baseline median: {r['baseline_median']/3600:.2f}h "
                f"(n={r['baseline_stats']['n']}, std={r['baseline_stats']['std']/3600:.2f}h, "
                f"min={r['baseline_stats']['min']/3600:.2f}h, max={r['baseline_stats']['max']/3600:.2f}h)",
                f"  - Optimized median: {r['optimized_median']/3600:.2f}h "
                f"(n={r['optimized_stats']['n']}, std={r['optimized_stats']['std']/3600:.2f}h, "
                f"min={r['optimized_stats']['min']/3600:.2f}h, max={r['optimized_stats']['max']/3600:.2f}h)",
                f"- Mann-Whitney U p-value: {r['p_value']:.4f} (one-sided), {r['p_value_two_sided']:.4f} (two-sided)",
                f"- Vargha-Delaney A12: {r['a12']:.3f} ({r['a12_label']})",
            ])

        if "coverage_p_value" in r:
            report_lines.extend([
                f"- Coverage: baseline={r.get('baseline_final_edges_median', 0):.0f} edges, "
                f"optimized={r.get('optimized_final_edges_median', 0):.0f} edges "
                f"(p={r['coverage_p_value']:.4f})",
            ])

        report_lines.append("")

    # Write report
    report_path = os.path.join(report_dir, "report.md")
    with open(report_path, "w") as f:
        f.write("\n".join(report_lines))
    logger.info("Wrote report to %s", report_path)

    # Write LaTeX table
    latex_path = os.path.join(report_dir, "table.tex")
    with open(latex_path, "w") as f:
        f.write(latex_table)
    logger.info("Wrote LaTeX table to %s", latex_path)

    # Write raw results JSON
    results_path = os.path.join(report_dir, "results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info("Wrote raw results to %s", results_path)


def main():
    parser = argparse.ArgumentParser(description="Phase 4: Statistical Analysis")
    parser.add_argument(
        "--manifest", default=config.MANIFEST_PATH,
        help="Path to manifest.json",
    )
    parser.add_argument(
        "--experiment-id", required=True,
        help="Experiment ID",
    )
    parser.add_argument(
        "--duration", type=int, default=None,
        help=(
            "Time-to-bug censoring cutoff in seconds: crashes at/after it are "
            "ignored. Default: the run length each trial recorded in its "
            "metadata.json (falling back to the longest recorded, then "
            f"{config.TRIAL_DURATION_SECS}s with a warning). Set it only to "
            "override, e.g. to truncate a 24h campaign at 6h."
        ),
    )
    parser.add_argument(
        "--output-dir", default=None,
        help="Report output directory (default: results/<experiment_id>/report)",
    )
    parser.add_argument(
        "--project", default=None,
        help="Only analyze a specific project",
    )
    args = parser.parse_args()
    if args.duration is not None and args.duration <= 0:
        parser.error("--duration must be a positive number of seconds")

    with open(args.manifest) as f:
        manifest = json.load(f)

    if args.project:
        manifest = [e for e in manifest if e["project"] == args.project]

    report_dir = args.output_dir or os.path.join(
        config.RESULTS_DIR, args.experiment_id, "report"
    )

    logger.info("Loading trial data for experiment %s...", args.experiment_id)
    all_data = load_trial_data(args.experiment_id, manifest, duration=args.duration)

    # Analyze each CVE
    results = []
    for key, data in all_data.items():
        logger.info("Analyzing %s...", key)
        result = analyze_cve(key, data, report_dir, duration=args.duration)
        if result:
            results.append(result)

    if not results:
        logger.error("No results to analyze")
        sys.exit(1)

    # Generate report
    generate_report(results, report_dir, args.experiment_id)

    # Print summary
    print(f"\n=== Analysis Summary ===")
    print(f"  CVEs analyzed: {len(results)}")
    for r in results:
        sig = "*" if r["p_value"] < 0.05 else " "
        print(
            f"  {sig} {r['project']}: "
            f"speedup={r.get('speedup', 'N/A')}x, "
            f"p={r['p_value']:.4f}, "
            f"A12={r['a12']:.3f} ({r['a12_label']}), "
            f"duration={format_duration(r['trial_durations'], r['trial_duration_source'])}"
        )
    print(f"\n  Report: {report_dir}/report.md")
    print()


if __name__ == "__main__":
    main()
