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
from lib import stats_util

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


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
        with open(log_path) as lf:
            log_text = lf.read()

        progress_execs = re.findall(r"exec/s:\s*(\d+)", log_text)
        if progress_execs:
            last_progress_exec_s = int(progress_execs[-1])
            if last_progress_exec_s > 0:
                return float(last_progress_exec_s)

        avg_match = re.search(r"stat::average_exec_per_sec:\s*(\d+)", log_text)
        if avg_match:
            avg_exec_s = int(avg_match.group(1))
            if avg_exec_s > 0:
                return float(avg_exec_s)

    return 0.0


def load_trial_data(
    experiment_id: str, manifest: list[dict],
    duration: int = None,
) -> dict[str, dict]:
    """Load all trial data for an experiment.

    Returns dict keyed by "{project}-{cve}" with structure:
    {
        "baseline": {"times": [...], "exec_s": [...], "coverage": [...]},
        "optimized": {"times": [...], "exec_s": [...], "coverage": [...]},
    }
    """
    results = {}

    for entry in manifest:
        project = entry["project"]
        cve = entry["cve"]
        key = f"{project}-{cve}"
        crash_type = entry.get("crash_type", "")

        data = {
            "baseline": {
                "times": [],
                "exec_s": [],
                "coverage": [],
                "trial_data": [],
            },
            "optimized": {
                "times": [],
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

                # Load metadata for exec/s and duration detection
                metadata_path = os.path.join(trial_dir, "metadata.json")
                trial_duration = duration or config.TRIAL_DURATION_SECS
                if os.path.exists(metadata_path):
                    with open(metadata_path) as f:
                        metadata = json.load(f)
                    exec_s = extract_execs_per_second(metadata, trial_dir)
                    data[variant]["exec_s"].append(exec_s)
                    data[variant]["trial_data"].append(metadata)
                    # Detect actual duration from metadata
                    if duration is None:
                        meta_duration = metadata.get("duration_seconds")
                        if meta_duration:
                            trial_duration = int(meta_duration)

                # Find time to the target bug
                time_to_bug = find_time_to_target_bug(
                    crash_times, crash_type, trial_dir,
                    trial_duration=trial_duration,
                )
                data[variant]["times"].append(time_to_bug)

                # Load coverage data if available
                coverage = load_coverage_data(trial_dir)
                if coverage:
                    data[variant]["coverage"].append(coverage)

        # Validate: log trial counts
        for variant in ["baseline", "optimized"]:
            n = len(data[variant]["times"])
            if n == 0:
                logger.warning("%s/%s: no trials for %s", project, cve, variant)
            else:
                logger.info("%s/%s: %d trials for %s", project, cve, n, variant)

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

    return results


def find_time_to_target_bug(
    crash_times: list[dict],
    target_crash_type: str,
    trial_dir: str,
    trial_duration: int = None,
) -> float:
    """Find the time to the first crash matching the target bug.

    If no matching crash is found, returns the censored value (trial duration).
    """
    censored = float(trial_duration or config.TRIAL_DURATION_SECS)
    if not crash_times:
        return censored

    # First, try to match by crash type
    for crash in sorted(crash_times, key=lambda c: c["timestamp_s"]):
        ct = crash.get("crash_type", "")

        # If we have the crash type, try to match
        if target_crash_type:
            if matches_crash_type(ct, target_crash_type):
                return crash["timestamp_s"]

            # Also check by re-analyzing the crash artifact
            artifact = crash.get("artifact", "")
            artifact_path = os.path.join(
                trial_dir, "crashes", artifact
            )
            if os.path.exists(artifact_path):
                analyzed_type = analyze_crash_artifact(artifact_path, trial_dir)
                if matches_crash_type(analyzed_type, target_crash_type):
                    return crash["timestamp_s"]
        else:
            # No target type specified; any crash counts
            if ct not in ("oom", "timeout"):
                return crash["timestamp_s"]

    return censored


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

    # Detect actual trial duration from the data
    trial_dur = duration or config.TRIAL_DURATION_SECS
    # If all times equal a round number, that's likely the censored duration
    all_times = baseline_times + optimized_times
    max_time = max(all_times) if all_times else trial_dur
    if max_time < trial_dur:
        trial_dur = int(max_time) if max_time == int(max_time) else trial_dur

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
            1 for t in baseline_times if t < trial_dur
        ),
        "optimized_found_bug": sum(
            1 for t in optimized_times if t < trial_dur
        ),
        "trial_duration": trial_dur,
    }

    # Generate plots
    project_report_dir = os.path.join(report_dir, key)
    os.makedirs(project_report_dir, exist_ok=True)

    # Time-to-bug box plot
    stats_util.plot_time_to_bug_boxplot(
        optimized_times, baseline_times,
        title=f"Time to Bug: {key}",
        output_path=os.path.join(project_report_dir, "time_to_bug_boxplot.png"),
    )

    # Survival curve
    stats_util.plot_survival_curve(
        optimized_times, baseline_times,
        title=f"Survival Curve: {key}",
        output_path=os.path.join(project_report_dir, "survival_curve.png"),
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

    # Detect actual trial duration from results
    trial_dur = results[0].get("trial_duration", config.TRIAL_DURATION_SECS) if results else config.TRIAL_DURATION_SECS
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
        f"**Duration per trial**: {trial_dur / 3600:.1f} hours",
        f"**Engine**: {config.ENGINE}",
        f"**Sanitizer**: {config.SANITIZER}",
        f"",
        f"## Summary",
        f"",
        f"- **CVEs tested**: {len(results)}",
    ]

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
        report_lines.append(f"- **Bugs found**: 0/{len(results)} CVEs (neither baseline nor optimized found bugs in {trial_dur/3600:.1f}h)")

    report_lines.extend([
        f"",
        f"## Results",
        f"",
        markdown_table,
        f"",
        f"## Per-CVE Details",
        f"",
    ])

    for r in results:
        cve_dur = r.get("trial_duration", config.TRIAL_DURATION_SECS)
        found_bug = r.get("baseline_found_bug", 0) > 0 or r.get("optimized_found_bug", 0) > 0

        report_lines.extend([
            f"### {r['project']} ({r['cve']})",
            f"",
        ])

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
        "--duration", type=int, default=config.TRIAL_DURATION_SECS,
        help=f"Trial duration in seconds (default: {config.TRIAL_DURATION_SECS})",
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
            f"A12={r['a12']:.3f} ({r['a12_label']})"
        )
    print(f"\n  Report: {report_dir}/report.md")
    print()


if __name__ == "__main__":
    main()
