"""Statistical analysis utilities for benchmark results.

Implements Mann-Whitney U test, Vargha-Delaney A12 effect size,
and survival analysis (Kaplan-Meier + log-rank) for time-to-bug data.
"""

import logging
import os
from typing import Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
import numpy as np
import seaborn as sns
from scipy import stats

logger = logging.getLogger(__name__)


def mann_whitney_u(
    optimized: list[float],
    baseline: list[float],
    alternative: str = "less",
) -> tuple[float, float]:
    """Perform Mann-Whitney U test.

    Args:
        optimized: Time-to-bug values for optimized variant.
        baseline: Time-to-bug values for baseline variant.
        alternative: 'less' (optimized < baseline), 'two-sided', or 'greater'.

    Returns:
        (U statistic, p-value)
    """
    u_stat, p_value = stats.mannwhitneyu(
        optimized, baseline, alternative=alternative
    )
    return float(u_stat), float(p_value)


def vargha_delaney_a12(optimized: list[float], baseline: list[float]) -> float:
    """Compute Vargha-Delaney A12 effect size.

    A12 > 0.5 means optimized tends to have smaller values (faster time-to-bug).
    Effect size interpretation:
        A12 > 0.56: small effect
        A12 > 0.64: medium effect
        A12 > 0.71: large effect

    Returns:
        A12 statistic in [0, 1].
    """
    m = len(optimized)
    n = len(baseline)

    if m == 0 or n == 0:
        return 0.5

    count = 0
    for o in optimized:
        for b in baseline:
            if o < b:
                count += 1
            elif o == b:
                count += 0.5

    return count / (m * n)


def a12_effect_label(a12: float) -> str:
    """Classify A12 effect size."""
    if a12 >= 0.71:
        return "large"
    if a12 >= 0.64:
        return "medium"
    if a12 >= 0.56:
        return "small"
    if a12 <= 0.29:
        return "large (negative)"
    if a12 <= 0.36:
        return "medium (negative)"
    if a12 <= 0.44:
        return "small (negative)"
    return "negligible"


def compute_speedup(
    optimized: list[float], baseline: list[float]
) -> Optional[float]:
    """Compute median speedup ratio.

    Returns:
        Ratio of baseline_median / optimized_median (>1 means optimized is faster).
        None if optimized median is 0.
    """
    opt_median = float(np.median(optimized))
    base_median = float(np.median(baseline))

    if opt_median == 0:
        return None
    return base_median / opt_median


def summary_stats(values: list[float]) -> dict:
    """Compute summary statistics for a list of values."""
    arr = np.array(values)
    return {
        "n": len(values),
        "mean": float(np.mean(arr)),
        "median": float(np.median(arr)),
        "std": float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0,
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "q25": float(np.percentile(arr, 25)),
        "q75": float(np.percentile(arr, 75)),
    }


def plot_time_to_bug_boxplot(
    optimized: list[float],
    baseline: list[float],
    title: str,
    output_path: str,
    duration_secs: int = 86400,
):
    """Create box plot comparing time-to-bug between variants."""
    fig, ax = plt.subplots(figsize=(8, 5))

    data = [baseline, optimized]
    labels = ["Baseline", "Optimized"]
    colors = ["#4C72B0", "#DD8452"]

    bp = ax.boxplot(data, labels=labels, patch_artist=True, widths=0.5)
    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)

    ax.set_ylabel("Time to Bug (seconds)")
    ax.set_title(title)
    ax.axhline(y=duration_secs, color="red", linestyle="--", alpha=0.5, label="24h limit")
    ax.legend()

    # Convert y-axis to hours
    ax.set_ylabel("Time to Bug (hours)")
    ax.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value/3600:.1f}"))

    plt.tight_layout()
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    logger.info("Saved box plot to %s", output_path)


def plot_coverage_over_time(
    optimized_coverage: list[list[tuple[float, int]]],
    baseline_coverage: list[list[tuple[float, int]]],
    title: str,
    output_path: str,
):
    """Plot coverage over time with median and IQR bands.

    Args:
        optimized_coverage: List of trials, each a list of (time_s, edge_count) tuples.
        baseline_coverage: Same format for baseline.
    """
    fig, ax = plt.subplots(figsize=(10, 6))

    for data, label, color in [
        (baseline_coverage, "Baseline", "#4C72B0"),
        (optimized_coverage, "Optimized", "#DD8452"),
    ]:
        if not data:
            continue

        # Interpolate all trials to common time points
        max_time = max(max(t for t, _ in trial) for trial in data if trial)
        time_points = np.linspace(0, max_time, 200)
        interpolated = []

        for trial in data:
            if not trial:
                continue
            times = [t for t, _ in trial]
            edges = [e for _, e in trial]
            interp = np.interp(time_points, times, edges)
            interpolated.append(interp)

        if not interpolated:
            continue

        matrix = np.array(interpolated)
        median = np.median(matrix, axis=0)
        q25 = np.percentile(matrix, 25, axis=0)
        q75 = np.percentile(matrix, 75, axis=0)

        hours = time_points / 3600
        ax.plot(hours, median, label=label, color=color)
        ax.fill_between(hours, q25, q75, alpha=0.2, color=color)

    ax.set_xlabel("Time (hours)")
    ax.set_ylabel("Edge Coverage")
    ax.set_title(title)
    ax.legend()

    plt.tight_layout()
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    logger.info("Saved coverage plot to %s", output_path)


def plot_execs_per_sec(
    optimized_eps: list[float],
    baseline_eps: list[float],
    title: str,
    output_path: str,
):
    """Create bar chart comparing exec/s between variants."""
    fig, ax = plt.subplots(figsize=(6, 5))

    means = [np.mean(baseline_eps), np.mean(optimized_eps)]
    stds = [np.std(baseline_eps, ddof=1) if len(baseline_eps) > 1 else 0,
            np.std(optimized_eps, ddof=1) if len(optimized_eps) > 1 else 0]
    colors = ["#4C72B0", "#DD8452"]
    labels = ["Baseline", "Optimized"]

    bars = ax.bar(labels, means, yerr=stds, color=colors, alpha=0.7, capsize=5)

    ax.set_ylabel("Executions per Second")
    ax.set_title(title)

    # Add value labels on bars
    for bar, mean in zip(bars, means):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{mean:.0f}",
            ha="center",
            va="bottom",
        )

    plt.tight_layout()
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    logger.info("Saved exec/s plot to %s", output_path)


def plot_survival_curve(
    optimized: list[float],
    baseline: list[float],
    title: str,
    output_path: str,
    duration_secs: int = 86400,
):
    """Plot Kaplan-Meier survival curves using lifelines (if available).

    Falls back to simple empirical survival curve if lifelines not installed.
    """
    fig, ax = plt.subplots(figsize=(10, 6))

    try:
        from lifelines import KaplanMeierFitter
        from lifelines.statistics import logrank_test

        # Create event data (1 = found bug, 0 = censored at duration limit)
        for data, label, color in [
            (baseline, "Baseline", "#4C72B0"),
            (optimized, "Optimized", "#DD8452"),
        ]:
            times = np.array(data)
            events = (times < duration_secs).astype(int)
            kmf = KaplanMeierFitter()
            kmf.fit(times, event_observed=events, label=label)
            kmf.plot_survival_function(ax=ax, color=color)

        # Log-rank test
        opt_times = np.array(optimized)
        base_times = np.array(baseline)
        opt_events = (opt_times < duration_secs).astype(int)
        base_events = (base_times < duration_secs).astype(int)
        lr = logrank_test(opt_times, base_times, opt_events, base_events)
        ax.text(
            0.95, 0.95,
            f"Log-rank p = {lr.p_value:.4f}",
            transform=ax.transAxes,
            ha="right", va="top",
            fontsize=10,
            bbox=dict(boxstyle="round", facecolor="wheat", alpha=0.5),
        )

    except ImportError:
        logger.warning("lifelines not installed, using simple survival curve")
        for data, label, color in [
            (baseline, "Baseline", "#4C72B0"),
            (optimized, "Optimized", "#DD8452"),
        ]:
            sorted_times = np.sort(data)
            n = len(sorted_times)
            survival = np.arange(n, 0, -1) / n
            ax.step(sorted_times / 3600, survival, where="post",
                    label=label, color=color)

    ax.set_xlabel("Time (hours)")
    ax.set_ylabel("Survival Probability (bug not found)")
    ax.set_title(title)
    ax.legend()

    plt.tight_layout()
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    logger.info("Saved survival curve to %s", output_path)


def generate_summary_table(results: list[dict]) -> tuple[str, str]:
    """Generate summary table in markdown and LaTeX formats.

    Args:
        results: List of per-CVE result dicts with keys:
            project, cve, baseline_median, optimized_median,
            speedup, p_value, a12, a12_label

    Returns:
        (markdown_table, latex_table)
    """
    # Check if any bugs were found across all results
    any_bugs = any(
        r.get("baseline_found_bug", 0) > 0 or r.get("optimized_found_bug", 0) > 0
        for r in results
    )

    # Markdown — include exec/s columns always, time-to-bug only when bugs found
    if any_bugs:
        md_lines = [
            "| Project | CVE | Base Med (h) | Opt Med (h) | TTB Speedup | p-value | A12 | Effect | Base exec/s | Opt exec/s | Exec/s Speedup |",
            "|---------|-----|------------:|------------:|------------:|--------:|----:|--------|------------:|-----------:|---------------:|",
        ]
    else:
        md_lines = [
            "| Project | CVE | Base exec/s | Opt exec/s | Exec/s Speedup | Bugs Found (Base) | Bugs Found (Opt) |",
            "|---------|-----|------------:|-----------:|---------------:|------------------:|-----------------:|",
        ]

    for r in results:
        base_eps = r.get("baseline_exec_s_median", 0)
        opt_eps = r.get("optimized_exec_s_median", 0)
        eps_speedup = r.get("exec_s_speedup", "N/A")
        if isinstance(eps_speedup, (int, float)):
            eps_speedup = f"{eps_speedup:.2f}x"

        if any_bugs:
            md_lines.append(
                f"| {r['project']} | {r['cve']} | "
                f"{r['baseline_median']/3600:.2f} | {r['optimized_median']/3600:.2f} | "
                f"{r.get('speedup', 'N/A')}x | {r['p_value']:.4f} | "
                f"{r['a12']:.3f} | {r['a12_label']} | "
                f"{base_eps:.0f} | {opt_eps:.0f} | {eps_speedup} |"
            )
        else:
            n_base = r.get("baseline_stats", {}).get("n", "?")
            n_opt = r.get("optimized_stats", {}).get("n", "?")
            md_lines.append(
                f"| {r['project']} | {r['cve']} | "
                f"{base_eps:.0f} | {opt_eps:.0f} | {eps_speedup} | "
                f"{r.get('baseline_found_bug', 0)}/{n_base} | "
                f"{r.get('optimized_found_bug', 0)}/{n_opt} |"
            )
    markdown = "\n".join(md_lines)

    # LaTeX
    if any_bugs:
        tex_header = r"Project & CVE & Base (h) & Opt (h) & TTB Speedup & p-value & A12 & Effect & Base exec/s & Opt exec/s & Exec/s $\times$ \\"
        tex_cols = r"\begin{tabular}{llrrrrrlrrr}"
    else:
        tex_header = r"Project & CVE & Base exec/s & Opt exec/s & Exec/s $\times$ & Bugs (Base) & Bugs (Opt) \\"
        tex_cols = r"\begin{tabular}{llrrrll}"

    tex_lines = [
        r"\begin{table}[h]",
        r"\centering",
        r"\caption{fold-deterministic-calls Benchmark Results}",
        tex_cols,
        r"\toprule",
        tex_header,
        r"\midrule",
    ]
    for r in results:
        base_eps = r.get("baseline_exec_s_median", 0)
        opt_eps = r.get("optimized_exec_s_median", 0)
        eps_speedup = r.get("exec_s_speedup", "N/A")
        if isinstance(eps_speedup, (int, float)):
            eps_str = f"{eps_speedup:.2f}$\\times$"
        else:
            eps_str = "N/A"

        if any_bugs:
            tex_lines.append(
                f"{r['project']} & {r['cve']} & "
                f"{r['baseline_median']/3600:.2f} & {r['optimized_median']/3600:.2f} & "
                f"{r.get('speedup', 'N/A')}$\\times$ & {r['p_value']:.4f} & "
                f"{r['a12']:.3f} & {r['a12_label']} & "
                f"{base_eps:.0f} & {opt_eps:.0f} & {eps_str} \\\\"
            )
        else:
            n_base = r.get("baseline_stats", {}).get("n", "?")
            n_opt = r.get("optimized_stats", {}).get("n", "?")
            tex_lines.append(
                f"{r['project']} & {r['cve']} & "
                f"{base_eps:.0f} & {opt_eps:.0f} & {eps_str} & "
                f"{r.get('baseline_found_bug', 0)}/{n_base} & "
                f"{r.get('optimized_found_bug', 0)}/{n_opt} \\\\"
            )
    tex_lines += [
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    latex = "\n".join(tex_lines)

    return markdown, latex
