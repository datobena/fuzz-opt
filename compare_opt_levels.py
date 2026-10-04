#!/usr/bin/env python3
"""Compare two online campaigns that differ in -O level and/or experiment design.

Built for the specific question behind online-24h-c1: how much of the optimizer's
measured speedup is headroom the COMPILER already had? b1..b6 built both arms at
the OSS-Fuzz default (-O1), so an optimizer win there was measured against a
baseline the compiler had not finished optimizing. Rebuilding both arms at -O3
and re-running the same project answers it directly.

Three numbers come out, and they answer different things:

  1. -O3 effect          c1-baseline  vs  b1-baseline
     What the compiler alone buys. Neither arm has an optimizer edit in it.
  2. optimizer effect    optimized    vs  baseline, WITHIN each campaign
     What the optimizer buys on top of whatever the compiler did.
  3. margin retention    (2) at -O3   vs  (2) at -O1
     If the optimizer's margin collapses at -O3, its wins were largely
     transformations -O2/-O3 already perform.

A CAVEAT THE OUTPUT REPEATS, because it changes how (2) may be read for b1..b6:
those campaigns ran ONE optimizer and hot-swapped ONE binary into all N optimized
trials. Every optimized trial ran an identical binary, so the spread across them
is AFL's randomness, not the optimizer's -- the arm is one draw reported as N. A
Mann-Whitney over it is not a test of the optimizer, and its p-value is reported
here only to be comparable with the older analysis, never as evidence.
Per-trial campaigns (design.per_trial_optimizer) do not have this problem.

Usage:
    python3 compare_opt_levels.py --baseline-run online-24h-b1-libxml2 \
                                  --treatment-run online-24h-c1-libxml2
"""
from __future__ import annotations

import argparse
import json
import os
import statistics as st
import sys

import config
from lib import stats_util

# final_exec_s is AFL's own execs_per_sec at the end of the run. total_execs and
# edges_found are cumulative. corpus_size is the queue size, which is what makes
# exec/s comparable across runs at all -- a bigger corpus means bigger inputs
# and a lower rate, so a rate difference between runs with very different corpus
# sizes is not purely a codegen difference.
METRICS = ("final_exec_s", "total_execs", "edges_found", "corpus_size")


def load_run(experiment_id: str) -> dict:
    """Load one campaign's per-arm metric vectors plus its design provenance."""
    base = os.path.join(config.RESULTS_DIR, experiment_id)
    results_path = os.path.join(base, "trial_results.json")
    if not os.path.isfile(results_path):
        raise SystemExit(f"no trial_results.json for {experiment_id} ({results_path})")
    with open(results_path) as f:
        rows = json.load(f)

    arms: dict[str, dict[str, list[float]]] = {
        "baseline": {m: [] for m in METRICS},
        "optimized": {m: [] for m in METRICS},
    }
    for r in rows:
        name = r.get("trial", "")
        arm = "baseline" if "baseline" in name else "optimized" if "optimized" in name else None
        stats = r.get("final_stats") or {}
        if arm is None or not stats:
            continue
        for m in METRICS:
            try:
                arms[arm][m].append(float(stats.get(m) or 0.0))
            except (TypeError, ValueError):
                pass

    # Design + -O level, when the campaign recorded them. b1..b6 predate both
    # fields, so absence means "legacy shared-binary design at the default -O1"
    # rather than "unknown" -- but say so explicitly rather than assuming.
    design, opt_level = {}, None
    for root, _dirs, files in os.walk(base):
        if "campaign_provenance.json" in files:
            try:
                with open(os.path.join(root, "campaign_provenance.json")) as f:
                    prov = json.load(f)
                design = prov.get("design") or {}
                opt_level = prov.get("build_opt_level")
            except (OSError, json.JSONDecodeError):
                pass
            break
    return {"id": experiment_id, "arms": arms, "design": design,
            "opt_level": opt_level}


def _med(v: list[float]) -> float:
    return st.median(v) if v else float("nan")


def _ratio(new: list[float], old: list[float]) -> float:
    a, b = _med(new), _med(old)
    return (a / b) if b else float("nan")


def _compare(label: str, treat: list[float], base: list[float],
             *, suspect: bool = False) -> str:
    """One comparison line: medians, ratio, Mann-Whitney p, and A12 effect size."""
    if not treat or not base:
        return f"  {label:<34} (insufficient data)"
    ratio = _ratio(treat, base)
    # DIRECTION. stats_util is written for TIME-TO-BUG, where LOWER is better:
    # mann_whitney_u defaults to alternative="less", and vargha_delaney_a12
    # counts (optimized < baseline), so A12 > 0.5 means "smaller values".
    # Every metric here is the opposite -- exec/s, total_execs, edges_found and
    # corpus_size are all higher-is-better. Calling them in the natural argument
    # order reports a 4.58x SPEEDUP as A12=0.00 "large (negative)" with p=0.9999.
    # So: ask for "greater" explicitly, and swap the A12 arguments so that
    # A12 > 0.5 continues to read as "the treatment is better".
    try:
        p = stats_util.mann_whitney_u(treat, base, alternative="greater")
        p = p[1] if isinstance(p, (tuple, list)) else p
    except Exception:  # noqa: BLE001 - a stats failure must not kill the report
        p = float("nan")
    try:
        a12 = stats_util.vargha_delaney_a12(base, treat)   # swapped on purpose
        eff = stats_util.a12_effect_label(a12)
    except Exception:  # noqa: BLE001
        a12, eff = float("nan"), "?"
    flag = "  [!] one-draw arm" if suspect else ""
    return (f"  {label:<34} {_med(treat):>14,.1f} vs {_med(base):>14,.1f}  "
            f"ratio={ratio:>6.2f}x  p={p:<8.4g} A12={a12:.2f} ({eff}){flag}")


def _one_draw(run: dict) -> bool:
    """True when the optimized arm is N copies of a single optimizer draw."""
    d = run.get("design") or {}
    # Explicit per-trial campaigns are fine. Anything without the field predates
    # the per-trial design and therefore WAS shared-binary.
    return not bool(d.get("per_trial_optimizer"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline-run", required=True,
                    help="reference campaign (e.g. the -O1 run)")
    ap.add_argument("--treatment-run", required=True,
                    help="campaign under test (e.g. the -O3 run)")
    args = ap.parse_args()

    old = load_run(args.baseline_run)
    new = load_run(args.treatment_run)

    def _describe(r: dict) -> str:
        d = r.get("design") or {}
        lvl = r.get("opt_level")
        lvl = f"-{lvl}" if lvl else "-O1 (default, not recorded)"
        shape = ("per-trial optimizers x%s" % d.get("optimizers")
                 if d.get("per_trial_optimizer") else "shared binary, 1 optimizer")
        n = len(r["arms"]["baseline"]["final_exec_s"])
        return f"{r['id']}: {lvl}, {shape}, n={n}/arm"

    print("=" * 100)
    print("REFERENCE:", _describe(old))
    print("TREATMENT:", _describe(new))
    print("=" * 100)

    print("\n[1] -O3 EFFECT -- compiler alone, no optimizer edit in either arm")
    for m in METRICS:
        print(_compare(m, new["arms"]["baseline"][m], old["arms"]["baseline"][m]))

    print(f"\n[2a] OPTIMIZER EFFECT within {old['id']}")
    for m in METRICS:
        print(_compare(m, old["arms"]["optimized"][m], old["arms"]["baseline"][m],
                       suspect=_one_draw(old)))

    print(f"\n[2b] OPTIMIZER EFFECT within {new['id']}")
    for m in METRICS:
        print(_compare(m, new["arms"]["optimized"][m], new["arms"]["baseline"][m],
                       suspect=_one_draw(new)))

    print("\n[3] MARGIN RETENTION -- does the optimizer's win survive -O3?")
    for m in ("final_exec_s", "total_execs"):
        r_old = _ratio(old["arms"]["optimized"][m], old["arms"]["baseline"][m])
        r_new = _ratio(new["arms"]["optimized"][m], new["arms"]["baseline"][m])
        keep = (r_new - 1.0) / (r_old - 1.0) if r_old > 1.0 else float("nan")
        print(f"  {m:<34} {r_old:>6.2f}x  ->  {r_new:>6.2f}x   "
              f"margin retained: {keep*100:>6.1f}%")

    if _one_draw(old) or _one_draw(new):
        print("\n[!] At least one campaign used the shared-binary design: its optimized")
        print("    trials all ran the SAME binary, so that arm is ONE optimizer draw")
        print("    reported as n. Its p-value is not evidence about the optimizer;")
        print("    only the median ratio is meaningful, and only as a point estimate.")

    # Corpus sizes gate whether the exec/s comparison means anything at all.
    cb, ct = _med(old["arms"]["baseline"]["corpus_size"]), _med(new["arms"]["baseline"]["corpus_size"])
    if cb and ct and not (0.5 <= ct / cb <= 2.0):
        print(f"\n[!] Baseline corpus sizes differ by {ct/cb:.2f}x ({cb:,.0f} -> {ct:,.0f}).")
        print("    exec/s is input-size sensitive, so the rate comparison above is")
        print("    NOT purely a codegen difference. Prefer total_execs and edges_found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
