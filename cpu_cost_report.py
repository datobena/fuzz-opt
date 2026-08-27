#!/usr/bin/env python3
"""Report the CPU cost of online optimization, for the coverage-plot timeline.

Reads the per-target ``cpu_ledger.jsonl`` an online campaign writes and reports
what the optimization would have cost had it run on the fuzzing cores, in
core-seconds and in the fuzzing wall-clock those core-seconds represent.

    python3 cpu_cost_report.py --experiment-id online-24h-libxml2
    python3 cpu_cost_report.py --ledger results/<exp>/<cve>/online/cpu_ledger.jsonl
    python3 cpu_cost_report.py --experiment-id <exp> --json   # for the plotter

``fuzz_seconds_equivalent`` is the number to overlay: core-seconds divided by
the online arm's trial count. With 9 online trials, a round costing 900
core-seconds set the arm back 100 seconds of wall-clock fuzzing -- which is what
a coverage-vs-time comparison against the baseline arm has to account for.

The agent's model-wait time is reported separately and never enters the cost.
It is in the ledger so a round's wall-clock stays reconstructable, but it burns
no CPU that fuzzing could have used.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import config
from lib import cpu_ledger


def find_ledgers(experiment_id: str) -> list[Path]:
    """Every per-target ledger under one experiment.

    The real layout is <target>/optimized/online/ -- the online dir lives under
    the OPTIMIZED variant, because that is the arm being optimized. rglob is the
    fallback rather than the primary so a stray ledger copied into results/ does
    not get reported as a target, while a layout change still surfaces something
    instead of "no cpu_ledger.jsonl", which reads as "the run recorded nothing".
    """
    root = Path(config.RESULTS_DIR) / experiment_id
    found = sorted(root.glob("*/optimized/online/cpu_ledger.jsonl"))
    return found or sorted(root.rglob("cpu_ledger.jsonl"))


def _fmt_hms(seconds: float) -> str:
    seconds = int(round(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h:d}h{m:02d}m{s:02d}s" if h else f"{m:d}m{s:02d}s"


def _recorded_trial_cores(experiment_id: str | None) -> int | None:
    """The trial count the campaign itself wrote alongside its ledger."""
    if not experiment_id:
        return None
    found = set()
    for f in (Path(config.RESULTS_DIR) / experiment_id).glob(
            "*/optimized/online/cpu_cost.json"):
        try:
            tc = json.loads(f.read_text()).get("trial_cores")
        except (OSError, json.JSONDecodeError):
            continue
        if tc:
            found.add(int(tc))
    # Differing values across targets would make one shared divisor wrong.
    return found.pop() if len(found) == 1 else None


def report_one(ledger: Path, trial_cores: int | None,
               charge: str = "per-replicate") -> dict:
    rows = cpu_ledger.load(ledger)
    summary = cpu_ledger.summarize(rows, trial_cores=trial_cores, charge=charge)
    summary["ledger"] = str(ledger)
    # <target>/optimized/online/cpu_ledger.jsonl -- three levels up, not two.
    # Two lands on "optimized", so every target in a multi-target experiment
    # printed under the same heading.
    summary["target"] = ledger.parent.parent.parent.name
    return summary


def print_human(summary: dict) -> None:
    tc = summary.get("trial_cores")
    print(f"\n=== {summary['target']} ===")
    print(f"  total optimization CPU : {summary['total_core_s']:.0f} core-seconds "
          f"({_fmt_hms(summary['total_core_s'])} of one core)")
    if tc:
        eq = summary["total_fuzz_seconds_equivalent"]
        print(f"  as lost fuzzing time   : {_fmt_hms(eq)} across {tc} online trials")

    print("\n  by stage (core-seconds):")
    for stage, cs in summary["by_stage"].items():
        if cs <= 0:
            continue
        pct = 100.0 * cs / summary["total_core_s"] if summary["total_core_s"] else 0.0
        print(f"    {stage:<22} {cs:>12.0f}  {pct:5.1f}%")

    agent = sum(r.get("agent_wait_s", 0.0) for r in summary["rounds"])
    if agent:
        print(f"\n  agent model-wait (NOT counted as CPU): {_fmt_hms(agent)}")
    # Uncounted-but-not-model-wait: today that is the shared baseline AFL build,
    # which both arms start from and so is not a cost of optimizing.
    other = sum(r.get("uncounted_wall_s", 0.0) for r in summary["rounds"]) - agent
    if other > 0.5:
        print(f"  shared setup, both arms (NOT counted as CPU): {_fmt_hms(other)}")

    print("\n  per round:")
    hdr = f"    {'iter':>4} {'core-s':>10} {'cumul':>11}"
    if tc:
        hdr += f" {'lost fuzz':>11} {'cumul lost':>11}"
    print(hdr)
    for b in summary["rounds"]:
        line = (f"    {str(b['iter']):>4} {b['core_s']:>10.0f} "
                f"{b['cumulative_core_s']:>11.0f}")
        if tc:
            line += (f" {_fmt_hms(b['fuzz_seconds_equivalent']):>11}"
                     f" {_fmt_hms(b['cumulative_fuzz_seconds_equivalent']):>11}")
        print(line)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--experiment-id", help="report every target in this experiment")
    ap.add_argument("--ledger", help="report one cpu_ledger.jsonl")
    ap.add_argument("--trial-cores", type=int, default=None,
                    help="online trials per target (default: config.NUM_TRIALS)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    ap.add_argument("--charge", choices=("per-replicate", "as-run"),
                    default="per-replicate",
                    help="per-replicate (default): every trial pays the FULL "
                         "optimizer cost, because each is a replicate of a "
                         "campaign that would run its own. as-run: divide by "
                         "trial_cores, i.e. what this machine actually spent.")
    args = ap.parse_args()

    if not args.experiment_id and not args.ledger:
        ap.error("need --experiment-id or --ledger")

    # Prefer the divisor the CAMPAIGN recorded. config.NUM_TRIALS is the default
    # (10), not what ran -- the launcher passes NUM_TRIALS=9 through the
    # environment, so a later shell reporting on finished results picks up 10 and
    # understates every charge by 10%. cpu_cost.json stores trial_cores at write
    # time; that is the only value that describes the run being reported on.
    trial_cores = args.trial_cores or _recorded_trial_cores(args.experiment_id)
    if not trial_cores:
        trial_cores = int(getattr(config, "NUM_TRIALS", 0)) or None
        if trial_cores:
            print(f"  note: no recorded trial_cores; falling back to "
                  f"config.NUM_TRIALS={trial_cores}")

    if args.ledger:
        ledgers = [Path(args.ledger)]
    else:
        ledgers = find_ledgers(args.experiment_id)
        if not ledgers:
            print(f"no cpu_ledger.jsonl under {config.RESULTS_DIR}/{args.experiment_id}",
                  file=sys.stderr)
            return 1

    summaries = []
    for path in ledgers:
        if not path.exists():
            print(f"missing: {path}", file=sys.stderr)
            continue
        summaries.append(report_one(path, trial_cores, args.charge))

    if args.json:
        json.dump(summaries, sys.stdout, indent=2)
        print()
        return 0

    for s in summaries:
        print_human(s)
    if len(summaries) > 1:
        total = sum(s["total_core_s"] for s in summaries)
        print(f"\n=== all targets: {total:.0f} core-seconds "
              f"({_fmt_hms(total)} of one core) ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
