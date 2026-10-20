"""Which binary an online trial was executing when one of its crashes fired.

Shared by the orchestrator (phase3_online._monitor_online_trial records it on
every crash as it is found) and the post-hoc analyses
(analysis/verify_crash_signatures.py, dedup_crashes.py, cross_check_bugs.py
replay each artifact against it). It lives in lib/ rather than in
verify_crash_signatures so the orchestrator can import it with no side effects:
the analysis script edits sys.path and pulls in its CLI's dependencies at import
time. phase3_online once called ``V.live_binary`` without ever importing ``V``;
the NameError was swallowed by the provenance try/except, so live_binary was
None on EVERY optimized crash record of every campaign.

Pure path/JSON logic -- stdlib only, no config, no docker.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path


def trial_online_dir(campaign_online: str | os.PathLike,
                     trial_name: str) -> Path:
    """This trial's own online dir, or the campaign one for legacy layouts.

    Under the per-trial-optimizer design each optimized trial has its own
    optimizer, its own swap timeline and its own iter_NN/bin snapshots at
    ``optimized/online/trials/trial_XX``. Reading the campaign-level dir there
    would resolve a crash against ANOTHER optimizer's binary -- silently, and
    producing exactly the mislabelled "does not reproduce" verdicts that the
    live_binary field exists to prevent.
    """
    m = re.search(r"trial_(\d+)", str(trial_name))
    if m:
        d = Path(campaign_online) / "trials" / f"trial_{int(m.group(1)):02d}"
        if d.is_dir():
            return d
    return Path(campaign_online)


def _swap_run_time(entry: dict) -> float | None:
    """The trial's AFL run_time at this swap, or None when the row has none.

    Per-trial rows carry ``state_at_swap``; _fuzzer_state stores fuzzer_stats
    values as strings, and records {} when it could not read the file. Legacy
    shared-binary rows nest it under ``per_trial`` keyed by a trial this
    function cannot know, so they keep the wall-clock comparison.
    """
    try:
        return float(entry["state_at_swap"]["run_time"])
    except (KeyError, TypeError, ValueError):
        return None


def live_binary(online_dir: str | os.PathLike, trial_start: float,
                crash_t: float,
                baseline_bin: str | os.PathLike) -> tuple[Path, str]:
    """The binary the trial was executing when a crash at ``crash_t`` fired.

    Before the first swap that is iter_00 (a copy of the baseline build); after
    swap N it is iter_NN's archived binary.

    A per-trial dir's swap_timeline.json lists EVERY trial's swaps (each row
    carries its trial_id), so only this trial's rows count. Without the filter a
    crash resolves to whatever round any trial swapped last -- often a round this
    trial rejected, whose bin dir is empty.

    Paths may be str or Path: the orchestrator builds them with os.path (str),
    and ``str / "swap_timeline.json"`` raised TypeError there -- swallowed, so
    that bug too read as "no live binary".

    ``crash_t`` is AFL's run_time, so it is compared against each swap's own
    run_time (``state_at_swap.run_time``, read from fuzzer_stats once the old
    binary had stopped) whenever the row carries one. AFL_AUTORESUME restores
    that exact value as the relaunched process's clock, so a crash at run_time
    >= it fired on the new binary. Only the old binary's last partial second
    (fuzzer_stats floors run_time) overlaps, and resolves to the new one.

    Rows without it fall back to ``wall = trial_start + crash_t``, which treats
    run_time as wall-clock and so runs EARLY by everything the run_time clock
    lost before the crash -- the logged ~20 s stop per earlier swap, and more
    (php r2 trial_02's run_time fell 60 s, 305 s, 574 s behind wall-clock at
    its three swaps). A crash in the first minutes after a swap can then
    resolve to the previous round. Never the other way round.
    """
    online_dir = Path(online_dir)
    baseline_bin = Path(baseline_bin)
    wall = trial_start + crash_t
    try:
        timeline = json.loads((online_dir / "swap_timeline.json").read_text())
    except (OSError, json.JSONDecodeError):
        timeline = []
    m = re.fullmatch(r"trial_(\d+)", online_dir.name)
    if m:
        tid = int(m.group(1))
        timeline = [e for e in timeline if e.get("trial_id", tid) == tid]
    live = None
    for entry in sorted(timeline, key=lambda e: e.get("ts", 0)):
        rt = _swap_run_time(entry)
        if (crash_t >= rt) if rt is not None else (entry.get("ts", 0) <= wall):
            live = entry.get("iter")
    if live is None:
        return baseline_bin, "iter_00"
    d = online_dir / f"iter_{int(live):02d}" / "bin"
    return (d, f"iter_{int(live):02d}") if d.is_dir() else (baseline_bin, "iter_00")
