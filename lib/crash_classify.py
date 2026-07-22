"""Canonical definition of "did this fuzzing trial find the TARGET bug?".

This module exists because the pipeline previously had NO single definition of a
bug find, so every analysis (the phase-3 summary, phase-4 TTB, ad-hoc recovery
scripts) re-invented it and silently miscounted. Two real incidents:

  * `phase3_runner` counted `has_crash = bool(crash_times)` — i.e. ANY artifact,
    including slow-units, timeouts, OOMs, and the end-of-run boundary artifact.
  * The `mut-8h` recovery counted pod-log `outcome=finding`, which the runner
    sets for crash | timeout | out-of-memory | leak alike.

Both massively over-count. A libFuzzer run drops several kinds of artifact into
the crashes dir, and only one of them means "the target bug reproduced":

  ┌────────────────┬───────────────┬──────────────────────────────────────────┐
  │ artifact prefix│ crash_type    │ is it the target bug?                      │
  ├────────────────┼───────────────┼──────────────────────────────────────────┤
  │ crash-<sha1>   │ "crash"       │ YES — a sanitizer/deadly-signal crash …    │
  │                │               │   …UNLESS it's the empty-input boundary    │
  │                │               │   artifact or occurs at the run cutoff     │
  │ slow-unit-<..> │ "unknown"     │ no — an input that ran too slow            │
  │ timeout-<..>   │ "timeout"     │ no — a per-unit timeout                    │
  │ oom-<..>       │ "oom"         │ no — out of memory                         │
  └────────────────┴───────────────┴──────────────────────────────────────────┘

The "boundary artifact" is a spurious `crash-` of the EMPTY input (sha1
da39a3ee…) written at t ≈ max_total_time as the run shuts down; it is not a real
find and must be excluded (libxml2's entire "10/10 crashes" were this).

Two tiers of classification:

  * `trial_found_bug` / `trial_time_to_bug` — CHEAP, metadata-only. Uses
    crash_type + timestamp + the empty-input exclusion. This is what the
    summaries and TTB use; it removes the slow-unit / timeout / OOM / boundary
    contamination. Use this everywhere by default.

  * `verify_crash_reproduces` — GOLD STANDARD. Replays a crash artifact on the
    target binary and confirms it actually crashes under the sanitizer, and
    (optionally) that the reported signature matches the manifest's expected
    crash type. This additionally catches (a) fold-induced FALSE-POSITIVE
    crashes that are not the target bug, and (b) NON-REPRODUCIBLE / flaky
    crashes (e.g. libavc's multithreaded decoder, where most recorded crashes
    don't replay). Run it when you need a fully trustworthy count.
"""
from __future__ import annotations

import os
import re
import subprocess

# sha1("") — the empty input. libFuzzer writes crash-<this> at shutdown as a
# boundary artifact on some targets; it is never a real find.
EMPTY_INPUT_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

RUNNER_IMAGE = "gcr.io/oss-fuzz-base/base-runner"


# --------------------------------------------------------------------------- #
# Tier 1 — cheap, metadata-only classification (no docker, no binary)
# --------------------------------------------------------------------------- #
def is_target_bug_find(entry: dict, max_total_time: float | int | None = None) -> bool:
    """True iff one crash_times entry is a genuine target-bug crash.

    Excludes slow-units (crash_type "unknown"), timeouts, OOMs, the empty-input
    boundary artifact, and any crash at/after the run cutoff.

    `entry` is one element of a trial's crash_times list:
        {"timestamp_s": float, "artifact": "crash-<sha1>", "crash_type": "crash"}
    `max_total_time` is the trial's -max_total_time (seconds). When None, only
    the cutoff check is skipped; crash_type + empty-input exclusion still apply.
    """
    if not isinstance(entry, dict):
        return False
    if entry.get("crash_type") != "crash":            # only real sanitizer crashes
        return False
    artifact = entry.get("artifact") or ""
    if EMPTY_INPUT_SHA1 in artifact:                  # empty-input boundary artifact
        return False
    ts = entry.get("timestamp_s")
    if ts is None:
        return False
    if max_total_time is not None and float(ts) >= float(max_total_time):
        return False                                  # end-of-run boundary artifact
    return True


def trial_time_to_bug(
    crash_times: list | None, max_total_time: float | int | None = None
) -> float | None:
    """Earliest genuine target-bug crash time for a trial, or None if not found
    (i.e. the trial is censored at max_total_time)."""
    hits = [
        float(e["timestamp_s"])
        for e in (crash_times or [])
        if is_target_bug_find(e, max_total_time)
    ]
    return min(hits) if hits else None


def trial_found_bug(
    crash_times: list | None, max_total_time: float | int | None = None
) -> bool:
    """True iff the trial found the target bug (a real, non-boundary crash)."""
    return trial_time_to_bug(crash_times, max_total_time) is not None


def summarize_trials(
    results: list[dict],
    max_total_time: float | int | None = None,
    time_key: str = "crash_times",
    cutoff_key: str = "max_total_time",
) -> dict:
    """Aggregate a list of trial-result dicts into found/total + TTBs.

    Each result may carry its own cutoff under `cutoff_key`; otherwise the
    `max_total_time` argument is used. Returns {found, total, ttbs:[...]}.
    """
    found, ttbs = 0, []
    for r in results:
        cutoff = r.get(cutoff_key) if isinstance(r, dict) else None
        if cutoff is None:
            cutoff = max_total_time
        t = trial_time_to_bug(r.get(time_key), cutoff)
        if t is not None:
            found += 1
            ttbs.append(t)
    return {"found": found, "total": len(results), "ttbs": ttbs}


# --------------------------------------------------------------------------- #
# Tier 2 — gold-standard: replay the artifact and confirm it reproduces
# --------------------------------------------------------------------------- #
_SUMMARY_RE = re.compile(r"SUMMARY:\s*\w*Sanitizer:\s*([a-zA-Z0-9_\- ]+)")


def normalize_signature(sig: str) -> str:
    """Normalize an ASan signature / manifest crash_type for comparison.

    "Heap-use-after-free READ 8" and "heap-use-after-free" both -> a common core.
    Keeps only the leading bug-class tokens (drops READ/WRITE/size/{*}).
    """
    if not sig:
        return ""
    s = sig.lower().replace("_", "-").replace(" ", "-")
    s = re.sub(r"-(read|write|\d+|\{\*\}|\*).*$", "", s)  # drop access/size suffix
    return s.strip("-")


def verify_crash_reproduces(
    artifact_path: str,
    out_dir: str,
    fuzz_target: str,
    expected_signature: str | None = None,
    timeout: int = 120,
    image: str = RUNNER_IMAGE,
) -> tuple[bool, str]:
    """Replay one crash artifact on the target binary; confirm it really crashes.

    Returns (reproduced, detected_signature). `reproduced` is True only if the
    binary aborts under the sanitizer on this input AND — when
    `expected_signature` (e.g. the manifest crash_type) is given — the detected
    ASan bug-class matches it. This is the strongest "is it the target bug?"
    signal: it rejects fold-induced false positives and non-reproducible flakes.

    Requires docker, the built target in `out_dir`, and the artifact file.
    """
    if not (os.path.isfile(artifact_path) and os.path.isdir(out_dir)):
        return False, ""
    cmd = [
        "docker", "run", "--rm", "--privileged",
        "-v", f"{os.path.abspath(out_dir)}:/out:ro",
        "-v", f"{os.path.abspath(artifact_path)}:/testcase:ro",
        image, "/bin/bash", "-lc",
        f"export ASAN_OPTIONS=detect_leaks=0; /out/{fuzz_target} /testcase",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, "timeout"
    blob = (r.stdout or "") + (r.stderr or "")
    m = _SUMMARY_RE.search(blob)
    detected = m.group(1).strip() if m else ""
    # A sanitizer crash exits non-zero and prints a SUMMARY line.
    crashed = bool(detected) or r.returncode not in (0, None)
    if not crashed:
        return False, detected
    if expected_signature:
        return normalize_signature(detected) == normalize_signature(expected_signature), detected
    return True, detected
