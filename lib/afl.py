"""Parse AFL++ campaign output: crash timing, fuzzer_stats, and plot_data.

Replaces the libFuzzer log-scraping in phase3_runner.parse_fuzzer_stats and the
wall-clock crash polling in monitor_trial.

Two things AFL++ gives us for free that libFuzzer did not:

  * Crash artifacts carry the discovery time IN THE FILENAME, so time-to-bug no
    longer depends on how often the orchestrator happened to poll the directory.
  * plot_data is a coverage/throughput time series, which retires
    tools/run_covtime.py's reconstruction of cov(t) from corpus ZIP mtimes.

UNITS: AFL++ writes `time:` in MILLISECONDS since campaign start. This is
asserted against a real run rather than assumed -- see test_afl_live_units.py.
"""
from __future__ import annotations

import re
from pathlib import Path

# `id:000003,sig:06,src:000001,time:45231,execs:99112,op:havoc,rep:4`
# Anchored on a field boundary so `runtime:` cannot be mistaken for `time:`.
_TIME_RE = re.compile(r"(?:^|,)time:(\d+)(?:,|$)")

MS_PER_SEC = 1000.0


def crash_time_secs(filename: str) -> float | None:
    """Seconds since campaign start, from an AFL++ artifact filename."""
    m = _TIME_RE.search(filename)
    if not m:
        return None
    return int(m.group(1)) / MS_PER_SEC


def _coerce(value: str):
    """int -> float -> str, so callers get numbers where numbers exist."""
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def parse_fuzzer_stats(text: str) -> dict:
    """Parse AFL++'s `key : value` fuzzer_stats file."""
    stats: dict = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if not key:
            continue
        stats[key] = _coerce(value)
    return stats


def parse_plot_data(text: str) -> list[dict]:
    """Parse AFL++'s plot_data time series, keyed by its OWN header.

    Column order has changed between AFL++ releases, so positions are never
    assumed: a file without a header returns nothing rather than being guessed
    at, because silently mislabelled columns would corrupt every coverage curve.
    """
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    if not lines or not lines[0].startswith("#"):
        return []
    columns = [c.strip() for c in lines[0].lstrip("#").split(",")]
    rows: list[dict] = []
    for line in lines[1:]:
        if line.startswith("#"):
            continue
        cells = [c.strip() for c in line.split(",")]
        if len(cells) != len(columns):
            continue
        rows.append({k: _coerce(v.rstrip("%")) for k, v in zip(columns, cells)})
    return rows


def collect_crashes(crashes_dir: str | Path) -> list[dict]:
    """Crash artifacts as [{timestamp_s, artifact}], earliest first.

    AFL drops a README.txt into crashes/; anything without a parseable `time:`
    field is not an artifact and is skipped.
    """
    crashes_dir = Path(crashes_dir)
    # AFL++ ARCHIVES this directory on every resume: it renames it to
    # crashes.<timestamp> and starts a fresh one. The online arm relaunches on
    # every hot swap, so reading only crashes/ returns just what was found since
    # the LAST swap -- while the baseline arm, which never relaunches, keeps
    # everything. That is a systematic bias against the optimized arm on the one
    # measurement this benchmark exists to compare: one trial's first crash read
    # as 21.4h when the artifact was actually written at 8.6 minutes.
    search = [crashes_dir] + sorted(
        p for p in crashes_dir.parent.glob(crashes_dir.name + ".*") if p.is_dir()
    ) if crashes_dir.parent.is_dir() else [crashes_dir]
    out: list[dict] = []
    seen: set[str] = set()
    for d in search:
        if not d.is_dir():
            continue
        for entry in d.iterdir():
            if not entry.is_file():
                continue
            ts = crash_time_secs(entry.name)
            if ts is None or entry.name in seen:
                continue
            seen.add(entry.name)
            out.append({"timestamp_s": round(ts, 3), "artifact": entry.name})
    return sorted(out, key=lambda c: c["timestamp_s"])
