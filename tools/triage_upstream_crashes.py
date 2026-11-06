#!/usr/bin/env python3
"""Triage a campaign's crashes into a 0-day report.

An ``upstream`` target has no known bug: whatever the two arms crash on is a
candidate 0-day. This tool turns a finished campaign's crash artifacts into a
report that says which DISTINCT crashes were found, by which arm, when, and
whether each reproduces on the PRISTINE baseline binary
(``baseline/bin/<fuzz_target>``, built from unmodified source). A crash that
does not reproduce there is never counted.

Evidence policy (per manifest entry in the experiment):

1. IDENTITY comes from one binary for every artifact of both arms: the
   pristine ``baseline/bin``. Each artifact under
   ``<arm>/trial_*/afl_out/default/crashes*`` (``lib.afl.collect_crashes``
   also reads the ``crashes.<ts>`` archives AFL leaves on every resume) is
   replayed on it, up to ``--tries`` times until it crashes, under the kind's
   own sanitizer options with ``symbolize=1``. Its key is
   ``dedupe_key(report)`` = ``(sanitizer kind, top 3 non-runtime frames of the
   crash stack)``. A folded binary inlines and moves frames, so keying on the
   binary that FOUND an optimized-arm crash would split one bug into an
   "optimized-only" key -- a false headline. This is what
   ``analysis/dedup_crashes.py`` does too.
2. A single run is ``crash`` (nonzero exit with a parsable sanitizer report),
   ``clean`` (exit 0), ``unparsed`` (nonzero exit, no parsable report) or
   ``infra`` (docker/loader failure, missing binary or library -- exit
   125/126/127 -- or timeout 124). An artifact reproduces if any try crashes;
   it is non-reproducing only when EVERY try is clean; anything else is
   ``unverified``. Infrastructure failures are never verdicts.
3. An optimized-arm artifact clean on every pristine try gets one CONTROL
   replay on the binary that found it (its live ``iter_NN`` binary,
   ``lib.live_binary``). Still crashes there -> its found-binary key goes to
   ``optimizer_induced`` (unless that key reproduces on pristine through other
   artifacts); clean there -> ``non_reproducing``; failed -> ``unverified``. A
   baseline-arm artifact is never optimizer-induced: its pristine replay IS its
   own replay.

``summarize(records, replay, control)`` applies the policy and is pure apart
from the two injected callables. Outputs
``results/<E>/<project>-<cve>/triage/zero_day_report.{json,md}``.

    python3 tools/triage_upstream_crashes.py --experiment-id E [--project P] \
        [--local-id N] [--cpu C] [--timeout SECS] [--tries N] [--jobs N]
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Iterable

# The pipeline modules live at the repo root, one level up; Python only puts
# THIS script's directory on sys.path.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib import afl  # noqa: E402
from lib import target_kind  # noqa: E402
from lib.crash_classify import (ASAN_REPLAY_OPTIONS, docker_env_args,  # noqa: E402
                                replay_sanitizer_env, sanitizer_identity)
from lib.live_binary import live_binary, live_iter, trial_online_dir  # noqa: E402
from lib.provenance import _FRAME, _OPTIMIZER_INSERTED, _RUNTIME  # noqa: E402

logger = logging.getLogger("triage_upstream")

ARMS = ("baseline", "optimized")
UNCLASSIFIED = ("unclassified", ())
KEY_DEPTH = 3
STACK_DEPTH = 10

# The same normalisation analysis/cross_check_bugs.py applies (and so
# dedup_crashes.py keys on): a fold that shifts allocation layout makes ASan
# report use-after-poison where the pristine build reports heap-use-after-free
# at the same frame -- one bug, two checks. Copied, not imported: that module
# pulls in config and the analysis CLI's dependencies at import time.
_KIND_ALIAS = {
    "use-after-poison": "heap-use-after-free",
    "container-overflow": "heap-buffer-overflow",
}
# On top of lib.provenance's runtime prefixes: glibc's assert machinery and the
# process entry, which are never the bug's location.
_EXTRA_RUNTIME = ("__assert_fail", "__assert_perror_fail", "__assert_rtn")
_EXTRA_RUNTIME_EXACT = ("_start",)
# MSan reports findings as WARNING, which crash_classify.SANITIZER_ERROR_RE
# (ERROR-only) does not see; the run still aborts (exit_code=86).
_MSAN_WARNING_RE = re.compile(r"WARNING: (MemorySanitizer): ([A-Za-z][A-Za-z0-9_\-]*)")
_FRAME_LINE_RE = re.compile(r"^\s*#(\d+)\s")
_UBSAN_LINE_RE = re.compile(r"runtime error:")


# --------------------------------------------------------------------------- #
# pure helpers
# --------------------------------------------------------------------------- #
def _identity(text: str) -> tuple[dict | None, int]:
    """(sanitizer identity, offset of the report's first line) or (None, -1)."""
    ident = sanitizer_identity(text)
    if ident and ident.get("sanitizer") == "UndefinedBehaviorSanitizer":
        m = _UBSAN_LINE_RE.search(text)
        return ident, (m.start() if m else 0)
    if ident:
        m = re.search(r"ERROR: \w*Sanitizer: ", text)
        return ident, (m.start() if m else 0)
    m = _MSAN_WARNING_RE.search(text)
    if m:
        return {"sanitizer": m.group(1), "kind": m.group(2)}, m.start()
    return None, -1


def crash_stack(text: str, start: int = 0) -> list[str]:
    """Function names of the FIRST stack after ``start`` (the crash stack), in
    order. The allocation/free stacks ASan prints below it never enter."""
    names: list[str] = []
    started = False
    for line in text[start:].splitlines():
        m = _FRAME_LINE_RE.match(line)
        if not m:
            if started:
                break
            continue
        if started and m.group(1) == "0":
            break
        started = True
        f = _FRAME.search(line)
        if f:
            names.append(f.group(1))
    return names


def _is_runtime(name: str) -> bool:
    return (name.startswith(_RUNTIME) or name.startswith(_EXTRA_RUNTIME)
            or name.startswith(_OPTIMIZER_INSERTED) or name in _EXTRA_RUNTIME_EXACT)


def dedupe_key(report_text: str | None) -> tuple:
    """(sanitizer kind, tuple of the top 3 non-runtime frames of the crash stack).

    Identity comes from crash_classify.sanitizer_identity and frame names from
    lib.provenance's frame regex and runtime/optimizer-inserted prefixes, so the
    key agrees with the rest of the pipeline. Addresses and line numbers never
    enter. A UBSan finding with no stack keys on its ``file:line``. No parsable
    sanitizer report -> ``("unclassified", ())``.
    """
    text = report_text or ""
    ident, start = _identity(text)
    if not ident:
        return UNCLASSIFIED
    kind = _KIND_ALIAS.get(ident["kind"], ident["kind"])
    frames = [f for f in crash_stack(text, start) if not _is_runtime(f)][:KEY_DEPTH]
    if not frames and ident.get("sanitizer") == "UndefinedBehaviorSanitizer":
        frames = [ident["location"]]
    return kind, tuple(frames)


def signature(key: tuple) -> str:
    """"kind:f1<-f2<-f3", the form dedup_crashes.py prints."""
    kind, frames = key
    return f"{kind}:{'<-'.join(frames) or '?'}"


def _key_json(key) -> list | None:
    return None if key is None else [key[0], list(key[1])]


# --------------------------------------------------------------------------- #
# one replay run -> status (pure)
# --------------------------------------------------------------------------- #
CRASH, CLEAN, UNPARSED, INFRA = "crash", "clean", "unparsed", "infra"
_INFRA_INNER = {124: "target timed out", 126: "target not executable (exit 126)",
                127: "target or a shared library not found (exit 127)"}


def classify_run(out: str, inner: int | None) -> dict:
    """One replay's ``{"status", "report"|"error"}`` from its output and the
    target's own exit status. Order matters: 126/127 (the target never ran) is
    infra even if a loader message looks like text; a parsable report with a
    nonzero exit is a crash; 124 without one is a timeout; exit 0 is clean
    (a recoverable UBSan report that still exits 0 is not a crash AFL saved)."""
    if inner is None:
        return {"status": INFRA, "error": f"no exit status from the target: {out.strip()[-300:]}"}
    if inner in (126, 127):
        return {"status": INFRA, "error": _INFRA_INNER[inner]}
    if inner == 0:
        return {"status": CLEAN}
    if dedupe_key(out) != UNCLASSIFIED:
        return {"status": CRASH, "report": out}
    if inner == 124:
        return {"status": INFRA, "error": _INFRA_INNER[124]}
    return {"status": UNPARSED, "error": f"exit {inner} without a parsable sanitizer report"}


def _runs(fn: Callable, arg) -> list[dict]:
    """Call an injected replay; an exception or an empty answer is one infra run."""
    try:
        r = fn(arg)
    except Exception as e:  # noqa: BLE001 - every failure is reported, not raised
        return [{"status": INFRA, "error": f"{type(e).__name__}: {e}"}]
    if isinstance(r, dict):
        r = [r]
    return list(r) if r else [{"status": INFRA, "error": "replay returned no runs"}]


def combine_runs(runs: list[dict]) -> dict:
    """``{"verdict": reproduces|clean|unverified, "tries", "hits", "report",
    "reason", "error"}`` over one artifact's tries."""
    hits = [r for r in runs if r.get("status") == CRASH]
    out = {"tries": len(runs), "hits": len(hits)}
    if hits:
        return {**out, "verdict": "reproduces", "report": hits[0]["report"]}
    if runs and all(r.get("status") == CLEAN for r in runs):
        return {**out, "verdict": "clean"}
    infra = any(r.get("status") == INFRA for r in runs)
    errs = sorted({r["error"] for r in runs if r.get("error")})
    return {**out, "verdict": "unverified", "reason": "infra" if infra else "unclassified",
            "error": "; ".join(errs) or "no run"}


# --------------------------------------------------------------------------- #
# summarize (pure apart from the injected replays)
# --------------------------------------------------------------------------- #
def _arm_order(a: str):
    return (a not in ARMS, ARMS.index(a) if a in ARMS else 0, a)


def _group(key: tuple, rows: list[dict], report_field: str) -> dict:
    rows = sorted(rows, key=lambda r: (r["time_s"], r["arm"], str(r["path"])))
    first = rows[0]
    arms = sorted({r["arm"] for r in rows}, key=_arm_order)
    text = first[report_field]
    _, start = _identity(text)
    return {
        "key": _key_json(key),
        "signature": signature(key),
        "kind": key[0],
        "first_seen_s": {a: min(r["time_s"] for r in rows if r["arm"] == a) for a in arms},
        "trials": {a: sorted({r["trial"] for r in rows if r["arm"] == a}) for a in arms},
        "artifacts": {a: sum(1 for r in rows if r["arm"] == a) for a in arms},
        "earliest_arm": first["arm"],
        "earliest_trial": first["trial"],
        "earliest_path": str(first["path"]),
        "earliest_iter": first.get("iter"),
        "stack": crash_stack(text, max(start, 0))[:STACK_DEPTH],
        "pristine_tries": sum(r["pristine_tries"] for r in rows),
        "pristine_hits": sum(r["pristine_hits"] for r in rows),
    }


def found_on_pristine(record: dict) -> bool:
    """True when the binary that found the artifact is the pristine binary:
    the record says so (``found_is_pristine``), or its live binary is
    ``iter_00`` (lib.live_binary's answer before the first swap or with no swap
    timeline). A record whose swapped-in bin dir is missing (``bin_missing``)
    is never found on pristine: the binary that found it is unknown."""
    if record.get("bin_missing"):
        return False
    return bool(record.get("found_is_pristine")) or record.get("iter") == "iter_00"


def summarize(records: Iterable[dict], replay: Callable,
              control: Callable | None = None) -> dict:
    """The 0-day report for one campaign. Pure apart from the injected replays.

    ``records``: per-artifact ``{"arm", "trial", "time_s", "path"}`` (optional
    ``"iter"``: the optimized arm's live binary id; ``"bin_missing"``: that
    iteration's archived ``bin`` dir is gone, so the artifact is ``unverified``
    at the control stage when clean on pristine). ``replay(path)`` runs the
    artifact on the PRISTINE binary and returns its runs, a list of
    ``{"status": crash|clean|unparsed|infra, "report"|"error"}`` (a single dict
    is one run). ``control(record)`` runs an optimized-arm artifact on the
    binary that found it, same shape; called only when every pristine try was
    clean and that binary is not the pristine one (``found_on_pristine``). A raised exception is an infra run.
    """
    rows: list[dict] = []
    for r in records:
        pr = combine_runs(_runs(replay, r["path"]))
        row = {k: r.get(k) for k in ("arm", "trial", "time_s", "path", "iter")}
        row["found_is_pristine"] = r.get("arm") == "baseline" or found_on_pristine(r)
        row.update({"pristine_tries": pr["tries"], "pristine_hits": pr["hits"],
                    "pristine_key": None, "found_key": None})
        if pr["verdict"] == "reproduces":
            row["verdict"], row["pristine_report"] = "reproduces", pr["report"]
            row["pristine_key"] = dedupe_key(pr["report"])
        elif pr["verdict"] == "unverified":
            row.update(verdict="unverified", stage="pristine",
                       reason=pr["reason"], error=pr["error"])
        elif r["arm"] != "optimized":
            row.update(verdict="non_reproducing", reason="clean on every pristine try")
        elif r.get("bin_missing"):
            # Post-swap, but the binary that found it is gone: no control is
            # possible, and it was not the pristine binary.
            row.update(verdict="unverified", stage="control",
                       reason=f"found binary {r.get('iter')}/bin missing", error=None)
        elif found_on_pristine(r):
            # Found before the trial's first swap (or with no live binary on
            # record): the binary that found it IS the pristine binary, so a
            # "control" there would be one more pristine try, never evidence
            # of an optimizer-made crash.
            row.update(verdict="non_reproducing",
                       reason="clean on every pristine try; the binary that found it "
                              "was the pristine binary (iter_00), so no control replay")
        elif control is None:
            row.update(verdict="non_reproducing",
                       reason="clean on every pristine try; no control replay")
        else:
            cr = combine_runs(_runs(control, r))
            row["control_tries"], row["control_hits"] = cr["tries"], cr["hits"]
            if cr["verdict"] == "reproduces":
                row["verdict"], row["found_report"] = "found_only", cr["report"]
                row["found_key"] = dedupe_key(cr["report"])
            elif cr["verdict"] == "clean":
                row.update(verdict="non_reproducing",
                           reason="clean on every pristine try and on the binary that found it")
            else:
                row.update(verdict="unverified", stage="control",
                           reason=cr["reason"], error=cr["error"])
        rows.append(row)

    by_key: dict[tuple, list[dict]] = {}
    for row in rows:
        if row["verdict"] == "reproduces":
            by_key.setdefault(row["pristine_key"], []).append(row)
    distinct = [_group(k, v, "pristine_report") for k, v in by_key.items()]
    for d in distinct:
        d["reproduces_on_pristine"] = True

    induced_rows: dict[tuple, list[dict]] = {}
    for row in rows:
        if row["verdict"] != "found_only":
            continue
        if row["found_key"] in by_key:
            # The same bug reproduces on pristine through other artifacts: this
            # input is a flaky/layout-dependent trigger of a real bug, not an
            # optimizer-made one.
            row.update(verdict="non_reproducing",
                       reason="crashes only on the binary that found it, but its key "
                              f"{signature(row['found_key'])} reproduces on pristine "
                              "through other artifacts")
            continue
        induced_rows.setdefault(row["found_key"], []).append(row)
    induced = [_group(k, v, "found_report") for k, v in induced_rows.items()]
    for d in induced:
        d["reproduces_on_pristine"] = False

    def art(row):
        a = {k: row.get(k) for k in ("arm", "trial", "time_s", "path", "iter",
                                      "found_is_pristine", "pristine_tries", "pristine_hits")}
        for k in ("control_tries", "control_hits", "stage", "reason", "error"):
            if k in row:
                a[k] = row[k]
        return a

    def order(items):
        return sorted(items, key=lambda d: (min(d["first_seen_s"].values()), d["signature"]))

    def art_order(items):
        return sorted(items, key=lambda a: (a["time_s"] if a["time_s"] is not None else 0,
                                            a["arm"], str(a["path"])))

    distinct, induced = order(distinct), order(induced)
    non_repro = art_order([art(r) for r in rows if r["verdict"] == "non_reproducing"])
    unverified = art_order([art(r) for r in rows if r["verdict"] == "unverified"])
    unclassified = [u for u in unverified if u.get("reason") == "unclassified"]

    arm_names = sorted({a for d in distinct for a in d["trials"]} | set(ARMS), key=_arm_order)
    per_arm = {a: {"distinct": sum(1 for d in distinct if a in d["trials"]),
                   "artifacts": sum(d["artifacts"].get(a, 0) for d in distinct),
                   "unverified": sum(1 for u in unverified if u["arm"] == a)}
               for a in arm_names}
    only_opt = [d for d in distinct
                if "optimized" in d["trials"] and "baseline" not in d["trials"]]
    artifacts = []
    for r in rows:
        a = art(r)
        a["verdict"] = "optimizer_induced" if r["verdict"] == "found_only" else r["verdict"]
        a["pristine_key"] = _key_json(r["pristine_key"])
        a["found_key"] = _key_json(r["found_key"])
        artifacts.append(a)
    return {
        "counts": {
            "distinct": len(distinct),
            "per_arm": per_arm,
            "only_optimized_found": len(only_opt),
            "optimizer_induced": len(induced),
            "non_reproducing": len(non_repro),
            "unverified": len(unverified),
            "unclassified": len(unclassified),
        },
        "distinct": distinct,
        "only_optimized_found": only_opt,
        "optimizer_induced": induced,
        "non_reproducing": non_repro,
        "unverified": unverified,
        "unclassified": unclassified,
        "artifacts": art_order(artifacts),
    }


def _fmt_s(v) -> str:
    if v is None:
        return "-"
    return f"{v:.0f}s ({v / 3600:.2f}h)" if v >= 3600 else f"{v:.1f}s"


def _md_cell(s) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def _crash_table(items: list[dict], verdict: Callable[[dict], str]) -> list[str]:
    if not items:
        return ["_none_", ""]
    rows = ["| key | kind | first seen (baseline) | first seen (optimized) | "
            "trials (baseline) | trials (optimized) | reproducer | pristine |",
            "|---|---|---|---|---|---|---|---|"]
    for d in items:
        fs, tr = d["first_seen_s"], d["trials"]
        rows.append("| " + " | ".join(_md_cell(x) for x in (
            f"`{d['signature']}`", d["kind"],
            _fmt_s(fs.get("baseline")), _fmt_s(fs.get("optimized")),
            ", ".join(tr.get("baseline", [])) or "-", ", ".join(tr.get("optimized", [])) or "-",
            f"`{d['earliest_path']}`", verdict(d))) + " |")
    return rows + [""]


def _artifact_list(items: list[dict]) -> list[str]:
    if not items:
        return ["_none_", ""]
    out = []
    for u in items:
        extra = f"pristine {u.get('pristine_hits', 0)}/{u.get('pristine_tries', 0)} crashed"
        if "control_tries" in u:
            extra += f", found binary {u['control_hits']}/{u['control_tries']}"
        if u.get("iter"):
            extra += f", {u['iter']}"
        why = u.get("error") or u.get("reason")
        if u.get("stage"):
            why = f"{u['stage']}: {why}"
        out.append(f"- {u['arm']} {u['trial']} at {_fmt_s(u['time_s'])}: `{u['path']}` "
                   f"({extra}{'; ' + why if why else ''})")
    return out + [""]


def render_markdown(report: dict) -> str:
    """The human-readable report. Pure."""
    entry = report.get("entry") or {}
    name = f"{entry.get('project', '?')}-{entry.get('cve', '?')}"
    pins = report.get("pins")
    c = report["counts"]
    out = [f"# 0-day triage: {name}", "",
           f"- experiment: `{report.get('experiment', '?')}`",
           f"- entry: `{name}`" + "".join(
               f", {k} `{entry[k]}`" for k in ("ossfuzz_project", "local_id", "fuzz_target", "sanitizer")
               if entry.get(k) is not None)]
    if report.get("image"):
        out.append(f"- image: `{report['image']}`")
    if pins:
        out.append(f"- pinned OSS-Fuzz commit: `{pins.get('ossfuzz_commit', '?')}`"
                   + (f" (from {report['pins_source']})" if report.get("pins_source") else ""))
        for d, sha in sorted((pins.get("checkouts") or {}).items()):
            out.append(f"  - `{d}` @ `{sha}`")
    else:
        out.append("- pinned commit: not recorded")
    pa = c["per_arm"]
    out += ["",
            "Crash identity is the key of each artifact's replay on the pristine baseline "
            "binary, for both arms. First-seen times are AFL's `time:` field: the trial's "
            "campaign-cumulative run time, which excludes hot-swap downtime.", "",
            f"**{c['distinct']} distinct crashes** reproduce on the pristine baseline binary "
            f"(baseline arm {pa.get('baseline', {}).get('distinct', 0)}, "
            f"optimized arm {pa.get('optimized', {}).get('distinct', 0)}; "
            f"{c['only_optimized_found']} found only by the optimized arm). "
            f"Not counted: {c['optimizer_induced']} optimizer-induced keys, "
            f"{c['non_reproducing']} non-reproducing and {c['unverified']} unverified "
            f"artifacts (baseline arm {pa.get('baseline', {}).get('unverified', 0)}, "
            f"optimized arm {pa.get('optimized', {}).get('unverified', 0)}; "
            f"{c['unclassified']} unclassified).", "",
            "## Distinct crashes", ""]
    out += _crash_table(report["distinct"], lambda d: f"reproduces ({d['pristine_hits']}/{d['pristine_tries']} tries)")
    out += ["## Only found by the optimized arm", ""]
    out += _crash_table(report["only_optimized_found"], lambda d: "reproduces")
    out += ["## Optimizer-induced (crash on the binary that found them, never on pristine; not counted)", ""]
    out += _crash_table(report["optimizer_induced"],
                        lambda d: f"0/{d['pristine_tries']} tries")
    out += ["## Non-reproducing (clean on pristine; not counted)", ""]
    out += _artifact_list(report["non_reproducing"])
    out += ["## Unverified (a replay failed or was inconclusive; not counted)", ""]
    out += _artifact_list(report["unverified"])
    out += ["## Unclassified (crashed without a parsable sanitizer report; unverified)", ""]
    out += _artifact_list(report["unclassified"])
    for d in report["distinct"]:
        out += [f"### `{d['signature']}`", "", "```"] + d["stack"] + ["```", ""]
    return "\n".join(out).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# campaign layout (filesystem only, no docker)
# --------------------------------------------------------------------------- #
def _trial_dirs(arm_dir: Path) -> list[Path]:
    """``<arm>/trial_*``. A per-trial optimizer's iter dirs live under
    ``optimized/online/trials/trial_NN`` and are reached through
    lib.live_binary, not here."""
    return sorted((p for p in arm_dir.glob("trial_*") if p.is_dir()), key=lambda p: p.name)


def campaign_artifacts(cve_dir: str | Path) -> list[dict]:
    """Every crash artifact of both arms: ``{arm, trial, time_s, path, own_bin, iter}``.

    ``time_s`` is AFL's ``time:`` field (ms of the trial's campaign-cumulative
    run time, restored across autoresume, so hot-swap downtime is excluded) in
    seconds, as lib.afl.collect_crashes reads it. ``own_bin`` is the binary
    that found the crash: ``baseline/bin`` for the baseline arm, the trial's
    live binary at ``time_s`` for the optimized arm, whose id (``iter_NN``)
    is ``iter``.
    """
    cve_dir = Path(cve_dir)
    base_bin = cve_dir / "baseline" / "bin"
    online = cve_dir / "optimized" / "online"
    out: list[dict] = []
    for arm in ARMS:
        for trial in _trial_dirs(cve_dir / arm):
            default = trial / "afl_out" / "default"
            try:
                meta = json.loads((trial / "metadata.json").read_text())
            except (OSError, json.JSONDecodeError):
                meta = {}
            for a in afl.collect_crashes(default / "crashes"):
                p = next(iter(sorted(default.glob(f"crashes*/{glob_escape(a['artifact'])}"))), None)
                if p is None:
                    continue
                missing = False
                if arm == "optimized":
                    tdir = trial_online_dir(online, trial.name)
                    t0 = meta.get("start_time", 0) or 0
                    own, it = live_binary(tdir, t0, a["timestamp_s"], base_bin)
                    want = live_iter(tdir, t0, a["timestamp_s"])
                    if want != it:
                        # Swapped in, but its archived bin dir is gone.
                        own, it, missing = None, want, True
                else:
                    own, it = base_bin, None
                out.append({"arm": arm, "trial": trial.name, "time_s": a["timestamp_s"],
                            "path": str(p), "own_bin": None if own is None else str(own),
                            "iter": it, "bin_missing": missing})
    return sorted(out, key=lambda r: (r["arm"] != "baseline", r["trial"], r["time_s"]))


def glob_escape(name: str) -> str:
    return re.sub(r"([*?\[])", r"[\1]", name)


def campaign_pins(cve_dir: str | Path, ossfuzz_project: str | None, *,
                  upstream_dir: str | Path | None = None) -> dict | None:
    """The pins the campaign ran against: the first trial metadata's
    ``toolchain.upstream.pins`` record, else
    ``prework/upstream/<ossfuzz_project>/pins.json``, else None."""
    p, _ = _campaign_pins_with_source(cve_dir, ossfuzz_project, upstream_dir=upstream_dir)
    return p


def _campaign_pins_with_source(cve_dir, ossfuzz_project, *, upstream_dir=None):
    cve_dir = Path(cve_dir)
    for arm in ARMS:
        for trial in _trial_dirs(cve_dir / arm):
            try:
                meta = json.loads((trial / "metadata.json").read_text())
            except (OSError, json.JSONDecodeError):
                continue
            pins = ((meta.get("toolchain") or {}).get("upstream") or {}).get("pins")
            if pins:
                return pins, str(trial / "metadata.json")
    if not ossfuzz_project:
        return None, None
    if upstream_dir is None:
        from prework.upstream_image import UPSTREAM_DIR  # noqa: PLC0415
        upstream_dir = UPSTREAM_DIR
    path = Path(upstream_dir) / ossfuzz_project / "pins.json"
    try:
        return json.loads(path.read_text()), str(path)
    except (OSError, ValueError):
        return None, None


def classify_env(entry: dict, bin_dir: str, fuzz_target: str) -> dict:
    """Sanitizer options for a classification replay.

    Upstream: the kind's own run-time options (lib.afl_launch
    .upstream_sanitizer_env) with every ``symbolize=0`` turned into
    ``symbolize=1``, as sandbox/broker.py's crash-report path does -- frame
    names are the dedupe key. Other kinds: the pipeline's replay options.
    """
    if target_kind.is_upstream(entry):
        from lib.afl_launch import upstream_sanitizer_env  # noqa: PLC0415
        return {k: v.replace("symbolize=0", "symbolize=1") for k, v in
                upstream_sanitizer_env(bin_dir, fuzz_target, target_kind.sanitizer_of(entry))}
    return replay_sanitizer_env(ASAN_REPLAY_OPTIONS)


# --------------------------------------------------------------------------- #
# docker (only reached from main; tests replace _run_docker)
# --------------------------------------------------------------------------- #
def _run_docker(cmd: list[str], timeout: int) -> tuple[int | None, str]:
    """(docker exit, output); exit None when docker itself could not run or
    exceeded the timeout."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"docker run exceeded {timeout}s"
    except OSError as e:
        return None, f"docker: {e}"
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def replay_once(image: str, bin_dir: str | Path, fuzz_target: str, artifact: str | Path,
                env: dict, *, cpu: int | None, timeout: int) -> dict:
    """One replay of one artifact, as a classify_run status.

    The artifact is staged under a neutral name (docker's -v parses AFL's
    colons as field separators, see lib.provenance.classify_artifact).
    """
    artifact = Path(artifact)
    if not artifact.is_file():
        return {"status": INFRA, "error": f"artifact missing: {artifact}"}
    with tempfile.TemporaryDirectory(prefix="triage-upstream-") as tmp:
        shutil.copyfile(artifact, Path(tmp) / "tc")
        cmd = ["docker", "run", "--rm", "--privileged"]
        if cpu is not None:
            cmd += ["--cpuset-cpus", str(cpu)]
        cmd += docker_env_args(env)
        cmd += ["-v", f"{Path(bin_dir).absolute()}:/out:ro", "-v", f"{tmp}:/tc:ro",
                "--entrypoint", "/bin/bash", image, "-lc",
                "[ -x /out/llvm-symbolizer ] && export ASAN_SYMBOLIZER_PATH=/out/llvm-symbolizer "
                "MSAN_SYMBOLIZER_PATH=/out/llvm-symbolizer; "
                f"timeout {max(timeout - 15, 10)} /out/{fuzz_target} /tc/tc 2>&1; echo __RC=$?"]
        rc, out = _run_docker(cmd, timeout)
    if rc is None:
        return {"status": INFRA, "error": out}
    if rc in (125, 126, 127):
        return {"status": INFRA, "error": f"docker exit {rc}: {out.strip()[-300:]}"}
    rcs = re.findall(r"^__RC=(\d+)\s*$", out, re.M)
    return classify_run(out, int(rcs[-1]) if rcs else None)


def replay_until_crash(image, bin_dir, fuzz_target, path, env, *, cpu, timeout, tries) -> list[dict]:
    """Up to ``tries`` runs, stopping at the first crash."""
    runs = []
    for _ in range(max(tries, 1)):
        runs.append(replay_once(image, bin_dir, fuzz_target, path, env, cpu=cpu, timeout=timeout))
        if runs[-1]["status"] == CRASH:
            break
    return runs


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--project", default=None, help="only this manifest project")
    ap.add_argument("--local-id", type=int, default=None, help="only this manifest local_id")
    ap.add_argument("--cpu", type=int, default=None,
                    help="pin replays to this CPU (with --jobs N: CPUs C..C+N-1)")
    ap.add_argument("--jobs", type=int, default=1, help="parallel replays (default 1)")
    ap.add_argument("--timeout", type=int, default=90, help="seconds per replay (default 90)")
    ap.add_argument("--tries", type=int, default=3,
                    help="replays per artifact before calling it clean (default 3)")
    return ap.parse_args(argv)


def _manifest(experiment_id: str) -> list[dict]:
    import config  # noqa: PLC0415
    for p in (Path(f"manifest_{experiment_id}.json"),
              Path(config.BENCHMARK_DIR) / f"manifest_{experiment_id}.json"):
        if p.is_file():
            return json.loads(p.read_text())
    return json.loads(Path(config.MANIFEST_PATH).read_text())


def triage_entry(experiment_id: str, entry: dict, cve_dir: Path, args) -> dict:
    from lib.provenance import experiment_image  # noqa: PLC0415
    image = experiment_image(cve_dir, entry)
    target = entry["fuzz_target"]
    base_bin = cve_dir / "baseline" / "bin"
    env = classify_env(entry, str(base_bin), target)
    arts = campaign_artifacts(cve_dir)
    logger.info("%s: %d artifacts, image %s", cve_dir.name, len(arts), image)

    jobs = max(args.jobs, 1)

    def cpu_for(i):
        return None if args.cpu is None else args.cpu + (i % jobs)

    # Pristine replays for every artifact of both arms, in parallel; summarize
    # reads them from this cache. For a baseline-arm artifact this IS its own
    # replay, so nothing is replayed twice.
    def pristine(i_a):
        i, a = i_a
        return a["path"], replay_until_crash(image, base_bin, target, a["path"], env,
                                             cpu=cpu_for(i), timeout=args.timeout,
                                             tries=args.tries)

    with ThreadPoolExecutor(max_workers=jobs) as ex:
        cache = dict(ex.map(pristine, enumerate(arts)))
    own_bin = {a["path"]: a["own_bin"] for a in arts}

    def control(rec):
        # Only reached for an optimized-arm artifact clean on every pristine try.
        return replay_until_crash(image, own_bin[rec["path"]], target, rec["path"], env,
                                  cpu=cpu_for(0), timeout=args.timeout, tries=args.tries)

    pristine_dir = base_bin.resolve()
    records = [{**{k: a[k] for k in ("arm", "trial", "time_s", "path", "iter",
                                     "bin_missing")},
                "found_is_pristine": bool(a["own_bin"])
                and Path(a["own_bin"]).resolve() == pristine_dir}
               for a in arts]
    report = summarize(records, replay=lambda path: cache[path], control=control)
    pins, src = _campaign_pins_with_source(cve_dir, entry.get("ossfuzz_project"))
    report.update({
        "experiment": experiment_id,
        "entry": {k: entry.get(k) for k in ("project", "cve", "kind", "ossfuzz_project",
                                            "local_id", "fuzz_target", "sanitizer")},
        "image": image,
        "pristine_bin": str(base_bin),
        "sanitizer_env": env,
        "artifacts_total": len(arts),
        "tries": args.tries,
        "pins": pins,
        "pins_source": src,
    })
    out = cve_dir / "triage"
    out.mkdir(parents=True, exist_ok=True)
    (out / "zero_day_report.json").write_text(json.dumps(report, indent=2) + "\n")
    (out / "zero_day_report.md").write_text(render_markdown(report))
    return report


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)
    import config  # noqa: PLC0415
    root = Path(config.RESULTS_DIR) / args.experiment_id
    done = 0
    for entry in _manifest(args.experiment_id):
        if args.project and entry.get("project") != args.project:
            continue
        if args.local_id is not None and str(entry.get("local_id")) != str(args.local_id):
            continue
        cve_dir = root / f"{entry['project']}-{entry['cve']}"
        if not cve_dir.is_dir():
            continue
        r = triage_entry(args.experiment_id, entry, cve_dir, args)
        c = r["counts"]
        print(f"{cve_dir.name}: {c['distinct']} distinct (only optimized {c['only_optimized_found']}), "
              f"{c['optimizer_induced']} optimizer-induced, {c['non_reproducing']} non-reproducing, "
              f"{c['unverified']} unverified, "
              f"{c['unclassified']} unclassified -> {cve_dir / 'triage'}")
        done += 1
    if not done:
        print(f"no manifest entry has a results dir under {root}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
