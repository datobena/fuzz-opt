#!/usr/bin/env python3
"""Triage a campaign's crashes into a 0-day report.

An ``upstream`` target has no known bug: whatever the two arms crash on is a
candidate 0-day. This tool turns a finished campaign's crash artifacts into a
report that says which DISTINCT crashes were found, by which arm, when, and
whether each one reproduces on the PRISTINE baseline binary
(``baseline/bin/<fuzz_target>``, built from unmodified source). A crash that
does not reproduce there was made by the optimizer and is never counted.

Pipeline, per manifest entry in the experiment:

1. Every artifact under ``<arm>/trial_*/afl_out/default/crashes*`` (both arms;
   ``lib.afl.collect_crashes`` also reads the ``crashes.<ts>`` archives AFL
   leaves on every resume) is replayed ONCE on the binary that found it
   (baseline: ``baseline/bin``; optimized: the trial's live binary at the
   crash's AFL ``time:``, ``lib.live_binary``) under the kind's own sanitizer
   options with ``symbolize=1``, giving its classification report.
2. ``dedupe_key(report)`` = ``(sanitizer kind, top 3 non-runtime frames of the
   crash stack)``. No parsable report -> ``("unclassified", ())``, listed
   separately.
3. ``summarize(records, replay=...)`` groups by key and replays the EARLIEST
   artifact of each key on the pristine binary through the injected
   ``replay`` callable: True -> ``distinct``; False -> ``optimizer_induced``
   (excluded from every count); raised or None -> ``unverified`` (an
   infrastructure failure is never a verdict either way).

Outputs ``results/<E>/<project>-<cve>/triage/zero_day_report.{json,md}``.

    python3 tools/triage_upstream_crashes.py --experiment-id E [--project P] \
        [--local-id N] [--cpu C] [--timeout SECS]
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
from lib.live_binary import live_binary, trial_online_dir  # noqa: E402
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


def _pristine_verdict(replay: Callable, path: str) -> tuple[bool | None, tuple | None, str | None]:
    """(reproduces, pristine_key, error). Any exception or a None return is an
    infrastructure failure: reproduces None, never a verdict."""
    try:
        r = replay(path)
    except Exception as e:  # noqa: BLE001 - every failure is reported, not raised
        return None, None, f"{type(e).__name__}: {e}"
    if isinstance(r, dict):
        rep, pk = r.get("reproduces"), r.get("pristine_key")
        pk = (pk[0], tuple(pk[1])) if pk else None
    else:
        rep, pk = r, None
    if rep is None:
        return None, pk, "replay returned no verdict"
    return bool(rep), pk, None


def summarize(records: Iterable[dict], replay: Callable) -> dict:
    """The 0-day report for one campaign. Pure apart from the injected ``replay``.

    ``records``: per-artifact ``{"arm", "trial", "time_s", "path", "report"}``
    (``report`` None = the artifact could not be replayed; it lands in
    ``unclassified`` with its ``error``). ``replay(path)`` replays one artifact
    on the pristine binary and returns True/False (or
    ``{"reproduces": bool, "pristine_key": key}``); raising or returning None
    means the replay itself failed. Only the earliest artifact of each key is
    replayed.
    """
    groups: dict[tuple, list[dict]] = {}
    unclassified: list[dict] = []
    for r in records:
        key = dedupe_key(r.get("report"))
        if key == UNCLASSIFIED:
            u = {k: r.get(k) for k in ("arm", "trial", "time_s", "path")}
            if r.get("report") is None:
                u["error"] = r.get("error") or "replay produced no output"
            unclassified.append(u)
            continue
        groups.setdefault(key, []).append(r)

    distinct, induced, unverified = [], [], []
    for key, rs in groups.items():
        rs = sorted(rs, key=lambda r: (r["time_s"], r["arm"], str(r["path"])))
        earliest = rs[0]
        arms = sorted({r["arm"] for r in rs}, key=lambda a: (a not in ARMS, ARMS.index(a) if a in ARMS else 0, a))
        text = earliest["report"]
        ident, start = _identity(text)
        item = {
            "key": _key_json(key),
            "signature": signature(key),
            "kind": key[0],
            "first_seen_s": {a: min(r["time_s"] for r in rs if r["arm"] == a) for a in arms},
            "trials": {a: sorted({r["trial"] for r in rs if r["arm"] == a}) for a in arms},
            "artifacts": {a: sum(1 for r in rs if r["arm"] == a) for a in arms},
            "earliest_arm": earliest["arm"],
            "earliest_trial": earliest["trial"],
            "earliest_path": str(earliest["path"]),
            "stack": crash_stack(text, max(start, 0))[:STACK_DEPTH],
        }
        rep, pk, err = _pristine_verdict(replay, item["earliest_path"])
        item["reproduces_on_pristine"] = rep
        if pk is not None:
            item["pristine_key"] = _key_json(pk)
            item["pristine_key_differs"] = pk != key
        if err is not None:
            item["pristine_error"] = err
            unverified.append(item)
        elif rep:
            distinct.append(item)
        else:
            induced.append(item)

    def order(items):
        return sorted(items, key=lambda d: (min(d["first_seen_s"].values()), d["signature"]))

    distinct, induced, unverified = order(distinct), order(induced), order(unverified)
    unclassified.sort(key=lambda u: (u["time_s"] if u["time_s"] is not None else 0, str(u["path"])))
    arm_names = sorted({a for d in distinct for a in d["trials"]} | set(ARMS),
                       key=lambda a: (a not in ARMS, ARMS.index(a) if a in ARMS else 0, a))
    per_arm = {a: {"distinct": sum(1 for d in distinct if a in d["trials"]),
                   "artifacts": sum(d["artifacts"].get(a, 0) for d in distinct)}
               for a in arm_names}
    only_opt = [d for d in distinct
                if "optimized" in d["trials"] and "baseline" not in d["trials"]]
    return {
        "counts": {
            "distinct": len(distinct),
            "per_arm": per_arm,
            "only_optimized_found": len(only_opt),
            "optimizer_induced": len(induced),
            "unverified": len(unverified),
            "unclassified": len(unclassified),
        },
        "distinct": distinct,
        "only_optimized_found": only_opt,
        "optimizer_induced": induced,
        "unverified": unverified,
        "unclassified": unclassified,
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
            f"**{c['distinct']} distinct crashes** reproduce on the pristine baseline binary "
            f"(baseline arm {pa.get('baseline', {}).get('distinct', 0)}, "
            f"optimized arm {pa.get('optimized', {}).get('distinct', 0)}; "
            f"{c['only_optimized_found']} found only by the optimized arm). "
            f"Not counted: {c['optimizer_induced']} optimizer-induced, "
            f"{c['unverified']} unverified, {c['unclassified']} unclassified artifacts.", "",
            "## Distinct crashes", ""]
    out += _crash_table(report["distinct"], lambda d: "reproduces"
                        + (" (pristine key differs)" if d.get("pristine_key_differs") else ""))
    out += ["## Only found by the optimized arm", ""]
    out += _crash_table(report["only_optimized_found"], lambda d: "reproduces")
    out += ["## Optimizer-induced (do not reproduce on the pristine binary; not counted)", ""]
    out += _crash_table(report["optimizer_induced"], lambda d: "does not reproduce")
    out += ["## Unverified (pristine replay failed; not counted)", ""]
    out += _crash_table(report["unverified"], lambda d: f"error: {d.get('pristine_error', '?')}")
    out += ["## Unclassified (no parsable sanitizer report)", ""]
    if report["unclassified"]:
        for u in report["unclassified"]:
            out.append(f"- {u['arm']} {u['trial']} at {_fmt_s(u['time_s'])}: `{u['path']}`"
                       + (f" ({u['error']})" if u.get("error") else ""))
        out.append("")
    else:
        out += ["_none_", ""]
    for d in report["distinct"]:
        out += [f"### `{d['signature']}`", "", "```"] + d["stack"] + ["```", ""]
    return "\n".join(out).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# campaign layout (filesystem only, no docker)
# --------------------------------------------------------------------------- #
def _trial_dirs(arm_dir: Path) -> list[Path]:
    """``<arm>/trial_*``, plus ``<arm>/trials/trial_*`` for a per-trial layout."""
    dirs = [p for p in arm_dir.glob("trial_*") if p.is_dir()]
    dirs += [p for p in (arm_dir / "trials").glob("trial_*") if p.is_dir()]
    return sorted(dirs, key=lambda p: p.name)


def campaign_artifacts(cve_dir: str | Path) -> list[dict]:
    """Every crash artifact of both arms: ``{arm, trial, time_s, path, own_bin}``.

    ``time_s`` is AFL's ``time:`` field (ms since the trial's campaign start,
    restored across autoresume) in seconds, as lib.afl.collect_crashes reads
    it. ``own_bin`` is the binary that found the crash: ``baseline/bin`` for the
    baseline arm, the trial's live binary at ``time_s`` for the optimized arm.
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
                own = (live_binary(trial_online_dir(online, trial.name),
                                   meta.get("start_time", 0) or 0, a["timestamp_s"], base_bin)[0]
                       if arm == "optimized" else base_bin)
                out.append({"arm": arm, "trial": trial.name, "time_s": a["timestamp_s"],
                            "path": str(p), "own_bin": str(own)})
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
class ReplayInfraError(RuntimeError):
    """The replay itself failed (docker, loader, timeout): not evidence."""


def _run_docker(cmd: list[str], timeout: int) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise ReplayInfraError(f"docker run exceeded {timeout}s") from e
    except OSError as e:
        raise ReplayInfraError(f"docker: {e}") from e
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def replay_report(image: str, bin_dir: str | Path, fuzz_target: str, artifact: str | Path,
                  env: dict, *, cpu: int | None, timeout: int) -> str:
    """Replay one artifact; return its combined output (the classification report).

    The artifact is staged under a neutral name (docker's -v parses AFL's
    colons as field separators, see lib.provenance.classify_artifact). Raises
    ReplayInfraError when the replay did not run or did not finish.
    """
    artifact = Path(artifact)
    if not artifact.is_file():
        raise ReplayInfraError(f"artifact missing: {artifact}")
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
    if rc in (125, 126, 127):
        raise ReplayInfraError(f"docker exit {rc}: {out.strip()[-300:]}")
    rcs = re.findall(r"^__RC=(\d+)\s*$", out, re.M)
    inner = int(rcs[-1]) if rcs else None
    if inner is None:
        raise ReplayInfraError(f"no exit status from the target: {out.strip()[-300:]}")
    if inner == 124 and dedupe_key(out) == UNCLASSIFIED:
        raise ReplayInfraError("target timed out")
    return out


def pristine_replay(image, base_bin, fuzz_target, env, *, cpu, timeout, tries=3) -> Callable:
    """``replay(path)`` for summarize: up to ``tries`` runs on the pristine
    binary. Crashes with a parsable report on any try -> reproduces. Ran clean
    on every try -> does not. Otherwise (some tries failed to run) -> raises,
    so the key is reported as unverified."""
    def replay(path):
        errors = []
        for _ in range(max(tries, 1)):
            try:
                out = replay_report(image, base_bin, fuzz_target, path, env,
                                    cpu=cpu, timeout=timeout)
            except ReplayInfraError as e:
                errors.append(str(e))
                continue
            key = dedupe_key(out)
            if key != UNCLASSIFIED:
                return {"reproduces": True, "pristine_key": key}
        if errors:
            raise ReplayInfraError("; ".join(errors))
        return {"reproduces": False}
    return replay


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
                    help="pristine replays before calling a key optimizer-induced (default 3)")
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

    def own(i_a):
        i, a = i_a
        rec = {k: a[k] for k in ("arm", "trial", "time_s", "path")}
        try:
            rec["report"] = replay_report(image, a["own_bin"], target, a["path"], env,
                                          cpu=cpu_for(i), timeout=args.timeout)
        except ReplayInfraError as e:
            rec["report"], rec["error"] = None, str(e)
        return rec

    with ThreadPoolExecutor(max_workers=jobs) as ex:
        records = list(ex.map(own, enumerate(arts)))
    report = summarize(records, replay=pristine_replay(
        image, base_bin, target, env, cpu=cpu_for(0), timeout=args.timeout, tries=args.tries))
    pins, src = _campaign_pins_with_source(cve_dir, entry.get("ossfuzz_project"))
    report.update({
        "experiment": experiment_id,
        "entry": {k: entry.get(k) for k in ("project", "cve", "kind", "ossfuzz_project",
                                            "local_id", "fuzz_target", "sanitizer")},
        "image": image,
        "pristine_bin": str(base_bin),
        "sanitizer_env": env,
        "artifacts_total": len(arts),
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
              f"{c['optimizer_induced']} optimizer-induced, {c['unverified']} unverified, "
              f"{c['unclassified']} unclassified -> {cve_dir / 'triage'}")
        done += 1
    if not done:
        print(f"no manifest entry has a results dir under {root}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
