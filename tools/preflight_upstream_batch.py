#!/usr/bin/env python3
"""Run tools/preflight_online.py over the upstream manifest entries in parallel.

Each worker owns one smoke core and one --build-cpus element. Entries are grouped
by (ossfuzz_project, sanitizer); the first entry of a group (manifest order) is
its builder: it extracts and builds the project's baseline, and the group's other
entries run with --baseline-from <builder's experiment dir> once it has finished
(or are written NOT READY without running when its build failed). Order: address,
then undefined, then memory; builders first within a pass, manifest order
otherwise; a worker takes the first eligible entry. Results land in
<out-dir>/<ossfuzz_project>/<sanitizer>/<fuzz_target>.json (+ .log); existing
results are skipped unless --rerun. An entry's experiment dir is wiped before it
runs and deleted once its verdict is copied; builders' at the end of the run
(--keep-exp-dirs keeps them all).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT_SECS = 4 * 3600
PASSES = ("address", "undefined", "memory")
GROUP_FAILED = "group baseline build failed"


def _csv(s: str | None) -> list[str] | None:
    return [x.strip() for x in s.split(",") if x.strip()] if s else None


def group_key(entry: dict) -> tuple[str, str]:
    """Entries of one (ossfuzz_project, sanitizer) build the same baseline."""
    return entry["ossfuzz_project"], entry.get("sanitizer")


def builders(entries: list[dict]) -> dict[tuple[str, str], dict]:
    """The builder of each group: its first entry in manifest order."""
    out: dict[tuple[str, str], dict] = {}
    for e in entries:
        out.setdefault(group_key(e), e)
    return out


def first_pass(entries: list[dict]) -> list[dict]:
    """Pass 1: the first address entry per ossfuzz_project (the address
    builders), manifest order."""
    return [e for e in builders(entries).values() if e.get("sanitizer") == "address"]


def order_entries(entries: list[dict]) -> list[dict]:
    """Address, then undefined, then memory; within a pass the builders first,
    then the other entries; manifest order otherwise."""
    b = {id(e) for e in builders(entries).values()}
    out = []
    for san in PASSES:
        p = [e for e in entries if e.get("sanitizer") == san]
        out += [e for e in p if id(e) in b] + [e for e in p if id(e) not in b]
    return out


def result_path_for(out_dir: Path | str, entry: dict) -> Path:
    return (Path(out_dir) / entry["ossfuzz_project"] / entry["sanitizer"]
            / f"{entry['fuzz_target']}.json")


def select(entries: list[dict], projects=None, sanitizers=None) -> list[dict]:
    """Upstream entries passing the optional project / sanitizer filters."""
    return [e for e in entries if e.get("kind") == "upstream"
            and (not projects or e["ossfuzz_project"] in projects)
            and (not sanitizers or e.get("sanitizer") in sanitizers)]


def pending(entries: list[dict], out_dir: Path | str, rerun: bool) -> list[dict]:
    """Entries still to run: those without a result file (all when rerun)."""
    return [e for e in entries if rerun or not result_path_for(out_dir, e).exists()]


def exp_dir_for(entry: dict, results_dir: Path | str) -> Path:
    """preflight_online's experiment dir for ``entry`` (phase2_setup.get_experiment_dir)."""
    return (Path(results_dir) / f"preflight-{entry['project']}"
            / f"{entry['project']}-{entry['cve']}")


def verdict_src_for(entry: dict, results_dir: Path | str) -> Path:
    """Where preflight_online writes ``entry``'s verdict (preflight_online.result_path)."""
    return (Path(results_dir) / f"preflight-{entry['project']}"
            / f"preflight_{entry['project']}_{entry['local_id']}.json")


def _restore_ownership(image: str, paths: list[str]) -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from prework import prework_build
    prework_build.restore_ownership(image, paths)


def wipe_entry_dirs(entry: dict, results_dir: Path | str) -> bool:
    """Delete ``entry``'s experiment dir and preflight verdict. Root-owned build
    leftovers make rmtree fail: hand them back (a chown in the entry's image)
    and retry once. Returns whether an experiment dir was there."""
    exp = exp_dir_for(entry, results_dir)
    there = exp.exists() or exp.is_symlink()
    if there:
        try:
            shutil.rmtree(exp)
        except PermissionError:
            _restore_ownership(entry["image"], [str(exp)])
            shutil.rmtree(exp)
    verdict_src_for(entry, results_dir).unlink(missing_ok=True)
    return there


def delete_exp_dir(entry: dict, results_dir: Path | str) -> None:
    """Part of the cleanup: wipe, one log line per deletion, never raise."""
    try:
        if wipe_entry_dirs(entry, results_dir):
            print(f"deleted {exp_dir_for(entry, results_dir)}", flush=True)
    except OSError as e:
        print(f"could not delete {exp_dir_for(entry, results_dir)}: {e}", flush=True)


def build_ok(verdict: dict) -> bool:
    """Whether a verdict shows a built baseline: extract passed and, unless the
    baseline was reused, aflbuild passed."""
    st = verdict.get("stages") or {}
    ex = st.get("extract") or {}
    if not ex.get("ok"):
        return False
    return bool(ex.get("reused_from")) or bool((st.get("aflbuild") or {}).get("ok"))


def cleanup_containers(project: str, lid) -> None:
    """Force-remove smoke containers a timed-out preflight left behind."""
    try:
        ps = subprocess.run(["docker", "ps", "-q", "--filter",
                             f"name=^preflight_{project}_{lid}_"],
                            capture_output=True, text=True, timeout=60)
        ids = (ps.stdout or "").split()
        if ids:
            subprocess.run(["docker", "rm", "-f", *ids], capture_output=True,
                           timeout=120)
    except (OSError, subprocess.SubprocessError):
        pass


def _write(entry: dict, a, verdict: dict) -> dict:
    res_path = result_path_for(a.out_dir, entry)
    res_path.parent.mkdir(parents=True, exist_ok=True)
    res_path.write_text(json.dumps(verdict, indent=2))
    return verdict


def write_group_failed(entry: dict, a) -> dict:
    """NOT READY without running: the group's builder could not build the baseline."""
    return _write(entry, a, {"ok": False, "driver_secs": 0, "stages": {
        "driver": {"ok": False, "error": GROUP_FAILED}}})


def run_one(entry: dict, core: int, a, build_cpus: str | None = None,
            baseline_from: Path | str | None = None) -> dict:
    """Preflight one entry on smoke core ``core``; return its verdict dict.

    Starts clean: the entry's experiment dir and verdict are wiped first (a
    stale tree from a crashed or earlier run breaks the extract)."""
    res_path = result_path_for(a.out_dir, entry)
    res_path.parent.mkdir(parents=True, exist_ok=True)
    log_path = res_path.with_suffix(".log")
    project, lid = entry["project"], entry["local_id"]
    results = ROOT / "results"
    try:
        wipe_entry_dirs(entry, results)
    except OSError as e:
        return _write(entry, a, {"ok": False, "driver_secs": 0, "stages": {"driver": {
            "ok": False, "error": f"could not wipe the old experiment dir: {e}"}}})
    cmd = [sys.executable, str(ROOT / "tools" / "preflight_online.py"),
           "--project", project, "--local-id", str(lid), "--cpu", str(core),
           "--build-cpus", a.build_cpus if build_cpus is None else build_cpus,
           "--smoke-secs", str(a.smoke_secs)]
    if baseline_from:
        cmd += ["--baseline-from", str(baseline_from)]
    env = dict(os.environ, BENCHMARK_MANIFEST_PATH=str(Path(a.manifest).resolve()))
    src = verdict_src_for(entry, results)
    t0 = time.time()
    verdict = None
    with open(log_path, "w") as log:
        try:
            r = subprocess.run(cmd, env=env, cwd=ROOT, stdout=log,
                               stderr=subprocess.STDOUT, timeout=TIMEOUT_SECS)
            rc = r.returncode
        except subprocess.TimeoutExpired:
            rc = None
            cleanup_containers(project, lid)
            verdict = {"ok": False, "stages": {"driver": {"ok": False, "error": "timeout"}}}
    if verdict is None:
        if src.exists():
            verdict = json.loads(src.read_text())
        else:
            tail = log_path.read_text(errors="replace").splitlines()[-40:]
            verdict = {"ok": False, "stages": {"driver": {
                "ok": False, "error": "no preflight result", "exit_code": rc,
                "log_tail": tail}}}
    verdict["driver_secs"] = round(time.time() - t0)
    return _write(entry, a, verdict)


def summarize(done: list[tuple[dict, bool]]) -> str:
    """Per project READY address harness counts and distinct projects with >=1."""
    counts: dict[str, int] = {}
    for e, ok in done:
        if e.get("sanitizer") == "address":
            counts[e["ossfuzz_project"]] = counts.get(e["ossfuzz_project"], 0) + int(ok)
    lines = [f"  {p}: {n} READY address harness(es)" for p, n in sorted(counts.items())]
    lines.append(f"projects with >=1 READY address harness: "
                 f"{sum(1 for n in counts.values() if n)}")
    return "\n".join(lines)


def _stored_verdict(a, entry: dict) -> dict:
    try:
        return json.loads(result_path_for(a.out_dir, entry).read_text())
    except (OSError, ValueError):
        return {}


def build_cpusets(spec: str) -> list[str]:
    """--build-cpus: ';'-separated cpusets, one per worker (round robin)."""
    parts = [p.strip() for p in spec.split(";") if p.strip()]
    return parts or [spec.strip()]


def collect(ordered: list[dict], todo: list[dict], a, runner=None) -> list[tuple[dict, bool]]:
    """Run ``todo`` on one worker per smoke core; return (entry, ok) for every
    entry of ``ordered``, reading the stored verdict of those skipped because a
    result already existed.

    A worker takes the first eligible entry of ``todo``: a group's builder at
    once, another entry once the builder has finished (with --baseline-from its
    experiment dir, or written NOT READY when its build failed). A skipped
    builder counts as finished; it serves as the source when its verdict shows a
    built baseline and its experiment dir is still there, otherwise the group's
    next pending entry builds instead."""
    runner = runner or run_one
    results = ROOT / "results"
    keep = bool(getattr(a, "keep_exp_dirs", False))
    cores = [int(c) for c in _csv(a.smoke_cpus) or []]
    if not cores:
        raise SystemExit("--smoke-cpus names no core")
    bsets = build_cpusets(a.build_cpus)

    groups: dict[tuple, list[dict]] = {}
    for e in ordered:
        groups.setdefault(group_key(e), []).append(e)
    remaining = list(todo)
    queued = {id(e) for e in todo}
    builder = {k: g[0] for k, g in groups.items()}   # the group's current builder
    status: dict[tuple, str] = {}                     # "ok" | "failed"; absent = waiting
    source: dict[tuple, Path] = {}
    kept: list[dict] = []                             # builder dirs, deleted at the end
    done: list[tuple[dict, bool]] = []
    running = [0]
    cv = threading.Condition()

    def resolve(k: tuple, b: dict, verdict: dict) -> None:
        """The group's builder ``b`` has finished with ``verdict`` (lock held)."""
        if not build_ok(verdict):
            status[k] = "failed"
            return
        d = exp_dir_for(b, results)
        if (d / "baseline" / "bin" / b["fuzz_target"]).is_file():
            status[k], source[k] = "ok", d
            return
        # Built, but its experiment dir is gone (deleted by an earlier run):
        # the next pending entry of the group builds again.
        nxt = [e for e in remaining if group_key(e) == k]
        if nxt:
            builder[k] = nxt[0]

    for k, b in builder.items():
        if id(b) not in queued:
            resolve(k, b, _stored_verdict(a, b))
            if status.get(k) == "ok":
                kept.append(b)

    def pick():
        for e in remaining:
            k = group_key(e)
            if builder[k] is e:
                return e, "run", None
            if status.get(k) == "ok":
                return e, "run", source[k]
            if status.get(k) == "failed":
                return e, "failed", None
        return None

    def work(i: int) -> None:
        core, bc = cores[i], bsets[i % len(bsets)]
        while True:
            with cv:
                while True:
                    if not remaining:
                        return
                    item = pick()
                    if item:
                        break
                    if not running[0]:
                        raise RuntimeError("preflight scheduler: nothing eligible, "
                                           "nothing running")
                    cv.wait()
                e, mode, src = item
                remaining.remove(e)
                running[0] += 1
            k, t0 = group_key(e), time.time()
            is_builder = mode == "run" and src is None
            verdict, ok = {}, False
            try:
                if mode == "failed":
                    verdict = write_group_failed(e, a)
                else:
                    try:
                        verdict = runner(e, core, a, build_cpus=bc, baseline_from=src)
                    except Exception as ex:  # noqa: BLE001 - one entry, not the run
                        verdict = _write(e, a, {"ok": False, "stages": {"driver": {
                            "ok": False, "error": f"{type(ex).__name__}: {ex}"}}})
                ok = bool(verdict.get("ok"))
                if mode == "run" and not is_builder and not keep:
                    delete_exp_dir(e, results)
            finally:
                with cv:
                    running[0] -= 1
                    if is_builder:
                        kept.append(e)
                        resolve(k, e, verdict)
                    cv.notify_all()
            done.append((e, ok))
            how = (" (group build failed, not run)" if mode == "failed"
                   else " (reused baseline)" if src else "")
            print(f"{'READY' if ok else 'NOT READY'}  {e['ossfuzz_project']}  "
                  f"{e['sanitizer']}  {e['fuzz_target']}  {round(time.time() - t0)}s{how}",
                  flush=True)

    errors: list[BaseException] = []

    def guarded(i: int) -> None:
        try:
            work(i)
        except BaseException as ex:  # noqa: BLE001 - re-raised below
            errors.append(ex)
            with cv:
                cv.notify_all()

    threads = [threading.Thread(target=guarded, args=(i,), daemon=True)
               for i in range(len(cores))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        raise errors[0]
    if not keep:
        for b in kept:
            delete_exp_dir(b, results)
    ran = {id(e) for e, _ in done}
    for e in ordered:
        if id(e) not in ran:
            done.append((e, bool(_stored_verdict(a, e).get("ok"))))
    return done


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", default="data/manifests/manifest_upstream.json")
    ap.add_argument("--out-dir", default="results/preflight-upstream")
    ap.add_argument("--smoke-cpus", default="0,1,2,3,4,5,6,7,8,9")
    ap.add_argument("--build-cpus", default="10-19,30-39",
                    help="cpuset(s) for the builds, ';'-separated: worker i builds on "
                         "element i %% len. The pipeline serializes builds that share "
                         "a cpuset string, so distinct elements let builders build in "
                         "parallel; one element = every build on the same cpuset")
    ap.add_argument("--smoke-secs", type=int, default=120)
    ap.add_argument("--projects", default=None)
    ap.add_argument("--sanitizers", default=None)
    ap.add_argument("--first-pass-only", action="store_true")
    ap.add_argument("--rerun", action="store_true")
    ap.add_argument("--keep-exp-dirs", action="store_true",
                    help="keep every experiment dir (default: an entry's is deleted "
                         "once its verdict is copied, a builder's at the end)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    entries = select(json.loads(Path(a.manifest).read_text()),
                     _csv(a.projects), _csv(a.sanitizers))
    ordered = first_pass(entries) if a.first_pass_only else order_entries(entries)
    todo = pending(ordered, a.out_dir, a.rerun)
    if a.dry_run:
        for e in todo:
            print(f"{e['ossfuzz_project']}\t{e['sanitizer']}\t{e['fuzz_target']}"
                  f"\t{e['local_id']}")
        return 0

    done = collect(ordered, todo, a)
    print(summarize(done))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
