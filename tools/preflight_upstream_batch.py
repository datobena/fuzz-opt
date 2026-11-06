#!/usr/bin/env python3
"""Run tools/preflight_online.py over the upstream manifest entries in parallel.

Each worker owns one smoke core; builds share --build-cpus. Order: one address
entry per project first, then the remaining address entries, then undefined, then
memory. Results land in <out-dir>/<ossfuzz_project>/<sanitizer>/<fuzz_target>.json
(+ .log); existing results are skipped unless --rerun.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT_SECS = 4 * 3600


def _csv(s: str | None) -> list[str] | None:
    return [x.strip() for x in s.split(",") if x.strip()] if s else None


def first_pass(entries: list[dict]) -> list[dict]:
    """Pass 1: the first address entry per ossfuzz_project, manifest order."""
    seen: set[str] = set()
    out = []
    for e in entries:
        if e.get("sanitizer") == "address" and e["ossfuzz_project"] not in seen:
            seen.add(e["ossfuzz_project"])
            out.append(e)
    return out


def order_entries(entries: list[dict]) -> list[dict]:
    """Pass 1: first address entry per ossfuzz_project; 2: other address;
    3: undefined; 4: memory. Manifest order within a pass."""
    p1 = first_pass(entries)
    ids = {id(e) for e in p1}
    p2 = [e for e in entries if e.get("sanitizer") == "address" and id(e) not in ids]
    p3 = [e for e in entries if e.get("sanitizer") == "undefined"]
    p4 = [e for e in entries if e.get("sanitizer") == "memory"]
    return p1 + p2 + p3 + p4


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


def run_one(entry: dict, core: int, a) -> dict:
    """Preflight one entry on smoke core ``core``; return its verdict dict."""
    res_path = result_path_for(a.out_dir, entry)
    res_path.parent.mkdir(parents=True, exist_ok=True)
    log_path = res_path.with_suffix(".log")
    project, lid = entry["project"], entry["local_id"]
    cmd = [sys.executable, str(ROOT / "tools" / "preflight_online.py"),
           "--project", project, "--local-id", str(lid), "--cpu", str(core),
           "--build-cpus", a.build_cpus, "--smoke-secs", str(a.smoke_secs)]
    env = dict(os.environ, BENCHMARK_MANIFEST_PATH=str(Path(a.manifest).resolve()))
    src = ROOT / "results" / f"preflight-{project}" / f"preflight_{project}_{lid}.json"
    src.unlink(missing_ok=True)  # a stale verdict must not pass for this run's
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
    res_path.write_text(json.dumps(verdict, indent=2))
    return verdict


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


def collect(ordered: list[dict], todo: list[dict], a, runner=None) -> list[tuple[dict, bool]]:
    """Run ``todo`` in parallel; return (entry, ok) for every entry of ``ordered``,
    reading the stored verdict of those skipped because a result already existed."""
    runner = runner or run_one
    cores: queue.Queue = queue.Queue()
    for c in _csv(a.smoke_cpus) or []:
        cores.put(int(c))
    done: list[tuple[dict, bool]] = []

    def work(entry: dict) -> None:
        core = cores.get()
        t0 = time.time()
        try:
            ok = bool(runner(entry, core, a)["ok"])
        finally:
            cores.put(core)
        done.append((entry, ok))
        print(f"{'READY' if ok else 'NOT READY'}  {entry['ossfuzz_project']}  "
              f"{entry['sanitizer']}  {entry['fuzz_target']}  {round(time.time() - t0)}s",
              flush=True)

    with ThreadPoolExecutor(max(1, cores.qsize())) as ex:
        list(ex.map(work, todo))
    ran = {id(e) for e in todo}
    for e in ordered:
        if id(e) not in ran:
            try:
                ok = bool(json.loads(result_path_for(a.out_dir, e).read_text()).get("ok"))
            except (OSError, ValueError):
                ok = False
            done.append((e, ok))
    return done


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", default="data/manifests/manifest_upstream.json")
    ap.add_argument("--out-dir", default="results/preflight-upstream")
    ap.add_argument("--smoke-cpus", default="0,1,2,3,4,5,6,7,8,9")
    ap.add_argument("--build-cpus", default="10-19,30-39")
    ap.add_argument("--smoke-secs", type=int, default=120)
    ap.add_argument("--projects", default=None)
    ap.add_argument("--sanitizers", default=None)
    ap.add_argument("--first-pass-only", action="store_true")
    ap.add_argument("--rerun", action="store_true")
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
