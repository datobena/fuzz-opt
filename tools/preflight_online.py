#!/usr/bin/env python3
"""Preflight one target for the ONLINE pipeline, using the real setup path.

Answers "will this project work when I run the experiment?" by executing the same
functions run_online() executes before it starts any trial, in the same order, and
reporting where it breaks:

  1. prework image present
  2. extract  -- baseline bin + editable source + PoC out of the ARVO image
  3. poc      -- the PoC reproduces on the HISTORICAL binary
  4. source   -- the extracted tree holds real project source, not just engine dirs
  5. seeds    -- a non-empty seed corpus (AFL aborts at startup on an empty -i)
  6. aflbuild -- the unmodified source rebuilds under the pinned AFL++ toolchain,
                 AND the PoC still reproduces afterwards (that is the binary the
                 campaign actually measures, not the historical one)
  7. smoke    -- afl-fuzz actually runs: exec rate, corpus growth, crash volume

Stage 7 is not redundant with 6. A target can build and reproduce its PoC and still
be unusable: c-blosc2 was observed producing 756 crashes in 10 minutes, which floods
the crash dir, and (with a userspace core_pattern) once left 36 apport processes
holding ~8000% CPU against 39 afl-fuzz processes at 188%.

Writes preflight_<project>.json next to the experiment dir. Exit 0 iff every stage
passed.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


# The pipeline modules (config, phase*, lib/, sandbox/) live at the repo root,
# one level up; Python only puts THIS script's directory on sys.path.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))


import config
import phase2_setup
import phase3_online
from lib import docker_util, tracked_git
from prework.prework_build import prework_image_for


def _entry(project: str) -> dict:
    for e in json.loads(Path(config.MANIFEST_PATH).read_text()):
        if e["project"] == project:
            return e
    raise SystemExit(f"no manifest entry for {project}")


def _count(p: Path) -> int:
    return sum(1 for _ in p.iterdir()) if p.is_dir() else 0


def smoke(entry, exp_dir, fuzz_target, cpu, secs) -> dict:
    """Run afl-fuzz briefly on the built baseline and report what it did."""
    bin_dir = Path(exp_dir) / "baseline" / "bin"
    seeds = Path(exp_dir) / "seed_corpus" / "merged"
    out = Path(exp_dir) / "preflight_afl_out"
    if out.exists():
        shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)
    name = f"preflight_{entry['project']}_{int(time.time())}"
    # Mirror phase3_runner.start_trial's invocation: --user so the output tree is
    # owned by the host user (without it afl_out is root-owned and unreadable),
    # HOME=/tmp because a pinned uid has no passwd entry, /out read-only, and the
    # same ASAN_OPTIONS the trials use.
    cmd = ["docker", "run", "--rm", "--name", name, "--privileged",
           "--cpuset-cpus", str(cpu), "--ulimit", "core=0",
           "--user", f"{os.getuid()}:{os.getgid()}",
           "-v", f"{bin_dir}:/out:ro", "-v", f"{seeds}:/corpus", "-v", f"{out}:/afl_out",
           "-e", "HOME=/tmp",
           "-e", "AFL_NO_AFFINITY=1", "-e", "AFL_SKIP_CPUFREQ=1",
           "-e", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1",
           "-e", "AFL_AUTORESUME=1",
           "-e", "ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0",
           prework_image_for(entry),
           "/out/afl-fuzz", "-i", "/corpus", "-o", "/afl_out", "-V", str(secs),
           "-m", "none", "-t", "5000+", "--", f"/out/{fuzz_target}"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=secs + 300)
    d = out / "default"
    stats = {}
    f = d / "fuzzer_stats"
    if f.exists():
        for line in f.read_text().splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                stats[k.strip()] = v.strip()
    crashes = _count(d / "crashes")
    queue = _count(d / "queue")
    execs = int(stats.get("execs_done", 0) or 0)
    rt = max(int(stats.get("run_time", 0) or 0), 1)
    return {"ok": execs > 0, "execs_done": execs, "run_time_s": rt,
            "execs_per_sec": round(execs / rt, 1), "corpus": queue,
            "crashes": max(crashes - 1, 0),  # README.txt
            "crashes_per_min": round(max(crashes - 1, 0) / (rt / 60.0), 1),
            "stderr_tail": (r.stderr or "")[-400:] if execs == 0 else ""}


def preflight(project: str, cpu: int, smoke_secs: int, keep: bool) -> dict:
    entry = _entry(project)
    fuzz_target = entry["fuzz_target"]
    exp_id = f"preflight-{project}"
    exp_dir = phase2_setup.get_experiment_dir(exp_id, entry)
    os.makedirs(exp_dir, exist_ok=True)
    online_dir = os.path.join(exp_dir, "optimized", "online")
    os.makedirs(online_dir, exist_ok=True)
    src_root = os.path.join(online_dir, "source_tree")
    bin_dir = os.path.join(exp_dir, "baseline", "bin")
    poc_dir = os.path.join(exp_dir, "poc")
    res = {"project": project, "cve": entry["cve"], "fuzz_target": fuzz_target,
           "experiment_dir": exp_dir, "stages": {}}

    def stage(name, ok, **kw):
        res["stages"][name] = {"ok": bool(ok), **kw}
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
              + (f"  {kw}" if kw else ""), flush=True)
        return ok

    t0 = time.time()
    try:
        img = prework_image_for(entry)
        have = subprocess.run(["docker", "image", "inspect", img],
                              capture_output=True).returncode == 0
        if not stage("image", have, image=img):
            return res

        t = time.time()
        crashed, poc_path, issue, source_root = phase3_online._extract_online_target(
            entry, src_root, bin_dir, poc_dir, fuzz_target, project)
        if not stage("extract", bool(source_root), secs=round(time.time() - t)):
            return res
        stage("poc", bool(crashed), reproduces_on_historical=bool(crashed))

        sub = Path(source_root)
        stage("source", phase3_online._src_subtree_has_files(sub), root=str(sub))

        n = phase3_online._stage_online_seed_corpus(exp_dir, bin_dir, fuzz_target)
        # A 1-byte fallback seed is legitimate (see _stage_online_seed_corpus:
        # only wolfssl/selinux ship a corpus zip). What is fatal is an EMPTY
        # directory -- AFL aborts at startup on an empty -i. So check the dir,
        # not the bundled count.
        merged = Path(exp_dir) / "seed_corpus" / "merged"
        staged = _count(merged)
        stage("seeds", staged > 0, bundled=n, staged_files=staged,
              fallback_only=(n == 0 and staged > 0))

        project_src_dir = str(phase2_setup._find_project_source(Path(source_root), project))
        stage("projectsrc", bool(project_src_dir), path=project_src_dir)

        # run_online strips the shipped repos BEFORE building (phase3_online 1a).
        # Skipping it made libredwg's build die on "detected dubious ownership in
        # repository", which is an artifact of preflighting, not a project defect.
        tracked_git.strip_vcs_metadata(source_root)
        stage("stripvcs", True)

        t = time.time()
        built = phase3_online._build_afl_baseline(
            entry=entry, project_src_dir=project_src_dir, baseline_bin_dir=bin_dir,
            fuzz_target=fuzz_target, poc_path=poc_path, profile_cpu=cpu)
        if not stage("aflbuild", built, secs=round(time.time() - t)):
            return res

        s = smoke(entry, exp_dir, fuzz_target, cpu, smoke_secs)
        stage("smoke", s.pop("ok"), **s)
    except Exception as e:  # noqa: BLE001 - a preflight reports failures, never raises
        stage("exception", False, error=f"{type(e).__name__}: {e}")
    finally:
        res["total_secs"] = round(time.time() - t0)
        res["ok"] = all(v["ok"] for v in res["stages"].values())
        out = Path(exp_dir).parent / f"preflight_{project}.json"
        out.write_text(json.dumps(res, indent=2))
        print(f"  -> {out}  ({'READY' if res['ok'] else 'NOT READY'})", flush=True)
        if not keep:
            shutil.rmtree(Path(exp_dir) / "preflight_afl_out", ignore_errors=True)
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", required=True)
    ap.add_argument("--cpu", type=int, default=3, help="core to pin builds/smoke to")
    ap.add_argument("--smoke-secs", type=int, default=120)
    ap.add_argument("--keep", action="store_true", help="keep the smoke afl_out")
    a = ap.parse_args()
    print(f"=== preflight {a.project} (cpu {a.cpu}, smoke {a.smoke_secs}s) ===", flush=True)
    return 0 if preflight(a.project, a.cpu, a.smoke_secs, a.keep)["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
