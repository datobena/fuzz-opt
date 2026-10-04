#!/usr/bin/env python3
"""Screen ARVO prebuilt images to collect N new working projects.

For each candidate (from arvo_meta_candidates.json) verify the n132/arvo image
"works" = builds from source AND reproduces its planted bug:

  1. docker pull n132/arvo:<id>-vul
  2. reproduce: `arvo`  -> exit!=0 and "ERROR/SUMMARY: AddressSanitizer: <type>"
  3. build:     `arvo compile` -> exit 0   (rebuilds the target from /src)
  4. discover fuzz_target from /bin/arvo (`/out/<target> /tmp/poc`)
  5. docker rmi (free disk; images are GB-scale)

Concurrency: one worker per project (sequential id-retry within a project,
parallel across projects), up to PHASE2_MAX_PARALLEL. Stop once TARGET distinct
projects pass. Resumable: prior verdicts in arvo_image_screen_results.json are
reused so reruns skip already-screened ids.

The arvo contract was locked by the Step-0 probe (see the plan file):
  - reproduce: `docker run --rm <img> arvo`
  - build:     `docker run --rm <img> arvo compile`
"""
import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import threading
import time

BENCH_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The pipeline modules (config, phase*, lib/, sandbox/) live at the repo root,
# one level up; Python only puts THIS script's directory on sys.path.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import config  # noqa: E402

CAND_PATH = os.path.join(BENCH_DIR, "data", "arvo", "arvo_meta_candidates.json")
RESULTS_PATH = os.path.join(BENCH_DIR, "data", "arvo", "arvo_image_screen_results.json")
KEEP_PATH = os.path.join(BENCH_DIR, "data", "arvo", "new_arvo_projects.json")

PULL_TIMEOUT = 600       # 10 min
REPRO_TIMEOUT = 300      # 5 min
COMPILE_TIMEOUT = 1800   # 30 min

ASAN_ERR = re.compile(r"(?:ERROR|SUMMARY): AddressSanitizer: ([a-zA-Z0-9_\-]+)")
LIBFUZZER_CRASH = re.compile(r"ERROR: libFuzzer: (deadly signal|[a-z-]+)")

_print_lock = threading.Lock()


def log(msg):
    with _print_lock:
        print(msg, flush=True)


def _run(cmd, timeout):
    """Run a command; return (exit_code|None-on-timeout, combined_output)."""
    try:
        p = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, text=True, errors="replace",
        )
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired as e:
        return None, (e.output or "") if isinstance(e.output, str) else ""


def docker_pull(image):
    return _run(["docker", "pull", image], PULL_TIMEOUT)


def docker_rmi(image):
    _run(["docker", "rmi", "-f", image], 120)


def reproduce(image):
    """Run the bundled PoC against the prebuilt target. Returns (ok, observed)."""
    rc, out = _run(["docker", "run", "--rm", image, "arvo"], REPRO_TIMEOUT)
    if rc is None:
        return False, "timeout", out
    m = ASAN_ERR.search(out)
    observed = m.group(1).lower() if m else None
    crashed = rc != 0 and (m is not None or LIBFUZZER_CRASH.search(out) is not None)
    return crashed, (observed or ("crash" if crashed else "no-crash")), out


def compile_from_src(image):
    rc, out = _run(["docker", "run", "--rm", image, "arvo", "compile"], COMPILE_TIMEOUT)
    if rc is None:
        return False, out
    return rc == 0, out


def discover_fuzz_target(image):
    rc, out = _run(
        ["docker", "run", "--rm", "--entrypoint", "bash", image, "-lc",
         "grep -oE '/out/[^ ]+ /tmp/poc' /bin/arvo | head -1"], 120)
    m = re.search(r"/out/(\S+)\s+/tmp/poc", out or "")
    if m:
        return m.group(1)
    rc, out = _run(
        ["docker", "run", "--rm", "--entrypoint", "bash", image, "-lc",
         "find /out -maxdepth 1 -type f -executable -printf '%f\\n' | head -1"], 120)
    return (out or "").strip().splitlines()[0] if out and out.strip() else ""


def screen_candidate(rec):
    """Full screen of one candidate. Returns a verdict dict."""
    image = rec["image"]
    proj = rec["project"]
    started = time.time()
    log(f"[screen] {proj} {image} : pulling...")
    rc, out = docker_pull(image)
    if rc != 0:
        docker_rmi(image)
        return {**rec, "status": "image_missing", "build_ok": False,
                "reproduce_ok": False, "notes": (out or "")[-300:].strip(),
                "elapsed": round(time.time() - started)}

    try:
        repro_ok, observed, _rlog = reproduce(image)
        if not repro_ok:
            log(f"[screen] {proj} {image} : NO reproduce ({observed})")
            return {**rec, "status": "no_reproduce", "build_ok": None,
                    "reproduce_ok": False, "observed_crash": observed,
                    "elapsed": round(time.time() - started)}

        log(f"[screen] {proj} {image} : reproduced ({observed}); compiling...")
        build_ok, clog = compile_from_src(image)
        fuzz_target = discover_fuzz_target(image) if build_ok else ""
        status = "working" if build_ok else "build_failed"
        log(f"[screen] {proj} {image} : build_ok={build_ok} -> {status}")
        return {**rec, "status": status, "build_ok": build_ok,
                "reproduce_ok": True, "observed_crash": observed,
                "fuzz_target": fuzz_target,
                "notes": "" if build_ok else (clog or "")[-300:].strip(),
                "elapsed": round(time.time() - started)}
    finally:
        docker_rmi(image)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=7,
                    help="number of distinct new working projects to collect")
    ap.add_argument("--max-parallel", type=int,
                    default=getattr(config, "PHASE2_MAX_PARALLEL", 4))
    ap.add_argument("--max-ids-per-project", type=int, default=3)
    args = ap.parse_args()

    candidates = json.load(open(CAND_PATH))

    # Group candidates by project, preserving file (ranked) order.
    proj_ids, proj_order = {}, []
    for rec in candidates:
        p = rec["project"]
        if p not in proj_ids:
            proj_ids[p] = []
            proj_order.append(p)
        if len(proj_ids[p]) < args.max_ids_per_project:
            proj_ids[p].append(rec)

    # Resume: reuse prior verdicts (skip already-screened local_ids).
    results, screened_ids = [], set()
    if os.path.exists(RESULTS_PATH):
        results = json.load(open(RESULTS_PATH))
        screened_ids = {r["local_id"] for r in results}
        log(f"[resume] loaded {len(results)} prior verdicts")

    res_lock = threading.Lock()
    working = []                      # passing verdicts, one per distinct project
    working_projs = set()
    done = threading.Event()

    def persist():
        json.dump(results, open(RESULTS_PATH, "w"), indent=2)

    # seed `working` from prior results so reruns accumulate toward TARGET
    for r in results:
        if r.get("status") == "working" and r["project"] not in working_projs:
            working_projs.add(r["project"])
            working.append(r)
    if len(working) >= args.target:
        done.set()

    def process_project(proj):
        if done.is_set() or proj in working_projs:
            return
        for rec in proj_ids[proj]:
            if done.is_set():
                return
            if rec["local_id"] in screened_ids:
                continue
            verdict = screen_candidate(rec)
            with res_lock:
                results.append(verdict)
                screened_ids.add(rec["local_id"])
                persist()
                if (verdict["status"] == "working"
                        and proj not in working_projs):
                    working_projs.add(proj)
                    working.append(verdict)
                    log(f"[progress] working projects: {len(working)}/{args.target} "
                        f"-> {sorted(working_projs)}")
                    if len(working) >= args.target:
                        done.set()
                    return
            if verdict["status"] == "working":
                return

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_parallel) as ex:
        futs = [ex.submit(process_project, p) for p in proj_order]
        for f in concurrent.futures.as_completed(futs):
            f.result()
            if done.is_set():
                break

    keep = working[:args.target]
    keep_out = [{
        "project": w["project"],
        "local_id": w["local_id"],
        "image": w["image"],
        "fuzz_target": w.get("fuzz_target", ""),
        "crash_type": w.get("crash_type", ""),
        "observed_crash": w.get("observed_crash", ""),
        "sanitizer": w.get("sanitizer", ""),
        "fuzzer": w.get("fuzzer", ""),
        "repo_addr": w.get("repo_addr", ""),
    } for w in keep]
    json.dump(keep_out, open(KEEP_PATH, "w"), indent=2)
    persist()

    by_status = {}
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    log("\n=== screening summary ===")
    log(f"screened verdicts: {len(results)}  by status: {by_status}")
    log(f"distinct working projects: {len(working)} (kept {len(keep_out)})")
    for w in keep_out:
        log(f"  {w['project']:18} id={w['local_id']:<7} {w['fuzz_target']:28} "
            f"crash='{w['observed_crash']}'")
    log(f"\nwrote {KEEP_PATH} and {RESULTS_PATH}")


if __name__ == "__main__":
    main()
