#!/usr/bin/env python3
"""Build a ranked candidate pool of NEW ARVO projects from the ARVO-Meta dataset.

Background (see plans/check-current-implementation-of-serene-acorn.md): the
benchmark's source-rebuild pipeline needs OSS-Fuzz *IssueTracker* ids
(`42xxxxxx`), and that pool (`cves.txt`) is exhausted. ARVO-Meta is keyed by old
*Monorail* ids that don't resolve at issues.oss-fuzz.com, BUT n132/ARVO publishes
prebuilt reproduce images (`n132/arvo:<monorail_id>-vul`) keyed by exactly those
ids. So we source NEW projects from ARVO-Meta metadata and verify them via the
prebuilt images (see screen_arvo_images.py).

This script: parse ARVO-Meta meta JSONs -> filter on measurement properties
(libFuzzer + ASAN + memory-safety crash) and novelty (project never touched) ->
rank for project diversity -> write arvo_meta_candidates.json.

Filter mirrors find_arvo_candidates.py:70 (engine/sanitizer), but sources from
ARVO-Meta instead of the exhausted cves.txt.
"""
import collections
import glob
import json
import os
import re
import sys

BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BENCH_DIR)
import config  # noqa: E402

META_DIR = os.path.join(BENCH_DIR, ".cache", "ARVO-Meta", "archive_data", "meta")
OUT_PATH = os.path.join(BENCH_DIR, "arvo_meta_candidates.json")

# Per project, keep this many fallback ids so the screener can retry a different
# bug of the same project if the first image fails to build/reproduce.
IDS_PER_PROJECT = 3

# Crash types that won't surface as a clean ASAN crash in the prebuilt image
# (libFuzzer/ASAN job with detect_leaks=0): skip them up front.
BAD_CRASH = ("leak", "timeout", "out-of-memory", "out of memory", "oom")

# Known very large / slow-to-compile projects — still eligible, but ranked last
# so the screener reaches 7 working projects without first burning time on a
# giant pull+compile. Not a correctness filter, purely a cost heuristic.
SLOW_PROJECTS = {
    "ghostpdl", "skia", "skia-ftz", "php-src", "binutils-gdb", "serenity",
    "envoy", "chromium", "llvm", "llvm_libcxxabi", "libreoffice", "mysql-server",
    "postgresql", "firefox", "node", "v8", "tensorflow", "qtbase", "wireshark",
}


def touched_projects():
    """Projects already tried = results/<exp>/<proj>-<CVE|OSV> dirs + denylist."""
    excl = set()
    for d in glob.glob(os.path.join(BENCH_DIR, "results", "*", "*")):
        if os.path.isdir(d):
            m = re.match(r"(.+?)-(CVE-\d+|OSV-\d+)", os.path.basename(d))
            if m:
                excl.add(m.group(1))
    try:
        for e in json.load(open(config.ARVO_BASELINE_DENYLIST_PATH)):
            excl.add(e["project"])
    except (FileNotFoundError, ValueError):
        pass
    return excl


def crash_ok(ct):
    ct = (ct or "").lower()
    return bool(ct) and not any(b in ct for b in BAD_CRASH)


def norm_crash(ct):
    """'Heap-buffer-overflow READ 1' -> 'heap-buffer-overflow' (first token)."""
    return (ct or "").strip().split()[0].lower() if ct else ""


def crash_quality(ct):
    """Rank clean memory-safety crashes above vague ones (lower = better)."""
    n = norm_crash(ct)
    if n in config.CRASH_TYPES:
        return 0
    if n in ("segv", "segv-on-unknown-address", "wild-address"):
        return 1
    if n in ("unknown", ""):
        return 3
    return 2


def main():
    if not os.path.isdir(META_DIR):
        sys.exit(f"ARVO-Meta metadata not found at {META_DIR}; sparse-clone it first.")

    excl = touched_projects()
    print(f"# {len(excl)} projects already touched (excluded)", flush=True)

    by_project = collections.defaultdict(list)
    total = 0
    for f in glob.glob(os.path.join(META_DIR, "*.json")):
        total += 1
        try:
            d = json.load(open(f))
        except ValueError:
            continue
        proj = d.get("project")
        if (
            d.get("fuzzer") == "libfuzzer"
            and d.get("sanitizer") == "asan"
            and proj
            and proj not in excl
            and crash_ok(d.get("crash_type"))
        ):
            try:
                lid = int(d["localId"])
            except (KeyError, ValueError):
                continue
            by_project[proj].append({
                "project": proj,
                "local_id": lid,           # ARVO/Monorail id == n132/arvo image tag
                "image": f"n132/arvo:{lid}-vul",
                "crash_type": d.get("crash_type", ""),
                "sanitizer": d.get("sanitizer", ""),
                "fuzzer": d.get("fuzzer", ""),
                "verify": d.get("verify", ""),
                "repo_addr": d.get("repo_addr", ""),
            })

    # Within each project: best crash quality first, then lowest id (older/stabler).
    for proj, items in by_project.items():
        items.sort(key=lambda r: (crash_quality(r["crash_type"]), r["local_id"]))

    # Project order: more available bugs first (more established / more fallbacks),
    # but push known-giant projects to the end (cost heuristic).
    proj_order = sorted(
        by_project,
        key=lambda p: (p in SLOW_PROJECTS, -len(by_project[p]), p),
    )

    candidates = []
    for proj in proj_order:
        for rec in by_project[proj][:IDS_PER_PROJECT]:
            candidates.append(rec)

    json.dump(candidates, open(OUT_PATH, "w"), indent=2)

    print(f"# parsed {total} meta files", flush=True)
    print(f"# {len(by_project)} distinct NEW projects available "
          f"({sum(len(v) for v in by_project.values())} total bugs)", flush=True)
    print(f"# wrote {len(candidates)} ranked candidates "
          f"(<= {IDS_PER_PROJECT}/project) -> {OUT_PATH}", flush=True)
    print("# first 15 projects in screening order:", flush=True)
    for proj in proj_order[:15]:
        top = by_project[proj][0]
        print(f"    {proj:20} bugs={len(by_project[proj]):<3} "
              f"first={top['local_id']} crash='{top['crash_type']}'", flush=True)


if __name__ == "__main__":
    main()
