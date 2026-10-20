#!/usr/bin/env python3
"""Per-trial, per-BUG first-discovery times — the input to a discovery curve.

dedup_crashes.py collapses artifacts into distinct bugs but reports only totals
(`trials`, `first_seen_s`) per bug. A discovery curve needs the earliest time
EACH TRIAL reached EACH bug, so this replays every artifact, takes the crash
report's identity via prework.verify.report_identity, and keeps the earliest
timestamp per (trial, bug).

Identity is (sanitizer kind, top non-runtime frame). The kind alone is not
enough and the raw artifact count is worse: yara-arvo-3848 yields two distinct
defects, and AFL re-saves the same one after every hot-swap resume, so counting
artifacts measures restarts rather than bugs.

Writes <exp>/bug_discovery.json:
    {"<variant>": {"<bug signature>": {"trial_00": first_seen_s, ...}, ...}, ...}
"""
import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


# The pipeline modules (config, phase*, lib/, sandbox/) live at the repo root,
# one level up; Python only puts THIS script's directory on sys.path.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import config
from lib import afl_triage
from lib.afl import collect_crashes
from lib.crash_classify import (SANITIZER_ERROR_RE, replay_sanitizer_env,
                                ubsan_identity)
from lib.provenance import experiment_image
from prework.verify import report_identity

_FRAME_RE = re.compile(r"#\d+ 0x[0-9a-f]+ in ([A-Za-z_][A-Za-z0-9_:]*)")
_RUNTIME_FRAMES = ("__asan", "__sanitizer", "__interceptor", "__lsan")

# Same normalisation dedup_crashes.py applies: a fold that shifts allocation
# layout can make ASan trip use-after-poison where the reference build reports
# heap-buffer-overflow at the same frame. One bug, two checks.
_KIND_ALIASES = {
    "use-after-poison": "heap-use-after-free",
    "heap-buffer-overflow": "heap-use-after-free",
}


def _identity(blob):
    """"<kind>:<top frame>" for ASan; "ubsan:<check>:<file>:<line>" for UBSan.

    report_identity only knows lowercase ASan classes, so deadly signals
    ("AddressSanitizer: SEGV") are read here too. ABRT is skipped: FuzzBench's
    UBSAN_OPTIONS (handle_abort=2) turns every assert() into an ASan ABRT
    report, and asserts are not counted as bugs here (as before).
    """
    blob = blob or ""
    kind, frames = report_identity(blob)
    if kind == "ABRT":
        return None
    if not kind:
        e = SANITIZER_ERROR_RE.search(blob)
        if e and e.group(1) == "AddressSanitizer" and e.group(2) != "ABRT":
            kind = e.group(2)
            frames = [f for f in _FRAME_RE.findall(blob)
                      if not f.startswith(_RUNTIME_FRAMES)]
    if not kind:
        ub = ubsan_identity(blob)
        return ub["signature"] if ub else None
    return f"{_KIND_ALIASES.get(kind, kind)}:{frames[0] if frames else '?'}"


def replay_one(ctx, path):
    """Replay and return (identity, verdict). Reuses afl_triage's docker call."""
    import subprocess
    import shutil
    import tempfile
    with tempfile.TemporaryDirectory(prefix="disc-") as td:
        staged = Path(td) / "testcase"
        shutil.copyfile(path, staged)
        cmd = [
            "docker", "run", "--rm", "--privileged",
            # FuzzBench UBSAN_OPTIONS + symbolize=1 (crash_classify.replay_sanitizer_env)
            "-e", "UBSAN_OPTIONS=" + replay_sanitizer_env("")["UBSAN_OPTIONS"],
            "-v", f"{Path(ctx.out_dir).absolute()}:/out:ro",
            "-v", f"{staged}:/testcase:ro",
            "--entrypoint", "/bin/bash", ctx.image, "-lc",
            f"export ASAN_OPTIONS=detect_leaks=0; /out/{ctx.fuzz_target} /testcase",
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               errors="replace", timeout=ctx.timeout)
        except subprocess.TimeoutExpired:
            return None
    return _identity((r.stdout or "") + (r.stderr or ""))


def trial_bugs(args_tuple):
    variant, tname, tdir, ctx = args_tuple
    crashes = os.path.join(tdir, "afl_out", "default", "crashes")
    if not os.path.isdir(crashes):
        return variant, tname, {}
    index = {}
    base = Path(crashes)
    for d in [base] + sorted(p for p in base.parent.glob(base.name + ".*") if p.is_dir()):
        if d.is_dir():
            for f in d.iterdir():
                if f.is_file():
                    index.setdefault(f.name, f)
    found = {}
    for e in collect_crashes(crashes):
        p = index.get(e["artifact"])
        if not p:
            continue
        ident = replay_one(ctx, p)
        if not ident:
            continue
        ts = float(e["timestamp_s"])
        if ident not in found or ts < found[ident]:
            found[ident] = ts
    return variant, tname, found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--experiment", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--jobs", type=int, default=8)
    args = ap.parse_args()

    entry = {e["project"]: e for e in json.load(open(config.MANIFEST_PATH))}[args.project]
    key = f"{args.project}-{entry['cve']}"
    root = os.path.join(config.RESULTS_DIR, args.experiment, key)

    tasks = []
    for variant in ("baseline", "optimized"):
        vdir = os.path.join(root, variant)
        if not os.path.isdir(vdir):
            continue
        # Replay on each arm's OWN binary: the question is what that arm's
        # fuzzer actually hit, not how its inputs behave elsewhere.
        # The image the experiment ran with (recorded in its provenance), else
        # prework_image_for(entry), else the legacy bench-aflpp tag.
        image = experiment_image(root, entry) or f"bench-aflpp/{key}"
        ctx = afl_triage._Ctx(image, os.path.join(vdir, "bin"),
                              entry["fuzz_target"], "", 120)
        for t in sorted(d for d in os.listdir(vdir) if d.startswith("trial_")):
            tasks.append((variant, t, os.path.join(vdir, t), ctx))

    out = {}
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = [ex.submit(trial_bugs, t) for t in tasks]
        for f in as_completed(futs):
            variant, tname, found = f.result()
            for ident, ts in found.items():
                out.setdefault(variant, {}).setdefault(ident, {})[tname] = ts
            print(f"  {variant}/{tname}: {len(found)} distinct bug(s)", flush=True)

    path = os.path.join(config.RESULTS_DIR, args.experiment, "bug_discovery.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nwrote {path}")
    for variant, bugs in out.items():
        for ident, trials in sorted(bugs.items()):
            print(f"  {variant:10s} {ident:48s} {len(trials)}/9 trials")
    return 0


if __name__ == "__main__":
    sys.exit(main())
