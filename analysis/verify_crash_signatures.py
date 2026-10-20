#!/usr/bin/env python3
"""Classify each online-arm crash against the binary that was LIVE when it fired.

Why this is needed
------------------
A crash artifact proves the target died; it does not prove the target died of
the bug under study. Two things make that distinction easy to lose in the online
arm:

  * The binary changes mid-run. Replaying against ``optimized/bin`` classifies a
    crash against whatever the LAST hot swap installed -- and after the final
    round that is a binary no trial ever executed.
  * An optimization can INTRODUCE a crash. Observed on wolfssl: round 5's fold
    added a stack-buffer-overflow absent from the baseline and from rounds 1-4,
    which round 7 then removed. Three artifacts came from it. Counting those as
    finds credits the arm with discovering a bug the optimizer itself created.

So each artifact is replayed against the binary live at its own timestamp, and
kept only if its sanitizer signature matches the reference the PoC produces on
the baseline binary.

    python3 verify_crash_signatures.py --experiment-id online-24h-b1-wolfssl
    python3 verify_crash_signatures.py --experiment-id ... --apply
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


# The pipeline modules (config, phase*, lib/, sandbox/) live at the repo root,
# one level up; Python only puts THIS script's directory on sys.path.
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))


import config
from lib import afl, crash_classify
from lib.provenance import experiment_image

# Lowercase classes AND deadly signals (SEGV, BUS, FPE, ILL): "[a-z-]+" alone
# never matched "AddressSanitizer: SEGV on unknown address". ABRT is left out
# on purpose: FuzzBench's UBSAN_OPTIONS (handle_abort=2) makes every assert()
# print an ASan ABRT report, and asserts are classified separately.
_ASAN = re.compile(r"ERROR: AddressSanitizer: (?!ABRT\b)([A-Za-z][A-Za-z0-9_-]*)")
_FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in ([A-Za-z_][A-Za-z0-9_:]*)")
_RUNTIME = ("__asan", "__sanitizer", "__interceptor", "__lsan", "operator new",
            "malloc", "free", "realloc", "calloc")


def signature(out: str) -> str | None:
    """(error kind, first non-runtime frame) -- the identity of a crash.

    The top frames are sanitizer interceptors (``__asan_memcpy`` and friends),
    identical for every overflow, so the first PROJECT frame is what separates
    one bug from another.

    A UBSan finding (FuzzBench bug builds) has no "ERROR: AddressSanitizer"
    line and no stack; its identity is "ubsan:<check>:<file>:<line>"
    (crash_classify.ubsan_identity).
    """
    kind = _ASAN.search(out)
    if not kind:
        ub = crash_classify.ubsan_identity(out)
        return ub["signature"] if ub else None
    for fn in _FRAME.findall(out):
        if not fn.startswith(_RUNTIME):
            return f"{kind.group(1)}:{fn}"
    return kind.group(1)


def replay(image: str, bin_dir: Path, fuzz_target: str, testcase: Path,
           cpu: int, timeout: int = 90) -> str:
    # AFL names artifacts "id:000000,sig:06,...". Docker parses colons in a -v
    # spec as field separators, so mounting the artifact directly fails with
    # "too many colons" -- and a failed mount looks exactly like a target that
    # did not crash. Stage it under a neutral name first.
    with tempfile.TemporaryDirectory(prefix="sigchk-") as tmp:
        staged = Path(tmp) / "tc"
        shutil.copyfile(testcase, staged)
        cmd = ["docker", "run", "--rm", "--privileged", "--cpuset-cpus", str(cpu),
               # alloc_dealloc_mismatch OFF: our targets link libc++/libc++abi
               # DYNAMICALLY while upstream ARVO links them statically. With two
               # copies of the teardown code, libc++.so.1 allocates
               # std::runtime_error's message with `operator new` and
               # libc++abi.so.1 frees it with `free`, so EVERY caught C++
               # exception reports alloc-dealloc-mismatch. It is a property of
               # our linkage, not the target: disabling this one option
               # reconciles our assimp build with the upstream reference on
               # 3042/3042 artifacts, and OSS-Fuzz's own runner disables it too.
               "-e", "ASAN_OPTIONS=detect_leaks=0:alloc_dealloc_mismatch=0",
               # FuzzBench's UBSAN_OPTIONS + symbolize=1: a FuzzBench bug build
               # reports UBSan exactly as under afl-fuzz, and symbolize=1 keeps
               # ASan frame names (UBSAN_OPTIONS' symbolize=0 would strip them).
               "-e", "UBSAN_OPTIONS=" + crash_classify.replay_sanitizer_env("")["UBSAN_OPTIONS"],
               "-v", f"{bin_dir.absolute()}:/out:ro",
               "-v", f"{staged}:/tc:ro",
               "--entrypoint", "/bin/bash", image, "-lc",
               f"timeout {timeout - 20} /out/{fuzz_target} /tc 2>&1"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               errors="replace", timeout=timeout)
        except subprocess.TimeoutExpired:
            return ""
    return (r.stdout or "") + (r.stderr or "")


# Moved to lib/ so the orchestrator can import them without this script's
# import-time sys.path edit and CLI dependencies. Re-exported under the old names:
# dedup_crashes.py, cross_check_bugs.py and the tests call V.live_binary.
from lib.live_binary import live_binary, trial_online_dir  # noqa: E402,F401


def resolve_entry(exp_dir_name: str, manifest: dict) -> dict | None:
    """Manifest entry for a results directory.

    The directory is named ``<project>-<cve>``, and the CVE half may itself
    contain hyphens ("selinux-CVE-2021-36085"). Splitting on hyphen count
    therefore yields "selinux-CVE" and silently matches nothing -- the target is
    skipped and the run reports success having done no work. Match the project
    prefix against the manifest instead of inferring it from the name.
    """
    for name, entry in manifest.items():
        if exp_dir_name == name or exp_dir_name.startswith(name + "-"):
            return entry
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--cpu", type=int, default=1)
    ap.add_argument("--apply", action="store_true",
                    help="rewrite crash_times.json/metadata.json (default: report)")
    args = ap.parse_args()

    manifest = {e["project"]: e for e in json.loads(Path(config.MANIFEST_PATH).read_text())}
    root = Path(config.RESULTS_DIR) / args.experiment_id
    if not root.is_dir():
        print(f"no such experiment: {root}", file=sys.stderr)
        return 1

    for exp_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        entry = resolve_entry(exp_dir.name, manifest)
        if entry is None:
            continue
        image = experiment_image(exp_dir, entry)
        fuzz_target = entry["fuzz_target"]
        baseline_bin = exp_dir / "baseline" / "bin"
        online_dir = exp_dir / "optimized" / "online"
        poc = exp_dir / "poc" / "poc_input"

        ref = signature(replay(image, baseline_bin, fuzz_target, poc, args.cpu))
        print(f"\n=== {exp_dir.name} ===\n  reference signature (PoC on baseline): {ref}")
        if not ref:
            print("  cannot establish a reference; skipping")
            continue

        for arm in ("baseline", "optimized"):
            for trial in sorted((exp_dir / arm).glob("trial_*")):
                try:
                    meta = json.loads((trial / "metadata.json").read_text())
                except (OSError, json.JSONDecodeError):
                    continue
                arts = afl.collect_crashes(trial / "afl_out" / "default" / "crashes")
                if not arts:
                    continue
                kept, rejected = [], []
                for a in arts:
                    path = next(iter(
                        (trial / "afl_out" / "default").glob(f"crashes*/{a['artifact']}")), None)
                    if path is None:
                        continue
                    if arm == "optimized":
                        b, label = live_binary(
                            trial_online_dir(online_dir, trial.name),
                            meta.get("start_time", 0),
                            a["timestamp_s"], baseline_bin)
                    else:
                        b, label = baseline_bin, "baseline"
                    sig = signature(replay(image, b, fuzz_target, path, args.cpu))
                    (kept if sig == ref else rejected).append((a, sig, label))
                ttb = crash_classify.trial_time_to_bug(
                    [{"timestamp_s": k[0]["timestamp_s"], "artifact": k[0]["artifact"],
                      "crash_type": "crash"} for k in kept], meta.get("duration_seconds"))
                note = "" if not rejected else "  rejected: " + ", ".join(
                    f"{s or 'no-crash'}@{lab}" for _, s, lab in rejected)
                print(f"  {arm:9} {trial.name}: {len(kept)}/{len(arts)} match"
                      f"  ttb={'-' if ttb is None else f'{ttb:.1f}s'}{note}")
                if args.apply:
                    ct = [{"timestamp_s": k[0]["timestamp_s"],
                           "artifact": k[0]["artifact"], "crash_type": "crash"}
                          for k in kept]
                    (trial / "crash_times.json").write_text(json.dumps(ct, indent=2))
                    meta["num_crashes"] = len(ct)
                    meta["found_bug"] = crash_classify.trial_found_bug(
                        ct, meta.get("duration_seconds"))
                    meta["time_to_bug_s"] = ttb
                    meta["crash_signatures_verified"] = True
                    (trial / "metadata.json").write_text(json.dumps(meta, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
