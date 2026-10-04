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

sys.path.insert(0, str(Path(__file__).resolve().parent))

import config
from lib import afl, crash_classify
from prework.prework_build import prework_image_for

_ASAN = re.compile(r"ERROR: AddressSanitizer: ([a-z-]+)")
_FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in ([A-Za-z_][A-Za-z0-9_:]*)")
_RUNTIME = ("__asan", "__sanitizer", "__interceptor", "__lsan", "operator new",
            "malloc", "free", "realloc", "calloc")


def signature(out: str) -> str | None:
    """(error kind, first non-runtime frame) -- the identity of a crash.

    The top frames are sanitizer interceptors (``__asan_memcpy`` and friends),
    identical for every overflow, so the first PROJECT frame is what separates
    one bug from another.
    """
    kind = _ASAN.search(out)
    if not kind:
        return None
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


def trial_online_dir(campaign_online: Path, trial_name: str) -> Path:
    """This trial's own online dir, or the campaign one for legacy layouts.

    Under the per-trial-optimizer design each optimized trial has its own
    optimizer, its own swap timeline and its own iter_NN/bin snapshots at
    ``optimized/online/trials/trial_XX``. Reading the campaign-level dir there
    would resolve a crash against ANOTHER optimizer's binary -- silently, and
    producing exactly the mislabelled "does not reproduce" verdicts that the
    live_binary field exists to prevent.
    """
    m = re.search(r"trial_(\d+)", str(trial_name))
    if m:
        d = Path(campaign_online) / "trials" / f"trial_{int(m.group(1)):02d}"
        if d.is_dir():
            return d
    return Path(campaign_online)


def live_binary(online_dir: Path, trial_start: float, crash_t: float,
                baseline_bin: Path) -> tuple[Path, str]:
    """The binary the trial was executing when a crash at ``crash_t`` fired.

    Before the first swap that is iter_00 (a copy of the baseline build); after
    swap N it is iter_NN's archived binary.
    """
    wall = trial_start + crash_t
    try:
        timeline = json.loads((online_dir / "swap_timeline.json").read_text())
    except (OSError, json.JSONDecodeError):
        timeline = []
    live = None
    for entry in sorted(timeline, key=lambda e: e.get("ts", 0)):
        if entry.get("ts", 0) <= wall:
            live = entry.get("iter")
    if live is None:
        return baseline_bin, "iter_00"
    d = online_dir / f"iter_{int(live):02d}" / "bin"
    return (d, f"iter_{int(live):02d}") if d.is_dir() else (baseline_bin, "iter_00")


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
        image = prework_image_for(entry)
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
