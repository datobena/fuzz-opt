#!/usr/bin/env python3
"""Check the six FuzzBench bug benchmarks' PoCs (data/fuzzbench_pocs/) against a build.

Each PoC runs one-shot (`/out/<target> <file>`), so LeakSanitizer gets its exit-time
scan -- the only way the mbedtls leak shows. It reproduces when the output contains
every string listed for it in manifest.json; every negative control must show no
sanitizer report, or the run is not trusted.

  python3 tools/check_fuzzbench_pocs.py --benchmark mbedtls_fuzz_dtlsclient_7c6b0e \\
      --bin-dir results/<exp>/<target>/baseline/bin
  python3 tools/check_fuzzbench_pocs.py --experiment results/online-24h-r2-mbedtls

--experiment checks baseline/bin and every optimized/bin_* (and, with --rounds, every
optimized/online/trials/*/iter_*/bin) of that campaign. Exit status 1 if a PoC does
not reproduce on a baseline or a negative control reports anything.

--per-trial checks each optimized trial's DEPLOYED binaries newest first (iter_00 and
every kept round), stopping at the first one where every PoC reproduces; the round
just above it is the one that stopped the bug from reproducing.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
POCS = REPO / "data" / "fuzzbench_pocs"
MANIFEST = POCS / "manifest.json"

# alloc_dealloc_mismatch=0: an old dynamic-libc++ build otherwise aborts on every
# caught C++ exception before reaching the bug (bloaty). detect_leaks=1: mbedtls.
ASAN = "detect_leaks=1:symbolize=1:abort_on_error=0:alloc_dealloc_mismatch=0"
UBSAN = "print_stacktrace=1:symbolize=1"
MARKERS = ("ERROR: AddressSanitizer", "ERROR: LeakSanitizer", "runtime error:",
           "Assertion", "SUMMARY: ")


def run_one(image: str, bin_dir: Path, bench_dir: Path, target: str, name: str,
            cpus: str) -> str:
    cmd = ["docker", "run", "--rm", "--memory", "8g", "--cpuset-cpus", cpus,
           "-v", f"{bin_dir.absolute()}:/out:ro", "-v", f"{bench_dir}:/pocs:ro",
           "-e", f"ASAN_OPTIONS={ASAN}", "-e", f"UBSAN_OPTIONS={UBSAN}",
           "--entrypoint", "/bin/sh", image,
           "-c", f"timeout 60 /out/{target} /pocs/{name} 2>&1"]
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=180)
    return r.stdout + r.stderr


def image_for(bench: str, bin_dir: Path, target: str, cpus: str, override: str | None) -> str:
    """fb-aflpp/<bench> for parity builds; old dynamic-libc++ builds only load in
    bench-fb/<bench>."""
    if override:
        return override
    for image in (f"fb-aflpp/{bench}", f"bench-fb/{bench}"):
        r = subprocess.run(
            ["docker", "run", "--rm", "--cpuset-cpus", cpus, "-v",
             f"{bin_dir.absolute()}:/out:ro", "--entrypoint", "/bin/sh", image, "-c",
             f"ldd /out/{target} | grep -q 'not found' && exit 1 || exit 0"],
            capture_output=True)
        if r.returncode == 0:
            return image
    return f"fb-aflpp/{bench}"


def check(bench: str, bin_dir: Path, cpus: str, image: str | None) -> dict:
    spec = json.loads(MANIFEST.read_text())[bench]
    target = spec["fuzz_target"]
    bench_dir = POCS / bench
    img = image_for(bench, bin_dir, target, cpus, image)
    res = {"bin_dir": str(bin_dir), "image": img, "pocs": {}, "negatives": {}}
    for name, expect in spec["pocs"].items():
        out = run_one(img, bin_dir, bench_dir, target, name, cpus)
        res["pocs"][name] = all(e in out for e in expect)
    for name in spec["negatives"]:
        out = run_one(img, bin_dir, bench_dir, target, name, cpus)
        res["negatives"][name] = not any(m in out for m in MARKERS)
    return res


def bench_of(experiment: Path) -> tuple[str, Path]:
    """(benchmark dir, target dir) for a campaign dir, via the binary it contains."""
    manifest = json.loads(MANIFEST.read_text())
    for target_dir in sorted(p for p in experiment.iterdir() if p.is_dir()):
        bins = target_dir / "baseline" / "bin"
        for bench, spec in manifest.items():
            if bench.startswith("_"):
                continue
            if (bins / spec["fuzz_target"]).is_file() and \
                    bench.split("_")[0] in target_dir.name:
                return bench, target_dir
    raise SystemExit(f"no known FuzzBench bug benchmark under {experiment}")


def deployed_bins(trial_dir: Path, target: str) -> list[Path]:
    """iter_00 plus every kept round's bin, oldest first. A rejected round's bin dir
    holds the previous best, and an unfinished round has no outcome; neither ran."""
    out = []
    for it in sorted(trial_dir.glob("iter_*")):
        if not (it / "bin" / target).is_file():
            continue
        prov = it / "round_provenance.json"
        outcome = json.loads(prov.read_text()).get("outcome") if prov.is_file() else None
        if it.name == "iter_00" or outcome == "kept":
            out.append(it / "bin")
    return out


def per_trial(bench: str, tdir: Path, cpus: str, image: str | None) -> bool:
    target = json.loads(MANIFEST.read_text())[bench]["fuzz_target"]
    bad = False
    for trial in sorted((tdir / "optimized" / "online" / "trials").glob("trial_*")):
        bins = deployed_bins(trial, target)
        newer = None
        for b in reversed(bins):
            r = check(bench, b, cpus, image)
            pocs = " ".join(f"{k}={'yes' if v else 'NO'}" for k, v in r["pocs"].items())
            negs = all(r["negatives"].values())
            print(f"  {trial.name} {b.parent.name}: {pocs}  "
                  f"negatives={'clean' if negs else 'REPORTED'}")
            bad |= not negs
            if all(r["pocs"].values()):
                if newer is not None:
                    print(f"  {trial.name}: stops reproducing at {newer.parent.name}")
                break
            newer = b
        else:
            print(f"  {trial.name}: does not reproduce on any deployed binary")
            bad = True
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--benchmark", help="e.g. mbedtls_fuzz_dtlsclient_7c6b0e")
    ap.add_argument("--bin-dir", type=Path, help="a /out dir holding the fuzz target")
    ap.add_argument("--experiment", type=Path, help="results/<exp> campaign dir")
    ap.add_argument("--rounds", action="store_true",
                    help="with --experiment, also every per-round optimized binary")
    ap.add_argument("--per-trial", action="store_true",
                    help="with --experiment, newest deployed binary per trial, walking "
                         "back only where a PoC does not reproduce")
    ap.add_argument("--cpus", default="32-39")
    ap.add_argument("--image", help="override the docker image")
    a = ap.parse_args()

    if a.experiment and a.per_trial:
        bench, tdir = bench_of(a.experiment)
        print(f"{bench}")
        return 1 if per_trial(bench, tdir, a.cpus, a.image) else 0
    if a.experiment:
        bench, tdir = bench_of(a.experiment)
        dirs = [tdir / "baseline" / "bin"] + sorted((tdir / "optimized").glob("bin_*"))
        if a.rounds:
            dirs += sorted(tdir.glob("optimized/online/trials/*/iter_*/bin"))
    elif a.benchmark and a.bin_dir:
        bench, dirs = a.benchmark, [a.bin_dir]
    else:
        ap.error("give --experiment, or --benchmark with --bin-dir")

    target = json.loads(MANIFEST.read_text())[bench]["fuzz_target"]
    bad = False
    print(f"{bench}")
    for d in dirs:
        if not (d / target).is_file():
            continue
        r = check(bench, d, a.cpus, a.image)
        pocs = " ".join(f"{k}={'yes' if v else 'NO'}" for k, v in r["pocs"].items())
        negs = all(r["negatives"].values())
        print(f"  {d}: {pocs}  negatives={'clean' if negs else 'REPORTED'}  [{r['image']}]")
        is_baseline = d.parent.name == "baseline" or a.bin_dir is not None
        if not negs or (is_baseline and not all(r["pocs"].values())):
            bad = True
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
