"""Capture the mutations AFL actually executes, for phase-2 profiling.

Phase 2 profiles and gates on the corpus the fuzzer really runs, not just the
seeds -- the hotspot ranking differs substantially between the two, which is why
mutation augmentation is mandatory rather than optional.

Much simpler than the libFuzzer version in mutation_capture.py. There,
LLVMFuzzerCustomMutator is a static weak symbol that cannot be LD_PRELOADed, so
the shim had to be compiled into a DIAGNOSTIC REBUILD of the target with an
object injected onto build.sh's link line. AFL++ loads custom mutators at runtime
through AFL_CUSTOM_MUTATOR_LIBRARY, so the target is never rebuilt: compile a
.so, set two env vars, fuzz.

The shim hooks afl_custom_post_process rather than afl_custom_fuzz. post_process
is a pass-through called on every input just before execution, so the mutation
DISTRIBUTION is unchanged and inputs AFL later discards are still seen -- the
profile has to reflect what the fuzzer executes, not what it keeps.
"""
from __future__ import annotations

import logging
import shlex
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

SHIM_SRC = Path(__file__).resolve().parent.parent / "mutation_dump_afl.c"
DEFAULT_CAP = 20000
DEFAULT_DURATION = 600


def build_capture_command(
    *, image: str, out_dir: str, seeds_dir: str, work_dir: str,
    fuzz_target: str, shim_src: str | Path = SHIM_SRC,
    duration: int = DEFAULT_DURATION, cap: int = DEFAULT_CAP,
    every: int = 1, seed: int = 1337, cpu: int | None = None,
    llvm_version: int = 18,
) -> list[str]:
    """One container that compiles the shim, fuzzes, and leaves the dump behind.

    Compiled with the image's pinned clang rather than afl-clang-fast: the shim
    is a plain host-side .so that AFL dlopens, and instrumenting it would only
    add noise to the coverage map.
    """
    script = (
        f"set -e; "
        f"clang-{llvm_version} -O2 -shared -fPIC -o /work/mutdump.so /work/shim.c; "
        f"export AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 "
        f"AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1; "
        f"export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0; "
        f"export AFL_CUSTOM_MUTATOR_LIBRARY=/work/mutdump.so; "
        f"export MUTATION_DUMP_DIR=/work/dump MUTATION_DUMP_CAP={int(cap)} "
        f"MUTATION_DUMP_EVERY={int(every)} MUTATION_DUMP_SEED={int(seed)}; "
        f"mkdir -p /work/dump /work/aflout; "
        f"/out/afl-fuzz -V {int(duration)} -s {int(seed)} -m none -t 5000+ "
        f"-i /seeds -o /work/aflout -- /out/{shlex.quote(fuzz_target)} "
        f"> /work/capture.log 2>&1 || true; "
        f"chmod -R a+rX /work"
    )
    cmd = ["docker", "run", "--rm", "--privileged"]
    if cpu is not None:
        cmd += ["--cpuset-cpus", str(cpu)]
    cmd += [
        "-v", f"{Path(out_dir).absolute()}:/out:ro",
        "-v", f"{Path(seeds_dir).absolute()}:/seeds:ro",
        "-v", f"{Path(work_dir).absolute()}:/work",
        "-v", f"{Path(shim_src).absolute()}:/work/shim.c:ro",
        "--entrypoint", "/bin/bash", image, "-lc", script,
    ]
    return cmd


def capture_mutations(
    *, image: str, out_dir: str, seeds_dir: str, work_dir: str,
    fuzz_target: str, duration: int = DEFAULT_DURATION, cap: int = DEFAULT_CAP,
    every: int = 1, seed: int = 1337, cpu: int | None = None,
    timeout: int | None = None,
) -> dict:
    """Run a capture. Returns {dump_dir, captured, ok, log_tail}.

    `captured == 0` is a FAILURE, not an empty result: phase 2 treats mutation
    augmentation as mandatory, and profiling seeds alone would silently measure
    the wrong workload.
    """
    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)
    dump = work / "dump"

    cmd = build_capture_command(
        image=image, out_dir=out_dir, seeds_dir=seeds_dir, work_dir=str(work),
        fuzz_target=fuzz_target, duration=duration, cap=cap, every=every,
        seed=seed, cpu=cpu,
    )
    logger.info("capturing AFL mutations for %s (%ds, cap %d)",
                fuzz_target, duration, cap)
    try:
        subprocess.run(
            cmd, capture_output=True, text=True, errors="replace",
            timeout=timeout or (duration + 900),
        )
    except subprocess.TimeoutExpired:
        logger.error("mutation capture timed out for %s", fuzz_target)

    captured = sum(1 for p in dump.rglob("*") if p.is_file()) if dump.is_dir() else 0
    log_path = work / "capture.log"
    tail = ""
    if log_path.is_file():
        tail = "\n".join(log_path.read_text(errors="replace").splitlines()[-40:])
    if captured == 0:
        logger.error("mutation capture produced NOTHING for %s; "
                     "profiling seeds alone would measure the wrong workload",
                     fuzz_target)
    return {
        "dump_dir": str(dump),
        "captured": captured,
        "ok": captured > 0,
        "log_tail": tail,
    }
