#!/usr/bin/env python3
"""Capture EVERY libFuzzer mutation into a saved corpus (regardless of coverage).

Shared by the tools/run_hotspotdiff.py diagnostic and phase-2 (phase2_setup.py). The
capture works by building a DIAGNOSTIC copy of the fuzz target with a custom
mutator shim (``mutation_dump_mutator.c``) linked in, fuzzing it from an initial
corpus, and having the shim persist every produced mutation. The result is frozen
into an immutable corpus that a later ``-runs=0`` replay can profile/time -- so the
profile, the acceptance gate, and the saved corpus are all the exact same inputs.

libFuzzer only persists coverage-increasing units and has no dump-all flag, and
``LLVMFuzzerCustomMutator`` is a static (weak) symbol that cannot be LD_PRELOADed,
so the shim must be linked into the target. It is injected as an object on the
fuzz-target link line in build.sh (before ``$LIB_FUZZING_ENGINE``, the OSS-Fuzz
convention) during an OSS-Fuzz ``compile``.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)

RUNNER_IMAGE = "gcr.io/oss-fuzz-base/base-runner"
SHIM_SRC_DEFAULT = str(Path(__file__).with_name("mutation_dump_mutator.c"))


def _run(cmd, *, timeout=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, capture_output=True, text=True, errors="replace",
        timeout=timeout, check=False,
    )


def _count_files(directory: str | Path) -> int:
    directory = Path(directory)
    if not directory.is_dir():
        return 0
    return sum(1 for p in directory.rglob("*") if p.is_file())


def _parse_final_stats(log_text: str) -> dict:
    stats = {}
    m = re.search(r"stat::number_of_executed_units:\s*(\d+)", log_text)
    if m:
        stats["executed_units"] = int(m.group(1))
    for m in re.finditer(r"cov:\s*(\d+)\s+ft:\s*(\d+)", log_text):
        stats["cov"], stats["ft"] = int(m.group(1)), int(m.group(2))
    m = re.search(r"gen_rc=(\d+)", log_text)
    if m:
        stats["gen_rc"] = int(m.group(1))
    # Emitted by the shim when the file cap is hit and it early-exits (libFuzzer's
    # DONE stats line is then skipped, so this carries the counts instead).
    m = re.search(r"MUTATION_DUMP_DONE saved=(\d+)\s+seen=(\d+)", log_text)
    if m:
        stats["dumped_saved"] = int(m.group(1))
        stats["dumped_seen"] = int(m.group(2))
    return stats


def build_shim_build_docker_command(
    *,
    image: str,
    shim_src: str | Path,
    out_dir: str | Path,
    sanitizer: str = "address",
    engine: str = "libfuzzer",
    arch: str = "x86_64",
    language: str = "c++",
    compile_cmd: str = "compile",
    container_name: str | None = None,
) -> list[str]:
    """Build a diagnostic fuzz target with the mutation-dump shim linked in.

    Compiles the shim, then sed-injects its object onto the fuzz-target LINK line in
    build.sh so it is compiled in as a real (defined) symbol -- picking whichever of
    the two OSS-Fuzz link conventions this project uses: the ``-lFuzzingEngine`` flag
    (e.g. libxml2) or ``$LIB_FUZZING_ENGINE`` = ``.../libFuzzingEngine.a`` (e.g.
    selinux, wolfssl, libavc, assimp) -- exactly one, so LLVMFuzzerCustomMutator is
    never duplicated. Then runs the project's normal ``compile`` (``arvo compile``
    for n132 images). The result in ``/out`` is the baseline target plus a DEFINED
    ``LLVMFuzzerCustomMutator`` (a PATH compiler-wrapper does not survive the OSS-Fuzz
    compile flow, hence the direct build.sh edit).
    """
    script = (
        "set -e; "
        "$CC $CFLAGS -c /mutation_shim.c -o /tmp/mutation_shim.o; "
        # (1) direct build.sh link line (selinux/libxml2/libavc/assimp)
        "if grep -q -- '-lFuzzingEngine' \"$SRC/build.sh\"; then "
        "sed -i 's| -lFuzzingEngine| /tmp/mutation_shim.o -lFuzzingEngine|g' \"$SRC/build.sh\"; "
        "else "
        "sed -i 's|\\$LIB_FUZZING_ENGINE|/tmp/mutation_shim.o \\$LIB_FUZZING_ENGINE|g' \"$SRC/build.sh\"; "
        "fi; "
        # (2) nested per-fuzzer Makefiles that link via a FUZZERS_LIBS variable
        # (wolfssl's triple-nested build); a no-op for projects without them.
        "for mk in $(find \"$SRC\" -path '*fuzzers/Makefile' 2>/dev/null); do "
        "grep -q '^FUZZERS_LIBS' \"$mk\" && sed -i 's|^\\(FUZZERS_LIBS[A-Z_]* =\\) |\\1 /tmp/mutation_shim.o |' \"$mk\"; "
        "done; "
        f"{compile_cmd}"
    )
    cmd = ["docker", "run", "--rm", "--privileged"]
    if container_name:
        cmd += ["--name", container_name]
    cmd += [
        "-e", f"FUZZING_ENGINE={engine}",
        "-e", f"SANITIZER={sanitizer}",
        "-e", f"ARCHITECTURE={arch}",
        "-e", f"FUZZING_LANGUAGE={language}",
        "-v", f"{Path(shim_src).resolve()}:/mutation_shim.c:ro",
        "-v", f"{Path(out_dir).resolve()}:/out",
        "--entrypoint", "/bin/bash",
        image, "-lc", script,
    ]
    return cmd


def build_generation_docker_command(
    *,
    gen_out_dir: str | Path,
    seed_corpus_dir: str | Path,
    work_corpus_dir: str | Path,
    mut_dir: str | Path,
    fuzz_target: str,
    duration: int,
    seed: int,
    cap: int = 50000,
    every: int = 1,
    reservoir: bool = True,
    sample_seed: int | None = None,
    guarantee_queue: bool = True,
    queue_depth: int = 5,
    cpu: int = 3,
    memory: str = "4g",
    shm_size: str = "2g",
    rss_limit_mb: int = 3072,
    malloc_limit_mb: int = 1536,
    runner_image: str = RUNNER_IMAGE,
    container_name: str | None = None,
) -> list[str]:
    """``docker run`` that fuzzes the shim target and dumps a sample of mutations.

    ``/seeds`` is the initial corpus (read-only), ``/corpus`` an empty writable dir
    (libFuzzer's evolving set), and ``/muts`` where the shim writes mutations
    (``cap`` files max). ``reservoir=True`` (default) makes the shim keep a UNIFORM
    random sample over the WHOLE run via Algorithm R -- it runs the full
    ``duration`` so the sample reaches deep/late-queue mutations. ``reservoir=False``
    is the legacy first-``cap`` prefix (early-exits once the cap is filled, biased
    toward the opening of the run). ``sample_seed`` seeds the reservoir PRNG
    (defaults to ``seed`` -> reproducible). A crash on the vulnerable target is
    tolerated -- mutations already written are kept, and docker exits 0 so we judge
    success by the file count.
    """
    fuzz_cmd = (
        f"/out/{fuzz_target} /corpus /seeds "
        f"-seed={int(seed)} -max_total_time={int(duration)} -print_final_stats=1 "
        f"-detect_leaks=0 -rss_limit_mb={int(rss_limit_mb)} -malloc_limit_mb={int(malloc_limit_mb)} "
        "-artifact_prefix=/tmp/gen-artifacts/"
    )
    cmd = ["docker", "run", "--rm"]
    if container_name:
        cmd += ["--name", container_name]
    cmd += [
        "--cpuset-cpus", str(cpu),
        "--memory", memory,
        "--shm-size", shm_size,
        "--privileged",
        "-e", "MUTATION_DUMP_DIR=/muts",
        "-e", f"MUTATION_DUMP_CAP={int(cap)}",
        "-e", f"MUTATION_DUMP_EVERY={int(every)}",
        "-e", f"MUTATION_DUMP_RESERVOIR={1 if reservoir else 0}",
        "-e", f"MUTATION_DUMP_SEED={int(sample_seed if sample_seed is not None else seed)}",
        # Guaranteed one-pass over the seed queue (/seeds): every input mutated
        # queue_depth times, reserved from reservoir eviction.
        *(["-e", "MUTATION_QUEUE_DIR=/seeds",
           "-e", f"MUTATION_QUEUE_DEPTH={int(queue_depth)}"] if guarantee_queue else []),
        "-v", f"{Path(gen_out_dir).resolve()}:/out:ro",
        "-v", f"{Path(seed_corpus_dir).resolve()}:/seeds:ro",
        "-v", f"{Path(work_corpus_dir).resolve()}:/corpus",
        "-v", f"{Path(mut_dir).resolve()}:/muts",
        runner_image,
        "/bin/bash", "-lc",
        (
            "mkdir -p /tmp/gen-artifacts; "
            f"{fuzz_cmd}; echo \"gen_rc=$?\"; exit 0"
        ),
    ]
    return cmd


def build_replay_timing_docker_command(
    *,
    gen_out_dir: str | Path,
    seed_corpus_dir: str | Path,
    fuzz_target: str,
    cpu: int = 3,
    memory: str = "4g",
    rss_limit_mb: int = 3072,
    runner_image: str = RUNNER_IMAGE,
    container_name: str | None = None,
) -> list[str]:
    """``-runs=0`` replay of the seed queue (executes every input once, no fuzzing).

    Timing this run = ``time_for_one_queue``: how long the fuzzer takes to traverse
    the initial queue once. A crash on the vulnerable target is tolerated (exit 0);
    the caller times wall-clock, so a crash just yields a shorter measured time.
    """
    cmd = ["docker", "run", "--rm"]
    if container_name:
        cmd += ["--name", container_name]
    cmd += [
        "--cpuset-cpus", str(cpu),
        "--memory", memory,
        "--privileged",
        "-v", f"{Path(gen_out_dir).resolve()}:/out:ro",
        "-v", f"{Path(seed_corpus_dir).resolve()}:/seeds:ro",
        runner_image,
        "/bin/bash", "-lc",
        (
            "export ASAN_OPTIONS=detect_leaks=0; "
            f"/out/{fuzz_target} /seeds -runs=0 -detect_leaks=0 "
            f"-rss_limit_mb={int(rss_limit_mb)} -print_final_stats=1 2>&1; exit 0"
        ),
    ]
    return cmd


def _freeze_flat_corpus(src_dir: str | Path, dst_dir: str | Path, *, prefix="unit") -> int:
    """Freeze a flat, immutable snapshot of a corpus (sequential <prefix>_ names)."""
    src_dir, dst_dir = Path(src_dir), Path(dst_dir)
    if dst_dir.exists():
        shutil.rmtree(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    for p in sorted(src_dir.rglob("*")):
        if p.is_file():
            shutil.copy2(p, dst_dir / f"{prefix}_{n:08d}")
            n += 1
    return n


def run_mutation_capture(
    *,
    image: str,
    shim_src: str | Path,
    gen_out_dir: str | Path,
    seed_corpus_dir: str | Path,
    work_corpus_dir: str | Path,
    mut_raw_dir: str | Path,
    frozen_dir: str | Path,
    fuzz_target: str,
    duration: int,
    seed: int,
    cap: int = 50000,
    every: int = 1,
    reservoir: bool = True,
    sample_seed: int | None = None,
    guarantee_queue: bool = True,
    queue_depth: int = 5,
    ensure_one_queue_pass: bool = True,
    cpu: int = 3,
    sanitizer: str = "address",
    engine: str = "libfuzzer",
    arch: str = "x86_64",
    language: str = "c++",
    compile_cmd: str = "compile",
    reuse_build: bool = True,
    build_timeout: int = 3600,
) -> tuple[Path, dict]:
    """Build the shim target, generate a saved mutation corpus, and freeze it.

    Returns ``(frozen_corpus_dir, metadata)``. The frozen corpus is the exact set
    of inputs a later ``-runs=0`` replay profiles, so profile == replay == corpus.
    """
    gen_out_dir = Path(gen_out_dir)
    gen_out_dir.mkdir(parents=True, exist_ok=True)
    shim_bin = gen_out_dir / fuzz_target

    # 1. Build the shim-instrumented target (skip if already present).
    built = bool(reuse_build and shim_bin.is_file())
    if not built:
        build_cmd = build_shim_build_docker_command(
            image=image, shim_src=shim_src, out_dir=gen_out_dir, sanitizer=sanitizer,
            engine=engine, arch=arch, language=language, compile_cmd=compile_cmd,
            container_name=f"mutcap-build-{os.getpid()}-{uuid.uuid4().hex[:8]}",
        )
        bres = _run(build_cmd, timeout=build_timeout)
        if not shim_bin.is_file():
            raise RuntimeError(
                f"shim build failed (no /out/{fuzz_target}); output:\n"
                + ((bres.stdout or "") + (bres.stderr or ""))[-2000:]
            )

    if _count_files(seed_corpus_dir) == 0:
        raise RuntimeError(f"mutation-capture seed corpus is empty: {seed_corpus_dir}")

    # 2. Run the capture for max(duration, time_for_one_queue): time a -runs=0
    #    replay of the seed queue so slow/large-queue targets still get at least
    #    one full traversal (otherwise the reservoir only sees the opening entries).
    queue_replay_secs = None
    effective_duration = int(duration)
    if ensure_one_queue_pass:
        t0 = time.time()
        _run(build_replay_timing_docker_command(
            gen_out_dir=gen_out_dir, seed_corpus_dir=seed_corpus_dir,
            fuzz_target=fuzz_target, cpu=cpu,
            container_name=f"mutcap-qtime-{os.getpid()}-{uuid.uuid4().hex[:8]}",
        ), timeout=int(duration) + 3600)
        queue_replay_secs = round(time.time() - t0, 1)
        effective_duration = max(int(duration), int(queue_replay_secs) + 1)
        logger.info("mutation capture: one-queue-pass=%.1fs, duration=%ds -> running %ds",
                    queue_replay_secs, int(duration), effective_duration)

    # 3. Generate: fuzz the shim target, dumping every mutation to mut_raw_dir.
    mut_raw, work = Path(mut_raw_dir), Path(work_corpus_dir)
    for d in (mut_raw, work):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)
    gen_cmd = build_generation_docker_command(
        gen_out_dir=gen_out_dir, seed_corpus_dir=seed_corpus_dir, work_corpus_dir=work,
        mut_dir=mut_raw, fuzz_target=fuzz_target, duration=effective_duration, seed=seed,
        cap=cap, every=every, reservoir=reservoir, sample_seed=sample_seed,
        guarantee_queue=guarantee_queue, queue_depth=queue_depth, cpu=cpu,
        container_name=f"mutcap-gen-{os.getpid()}-{uuid.uuid4().hex[:8]}",
    )
    gres = _run(gen_cmd, timeout=int(effective_duration) + 900)
    raw_n = _count_files(mut_raw)
    if raw_n == 0:
        raise RuntimeError(
            "mutation generation produced no inputs; output:\n"
            + ((gres.stdout or "") + (gres.stderr or ""))[-2000:]
        )

    # 3. Freeze the saved mutations into an immutable replay set.
    frozen_n = _freeze_flat_corpus(mut_raw, frozen_dir)
    shutil.rmtree(work, ignore_errors=True)
    shutil.rmtree(mut_raw, ignore_errors=True)  # frozen copy is the deliverable
    meta = {
        "mode": "mutation-capture",
        "image": image,
        "duration": duration,
        "queue_replay_secs": queue_replay_secs,
        "effective_duration": effective_duration,
        "seed": seed,
        "cap": cap,
        "every": every,
        "reservoir": reservoir,
        "sample_seed": int(sample_seed if sample_seed is not None else seed),
        "guarantee_queue": guarantee_queue,
        "queue_depth": queue_depth,
        "built_shim": not built,
        "raw_count": raw_n,
        "frozen_count": frozen_n,
        "seed_corpus_dir": str(seed_corpus_dir),
        "seed_corpus_file_count": _count_files(seed_corpus_dir),
        "final_stats": _parse_final_stats((gres.stdout or "") + (gres.stderr or "")),
    }
    Path(frozen_dir).parent.mkdir(parents=True, exist_ok=True)
    (Path(frozen_dir).parent / "capture_metadata.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True)
    )
    return Path(frozen_dir), meta
