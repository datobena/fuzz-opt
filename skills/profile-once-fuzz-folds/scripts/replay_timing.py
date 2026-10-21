#!/usr/bin/env python3
"""Deterministic fixed-corpus replay timer for fuzz-target optimization.

Replays an identical, frozen corpus through a fuzz-target binary in libFuzzer's
non-mutating replay mode (`-runs=0`) and measures how long it takes. Because the
exact same inputs are run on both the baseline and the optimized binary, the
comparison is apples-to-apples and immune to the coverage-gradient divergence
that makes live `exec/s` misleading: an "optimization" that only changes which
inputs the fuzzer discovers (e.g. demoting error logging) cannot move this
number, so it is correctly judged "no good".

Speed is the *only* judge here. Coverage is deliberately ignored — removing
code (and the edges it carried) is a legitimate optimization, so a drop in
coverage is acceptable as long as replay gets faster.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import time
from pathlib import Path


RUNNER_IMAGE = "gcr.io/oss-fuzz-base/base-runner"


def build_replay_docker_command(
    *,
    out_dir: str | Path,
    corpus_dir: str | Path,
    fuzz_target: str,
    seed: int,
    cpu: int,
    memory: str,
    shm_size: str,
    rss_limit_mb: int = 3072,
    malloc_limit_mb: int = 1536,
    container_name: str | None = None,
) -> list[str]:
    """Build a `docker run` command that replays the corpus once, no mutation.

    `-runs=0` makes libFuzzer execute every unit in the corpus directory exactly
    once and then exit, without performing any mutation runs. Pinning the
    container to a single CPU and fixing the seed keep the measurement stable.
    The corpus and binary are both mounted read-only so a replay can never
    mutate the frozen evaluation set.
    """
    cmd = ["docker", "run", "--rm"]
    if container_name:
        cmd += ["--name", container_name]
    cmd += [
        "--cpuset-cpus", str(cpu),
        "--memory", memory,
        "--shm-size", shm_size,
        "--privileged",
        "-v", f"{Path(out_dir).absolute()}:/out:ro",
        "-v", f"{Path(corpus_dir).absolute()}:/corpus:ro",
        RUNNER_IMAGE,
        "/bin/bash", "-lc",
        (
            # Leak detection OFF (as in the phase-3 entrypoint): a benign leak in
            # a corpus input must not abort the replay -- that truncates the timing
            # and, worse, makes baseline and optimized replay a different number of
            # units (unfair). We are timing exec speed, not leak-checking.
            # symbolize=0 for the same reason leak detection is off: it is work
            # no source fold can reduce. A sanitizer finding otherwise spawns
            # llvm-symbolizer to parse DWARF (42-52% of a pass on assimp and
            # PcapPlusPlus), diluting the ratio this gate exists to measure.
            # Keep identical to replay_fuzzer_profile.py: profile and gate must
            # execute the same work.
            "export ASAN_OPTIONS=detect_leaks=0:symbolize=0 "
            "UBSAN_OPTIONS=symbolize=0 MSAN_OPTIONS=symbolize=0; "
            f"exec /out/{fuzz_target} /corpus "
            "-runs=0 "
            f"-seed={seed} "
            "-detect_leaks=0 "
            f"-rss_limit_mb={rss_limit_mb} "
            f"-malloc_limit_mb={malloc_limit_mb} "
            "-print_final_stats=1"
        ),
    ]
    return cmd


def parse_replay_stats(log: str) -> dict:
    """Pull libFuzzer's self-reported replay counters from its output."""
    import re

    stats: dict[str, int] = {}
    patterns = {
        "executed_units": r"stat::number_of_executed_units:\s*(\d+)",
        "average_exec_per_sec": r"stat::average_exec_per_sec:\s*(\d+)",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, log)
        if match:
            stats[key] = int(match.group(1))
    return stats


def median_of(values: list[float]) -> float:
    """Median of a non-empty list of measurements."""
    if not values:
        raise ValueError("no measurements to take the median of")
    return float(statistics.median(values))


def _run(cmd: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        errors="replace",  # libFuzzer replay output can contain non-UTF-8 bytes
        timeout=timeout,
        check=False,
    )


def measure_binary(
    *,
    out_dir: str | Path,
    corpus_dir: str | Path,
    fuzz_target: str,
    cpu: int,
    repeats: int,
    seed: int,
    memory: str,
    shm_size: str,
    run_timeout: int,
    max_attempts: int = 3,
    min_partial_units: int = 0,
    runner=_run,
    clock=time.monotonic,
) -> dict:
    """Replay the corpus `repeats` times and return median wall-clock time.

    Wall-clock per replay is the headline measurement; `repeats` runs are taken
    and reduced to a median to suppress scheduler noise. The libFuzzer
    `number_of_executed_units` counter is captured from a good run so the caller
    can sanity-check that both binaries replayed the same number of inputs.

    Crash tolerance (two tiers). A `-runs=0` replay runs every corpus unit in one
    process, so a single unit that hard-crashes (SIGSEGV/abort/OOM, exit != 0)
    aborts the pass *partway*. We prefer a clean full-corpus run: each slot is
    retried up to `max_attempts` times and a clean (exit 0) run wins. Retry alone
    recovers *non-deterministic*/transient crashers.

    But a *deterministic* crasher (an order/heap-dependent input the per-unit
    filter can't catch — every attempt dies at the same unit) would leave us with
    no clean run at all. Rather than blank the whole measurement to None
    ("unmeasurable" -> reverted), we salvage a **partial** measurement: a crashed
    run still executed a deterministic prefix of the corpus and prints
    `number_of_executed_units`, so `executed_units / elapsed` is a valid replay
    *rate* over that prefix. Because the crash is deterministic, every slot (and
    both the baseline and optimized binaries) crash at the **same** unit count, so
    comparing the rates is apples-to-apples over an identical prefix. A partial run
    is only accepted when it executed at least `min_partial_units` (below that the
    ~startup time dominates and the rate is noise). Clean runs always take
    precedence; partials are used only when NO clean run succeeded. The returned
    dict carries `partial=True` and `executed_units` so the caller can
    rate-normalize the speedup and flag it. `failed_runs` counts discarded (too
    few units / no stats) attempts.
    """
    times: list[float] = []            # clean full-corpus run times
    partial_times: list[float] = []    # crashed-but-usable prefix run times
    partial_units: list[int] = []      # executed_units for those partial runs
    last_stats: dict = {}
    last_partial_stats: dict = {}
    failed_runs = 0
    last_error = ""
    for i in range(repeats):
        for attempt in range(max_attempts):
            cmd = build_replay_docker_command(
                out_dir=out_dir,
                corpus_dir=corpus_dir,
                fuzz_target=fuzz_target,
                seed=seed,
                cpu=cpu,
                memory=memory,
                shm_size=shm_size,
                container_name=f"replay-{fuzz_target}-{i}-{attempt}",
            )
            start = clock()
            result = runner(cmd, timeout=run_timeout)
            elapsed = clock() - start
            stats = parse_replay_stats((result.stdout or "") + (result.stderr or ""))
            if result.returncode == 0:
                times.append(elapsed)
                if stats:
                    last_stats = stats
                break  # clean full-corpus run for this slot; move on
            # Crashed. Salvage a partial rate if a solid prefix ran, else retry
            # (transient/flaky/startup-only failures are worth another attempt).
            units = stats.get("executed_units")
            if units and units >= min_partial_units and elapsed > 0:
                partial_times.append(elapsed)
                partial_units.append(int(units))
                if stats:
                    last_partial_stats = stats
                break  # deterministic crash with a usable prefix; retry won't clean it
            failed_runs += 1
            last_error = (
                f"replay run {i} attempt {attempt} failed "
                f"(exit {result.returncode}, units={units}): "
                f"{(result.stderr or result.stdout or '')[-2000:]}"
            )

    if times:  # at least one clean full-corpus run -> pristine measurement
        return {
            "median_time_s": median_of(times),
            "times_s": times,
            "repeats": repeats,
            "successful_runs": len(times),
            "failed_runs": failed_runs,
            "executed_units": last_stats.get("executed_units"),
            "partial": False,
        }
    if partial_times:  # no clean run, but a deterministic prefix -> partial rate
        return {
            "median_time_s": median_of(partial_times),
            "times_s": partial_times,
            "repeats": repeats,
            "successful_runs": len(partial_times),
            "failed_runs": failed_runs,
            "executed_units": int(statistics.median(partial_units)),
            "partial": True,
        }
    raise RuntimeError(
        f"all {repeats} replay slots crashed after {max_attempts} attempts each "
        f"with no usable prefix (>= {min_partial_units} units); last error: {last_error}"
    )


def compare(baseline: dict, optimized: dict) -> float | None:
    """replay_speedup: how much faster the optimized binary replays the corpus.

    Clean runs (both timed the full corpus): ``baseline_time / optimized_time``.
    Partial runs (a deterministic crasher truncated the pass): rate-normalize by
    the executed-unit count so the comparison stays apples-to-apples over the
    prefix each binary reached::

        speedup = (opt_units / opt_time) / (base_units / base_time)

    which reduces to ``base_time / opt_time`` when both binaries crashed at the
    same unit count (the usual case, since the crash is deterministic).
    """
    b = baseline.get("median_time_s")
    o = optimized.get("median_time_s")
    if not b or not o:
        return None
    if baseline.get("partial") or optimized.get("partial"):
        bu = baseline.get("executed_units")
        ou = optimized.get("executed_units")
        if not bu or not ou:
            return None
        return round((ou / o) / (bu / b), 4)
    return round(b / o, 4)


def run(args: argparse.Namespace) -> int:
    common = dict(
        corpus_dir=args.corpus_dir,
        fuzz_target=args.fuzz_target,
        cpu=args.cpu,
        repeats=args.repeats,
        seed=args.seed,
        memory=args.memory,
        shm_size=args.shm_size,
        run_timeout=args.run_timeout,
        min_partial_units=args.min_partial_units,
    )
    optimized = measure_binary(out_dir=args.out_dir, **common)
    output = {
        "fuzz_target": args.fuzz_target,
        "corpus_dir": str(args.corpus_dir),
        "corpus_file_count": sum(
            1 for p in Path(args.corpus_dir).rglob("*") if p.is_file()
        ),
        "optimized": optimized,
    }
    if args.baseline_out_dir:
        baseline = measure_binary(out_dir=args.baseline_out_dir, **common)
        output["baseline"] = baseline
        output["replay_speedup"] = compare(baseline, optimized)
        output["replay_partial"] = bool(
            baseline.get("partial") or optimized.get("partial")
        )

    text = json.dumps(output, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(text)
    print(text)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Time deterministic corpus replay on a fuzz-target binary."
    )
    parser.add_argument("--out-dir", required=True,
                        help="/out dir of the binary under test (optimized)")
    parser.add_argument("--baseline-out-dir", default=None,
                        help="if set, also time the baseline binary and emit "
                             "replay_speedup = baseline_time / optimized_time")
    parser.add_argument("--corpus-dir", required=True,
                        help="frozen corpus snapshot replayed identically on "
                             "both binaries")
    parser.add_argument("--fuzz-target", required=True)
    parser.add_argument("--output", default=None, help="write JSON result here")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--cpu", type=int, default=3)
    parser.add_argument("--memory", default="4g")
    parser.add_argument("--shm-size", default="2g")
    parser.add_argument("--run-timeout", type=int, default=3600)
    parser.add_argument("--min-partial-units", type=int, default=0,
                        help="if a replay crashes but executed at least this many "
                             "units, salvage a partial rate measurement instead of "
                             "failing (0 accepts any prefix with >0 units)")
    return parser.parse_args()


def main() -> int:
    return run(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
