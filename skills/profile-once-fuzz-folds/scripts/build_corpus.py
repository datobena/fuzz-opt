#!/usr/bin/env python3
"""Grow a fuzzing corpus once off the baseline binary, then freeze it.

``profile-once-fuzz-folds`` builds ONE fixed corpus up front:

1. Flat-copy the merged seed corpus into a grow working dir.
1b. (optional) Time-budget sizing: probe per-unit replay time on a small random
   sample and cap the corpus to the largest N whose full replay-gate measurement
   fits ``--replay-budget-secs``. A slow target (radare2/ia_fuzz) thus gets a
   small corpus that actually completes filter/profile/gate; a fast target keeps
   its full corpus. Off by default (``--replay-budget-secs 0``).
2. Crash-filter it. The baseline is the *vulnerable* version, so a public-corpus
   input can legitimately crash it, and an unfiltered crasher would abort both
   the grow run (libFuzzer dies reading a crashing seed) and the later
   replay-timing gate. Filtering is done efficiently: a single bulk ``-runs=0``
   replay over the whole corpus detects whether *any* unit crashes; only then is
   a per-unit filter run -- and that filter is ONE container that executes the
   target on each unit as a subprocess (not one ``docker run`` per file, which is
   prohibitive for a 10k+ file public corpus).
3. Fuzz the baseline read-write for a fixed duration so libFuzzer appends newly
   discovered units in place. No perf here -- the authoritative profile is taken
   later by ``replay_fuzzer_profile.py``.
4. Freeze a flat, immutable snapshot of the GROWN corpus (reuses
   ``real_fuzzer_profile.snapshot_corpus``).

The snapshot is frozen AFTER the grow window, so it reflects the full duration of
fuzzing. That snapshot is the fixed evaluation set used by both the one-shot
replay profile and the per-cycle replay-timing acceptance gate.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import re
import shutil
import subprocess
import os
import time
import uuid
from pathlib import Path


def _load_sibling(mod_name: str):
    """Load a sibling script module by file name to reuse its shared helpers."""
    path = Path(__file__).with_name(f"{mod_name}.py")
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {mod_name} from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rfp = _load_sibling("real_fuzzer_profile")
# replay_timing supplies the exact -runs=0 replay command + stats parser the
# acceptance gate uses, so the sizing probe measures per-unit time the same way.
rt = _load_sibling("replay_timing")
RUNNER_IMAGE = rfp.RUNNER_IMAGE


def _run(cmd, *, timeout=None) -> subprocess.CompletedProcess:
    """subprocess.run with errors='replace'. libFuzzer/corpus output is often not
    valid UTF-8 (raw corpus bytes get echoed), which would crash the default text
    decoding that ``real_fuzzer_profile._run`` uses."""
    return subprocess.run(
        cmd, capture_output=True, text=True, errors="replace",
        timeout=timeout, check=False,
    )


def _flat_copy_corpus(src_dir: str | Path, dst_dir: str | Path) -> int:
    """Flatten-copy every file under src into dst as unit_XXXXXXXX; return count."""
    src_dir = Path(src_dir)
    dst_dir = Path(dst_dir)
    if dst_dir.exists():
        shutil.rmtree(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for src_path in sorted(src_dir.rglob("*")):
        if src_path.is_file():
            shutil.copy2(src_path, dst_dir / f"unit_{count:08d}")
            count += 1
    return count


def _mount_flags(out_dir, corpus_dir, *, corpus_ro, cpu, memory, shm_size, cpus=None):
    corpus_mount = f"{Path(corpus_dir).resolve()}:/corpus" + (":ro" if corpus_ro else "")
    # `cpus` (a CFS quota, e.g. --cpus 8) lets the parallel crash-filter use N
    # cores without pinning to specific ones (avoids cpuset collisions with
    # other concurrent phase-2 workers). Timing steps still pin one core via
    # `cpu`/--cpuset-cpus for stable measurements.
    cpu_flags = ["--cpus", str(cpus)] if cpus is not None else ["--cpuset-cpus", str(cpu)]
    return cpu_flags + [
        "--memory", memory,
        "--shm-size", shm_size,
        "--privileged",
        # Absolute paths required: docker treats a relative `-v src:/dst` as a
        # named volume, not a bind mount.
        "-v", f"{Path(out_dir).resolve()}:/out:ro",
        "-v", corpus_mount,
    ]


def build_bulk_replay_command(
    *, out_dir, corpus_dir, fuzz_target, seed, cpu, memory, shm_size,
    container_name: str | None = None,
) -> list[str]:
    """One-shot ``-runs=0`` replay over the whole corpus (read-only) to detect
    quickly whether any unit crashes the baseline."""
    cmd = ["docker", "run", "--rm"]
    if container_name:
        cmd += ["--name", container_name]
    cmd += _mount_flags(out_dir, corpus_dir, corpus_ro=True, cpu=cpu, memory=memory, shm_size=shm_size)
    cmd += [
        RUNNER_IMAGE, "/bin/bash", "-lc",
        (
            f"exec /out/{fuzz_target} /corpus -runs=0 -seed={seed} "
            "-rss_limit_mb=3072 -malloc_limit_mb=1536 -print_final_stats=1"
        ),
    ]
    return cmd


def build_crash_filter_command(
    *, out_dir, corpus_dir, fuzz_target, per_unit_timeout, ncpu, memory, shm_size,
    container_name: str | None = None,
) -> list[str]:
    """ONE container that runs the target on each unit as a subprocess and removes
    any unit that crashes or hangs (corpus mounted read-write). This avoids a
    ``docker run`` per file, which is prohibitive for large public corpora.

    Runs the per-unit checks in parallel with ``xargs -P{ncpu}`` (given ``--cpus
    {ncpu}`` of quota) so a slow target's large corpus is filtered in wall-clock
    ~1/ncpu of a serial pass. Uses ``detect_leaks=0`` -- matching the replay and
    profile steps -- so a benign leak is NOT mistaken for a crash and the unit is
    not wrongly removed, and each unit runs at the same speed the replay sees.
    """
    # Per-unit check, single-quoted for the xargs child shell. `$0` is the
    # filename xargs appends. Same -rss/-malloc caps + detect_leaks=0 as replay.
    inner = (
        f"timeout {int(per_unit_timeout)} /out/{fuzz_target} "
        "-rss_limit_mb=3072 -malloc_limit_mb=1536 -detect_leaks=0 "
        '"$0" >/dev/null 2>&1 || rm -f "$0"'
    )
    cmd = ["docker", "run", "--rm"]
    if container_name:
        cmd += ["--name", container_name]
    cmd += _mount_flags(out_dir, corpus_dir, corpus_ro=False, cpu=0,
                        memory=memory, shm_size=shm_size, cpus=int(ncpu))
    cmd += [
        RUNNER_IMAGE, "/bin/bash", "-lc",
        (
            "set -u; export ASAN_OPTIONS=detect_leaks=0; "
            "before=$(find /corpus -maxdepth 1 -type f | wc -l); "
            "find /corpus -maxdepth 1 -type f -print0 | "
            f"xargs -0 -P{int(ncpu)} -n1 bash -c '{inner}'; "
            "after=$(find /corpus -maxdepth 1 -type f | wc -l); "
            'echo "REMOVED=$((before-after)) KEPT=$after"'
        ),
    ]
    return cmd


def build_grow_docker_command(
    *,
    out_dir: str | Path,
    corpus_dir: str | Path,
    artifact_dir: str | Path,
    fuzz_target: str,
    duration: int,
    seed: int,
    cpu: int,
    memory: str,
    shm_size: str,
    rss_limit_mb: int = 3072,
    malloc_limit_mb: int = 1536,
    container_name: str | None = None,
) -> list[str]:
    """``docker run`` that fuzzes the corpus read-write to grow it (no perf).

    The corpus is bind-mounted read-write and passed as libFuzzer's primary corpus
    directory, so units discovered during the window are appended in place and
    persist on the host. Profiling is intentionally not done here.
    """
    cmd = ["docker", "run", "--rm"]
    if container_name:
        cmd += ["--name", container_name]
    cmd += _mount_flags(out_dir, corpus_dir, corpus_ro=False, cpu=cpu, memory=memory, shm_size=shm_size)
    cmd += [
        "-v", f"{Path(artifact_dir).resolve()}:/artifacts",
        RUNNER_IMAGE, "/bin/bash", "-lc",
        (
            "set -uo pipefail; "
            "mkdir -p /tmp/grow-artifacts; "
            "rc=0; "
            f"/out/{fuzz_target} /corpus "
            f"-seed={seed} "
            f"-max_total_time={duration} "
            # Crash-tolerant fork mode: a timed grow on a VULNERABLE baseline must
            # not stop at the first crash (that yields an empty/tiny corpus and a
            # meaningless replay). -fork keeps generating past crashes/timeouts/OOMs
            # so the replay corpus reflects a real fuzzing workload.
            "-fork=1 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 "
            "-print_final_stats=1 "
            f"-rss_limit_mb={rss_limit_mb} "
            f"-malloc_limit_mb={malloc_limit_mb} "
            "-artifact_prefix=/tmp/grow-artifacts/ "
            "> /artifacts/grow.log 2>&1 || rc=$?; "
            "chmod a+r /artifacts/grow.log 2>/dev/null || true; "
            "exit $rc"
        ),
    ]
    return cmd


def filter_crashers(args, grow_dir: Path) -> dict:
    """Drop units that crash the (vulnerable) baseline. Bulk-check first; only run
    the per-unit filter if the bulk replay actually crashes."""
    if rfp._count_files(grow_dir) == 0:
        return {"bulk_replay_exit": 0, "removed_crashers": 0, "filtered": False}

    bulk = _run(
        build_bulk_replay_command(
            out_dir=args.out_dir, corpus_dir=grow_dir, fuzz_target=args.fuzz_target,
            seed=args.seed, cpu=args.cpu, memory=args.memory, shm_size=args.shm_size,
            container_name=f"poff-bulk-{os.getpid()}-{uuid.uuid4().hex[:8]}",
        ),
        timeout=args.filter_timeout,
    )
    if bulk.returncode == 0:
        return {"bulk_replay_exit": 0, "removed_crashers": 0, "filtered": False}

    filt = _run(
        build_crash_filter_command(
            out_dir=args.out_dir, corpus_dir=grow_dir, fuzz_target=args.fuzz_target,
            per_unit_timeout=args.per_unit_timeout, ncpu=args.filter_ncpu,
            memory=args.memory, shm_size=args.shm_size,
            container_name=f"poff-filter-{os.getpid()}-{uuid.uuid4().hex[:8]}",
        ),
        timeout=args.filter_timeout,
    )
    m = re.search(r"REMOVED=(\d+)", (filt.stdout or "") + (filt.stderr or ""))
    removed = int(m.group(1)) if m else 0
    return {"bulk_replay_exit": bulk.returncode, "removed_crashers": removed, "filtered": True}


# --------------------------------------------------------------------------- #
# Time-budgeted corpus sizing
#
# A full -runs=0 pass over the corpus costs T_pass = N * T_unit. The replay
# acceptance gate replays the whole corpus `repeats` times on BOTH the baseline
# and optimized binaries (2*repeats passes) -- the most expensive single replay
# op -- and the perf profile is one pass, so sizing N to fit the gate makes
# profiling fit too. For a slow target (radare2/ia_fuzz ~seconds/unit) an
# unsized corpus makes one pass take tens of minutes to hours, blowing the
# filter/profile/gate budgets. So: probe per-unit replay time on a small random
# sample, then keep the largest N with 2*repeats*N*T_unit <= budget.
# --------------------------------------------------------------------------- #

def _corpus_files(d: Path) -> list[Path]:
    return sorted(p for p in Path(d).glob("*") if p.is_file())


def _sample_units(grow_dir: Path, k: int, seed: int) -> tuple[Path, list[Path]]:
    """Copy a seeded random sample of up to k units into a disposable sibling
    dir `probe_sample/` (so probing never mutates grow_dir). Returns
    (sample_dir, chosen)."""
    units = _corpus_files(grow_dir)
    chosen = units if len(units) <= k else random.Random(seed).sample(units, k)
    sample_dir = Path(grow_dir).parent / "probe_sample"
    if sample_dir.exists():
        shutil.rmtree(sample_dir)
    sample_dir.mkdir(parents=True, exist_ok=True)
    for i, p in enumerate(chosen):
        shutil.copy2(p, sample_dir / f"unit_{i:08d}")
    return sample_dir, chosen


def measure_unit_replay_time(args, grow_dir: Path) -> dict:
    """Measure mean per-unit replay time T_unit on the baseline binary.

    Works on a disposable copy of a random K-unit sample: first crash-filter the
    copy (so the timing pass isn't aborted by a crasher), then run one in-process
    ``-runs=0`` replay and take T_unit from libFuzzer's own average_exec_per_sec
    (startup-independent; falls back to elapsed/executed_units). Returns a dict
    with `t_unit` (None if it could not be measured) and probe diagnostics.
    """
    sample_dir, chosen = _sample_units(grow_dir, args.probe_sample, args.seed)
    try:
        n0 = len(chosen)
        if n0 == 0:
            return {"t_unit": None, "method": "empty", "probe_units": 0}
        # Strip crashers from the disposable sample (cheap: <= K units) so the
        # timing pass runs to completion. Parallel + detect_leaks=0, same as the
        # real filter.
        _run(
            build_crash_filter_command(
                out_dir=args.out_dir, corpus_dir=sample_dir,
                fuzz_target=args.fuzz_target, per_unit_timeout=args.per_unit_timeout,
                ncpu=args.filter_ncpu, memory=args.memory, shm_size=args.shm_size,
                container_name=f"poff-probe-filt-{os.getpid()}-{uuid.uuid4().hex[:8]}",
            ),
            timeout=args.probe_timeout,
        )
        n_clean = len(_corpus_files(sample_dir))
        if n_clean == 0:
            return {"t_unit": None, "method": "all_crashed", "probe_units": n0}
        cmd = rt.build_replay_docker_command(
            out_dir=args.out_dir, corpus_dir=sample_dir, fuzz_target=args.fuzz_target,
            seed=args.seed, cpu=args.cpu, memory=args.memory, shm_size=args.shm_size,
            container_name=f"poff-probe-{os.getpid()}-{uuid.uuid4().hex[:8]}",
        )
        start = time.monotonic()
        res = _run(cmd, timeout=args.probe_timeout)
        elapsed = time.monotonic() - start
        stats = rt.parse_replay_stats((res.stdout or "") + (res.stderr or ""))
        eps = stats.get("average_exec_per_sec")
        executed = stats.get("executed_units")
        if eps and eps > 0:
            t_unit, method = 1.0 / eps, "inprocess_eps"
        elif executed and executed > 0 and elapsed > 0:
            t_unit, method = elapsed / executed, "inprocess_wall"
        else:
            t_unit, method = None, "no_stats"
        return {
            "t_unit": t_unit, "method": method, "probe_units": n0,
            "probe_clean": n_clean, "probe_executed": executed,
            "probe_exec_per_sec": eps, "probe_elapsed_s": round(elapsed, 3),
        }
    finally:
        if sample_dir.exists():
            shutil.rmtree(sample_dir, ignore_errors=True)


def _compute_target_n(t_unit, corpus_size, *, budget_secs, repeats, margin,
                      n_min, abs_ceiling) -> tuple[int, str]:
    """N = floor(margin * budget / (2*repeats*T_unit)), clamped to [n_min, size]
    then to abs_ceiling if set. Returns (N, flag)."""
    if not t_unit or t_unit <= 0:
        return corpus_size, "no_estimate"          # keep all; filter still culls
    raw = int((margin * budget_secs) / (2 * repeats * t_unit))
    n = max(n_min, min(raw, corpus_size))
    if abs_ceiling and abs_ceiling > 0:
        n = min(n, abs_ceiling)
    if n >= corpus_size:
        flag = "full"
    elif raw < n_min:
        flag = "too_slow"                            # even n_min overruns budget
    else:
        flag = "capped"
    return n, flag


def _downselect_corpus(grow_dir: Path, n: int, seed: int) -> int:
    """Keep a seeded RANDOM n-subset of grow_dir in place, delete the rest.
    Random (not first-N) preserves the input-size distribution / hot tail."""
    units = _corpus_files(grow_dir)
    if len(units) <= n:
        return len(units)
    keep = set(random.Random(seed).sample(units, n))
    for p in units:
        if p not in keep:
            p.unlink()
    return n


def apply_corpus_sizing(args, grow_dir: Path) -> dict:
    """Probe per-unit replay time and cap grow_dir to the largest N that fits the
    replay budget. No-op (returns {"applied": False}) when --replay-budget-secs<=0."""
    if not args.replay_budget_secs or args.replay_budget_secs <= 0:
        return {"applied": False}
    corpus_size = len(_corpus_files(grow_dir))
    if corpus_size == 0:
        return {"applied": False, "reason": "empty_corpus"}
    probe = measure_unit_replay_time(args, grow_dir)
    n, flag = _compute_target_n(
        probe.get("t_unit"), corpus_size,
        budget_secs=args.replay_budget_secs, repeats=args.replay_repeats,
        margin=args.sizing_margin, n_min=args.n_min,
        abs_ceiling=args.max_corpus_files,
    )
    kept = _downselect_corpus(grow_dir, n, args.seed) if flag in ("capped", "too_slow") else corpus_size
    return {
        "applied": True, "flag": flag, "t_unit_s": probe.get("t_unit"),
        "probe_method": probe.get("method"), "probe_units": probe.get("probe_units"),
        "probe_exec_per_sec": probe.get("probe_exec_per_sec"),
        "corpus_before_sizing": corpus_size, "target_n": n, "kept": kept,
        "budget_secs": args.replay_budget_secs, "replay_repeats": args.replay_repeats,
        "margin": args.sizing_margin, "n_min": args.n_min,
    }


def run_build_corpus(args: argparse.Namespace) -> int:
    artifact_dir = Path(args.artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    grow_dir = Path(args.evolving_corpus_dir)
    snapshot_dir = Path(args.snapshot_dir)

    # 1) Flat-copy the seed corpus into the grow dir.
    seeded = _flat_copy_corpus(args.corpus_dir, grow_dir)

    # 1b) Time-budget sizing (before the filter, so the filter is bounded too):
    #     probe per-unit replay time and cap grow_dir to the largest N that a full
    #     replay-gate measurement fits within --replay-budget-secs. No-op if 0.
    sizing = apply_corpus_sizing(args, grow_dir)

    # 2) Crash-filter (bulk check, then per-unit only if needed).
    filter_summary = filter_crashers(args, grow_dir)
    files_before = rfp._count_files(grow_dir)

    # 3) Optionally grow the corpus. If a real seed corpus already exists the
    #    caller passes duration<=0: DON'T fuzz it further -- profile on those
    #    (crash-filtered) inputs directly. Only grow when there was no usable seed
    #    corpus (caller passes the 1h duration) so we generate one from scratch.
    grow_rc = None
    if int(args.duration) > 0:
        grow_result = _run(
            build_grow_docker_command(
                out_dir=args.out_dir, corpus_dir=grow_dir, artifact_dir=artifact_dir,
                fuzz_target=args.fuzz_target, duration=args.duration, seed=args.seed,
                cpu=args.cpu, memory=args.memory, shm_size=args.shm_size,
                container_name=f"poff-grow-{os.getpid()}-{uuid.uuid4().hex[:8]}",
            ),
            timeout=args.duration + 600,
        )
        grow_rc = grow_result.returncode
        # Grow (-fork=1) appends units, re-inflating past the sized target; re-cap
        # so the frozen snapshot honors the replay budget.
        if sizing.get("applied") and sizing.get("flag") in ("capped", "too_slow"):
            sizing["kept_after_grow"] = _downselect_corpus(
                grow_dir, sizing["target_n"], args.seed + 1
            )
    files_after = rfp._count_files(grow_dir)

    # 4) Freeze the GROWN corpus into the fixed snapshot used everywhere after.
    snapshot_count = rfp.snapshot_corpus(grow_dir, snapshot_dir)
    if snapshot_count == 0:
        raise RuntimeError(
            f"fixed corpus is empty after grow+freeze (snapshot {snapshot_dir})"
        )

    metadata = {
        "duration": args.duration,
        "seed": args.seed,
        "cpu": args.cpu,
        "seeded_from_merged": seeded,
        "removed_crashers": filter_summary["removed_crashers"],
        "crash_filter_ran": filter_summary["filtered"],
        "bulk_replay_exit": filter_summary["bulk_replay_exit"],
        "corpus_files_before": files_before,
        "corpus_files_after": files_after,
        "corpus_files_discovered": max(files_after - files_before, 0),
        "grew": grow_rc is not None,
        "snapshot_dir": str(snapshot_dir),
        "snapshot_file_count": snapshot_count,
        "grow_exit_code": grow_rc,
        "sizing": sizing,
    }
    (artifact_dir / "corpus_build_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True)
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Grow a fuzzing corpus off the baseline binary, then freeze it."
    )
    parser.add_argument("--out-dir", required=True,
                        help="/out dir of the baseline binary used to grow the corpus")
    parser.add_argument("--corpus-dir", required=True,
                        help="merged seed corpus; flat-copied into the grow dir")
    parser.add_argument("--evolving-corpus-dir", required=True,
                        help="working dir the grow window fuzzes into (read-write)")
    parser.add_argument("--snapshot-dir", required=True,
                        help="where to freeze the immutable fixed-corpus snapshot")
    parser.add_argument("--artifact-dir", required=True,
                        help="where corpus_build_metadata.json / grow.log go")
    parser.add_argument("--fuzz-target", required=True)
    parser.add_argument("--duration", type=int, default=3600,
                        help="seconds to fuzz the baseline to grow the corpus")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--cpu", type=int, default=3)
    parser.add_argument("--memory", default="4g")
    parser.add_argument("--shm-size", default="2g")
    parser.add_argument("--per-unit-timeout", type=int, default=10,
                        help="per-unit wall-clock cap during crash filtering")
    parser.add_argument("--filter-timeout", type=int, default=5400,
                        help="overall wall-clock cap for each crash-filter container "
                             "(the per-unit pass over a large public corpus can take "
                             "~30 min)")
    parser.add_argument("--filter-ncpu", type=int, default=1,
                        help="parallelism (and --cpus quota) for the per-unit "
                             "crash-filter; >1 filters a large corpus in ~1/N the "
                             "wall-clock")
    # Time-budgeted corpus sizing (0 = disabled: keep the whole corpus).
    parser.add_argument("--replay-budget-secs", type=int, default=0,
                        help="cap the corpus to the largest N whose full replay-gate "
                             "measurement (2*repeats passes) fits this budget; 0=off")
    parser.add_argument("--replay-repeats", type=int, default=3,
                        help="replay repeats the timing gate uses (the 2*repeats "
                             "factor in the sizing formula)")
    parser.add_argument("--probe-sample", type=int, default=100,
                        help="number of random units to probe for per-unit time")
    parser.add_argument("--probe-timeout", type=int, default=1800,
                        help="wall-clock cap for each sizing-probe container")
    parser.add_argument("--sizing-margin", type=float, default=0.7,
                        help="fraction of the budget to target (absorbs startup + "
                             "estimation/heavy-tail variance)")
    parser.add_argument("--n-min", type=int, default=200,
                        help="floor on the sized corpus; a target too slow to fit "
                             "n_min in the budget is flagged 'too_slow' but kept at "
                             "n_min")
    parser.add_argument("--max-corpus-files", type=int, default=0,
                        help="optional absolute ceiling applied after time-sizing "
                             "(min of the two); 0=off")
    return parser.parse_args()


def main() -> int:
    return run_build_corpus(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
