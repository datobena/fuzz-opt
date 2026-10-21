#!/usr/bin/env python3
"""Profile a real fuzz target under Docker with perf."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import os
import tempfile
import time
from pathlib import Path


# Overridable so a build that base-runner cannot LOAD can be profiled in the
# image it was built in. A target linked against the pinned LLVM's libc++
# dies at exit 127 before main in base-runner -- and perf still exits 0 and
# writes a profile, of the loader and the timing loop. Unset = unchanged.
RUNNER_IMAGE = os.environ.get(
    "FUZZ_SOURCE_FOLDS_RUNNER_IMAGE", "gcr.io/oss-fuzz-base/base-runner")


def build_profile_docker_command(
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
    container_name: str | None = None,
    corpus_writable: bool = False,
) -> list[str]:
    # When corpus_writable is True the corpus is bind-mounted read-write and
    # passed to libFuzzer as its primary corpus directory, so any new units the
    # profiling window discovers are appended in place and persist on the host
    # after the container exits. This is what lets the corpus deepen across
    # optimization cycles instead of restarting from the shallow seed set every
    # refresh window. The read-only mode is kept for one-shot profiling.
    corpus_mount = f"{Path(corpus_dir)}:/corpus" + ("" if corpus_writable else ":ro")
    cmd = ["docker", "run", "--rm"]
    if container_name:
        cmd += ["--name", container_name]
    cmd += [
        "--cpuset-cpus", str(cpu),
        "--memory", memory,
        "--shm-size", shm_size,
        "--privileged",
        "-v", f"{Path(out_dir)}:/out:ro",
        "-v", corpus_mount,
        "-v", f"{Path(artifact_dir)}:/artifacts",
        RUNNER_IMAGE,
        "/bin/bash", "-lc",
        (
            "set -uo pipefail; "
            "apt-get update >/dev/null; "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y linux-tools-generic >/dev/null; "
            "PERF_BIN=$(find /usr/lib -path '*/linux-tools*' -name perf | sort | head -n 1); "
            "test -n \"$PERF_BIN\"; "
            "mkdir -p /tmp/profile-artifacts; "
            "rc=0; "
            "\"$PERF_BIN\" record -g --call-graph dwarf -F 997 "
            "-o /artifacts/perf.data -- "
            f"/out/{fuzz_target} /corpus "
            f"-seed={seed} "
            f"-max_total_time={duration} "
            "-print_final_stats=1 "
            "-rss_limit_mb=3072 "
            "-malloc_limit_mb=1536 "
            "-artifact_prefix=/tmp/profile-artifacts/ "
            "> /artifacts/fuzzer.log 2>&1 || rc=$?; "
            "chmod a+r /artifacts/perf.data /artifacts/fuzzer.log 2>/dev/null || true; "
            "exit $rc"
        ),
    ]
    return cmd


def build_perf_record_command(
    *, pid: int, duration: int, output_path: str | Path
) -> list[str]:
    return [
        "perf", "record",
        "-g",
        "--call-graph", "dwarf",
        "-F", "997",
        "-o", str(Path(output_path)),
        "-p", str(pid),
        "--",
        "sleep", str(duration),
    ]


def sanitize_corpus_copy(
    *,
    source_dir: str | Path,
    dest_dir: str | Path,
    probe_seed,
) -> dict:
    source_dir = Path(source_dir)
    dest_dir = Path(dest_dir)
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    kept_files: list[str] = []
    removed_files: list[dict[str, str]] = []

    for src_path in sorted(source_dir.rglob("*")):
        if not src_path.is_file():
            continue
        rel = src_path.relative_to(source_dir)
        dest_path = dest_dir / rel
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_path, dest_path)
        result = probe_seed(dest_path)
        rel_text = rel.as_posix()
        if result != "ok":
            dest_path.unlink(missing_ok=True)
            removed_files.append({"file": rel_text, "reason": result})
            continue
        kept_files.append(rel_text)

    return {
        "kept_files": kept_files,
        "removed_files": removed_files,
    }


def _count_files(directory: str | Path) -> int:
    directory = Path(directory)
    if not directory.is_dir():
        return 0
    return sum(1 for p in directory.rglob("*") if p.is_file())


def snapshot_corpus(source_dir: str | Path, dest_dir: str | Path) -> int:
    """Freeze a flat copy of the current corpus for a reproducible replay set.

    Returns the number of files copied. The destination is replaced wholesale so
    each snapshot is an exact, immutable picture of the corpus at that cycle.
    """
    source_dir = Path(source_dir)
    dest_dir = Path(dest_dir)
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for src_path in sorted(source_dir.rglob("*")):
        if not src_path.is_file():
            continue
        shutil.copy2(src_path, dest_dir / f"unit_{count:08d}")
        count += 1
    return count


def seed_evolving_corpus(
    *,
    evolving_dir: str | Path,
    seed_corpus_dir: str | Path,
    probe_seed,
) -> dict:
    """Seed a persistent evolving-corpus dir on first use, or reuse it as-is.

    On the first window the evolving dir is empty, so it is seeded from the merged
    seed corpus with crashing/hanging inputs filtered out. On every later window
    it already holds the inputs the previous windows discovered, so it is reused
    unchanged and libFuzzer continues fuzzing from those accumulated inputs.
    """
    evolving_dir = Path(evolving_dir)
    evolving_dir.mkdir(parents=True, exist_ok=True)
    existing = _count_files(evolving_dir)
    if existing > 0:
        return {"seeded": False, "file_count": existing, "kept_files": [], "removed_files": []}

    summary = sanitize_corpus_copy(
        source_dir=seed_corpus_dir,
        dest_dir=evolving_dir,
        probe_seed=probe_seed,
    )
    summary["seeded"] = True
    summary["file_count"] = _count_files(evolving_dir)
    return summary


def _run(cmd: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _probe_seed(
    *,
    out_dir: Path,
    fuzz_target: str,
    seed_path: Path,
    memory: str,
    shm_size: str,
    timeout_s: int,
) -> str:
    with tempfile.TemporaryDirectory(prefix="pgf-probe-") as probe_dir:
        probe_root = Path(probe_dir)
        shutil.copy2(seed_path, probe_root / seed_path.name)
        cmd = [
            "docker", "run", "--rm",
            "--memory", memory,
            "--shm-size", shm_size,
            "--privileged",
            "-v", f"{out_dir}:/out:ro",
            "-v", f"{probe_root}:/corpus:ro",
            RUNNER_IMAGE,
            "/bin/bash", "-lc",
            (
                f"exec /out/{fuzz_target} /corpus "
                "-runs=1 "
                "-seed=1337 "
                "-print_final_stats=1"
            ),
        ]
        try:
            result = _run(cmd, timeout=timeout_s)
        except subprocess.TimeoutExpired:
            return "timeout"
        return "ok" if result.returncode == 0 else "crash"


def _inspect_pid(container_name: str) -> int:
    result = _run(
        ["docker", "inspect", "-f", "{{.State.Pid}}", container_name]
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError("failed to inspect container pid")
    return int(result.stdout.strip())


def _write_perf_reports(perf_data: Path, artifact_dir: Path) -> None:
    flat = artifact_dir / "flat.txt"
    callgraph = artifact_dir / "callgraph.txt"
    flat_result = _run([
        "perf", "report", "--stdio", "--no-children", "-g", "none",
        "--percent-limit", "0.5",
        "-i", str(perf_data),
    ])
    if flat_result.returncode != 0:
        raise RuntimeError("perf flat report failed")
    flat.write_text(flat_result.stdout)

    callgraph_result = _run([
        "perf", "report", "--stdio", "-g", "callee,0.5",
        "--percent-limit", "0.5",
        "-i", str(perf_data),
    ])
    if callgraph_result.returncode != 0:
        raise RuntimeError("perf callgraph report failed")
    callgraph.write_text(callgraph_result.stdout)


def run_profile(args: argparse.Namespace) -> int:
    artifact_dir = Path(args.artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    probe = lambda seed_path: _probe_seed(
        out_dir=Path(args.out_dir),
        fuzz_target=args.fuzz_target,
        seed_path=seed_path,
        memory=args.memory,
        shm_size=args.shm_size,
        timeout_s=args.preflight_timeout,
    )

    evolving = bool(args.evolving_corpus_dir)
    if evolving:
        # Persistent, deepening corpus: continue from whatever previous windows
        # discovered and let libFuzzer append new units in place.
        profile_corpus = Path(args.evolving_corpus_dir)
        summary = seed_evolving_corpus(
            evolving_dir=profile_corpus,
            seed_corpus_dir=args.corpus_dir,
            probe_seed=probe,
        )
        if _count_files(profile_corpus) == 0:
            raise RuntimeError("evolving corpus is empty after seeding/filtering")
    else:
        profile_corpus = artifact_dir / "corpus"
        summary = sanitize_corpus_copy(
            source_dir=args.corpus_dir,
            dest_dir=profile_corpus,
            probe_seed=probe,
        )
        if not summary["kept_files"]:
            raise RuntimeError("profiling corpus is empty after filtering")

    (artifact_dir / "corpus_filter.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True)
    )

    files_before = _count_files(profile_corpus)
    # Freeze an immutable snapshot of the corpus as it stands going into this
    # window. The replay-timing gate replays this exact set on both binaries.
    snapshot_dir = Path(args.snapshot_dir) if args.snapshot_dir else artifact_dir / "snapshot"
    snapshot_count = snapshot_corpus(profile_corpus, snapshot_dir)

    docker_cmd = build_profile_docker_command(
        out_dir=args.out_dir,
        corpus_dir=profile_corpus,
        artifact_dir=artifact_dir,
        fuzz_target=args.fuzz_target,
        duration=args.duration,
        seed=args.seed,
        cpu=args.cpu,
        memory=args.memory,
        shm_size=args.shm_size,
        container_name=f"pgf-real-{int(time.time())}",
        corpus_writable=evolving,
    )

    perf_data = artifact_dir / "perf.data"
    docker_result = _run(docker_cmd, timeout=args.duration + 300)
    if docker_result.returncode != 0 and not perf_data.exists():
        raise RuntimeError("perf record failed")
    if not perf_data.exists() or perf_data.stat().st_size == 0:
        raise RuntimeError("perf data missing")

    _write_perf_reports(perf_data, artifact_dir)

    files_after = _count_files(profile_corpus)
    metadata = {
        "duration": args.duration,
        "seed": args.seed,
        "cpu": args.cpu,
        "corpus_summary": summary,
        "docker_exit_code": docker_result.returncode,
        "evolving_corpus": evolving,
        "corpus_files_before": files_before,
        "corpus_files_after": files_after,
        "corpus_files_discovered": max(files_after - files_before, 0),
        "snapshot_dir": str(snapshot_dir),
        "snapshot_file_count": snapshot_count,
    }
    (artifact_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True)
    )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Profile a real fuzz target with perf.")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--corpus-dir", required=True,
                        help="merged seed corpus; used to seed the evolving "
                             "corpus on its first window")
    parser.add_argument("--evolving-corpus-dir", default=None,
                        help="persistent corpus that deepens across cycles. When "
                             "set, it is mounted read-write so libFuzzer appends "
                             "newly discovered units in place; later windows "
                             "continue fuzzing from the accumulated inputs.")
    parser.add_argument("--snapshot-dir", default=None,
                        help="where to freeze the immutable corpus snapshot used "
                             "by the replay-timing gate; defaults to "
                             "<artifact-dir>/snapshot")
    parser.add_argument("--fuzz-target", required=True)
    parser.add_argument("--artifact-dir", required=True)
    parser.add_argument("--duration", type=int, default=300)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--cpu", type=int, default=3)
    parser.add_argument("--memory", default="4g")
    parser.add_argument("--shm-size", default="2g")
    parser.add_argument("--preflight-timeout", type=int, default=10)
    return parser.parse_args()


def main() -> int:
    return run_profile(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
