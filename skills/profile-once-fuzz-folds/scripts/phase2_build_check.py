#!/usr/bin/env python3
"""Run the benchmark phase-2-equivalent Docker build for a modified source tree."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def env_int(primary: str, legacy: str, default: str) -> int:
    raw = os.environ.get(primary)
    if raw in (None, ""):
        raw = os.environ.get(legacy, default)
    return int(raw)


BUILD_TIMEOUT = env_int(
    "APPLY_PROFILE_GUIDED_FOLDS_BUILD_TIMEOUT",
    "APPLY_FOLD_STEPS_BUILD_TIMEOUT",
    "3600",
)
RUN_TIMEOUT = env_int(
    "APPLY_PROFILE_GUIDED_FOLDS_RUN_TIMEOUT",
    "APPLY_FOLD_STEPS_RUN_TIMEOUT",
    "300",
)
SMOKE_RUNS = env_int(
    "APPLY_PROFILE_GUIDED_FOLDS_SMOKE_RUNS",
    "APPLY_FOLD_STEPS_SMOKE_RUNS",
    "256",
)
SMOKE_SEED = env_int(
    "APPLY_PROFILE_GUIDED_FOLDS_SMOKE_SEED",
    "APPLY_FOLD_STEPS_SMOKE_SEED",
    "1337",
)
DOCKER_CLEANUP_IMAGE = "alpine:3.19"


def emit(payload: dict, exit_code: int) -> int:
    print(json.dumps(payload, indent=2, sort_keys=True))
    return exit_code


def remove_path(path: Path) -> None:
    if not path.exists():
        return
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
        return
    except PermissionError:
        pass

    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{path}:/cleanup",
            DOCKER_CLEANUP_IMAGE,
            "rm",
            "-rf",
            "/cleanup",
        ],
        capture_output=True,
        timeout=120,
        check=False,
    )
    try:
        if path.is_dir() and not path.is_symlink():
            path.rmdir()
        else:
            path.unlink()
    except OSError:
        pass


def clean_build_artifacts(source_dir: Path) -> dict[str, int]:
    removed_files = 0
    removed_dirs = 0
    cache_names = {"cachedObjs", "CMakeCache.txt", "CMakeFiles", "build", "_build"}

    def is_binary_artifact(name: str) -> bool:
        if name.startswith("llvm-"):
            return False
        return (
            name.endswith(".o")
            or name.endswith(".a")
            or name.endswith(".so")
            or ".so." in name
            or name.endswith(".dylib")
        )

    for path in source_dir.rglob("*"):
        if path.is_file() and is_binary_artifact(path.name):
            remove_path(path)
            removed_files += 1

    for name in cache_names:
        for path in source_dir.rglob(name):
            remove_path(path)
            if name == "CMakeCache.txt":
                removed_files += 1
            else:
                removed_dirs += 1

    return {
        "removed_files": removed_files,
        "removed_dirs": removed_dirs,
    }


def run_command(
    cmd: list[str],
    cwd: Path,
    timeout: int,
    input_text: str | None = None,
) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
    except subprocess.TimeoutExpired as exc:
        log = (exc.stdout or "") + (exc.stderr or "")
        return False, log + f"\nTimed out after {timeout}s"

    log = (result.stdout or "") + (result.stderr or "")
    return result.returncode == 0, log


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the benchmark phase-2-equivalent Docker build check."
    )
    parser.add_argument("source_dir", help="Modified project source directory")
    parser.add_argument(
        "--run-fuzzer",
        help="Optional fuzz target to smoke-run after a successful build.",
    )
    parser.add_argument(
        "--smoke-runs",
        type=int,
        default=SMOKE_RUNS,
        help=f"Total libFuzzer executions for the smoke run (default: {SMOKE_RUNS})",
    )
    parser.add_argument(
        "--smoke-seed",
        type=int,
        default=SMOKE_SEED,
        help=f"libFuzzer seed for the smoke run (default: {SMOKE_SEED})",
    )
    parser.add_argument(
        "--run-timeout",
        type=int,
        default=RUN_TIMEOUT,
        help=f"Timeout in seconds for the optional smoke run (default: {RUN_TIMEOUT})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=BUILD_TIMEOUT,
        help=f"Per-command timeout in seconds (default: {BUILD_TIMEOUT})",
    )
    args = parser.parse_args()

    source_dir = Path(args.source_dir).expanduser().resolve()
    if not source_dir.is_dir():
        return emit(
            {
                "ok": False,
                "success": False,
                "error": f"source_dir is not a directory: {source_dir}",
            },
            1,
        )

    missing_env = [
        var for var in ("OSS_FUZZ_PROJECT", "OSS_FUZZ_DIR") if not os.environ.get(var)
    ]
    if missing_env:
        return emit(
            {
                "ok": False,
                "success": False,
                "error": "missing required environment variables",
                "missing_env": missing_env,
            },
            1,
        )

    missing_tools = [
        tool for tool in ("docker", "python3") if shutil.which(tool) is None
    ]
    if missing_tools:
        return emit(
            {
                "ok": False,
                "success": False,
                "error": "required tools not found in PATH",
                "missing_tools": missing_tools,
            },
            1,
        )

    oss_fuzz_dir = Path(os.environ["OSS_FUZZ_DIR"]).expanduser().resolve()
    if not oss_fuzz_dir.is_dir():
        return emit(
            {
                "ok": False,
                "success": False,
                "error": f"OSS_FUZZ_DIR is not a directory: {oss_fuzz_dir}",
            },
            1,
        )

    helper = oss_fuzz_dir / "infra" / "helper.py"
    if not helper.is_file():
        return emit(
            {
                "ok": False,
                "success": False,
                "error": f"helper.py not found: {helper}",
            },
            1,
        )

    project = os.environ["OSS_FUZZ_PROJECT"]
    cleanup_summary = clean_build_artifacts(source_dir)

    build_image_cmd = [
        "python3",
        str(helper),
        "build_image",
        "--no-pull",
        "--cache",
        project,
    ]
    build_fuzzers_cmd = [
        "python3",
        str(helper),
        "build_fuzzers",
        "--sanitizer",
        "address",
        "--engine",
        "libfuzzer",
        project,
        str(source_dir),
    ]
    run_fuzzer_cmd = None
    if args.run_fuzzer:
        run_fuzzer_cmd = [
            "python3",
            str(helper),
            "run_fuzzer",
            "--sanitizer",
            "address",
            "--engine",
            "libfuzzer",
            project,
            args.run_fuzzer,
            "--",
            f"-runs={args.smoke_runs}",
            f"-seed={args.smoke_seed}",
            "-print_final_stats=1",
        ]

    build_image_ok, build_image_log = run_command(
        build_image_cmd,
        cwd=oss_fuzz_dir,
        timeout=args.timeout,
    )
    if not build_image_ok:
        return emit(
            {
                "ok": True,
                "success": False,
                "cleanup_summary": cleanup_summary,
                "build_image_ok": False,
                "build_fuzzers_ok": False,
                "run_fuzzer_requested": bool(run_fuzzer_cmd),
                "run_fuzzer_ok": False,
                "run_fuzzer_target": args.run_fuzzer,
                "build_image_log": build_image_log,
                "build_fuzzers_log": "",
                "run_fuzzer_log": "",
            },
            1,
        )

    build_fuzzers_ok, build_fuzzers_log = run_command(
        build_fuzzers_cmd,
        cwd=oss_fuzz_dir,
        timeout=args.timeout,
    )
    run_fuzzer_ok = False
    run_fuzzer_log = ""
    if build_fuzzers_ok and run_fuzzer_cmd:
        run_fuzzer_ok, run_fuzzer_log = run_command(
            run_fuzzer_cmd,
            cwd=oss_fuzz_dir,
            timeout=args.run_timeout,
            input_text="\n",
        )

    success = build_image_ok and build_fuzzers_ok and (
        not run_fuzzer_cmd or run_fuzzer_ok
    )
    return emit(
        {
            "ok": True,
            "success": success,
            "cleanup_summary": cleanup_summary,
            "build_image_ok": build_image_ok,
            "build_fuzzers_ok": build_fuzzers_ok,
            "run_fuzzer_requested": bool(run_fuzzer_cmd),
            "run_fuzzer_ok": run_fuzzer_ok if run_fuzzer_cmd else False,
            "run_fuzzer_target": args.run_fuzzer,
            "build_image_log": build_image_log,
            "build_fuzzers_log": build_fuzzers_log,
            "run_fuzzer_log": run_fuzzer_log,
        },
        0 if success else 1,
    )


if __name__ == "__main__":
    sys.exit(main())
