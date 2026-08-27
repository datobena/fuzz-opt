"""Docker container management utilities for benchmark trials."""

import json
import logging
import os
import shlex
import subprocess
import time
from datetime import datetime
from typing import Optional

import config

logger = logging.getLogger(__name__)


def run_container(
    image: str,
    command: list[str],
    *,
    name: Optional[str] = None,
    cpuset_cpus: Optional[str] = None,
    memory: str = config.MEMORY_LIMIT,
    shm_size: str = config.DOCKER_SHM_SIZE,
    volumes: Optional[dict[str, str]] = None,
    env: Optional[dict[str, str]] = None,
    detach: bool = False,
    remove: bool = True,
    timeout: Optional[int] = None,
) -> subprocess.CompletedProcess:
    """Run a Docker container with specified resource constraints.

    Args:
        image: Docker image name.
        command: Command to run inside container.
        name: Container name.
        cpuset_cpus: CPU cores to pin to (e.g. "0" or "0-3").
        memory: Memory limit (e.g. "4g").
        shm_size: Shared memory size.
        volumes: Dict of host_path -> container_path.
        env: Dict of environment variables.
        detach: Run in background.
        remove: Remove container after exit.
        timeout: Timeout in seconds.

    Returns:
        CompletedProcess result.
    """
    cmd = ["docker", "run"]

    if name:
        cmd += ["--name", name]
    if cpuset_cpus is not None:
        cmd += ["--cpuset-cpus", str(cpuset_cpus)]
    if memory:
        cmd += ["--memory", memory]
    if shm_size:
        cmd += ["--shm-size", shm_size]
    if detach:
        cmd.append("-d")
    if remove and not detach:
        cmd.append("--rm")

    cmd += ["--privileged"]

    if volumes:
        for host_path, container_path in volumes.items():
            cmd += ["-v", f"{host_path}:{container_path}"]

    if env:
        for key, value in env.items():
            cmd += ["-e", f"{key}={value}"]

    cmd.append(image)
    cmd.extend(command)

    logger.info("Running: %s", " ".join(shlex.quote(c) for c in cmd))

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_fuzzer_trial(
    fuzzer_binary: str,
    corpus_dir: str,
    crashes_dir: str,
    log_file: str,
    *,
    seed: int,
    duration: int = config.TRIAL_DURATION_SECS,
    cpu: int,
    memory: str = config.MEMORY_LIMIT,
    container_name: Optional[str] = None,
    extra_volumes: Optional[dict[str, str]] = None,
) -> str:
    """Start a libFuzzer trial in a detached Docker container.

    Returns the container ID.
    """
    os.makedirs(corpus_dir, exist_ok=True)
    os.makedirs(crashes_dir, exist_ok=True)
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    volumes = {
        fuzzer_binary: "/fuzzer",
        corpus_dir: "/corpus",
        crashes_dir: "/crashes",
    }
    if extra_volumes:
        volumes.update(extra_volumes)

    # Build libFuzzer command
    fuzzer_cmd = [
        "/fuzzer",
        "/corpus",
        f"-seed={seed}",
        f"-max_total_time={duration}",
        "-print_final_stats=1",
        f"-rss_limit_mb={config.RSS_LIMIT_MB}",
        "-artifact_prefix=/crashes/",
    ]

    cmd = ["docker", "run", "-d", "--privileged"]
    cmd += ["--cpuset-cpus", str(cpu)]
    cmd += ["--memory", memory]
    cmd += ["--shm-size", config.DOCKER_SHM_SIZE]

    if container_name:
        cmd += ["--name", container_name]

    for host_path, container_path in volumes.items():
        cmd += ["-v", f"{host_path}:{container_path}"]

    # Use base-runner image which has ASAN runtime
    cmd.append("gcr.io/oss-fuzz-base/base-runner")
    cmd.extend(fuzzer_cmd)

    logger.info("Starting trial container: %s", container_name or "unnamed")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"Failed to start container: {result.stderr}")

    container_id = result.stdout.strip()
    return container_id


def wait_for_container(container_id: str, timeout: Optional[int] = None) -> int:
    """Wait for a container to finish. Returns exit code."""
    cmd = ["docker", "wait", container_id]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return int(result.stdout.strip())
    except (subprocess.TimeoutExpired, ValueError):
        return -1


def write_container_logs(container_id: str, dest_path: str) -> int:
    """Stream a container's combined output straight to dest_path.

    Returns the number of bytes written.

    Never materializes the log in memory. A 24h AFL++ campaign writes several
    GB to the console, and capturing that through a pipe costs three live
    copies (communicate() joins the chunks, text=True decodes them, and
    stdout + stderr concatenates the result). Nine trials finalizing at once
    put 239 GiB behind that arithmetic and OOM-killed the Aug 10 run; the
    kernel had 716 MB left when it fired. Handing docker an fd keeps the whole
    thing at O(1) regardless of campaign length.
    """
    os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
    with open(dest_path, "wb") as f:
        subprocess.run(
            ["docker", "logs", container_id],
            stdout=f,
            stderr=subprocess.STDOUT,
        )
    try:
        return os.path.getsize(dest_path)
    except OSError:
        return 0


def get_container_logs(container_id: str, max_bytes: int = 1 << 20) -> str:
    """Return at most max_bytes of a container's combined output.

    Bounded on purpose: the unbounded version of this call is what exhausted
    memory on Aug 10. Use write_container_logs() when the full log has to be
    kept; use this only for probes where a truncated head is enough.
    """
    proc = subprocess.Popen(
        ["docker", "logs", container_id],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        data = proc.stdout.read(max_bytes) or b""
    finally:
        proc.stdout.close()
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    return data.decode("utf-8", errors="replace")


def inspect_container_state(container_id: str) -> dict:
    """Capture post-exit state of a container before it is removed.

    Returns the parsed .State JSON (ExitCode, OOMKilled, Error, StartedAt,
    FinishedAt, Pid, Status, ...). On failure, returns a dict with an
    "error" key describing what went wrong.

    Callers should invoke this BEFORE remove_container() — once the
    container is gone, none of this data is recoverable.
    """
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{json .State}}", container_id],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return {
            "error": "inspect_failed",
            "returncode": result.returncode,
            "stderr": (result.stderr or "").strip(),
        }
    raw = (result.stdout or "").strip()
    if not raw:
        return {"error": "empty_inspect_output"}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        return {"error": "json_decode_failed", "reason": str(e), "raw": raw}


def stop_container(container_id: str, timeout: int = 10):
    """Stop a running container."""
    subprocess.run(
        ["docker", "stop", "-t", str(timeout), container_id],
        capture_output=True,
    )


def remove_container(container_id: str):
    """Remove a container."""
    subprocess.run(
        ["docker", "rm", "-f", container_id],
        capture_output=True,
    )


def container_is_running(container_id: str) -> bool:
    """Check if a container is still running."""
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container_id],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() == "true"


def _parse_docker_timestamp(value: str) -> Optional[datetime]:
    """Parse a Docker RFC3339 timestamp into a datetime."""
    value = value.strip()
    if not value or value.startswith("0001-01-01T00:00:00"):
        return None

    if value.endswith("Z"):
        value = value[:-1]
        tz_suffix = "+00:00"
    else:
        tz_suffix = ""

    if "." in value:
        head, frac = value.split(".", 1)
        value = f"{head}.{frac[:6]}{tz_suffix}"
    else:
        value = f"{value}{tz_suffix}"

    return datetime.fromisoformat(value)


def get_container_duration_seconds(container_id: str) -> Optional[float]:
    """Return the container runtime duration in seconds."""
    result = subprocess.run(
        [
            "docker", "inspect", "-f",
            "{{.State.StartedAt}}\n{{.State.FinishedAt}}",
            container_id,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None

    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if len(lines) < 2:
        return None

    started_at = _parse_docker_timestamp(lines[0])
    finished_at = _parse_docker_timestamp(lines[1])
    if not started_at or not finished_at:
        return None

    return round(max((finished_at - started_at).total_seconds(), 0.0), 2)


def copy_from_container(container_id: str, src: str, dst: str):
    """Copy file/directory from container to host."""
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    subprocess.run(
        ["docker", "cp", f"{container_id}:{src}", dst],
        check=True,
    )


def build_image(project_name: str) -> bool:
    """Build the OSS-Fuzz Docker image for a project.

    Streams output to terminal so build progress is visible.
    Uses --cache to ensure consistent base layers between build and run.
    """
    cmd = [
        "python3", os.path.join(config.OSS_FUZZ_DIR, "infra", "helper.py"),
        "build_image", "--no-pull", "--cache", project_name,
    ]
    logger.info("Running: %s", " ".join(cmd))
    result = subprocess.run(
        cmd,
        cwd=config.OSS_FUZZ_DIR,
        input="n\n",
        text=True,
    )
    if result.returncode != 0:
        logger.error("build_image failed for %s (exit %d)",
                      project_name, result.returncode)
    return result.returncode == 0


def build_fuzzers(
    project_name: str,
    sanitizer: str = config.SANITIZER,
    engine: str = config.ENGINE,
    source_path: Optional[str] = None,
    capture_log: bool = False,
) -> bool | tuple[bool, str]:
    """Build fuzzers for a project using helper.py.

    Args:
        capture_log: If True, capture build output and return (success, log).
                     If False (default), stream to terminal and return bool.
    """
    cmd = [
        "python3", os.path.join(config.OSS_FUZZ_DIR, "infra", "helper.py"),
        "build_fuzzers",
        "--sanitizer", sanitizer,
        "--engine", engine,
        project_name,
    ]
    if source_path:
        cmd.append(source_path)  # source_path is a positional argument

    logger.info("Running: %s", " ".join(cmd))
    try:
        if capture_log:
            result = subprocess.run(
                cmd,
                cwd=config.OSS_FUZZ_DIR,
                capture_output=True,
                text=True,
                timeout=3600,
            )
            log = result.stdout + "\n" + result.stderr
        else:
            result = subprocess.run(
                cmd,
                cwd=config.OSS_FUZZ_DIR,
                timeout=3600,
            )
            log = ""
    except subprocess.TimeoutExpired:
        logger.error("build_fuzzers timed out for %s", project_name)
        if capture_log:
            return False, "Build timed out after 3600s"
        return False

    if result.returncode != 0:
        logger.error("build_fuzzers failed for %s (exit %d)",
                      project_name, result.returncode)

    success = result.returncode == 0
    if capture_log:
        return success, log
    return success


def reproduce_crash(
    project_name: str,
    fuzzer_name: str,
    testcase_path: str,
) -> tuple[bool, str]:
    """Reproduce a crash using helper.py reproduce.

    Returns (crashed, output).
    """
    cmd = [
        "python3", os.path.join(config.OSS_FUZZ_DIR, "infra", "helper.py"),
        "reproduce",
        project_name,
        fuzzer_name,
        testcase_path,
    ]
    result = subprocess.run(
        cmd,
        cwd=config.OSS_FUZZ_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )
    output = result.stdout + result.stderr
    crashed = result.returncode != 0 or "SUMMARY:" in output
    return crashed, output
