"""Host-side broker: the ONLY channel from the sandboxed optimizer to docker.

The agent container has no docker socket and no host filesystem. When it needs a
build, a smoke run, or a replay timing, it writes one JSON object to a unix
socket and gets one JSON object back. The broker performs the docker work against
the pinned prework image and returns a scrubbed result.

Two invariants make this a boundary rather than a suggestion:

  1. The request surface is a CLOSED ENUM. There is no field anywhere that
     reaches a shell, a path, or an image name. The agent chooses WHICH of three
     operations runs, never HOW it runs -- everything else comes from
     BrokerContext, which the orchestrator sets.

  2. Everything returned to the agent goes through sandbox.scrub. The broker
     keeps the UNSCRUBBED output host-side in an audit log, so a human can always
     reconstruct what really happened without that ever reaching the agent.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sandbox.scrub import scrub

logger = logging.getLogger(__name__)

# An agent asking for a huge repeat count must not be able to wedge the host.
MAX_REPLAY_REPEATS = 5
DEFAULT_REPLAY_REPEATS = 3
BUILD_TIMEOUT_SECS = 5400
REPLAY_TIMEOUT_SECS = 3600


@dataclass
class BrokerContext:
    """Everything the agent is NOT allowed to choose."""
    image: str
    source_dir: str
    out_dir: str
    corpus_dir: str
    fuzz_target: str
    project: str
    cpu: int
    audit_log: str = ""


def _audit(ctx: BrokerContext, op: str, blob: str) -> None:
    """Record unscrubbed output host-side. Never returned to the agent."""
    if not ctx.audit_log:
        return
    try:
        with open(ctx.audit_log, "a") as f:
            f.write(f"\n===== {op} @ {time.time():.0f} =====\n{blob}\n")
    except OSError as e:
        logger.warning("audit log write failed: %s", e)


def _run(cmd: list[str], timeout: int) -> tuple[int, str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def _build_command(ctx: BrokerContext) -> list[str]:
    """OSS-Fuzz `compile` with the agent's current source bind-mounted over $SRC."""
    return [
        "docker", "run", "--rm", "--privileged",
        "--cpuset-cpus", str(ctx.cpu),
        "-e", "FUZZING_ENGINE=afl",
        "-e", "SANITIZER=address",
        "-e", "ARCHITECTURE=x86_64",
        "-e", "FUZZING_LANGUAGE=c++",
        "-v", f"{Path(ctx.source_dir).absolute()}:/src/{ctx.project}",
        "-v", f"{Path(ctx.out_dir).absolute()}:/out",
        ctx.image, "compile",
    ]


def _replay_command(ctx: BrokerContext) -> list[str]:
    """Deterministic corpus replay via afl-showmap.

    afl-showmap -i replays every file in a directory exactly once through the
    forkserver -- the AFL analogue of libFuzzer's -runs=0, and the measurement
    the replay-speedup gate is built on. Pinned to one CPU so timings are stable.
    """
    return [
        "docker", "run", "--rm", "--privileged",
        "--cpuset-cpus", str(ctx.cpu),
        "-v", f"{Path(ctx.out_dir).absolute()}:/out:ro",
        "-v", f"{Path(ctx.corpus_dir).absolute()}:/corpus:ro",
        "--entrypoint", "/bin/bash", ctx.image, "-lc",
        "export AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 "
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 ASAN_OPTIONS=detect_leaks=0; "
        f"/out/afl-showmap -i /corpus -o /dev/null -t 5000+ -m none -- "
        f"/out/{ctx.fuzz_target}",
    ]


def _run_build(ctx: BrokerContext) -> tuple[bool, str]:
    rc, blob = _run(_build_command(ctx), BUILD_TIMEOUT_SECS)
    _audit(ctx, "build", blob)
    return rc == 0, blob


def _run_smoke(ctx: BrokerContext) -> tuple[bool, str]:
    """Run the built target briefly to confirm it is not dead on arrival."""
    cmd = [
        "docker", "run", "--rm", "--privileged",
        "--cpuset-cpus", str(ctx.cpu),
        "-v", f"{Path(ctx.out_dir).absolute()}:/out:ro",
        "--entrypoint", "/bin/bash", ctx.image, "-lc",
        f"export ASAN_OPTIONS=detect_leaks=0; printf '' > /tmp/e; "
        f"timeout 120 /out/{ctx.fuzz_target} /tmp/e",
    ]
    rc, blob = _run(cmd, 300)
    _audit(ctx, "smoke", blob)
    return rc == 0, blob


def _run_replay(ctx: BrokerContext, repeats: int) -> float | None:
    """Median wall-clock of `repeats` deterministic replays, in seconds."""
    times: list[float] = []
    for _ in range(repeats):
        t0 = time.monotonic()
        rc, blob = _run(_replay_command(ctx), REPLAY_TIMEOUT_SECS)
        elapsed = time.monotonic() - t0
        _audit(ctx, "replay", f"rc={rc} elapsed={elapsed:.3f}\n{blob[-2000:]}")
        if rc == 124:
            return None
        times.append(elapsed)
    return statistics.median(times) if times else None


def handle_request(req, ctx: BrokerContext) -> dict:
    """Dispatch one request. Never raises -- a broker crash would kill the round."""
    if not isinstance(req, dict):
        return {"ok": False, "error": "malformed request"}
    op = req.get("op")
    if not isinstance(op, str) or not op:
        return {"ok": False, "error": "missing or malformed op"}

    if op == "build":
        ok, blob = _run_build(ctx)
        return {"ok": ok, "log": scrub(blob)}

    if op == "smoke":
        ok, blob = _run_smoke(ctx)
        return {"ok": ok, "log": scrub(blob)}

    if op == "replay_time":
        raw = req.get("repeats", DEFAULT_REPLAY_REPEATS)
        if isinstance(raw, bool) or not isinstance(raw, int):
            return {"ok": False, "error": "repeats must be an integer"}
        repeats = max(1, min(raw, MAX_REPLAY_REPEATS))
        seconds = _run_replay(ctx, repeats)
        if seconds is None:
            return {"ok": False, "error": "replay did not complete"}
        return {"ok": True, "seconds": seconds, "repeats": repeats}

    return {"ok": False, "error": f"unknown op: {op}"}


def serve(socket_path: str, ctx: BrokerContext) -> None:
    """Serve requests until interrupted. One JSON object per connection."""
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(socket_path)
    os.chmod(socket_path, 0o666)
    srv.listen(4)
    logger.info("broker listening on %s", socket_path)
    try:
        while True:
            conn, _ = srv.accept()
            with conn:
                try:
                    chunks = []
                    while True:
                        b = conn.recv(65536)
                        if not b:
                            break
                        chunks.append(b)
                        if b.endswith(b"\n"):
                            break
                    req = json.loads(b"".join(chunks).decode("utf-8", "replace") or "{}")
                except (ValueError, OSError) as e:
                    conn.sendall(json.dumps(
                        {"ok": False, "error": f"bad request: {e}"}).encode() + b"\n")
                    continue
                reply = handle_request(req, ctx)
                conn.sendall(json.dumps(reply).encode() + b"\n")
    finally:
        srv.close()
        if os.path.exists(socket_path):
            os.unlink(socket_path)
