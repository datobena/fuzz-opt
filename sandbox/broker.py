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
from lib import cpu_ledger
from prework.prework_build import restore_ownership
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
        # No core dumps: these containers run the target too, and a
        # smoke/replay that crashes would otherwise dump its image
        # synchronously. See phase3_runner for the full reasoning.
        "--ulimit", "core=0",
        "-e", "FUZZING_ENGINE=afl",
        # Exclude the optimizer's INSERTED helpers from coverage instrumentation.
        # A coverage-guided fuzzer biases mutation toward inputs that reach new
        # edges, so helpers the skill adds shift the gradient away from the code
        # under test -- the skill records a ~5x time-to-bug swing from exactly
        # this. Its prescribed `no_sanitize("coverage")` is libFuzzer's mechanism
        # and does NOT work here: AFL++ 5.02c runs LLVM-PCGUARD, its own fork of
        # the sancov pass, and instruments a marked helper identically to an
        # unmarked one (verified by counting __afl_area_ptr relocations). The
        # denylist is the mechanism that does work, which is why the skill
        # requires every inserted function to be named fold_*.
        "-e", "AFL_LLVM_DENYLIST=/src/aflpp_fold_denylist.txt",
        "-e", "SANITIZER=address",
        "-e", "ARCHITECTURE=x86_64",
        "-e", "FUZZING_LANGUAGE=c++",
        "-v", f"{Path(__file__).resolve().parent.parent / 'prework' / 'aflpp_fold_denylist.txt'}"
              f":/src/aflpp_fold_denylist.txt:ro",
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
        # No core dumps: these containers run the target too, and a
        # smoke/replay that crashes would otherwise dump its image
        # synchronously. See phase3_runner for the full reasoning.
        "--ulimit", "core=0",
        "-v", f"{Path(ctx.out_dir).absolute()}:/out:ro",
        "-v", f"{Path(ctx.corpus_dir).absolute()}:/corpus:ro",
        "--entrypoint", "/bin/bash", ctx.image, "-lc",
        "export AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 "
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 ASAN_OPTIONS=detect_leaks=0; "
        # -C (collect-coverage) is REQUIRED with -i <dir>. Without it afl-showmap
        # treats -o as a DIRECTORY to write one bitmap per input into, so
        # `-o /dev/null` aborts instantly with
        #   SYSTEM ERROR : cannot create output directory /dev/null (File exists)
        # and the call still returns a plausible-looking wall-clock. Every fold
        # was then accepted or rejected on ~0.5s of start-up failure rather than
        # on execution time. With -C the whole corpus is replayed and -o is a
        # single file, so /dev/null is valid and no per-input I/O pollutes the
        # timing.
        f"/out/afl-showmap -C -i /corpus -o /dev/null -t 5000+ -m none -- "
        f"/out/{ctx.fuzz_target}",
    ]


def _run_build(ctx: BrokerContext) -> tuple[bool, str]:
    rc, blob = _run(_build_command(ctx), BUILD_TIMEOUT_SECS)
    _audit(ctx, "build", blob)
    # `compile` runs as root through a bind mount, so it leaves root-owned objects
    # in the tree the AGENT (uid 1000) is editing and the orchestrator later has to
    # `git clean` when a round is rejected. Restored on failure too: a build that
    # died halfway leaves exactly the artifacts that have to be cleanable.
    restore_ownership(ctx.image, [ctx.source_dir, ctx.out_dir])
    return rc == 0, blob


def _run_smoke(ctx: BrokerContext) -> tuple[bool, str]:
    """Run the built target briefly to confirm it is not dead on arrival."""
    cmd = [
        "docker", "run", "--rm", "--privileged",
        "--cpuset-cpus", str(ctx.cpu),
        # No core dumps: these containers run the target too, and a
        # smoke/replay that crashes would otherwise dump its image
        # synchronously. See phase3_runner for the full reasoning.
        "--ulimit", "core=0",
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
        # A replay that did not actually execute the corpus must not be timed.
        # afl-showmap reports its own outcome; absent that line the run failed
        # before the forkserver and the "elapsed" is pure start-up cost, which
        # is indistinguishable from a very fast binary.
        if "coverage of" not in blob and "Captured" not in blob:
            logger.error("replay produced no coverage report; refusing to time "
                         "it: %s", blob[-300:])
            return None
        times.append(elapsed)
    return statistics.median(times) if times else None


def handle_request(req, ctx: BrokerContext) -> dict:
    """Dispatch one request. Never raises -- a broker crash would kill the round.

    Every op here is real CPU work the optimizer causes, so each is timed into
    the CPU ledger. This is the ONLY place agent-requested compute can happen --
    the request surface is a closed enum -- which is what makes "everything
    except the model wait" measurable at a single point. All three ops are
    pinned to ctx.cpu, so core-seconds equal wall-seconds.
    """
    if not isinstance(req, dict):
        return {"ok": False, "error": "malformed request"}
    op = req.get("op")
    if not isinstance(op, str) or not op:
        return {"ok": False, "error": "missing or malformed op"}

    if op == "build":
        with cpu_ledger.timed("broker_build", cores=1) as info:
            ok, blob = _run_build(ctx)
            info["ok"] = ok
        return {"ok": ok, "log": scrub(blob)}

    if op == "smoke":
        with cpu_ledger.timed("broker_smoke", cores=1) as info:
            ok, blob = _run_smoke(ctx)
            info["ok"] = ok
        return {"ok": ok, "log": scrub(blob)}

    if op == "replay_time":
        raw = req.get("repeats", DEFAULT_REPLAY_REPEATS)
        if isinstance(raw, bool) or not isinstance(raw, int):
            return {"ok": False, "error": "repeats must be an integer"}
        repeats = max(1, min(raw, MAX_REPLAY_REPEATS))
        with cpu_ledger.timed("broker_replay", cores=1) as info:
            seconds = _run_replay(ctx, repeats)
            info["repeats"] = repeats
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
                try:
                    reply = handle_request(req, ctx)
                    conn.sendall(json.dumps(reply).encode() + b"\n")
                except OSError as e:
                    # The CLIENT went away (BrokenPipeError/ECONNRESET) -- the
                    # agent abandoned a slow build or replay. Without this the
                    # exception escapes the accept loop, `finally` closes the
                    # listener and UNLINKS the socket, and the broker is gone for
                    # the rest of the agent session: every later build/smoke/
                    # replay fails with ENOENT and the round produces nothing.
                    # One disconnected client must not end the service.
                    logger.warning("client disconnected mid-reply: %s", e)
                    continue
    finally:
        srv.close()
        if os.path.exists(socket_path):
            os.unlink(socket_path)
