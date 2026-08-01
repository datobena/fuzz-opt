"""Run one optimizer session inside the sandbox.

This is the piece that makes the sandbox real. Everything else -- scrubber,
broker, agent container, leak audit -- exists independently, but until phase 2
routes through here it still invokes the optimizer with
`--dangerously-skip-permissions` and a copy of the entire host environment.

Shape of a session:

    orchestrator                     agent container
    ------------                     ---------------
    start broker on a unix socket <--- /work/bin/fold-build
    (does all docker work)        <--- /work/bin/fold-smoke
                                  <--- /work/bin/fold-replay-time
    launch agent container ---------> edits /work/src
    wait, then tear down

The optimizer skill needs no changes: it already consumes the
FUZZ_SOURCE_FOLDS_{BUILD,SMOKE,VALIDATE}_COMMAND contract. Those values simply
stop being docker command lines and become broker clients.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sandbox import broker as broker_mod
from sandbox import egress
from sandbox.launch import (
    SRC_MOUNT,
    TOOLS_MOUNT,
    build_agent_docker_command,
    build_agent_env,
)

logger = logging.getLogger(__name__)

AGENT_IMAGE = os.environ.get("SANDBOX_AGENT_IMAGE", "bench-sandbox/agent")
# Pre-created docker network whose egress is allowlisted to the model API.
# Deliberately not `--network none`: an LLM CLI cannot function without its API.
AGENT_NETWORK = os.environ.get("SANDBOX_AGENT_NETWORK", "bench-agent-egress")

SANDBOX_BUILD_CMD = f"{TOOLS_MOUNT}/fold-build"
SANDBOX_SMOKE_CMD = f"{TOOLS_MOUNT}/fold-smoke"
SANDBOX_REPLAY_CMD = f"{TOOLS_MOUNT}/fold-replay-time"
# Sequential on purpose: smoke consumes build artifacts, so running them in
# parallel races. The old docker-based wrapper env carried the same warning.
SANDBOX_VALIDATE_CMD = f"{SANDBOX_BUILD_CMD} && {SANDBOX_SMOKE_CMD}"


def build_sandbox_validation_env() -> dict[str, str]:
    """The FUZZ_SOURCE_FOLDS_* validation contract, pointed at broker clients."""
    return {
        "FUZZ_SOURCE_FOLDS_VALIDATION_MODE": "wrapper",
        "FUZZ_SOURCE_FOLDS_BUILD_COMMAND": SANDBOX_BUILD_CMD,
        "FUZZ_SOURCE_FOLDS_SMOKE_COMMAND": SANDBOX_SMOKE_CMD,
        "FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND": SANDBOX_VALIDATE_CMD,
    }


def _image_exists(image: str) -> bool:
    return subprocess.run(
        ["docker", "image", "inspect", image], capture_output=True
    ).returncode == 0


def assert_sandbox_available() -> None:
    """Fail loudly if the sandbox cannot run.

    There is deliberately NO fallback to the old unconfined invocation. With the
    bug-preservation gate gone, confinement is the only thing making a measured
    bug-survival rate meaningful, so silently running unsandboxed would produce
    numbers that look fine and mean nothing.
    """
    if not _image_exists(AGENT_IMAGE):
        raise RuntimeError(
            f"agent image {AGENT_IMAGE!r} not found. Build it with:\n"
            f"  docker build -t {AGENT_IMAGE} -f sandbox/Dockerfile.agent sandbox/\n"
            "Refusing to run the optimizer unsandboxed."
        )


def ensure_network() -> str:
    """Create the agent network if absent. Internal by default (no egress).

    An operator wanting real model-API access replaces this network with one
    carrying an egress allowlist; making the default internal means a
    misconfiguration fails closed rather than silently granting the internet.
    """
    exists = subprocess.run(
        ["docker", "network", "inspect", AGENT_NETWORK], capture_output=True
    ).returncode == 0
    if not exists:
        logger.info("creating internal docker network %s", AGENT_NETWORK)
        subprocess.run(
            ["docker", "network", "create", "--internal", AGENT_NETWORK],
            capture_output=True,
        )
    return AGENT_NETWORK


def run_sandboxed_optimizer(
    *, source_dir: str, profile_dir: str, out_dir: str, corpus_dir: str,
    image: str, fuzz_target: str, project: str, prompt: str,
    cpu: int = 0, timeout: int | None = None, audit_log: str = "",
    base_env: dict | None = None,
) -> dict:
    """Run one optimizer session confined to a container.

    `image` is the pinned prework image the broker builds in -- NOT the image the
    agent runs in, which is AGENT_IMAGE and contains no project source at all.
    """
    assert_sandbox_available()
    network = ensure_network()

    session_dir = Path(out_dir).parent / "sandbox"
    session_dir.mkdir(parents=True, exist_ok=True)
    sock_path = str(session_dir / "broker.sock")

    ctx = broker_mod.BrokerContext(
        image=image, source_dir=source_dir, out_dir=out_dir,
        corpus_dir=corpus_dir, fuzz_target=fuzz_target, project=project,
        cpu=cpu, audit_log=audit_log or str(session_dir / "broker_audit.log"),
    )

    stop = threading.Event()

    def _serve():
        try:
            broker_mod.serve(sock_path, ctx)
        except Exception as e:                       # noqa: BLE001
            if not stop.is_set():
                logger.error("broker died: %s", e)

    t = threading.Thread(target=_serve, daemon=True)
    t.start()

    # The agent's only route out: an allowlisting proxy on both networks.
    proxy = egress.start_proxy(
        internal_network=network, log_dir=str(session_dir / "egress"),
    )

    env = build_agent_env({**(base_env or {}), **build_sandbox_validation_env()})
    # Proxy settings are not part of the FUZZ_SOURCE_FOLDS allowlist -- they are
    # sandbox plumbing, added after scrubbing. NO_PROXY keeps the broker socket
    # and loopback off the proxy path.
    env.update({
        "HTTPS_PROXY": proxy, "https_proxy": proxy,
        "HTTP_PROXY": proxy, "http_proxy": proxy,
        "NO_PROXY": "localhost,127.0.0.1", "no_proxy": "localhost,127.0.0.1",
    })

    tools = str(Path(__file__).resolve().parent / "agent_tools")
    cmd = build_agent_docker_command(
        image=AGENT_IMAGE, src=source_dir, profile=profile_dir, tools=tools,
        sock=sock_path, network=network, env=env,
    )
    # Subscription OAuth: the credential is a FILE, mounted as a writable copy so
    # the CLI can refresh a short-lived access token without touching the host's.
    # Only the credential itself -- never ~/.claude, which holds prior-run
    # transcripts naming these bugs.
    insert = cmd.index("-w")
    for spec in egress.stage_credentials(session_dir):
        cmd[insert:insert] = ["-v", spec]
        insert += 2
    # The prompt becomes the container's argv, which is readable from inside via
    # /proc/1/cmdline -- so it must carry nothing identifying about the target.
    cmd += ["claude", "-p", prompt, "--dangerously-skip-permissions"]

    logger.info("launching sandboxed optimizer for %s", project)
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
        )
        return {
            "ok": r.returncode == 0,
            "stdout": r.stdout or "",
            "stderr": r.stderr or "",
            "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        logger.warning("sandboxed optimizer timed out after %ss", timeout)
        return {"ok": False, "stdout": "", "stderr": "", "timed_out": True}
    finally:
        # Fold any token refresh the session performed back into the store.
        # Skipping this means re-seeding from a stale credential next time, which
        # under refresh-token rotation stops authenticating entirely.
        try:
            egress.harvest_credentials(session_dir)
        except Exception as e:                       # noqa: BLE001
            logger.warning("credential harvest failed: %s", e)
        stop.set()
        try:
            os.unlink(sock_path)
        except OSError:
            pass
