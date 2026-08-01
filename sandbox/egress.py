"""Bring up the egress proxy and stage the agent's credentials.

Topology:

    agent container            proxy container          internet
    (bench-agent-egress,  -->  (both networks)     -->  allowlisted hosts only
     --internal, no route)          |
                                    +--> egress.log  (ALLOW/DENY audit trail)

The agent has no route out at all; the proxy is the only path, and it forwards
only to allowlisted hosts. Every decision is logged, so "the agent never reached
the CVE database" is something you can show rather than assert.

Credentials: both backends use subscription OAuth (a claude.ai Max plan, a
ChatGPT plan) rather than API keys. Two consequences:

  * The credential is a FILE, not an env var, so it has to be mounted.
  * Access tokens are short-lived (hours) while runs are long, so the CLI must
    refresh -- which needs the file to be WRITABLE. A read-only mount works until
    the first expiry and then fails partway through a campaign.

So a per-session COPY is mounted writable. The host credential is never exposed
to the container, and a refresh inside the sandbox cannot corrupt it.

Critically, only the single credentials FILE is mounted -- never ~/.claude, which
holds projects/ with session transcripts from prior runs on these very targets
(ASAN traces, CVE ids, bug locations). Mounting the parent directory to get the
credential would hand the agent the answer through the door the sandbox exists
to close. That is leak-inventory item 10.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

PROXY_IMAGE = os.environ.get("SANDBOX_PROXY_IMAGE", "bench-sandbox/egress")
PROXY_NAME = os.environ.get("SANDBOX_PROXY_NAME", "bench-egress-proxy")
PROXY_PORT = 8888
EXTERNAL_NETWORK = os.environ.get("SANDBOX_EXTERNAL_NETWORK", "bridge")

# Host paths holding subscription credentials, and where each backend expects
# them inside the container.
CREDENTIAL_FILES = {
    "claude": (Path.home() / ".claude" / ".credentials.json", "/home/agent/.claude/.credentials.json"),
    "codex": (Path.home() / ".codex" / "auth.json", "/home/agent/.codex/auth.json"),
}


def proxy_url() -> str:
    return f"http://{PROXY_NAME}:{PROXY_PORT}"


def _container_running(name: str) -> bool:
    r = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        capture_output=True, text=True,
    )
    return r.stdout.strip() == "true"


def build_proxy_image(context_dir: str | Path) -> bool:
    """Build the proxy image. Python-only, so no package installs are needed."""
    context_dir = Path(context_dir)
    dockerfile = context_dir / "Dockerfile.egress"
    dockerfile.write_text(
        "# syntax=docker/dockerfile:1\n"
        "FROM python:3.12-alpine\n"
        "COPY egress_proxy.py /egress_proxy.py\n"
        "ENTRYPOINT [\"python3\", \"/egress_proxy.py\"]\n"
    )
    r = subprocess.run(
        ["docker", "build", "-t", PROXY_IMAGE, "-f", str(dockerfile), str(context_dir)],
        capture_output=True, text=True, errors="replace",
    )
    if r.returncode != 0:
        logger.error("egress proxy image build failed: %s", (r.stderr or "")[-500:])
    return r.returncode == 0


def build_proxy_run_command(
    *, internal_network: str, log_dir: str, extra_allow: list[str] | None = None,
) -> list[str]:
    """Run the proxy attached to the INTERNAL network, then join it to a routed one."""
    cmd = [
        "docker", "run", "-d", "--rm",
        "--name", PROXY_NAME,
        "--network", internal_network,
        "-v", f"{Path(log_dir).absolute()}:/logs",
        PROXY_IMAGE,
        "--port", str(PROXY_PORT),
    ]
    for host in (extra_allow or []):
        cmd += ["--allow", host]
    return cmd


def start_proxy(*, internal_network: str, log_dir: str,
                extra_allow: list[str] | None = None) -> str:
    """Start (or reuse) the proxy and return the URL agents should point at."""
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    if _container_running(PROXY_NAME):
        return proxy_url()

    subprocess.run(["docker", "rm", "-f", PROXY_NAME], capture_output=True)
    cmd = build_proxy_run_command(
        internal_network=internal_network, log_dir=log_dir, extra_allow=extra_allow,
    )
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        raise RuntimeError(f"could not start egress proxy: {(r.stderr or '')[-400:]}")

    # Second network gives the proxy -- and ONLY the proxy -- a route out.
    join = subprocess.run(
        ["docker", "network", "connect", EXTERNAL_NETWORK, PROXY_NAME],
        capture_output=True, text=True,
    )
    if join.returncode != 0 and "already exists" not in (join.stderr or ""):
        raise RuntimeError(
            f"proxy has no route out: {(join.stderr or '')[-300:]}"
        )
    logger.info("egress proxy up at %s (allowlisted hosts only)", proxy_url())
    return proxy_url()


def stop_proxy() -> None:
    subprocess.run(["docker", "rm", "-f", PROXY_NAME], capture_output=True)


def stage_credentials(session_dir: str | Path, backends=None) -> list[str]:
    """Copy each backend's credential into the session dir; return -v specs.

    A COPY, mounted writable, so the CLI can refresh an expired access token
    without touching the host file. Only the credential file itself is exposed --
    never its parent directory.
    """
    session_dir = Path(session_dir)
    creds_dir = session_dir / "creds"
    creds_dir.mkdir(parents=True, exist_ok=True)
    mounts: list[str] = []
    # Default to whatever backends are actually configured, so adding or
    # removing one cannot KeyError at run time.
    for backend in (backends if backends is not None else CREDENTIAL_FILES):
        entry = CREDENTIAL_FILES.get(backend)
        if entry is None:
            logger.warning("no credential path configured for %s", backend)
            continue
        host_path, container_path = entry
        if not host_path.is_file():
            logger.info("no %s credential at %s; skipping", backend, host_path)
            continue
        staged = creds_dir / f"{backend}{host_path.suffix or '.json'}"
        shutil.copy2(host_path, staged)
        os.chmod(staged, 0o600)
        mounts.append(f"{staged}:{container_path}")
        logger.info("staged %s credential (writable copy) for the sandbox", backend)
    return mounts
