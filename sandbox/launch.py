"""Launch the optimizer agent inside a confined container.

Replaces the current path, where phase2_setup._agent_child_env copies the ENTIRE
orchestrator os.environ into a `claude -p --dangerously-skip-permissions` child
with full filesystem, network, and docker access.

What the agent gets:
    /work/src       the source tree, writable, .git stripped
    /work/profile   the hotspot list, read-only
    /work/bin       broker-client scripts, read-only
    /run/broker.sock the only way to reach docker

What it does not get: a docker socket, the host filesystem, the experiment
directory, the benchmark repo, the PoC, or any environment variable outside
ENV_ALLOWLIST. Egress is restricted to a pre-created docker network whose rules
permit only the model API -- `--network none` is not an option because an LLM
CLI cannot function without reaching its API.

Paths matter as much as contents: the experiment directory is named
`<project>-<cve>`, so a host path forwarded verbatim leaks the ARVO id and CVE in
the string itself (leak inventory item 5). Every allowlisted value that looks
like a host path is rewritten under /work.
"""
from __future__ import annotations

import logging
from pathlib import PurePosixPath

logger = logging.getLogger(__name__)

# Sandbox-internal layout. Deliberately neutral -- nothing here names a project,
# a CVE, an ARVO id, or an experiment.
WORK_ROOT = "/work"
SRC_MOUNT = f"{WORK_ROOT}/src"
PROFILE_MOUNT = f"{WORK_ROOT}/profile"
TOOLS_MOUNT = f"{WORK_ROOT}/bin"
SOCK_MOUNT = "/run/broker.sock"

# Only the variables the optimizer skill actually reads. Anything absent here is
# dropped rather than forwarded -- an allowlist, so a newly-added orchestrator
# variable cannot leak by default.
ENV_ALLOWLIST: tuple[str, ...] = (
    "FUZZ_SOURCE_FOLDS_OUT_DIR",
    "FUZZ_SOURCE_FOLDS_BASELINE_OUT_DIR",
    "FUZZ_SOURCE_FOLDS_CORPUS_DIR",
    "FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR",
    "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR",
    "FUZZ_SOURCE_FOLDS_REPLAY_REPEATS",
    "FUZZ_SOURCE_FOLDS_CORPUS_BUILD_DURATION",
    "FUZZ_SOURCE_FOLDS_VALIDATION_MODE",
)

# Where each allowlisted path variable is remapped inside the sandbox.
_PATH_REWRITES = {
    "FUZZ_SOURCE_FOLDS_OUT_DIR": f"{WORK_ROOT}/out",
    "FUZZ_SOURCE_FOLDS_BASELINE_OUT_DIR": f"{WORK_ROOT}/baseline-out",
    "FUZZ_SOURCE_FOLDS_CORPUS_DIR": f"{WORK_ROOT}/corpus",
    "FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR": f"{WORK_ROOT}/corpus-fixed",
    "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR": PROFILE_MOUNT,
}


def build_agent_env(base: dict) -> dict:
    """Rebuild the child environment from the allowlist, rewriting host paths."""
    env: dict[str, str] = {}
    for key in ENV_ALLOWLIST:
        if key not in base:
            continue
        if key in _PATH_REWRITES:
            env[key] = _PATH_REWRITES[key]
        else:
            value = str(base[key])
            # Defence in depth: never forward something path-shaped that we did
            # not explicitly plan to rewrite.
            if value.startswith("/") or PurePosixPath(value).is_absolute():
                logger.warning("dropping unexpected path-valued env %s", key)
                continue
            env[key] = value
    return env


def build_agent_docker_command(
    *, image: str, src: str, profile: str, tools: str, sock: str, network: str,
    env: dict, memory: str = "8g", cpus: str = "",
) -> list[str]:
    """`docker run` for the agent container. No socket, no host filesystem."""
    cmd = [
        "docker", "run", "--rm",
        "--network", network,
        # The agent compiles nothing and runs nothing privileged -- all docker
        # work happens broker-side, so it needs no capabilities at all.
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", memory,
    ]
    if cpus:
        cmd += ["--cpuset-cpus", cpus]
    cmd += [
        "-v", f"{src}:{SRC_MOUNT}",                 # writable: the agent edits here
        "-v", f"{profile}:{PROFILE_MOUNT}:ro",
        "-v", f"{tools}:{TOOLS_MOUNT}:ro",
        "-v", f"{sock}:{SOCK_MOUNT}",
        "-w", SRC_MOUNT,
    ]
    for key, value in sorted(env.items()):
        cmd += ["-e", f"{key}={value}"]
    cmd.append(image)
    return cmd
