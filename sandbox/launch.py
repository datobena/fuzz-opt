"""Launch the optimizer agent inside a confined container.

Replaces the current path, where phase2_setup._agent_child_env copies the ENTIRE
orchestrator os.environ into a `claude -p --dangerously-skip-permissions` child
with full filesystem, network, and docker access.

What the agent gets:
    /work/src       the source tree, writable, .git stripped
    /work/profile   the harness-built profile (hotspots.txt ...) and fixed corpus, read-only
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

import functools
import logging
import os
import threading
from pathlib import Path, PurePosixPath

logger = logging.getLogger(__name__)

# Sandbox-internal layout. Deliberately neutral -- nothing here names a project,
# a CVE, an ARVO id, or an experiment.
WORK_ROOT = "/work"
SRC_MOUNT = f"{WORK_ROOT}/src"
PROFILE_MOUNT = f"{WORK_ROOT}/profile"
TOOLS_MOUNT = f"{WORK_ROOT}/bin"
SOCK_MOUNT = "/run/broker.sock"
# Where the CLI looks for skills. NOT under /work: the agent's HOME is the only
# place it searches, and only this ONE skill directory is mounted -- never
# ~/.claude itself, which holds transcripts from prior runs on these targets.
AGENT_HOME = "/home/agent"
SKILLS_MOUNT = f"{AGENT_HOME}/.claude/skills"
# The CLI writes one session JSONL per run under here: every assistant turn,
# every tool_use and tool_result, and the model that served each turn.
TRANSCRIPTS_MOUNT = f"{AGENT_HOME}/.claude/projects"
HARNESS_MOUNT = f"{WORK_ROOT}/harness"

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
    # The build/smoke/validate contract. Under the sandbox these are broker
    # clients under /work/bin rather than docker command lines; without them
    # allowlisted the agent reaches its source with no way to build it.
    "FUZZ_SOURCE_FOLDS_BUILD_COMMAND",
    "FUZZ_SOURCE_FOLDS_SMOKE_COMMAND",
    "FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND",
)

# Where each allowlisted path variable is remapped inside the sandbox.
_PATH_REWRITES = {
    "FUZZ_SOURCE_FOLDS_OUT_DIR": f"{WORK_ROOT}/out",
    "FUZZ_SOURCE_FOLDS_BASELINE_OUT_DIR": f"{WORK_ROOT}/baseline-out",
    "FUZZ_SOURCE_FOLDS_CORPUS_DIR": f"{WORK_ROOT}/corpus",
    "FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR": f"{WORK_ROOT}/corpus-fixed",
    "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR": PROFILE_MOUNT,
}


# Docker labels on every agent container and every container the broker starts.
# A timed-out `docker run` kills only the docker CLIENT, and the container ran on
# -- 56 of 56 timed-out rounds, 7-193 min past the timeout, still building
# through the broker. The labels are how the session, the launcher's exit
# handler and the next launcher's start-up sweep find such a container and tell
# whose it is.
#
# Host-side metadata only: labels are not visible inside the container (no
# docker socket; they are not put in its env or filesystem), so naming the
# experiment here leaks nothing. Container NAMES are different -- the network's
# DNS answers for them -- so names carry only a pid and a random id.
LABEL_ROLE = "bench.sandbox.role"                  # "agent" | "broker"
# <pid>:<start time>:<boot id>. The pid alone is not an identity -- pids are
# reused -- but with the process's start time (clock ticks since boot) and the
# boot it names exactly one process, so a live launcher's containers can never
# be mistaken for a dead one's.
LABEL_LAUNCHER = "bench.sandbox.launcher"
LABEL_LAUNCHER_PID = "bench.sandbox.launcher-pid"  # readable copy of the pid
LABEL_EXPERIMENT = "bench.sandbox.experiment"
LABEL_PROJECT = "bench.sandbox.project"
LABEL_SESSION = "bench.sandbox.session"            # one optimizer session
LABEL_TRIAL = "bench.sandbox.trial"
LABEL_ITER = "bench.sandbox.iter"

# Set once by the launcher (session.install_launcher_cleanup); labels only.
_LAUNCHER_EXPERIMENT = ""

# Set once the launcher is going down (a signal, or exit): from then on no agent
# session starts and the broker starts no container -- one started after the
# launcher swept its containers would outlive it. Here rather than in session.py
# because the broker reads it too, and session imports broker.
SHUTTING_DOWN = threading.Event()


def boot_id() -> str:
    """This boot's id, or '' where the kernel does not expose one."""
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return ""


def process_start_time(pid: int) -> str:
    """Start time of ``pid`` in clock ticks since boot (/proc/<pid>/stat field
    22), or '' when it cannot be read. Fields are counted after the LAST ')':
    the command name before it may itself contain spaces and parentheses."""
    try:
        return Path(f"/proc/{int(pid)}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError, ValueError):
        return ""


@functools.lru_cache(maxsize=None)
def _token_for(pid: int) -> str:
    return f"{pid}:{process_start_time(pid)}:{boot_id()}"


def launcher_token() -> str:
    """This process's LABEL_LAUNCHER value."""
    return _token_for(os.getpid())


def set_launcher_experiment(experiment_id: str) -> None:
    global _LAUNCHER_EXPERIMENT
    _LAUNCHER_EXPERIMENT = str(experiment_id or "")


def launcher_labels() -> dict[str, str]:
    """The labels naming this launcher, carried by every container it starts."""
    labels = {LABEL_LAUNCHER: launcher_token(), LABEL_LAUNCHER_PID: str(os.getpid())}
    if _LAUNCHER_EXPERIMENT:
        labels[LABEL_EXPERIMENT] = _LAUNCHER_EXPERIMENT
    return labels


def label_args(labels: dict | None) -> list[str]:
    """`--label k=v` for each label with a value, in a stable order."""
    out: list[str] = []
    for key, value in sorted((labels or {}).items()):
        if value is None or value == "":
            continue
        out += ["--label", f"{key}={value}"]
    return out


def _relative_to(path, root) -> str:
    """``path`` relative to ``root`` when strictly inside it, else ''. The result
    is a sub-path of the profile dir (e.g. 'fixed_corpus'), never a host path."""
    if not path or not root:
        return ""
    p, r = PurePosixPath(str(path)), PurePosixPath(str(root))
    try:
        rel = p.relative_to(r)
    except ValueError:
        return ""
    rel_s = str(rel)
    if rel_s in ("", ".") or ".." in rel.parts:
        return ""
    return rel_s


def build_agent_env(base: dict) -> dict:
    """Rebuild the child environment from the allowlist, rewriting host paths."""
    env: dict[str, str] = {}
    for key in ENV_ALLOWLIST:
        if key not in base:
            continue
        if key == "FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR":
            # The harness freezes the fixed corpus INSIDE the profile artifact
            # dir (<profiles>/fixed_corpus), and only that dir is mounted
            # (/work/profile). Point the agent at the copy it can actually read;
            # the skill treats a missing or empty fixed corpus as
            # BLOCKED_LOW_CONFIDENCE, so a dangling /work/corpus-fixed would end
            # every round.
            rel = _relative_to(base[key], base.get("FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR"))
            env[key] = f"{PROFILE_MOUNT}/{rel}" if rel else _PATH_REWRITES[key]
            continue
        if key in _PATH_REWRITES:
            env[key] = _PATH_REWRITES[key]
        else:
            value = str(base[key])
            # A value already rooted at /work is sandbox-internal by
            # construction -- it names nothing on the host and cannot leak the
            # project, CVE, or experiment. The validation commands are exactly
            # this shape (/work/bin/fold-build).
            if value.startswith(WORK_ROOT + "/"):
                env[key] = value
                continue
            # Defence in depth: never forward any OTHER path-shaped value, since
            # host paths carry the experiment dir name <project>-<cve>.
            if value.startswith("/") or PurePosixPath(value).is_absolute():
                logger.warning("dropping unexpected path-valued env %s", key)
                continue
            env[key] = value
    return env


def build_agent_docker_command(
    *, image: str, src: str, profile: str, tools: str, sock: str, network: str,
    env: dict, memory: str = "8g", cpus: str = "", skill: str = "",
    skill_name: str = "", harness: str = "", transcripts: str = "",
    name: str = "", labels: dict | None = None,
) -> list[str]:
    """`docker run` for the agent container. No socket, no host filesystem.

    ``name`` and ``labels`` (LABEL_*) are what let the session remove the
    container when the `docker run` client is killed on a timeout -- the
    container outlives its client otherwise.

    ``skill`` is the host path of the ONE optimizer skill directory to expose,
    read-only, under the agent's own skills dir. The prompt says "Use the <skill>
    skill", and without this the CLI has no such skill: the agent correctly
    refuses with BLOCKED_LOW_CONFIDENCE and every round is lost.

    Read-only and single-skill on purpose. The mount target is a child of
    ~/.claude, never ~/.claude itself -- that directory holds transcripts from
    prior runs naming these very bugs (leak-inventory item 10), which is the same
    reason the credential is mounted as one file rather than its parent.

    NOTE the skill's own text is part of the leak surface: methodology is neutral,
    but a worked example naming a target hands the agent prior knowledge about it.
    That is a property of the tree being mounted, not of this function -- check it
    before pointing this at a new skill.
    """
    cmd = ["docker", "run", "--rm"]
    if name:
        cmd += ["--name", name]
    cmd += label_args(labels)
    cmd += [
        # PID 1 is docker's init, not `claude`: PID 1 gets no default signal
        # actions, so a `docker stop` SIGTERM is ignored unless the CLI handles
        # it itself. The init forwards it, and reaps what the agent's shell
        # commands leave behind.
        "--init",
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
    ]
    if skill:
        name = skill_name or PurePosixPath(skill).name
        cmd += ["-v", f"{skill}:{SKILLS_MOUNT}/{name}:ro"]
    if transcripts:
        # Writable: this is where the CLI persists the session transcript,
        # the only record of what the agent actually thought and ran --
        # stdout carries just its closing summary.
        #
        # Mounted as an EMPTY per-run directory, never the host's
        # ~/.claude/projects, which holds transcripts from prior runs naming
        # these very bugs (leak-inventory item 10). Nothing prior is visible
        # to the agent; only this run's record travels back out.
        cmd += ["-v", f"{transcripts}:{TRANSCRIPTS_MOUNT}"]
    if harness:
        # OSS-Fuzz keeps the harness NEXT TO the project dir, not inside it, so
        # it falls outside the /work/src mount. Read-only: the prompt forbids
        # editing it, and the agent only needs to read the entry point.
        cmd += ["-v", f"{harness}:{HARNESS_MOUNT}/{PurePosixPath(harness).name}:ro"]
    cmd += ["-w", SRC_MOUNT]
    for key, value in sorted(env.items()):
        cmd += ["-e", f"{key}={value}"]
    cmd.append(image)
    return cmd
