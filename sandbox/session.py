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

import atexit
import functools
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib import cpu_ledger
from sandbox import broker as broker_mod
from sandbox import egress
from sandbox import launch
from sandbox.launch import (
    LABEL_ITER,
    LABEL_LAUNCHER,
    LABEL_PROJECT,
    LABEL_ROLE,
    LABEL_SESSION,
    LABEL_TRIAL,
    SRC_MOUNT,
    TOOLS_MOUNT,
    build_agent_docker_command,
    build_agent_env,
    launcher_labels,
    launcher_token,
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

# Teardown bound: how long a session waits for its broker thread to return once
# the agent and the broker's containers are gone. Past it the thread is left to
# finish its current request (it starts no new container) on its own.
BROKER_JOIN_SECS = 60

# The launcher-wide "going down" flag lives in launch.SHUTTING_DOWN (the broker
# reads it too). After the signal handler's first sweep it waits this long and
# sweeps again, for a container a racing session or broker call started meanwhile.
SIGNAL_RESWEEP_SECS = 2.0
_launcher_cleanup_installed = False

# Private credential dirs (egress.stage_secret) of sessions still running. A
# SIGTERM ends the process before any session's finally runs, so the launcher's
# signal and exit handlers delete what is registered here.
_LIVE_SECRET_DIRS: set[str] = set()
_LIVE_SECRET_LOCK = threading.Lock()


def _optimizer_skill_dir() -> tuple[str, str]:
    """(host path, name) of the optimizer skill to mount, or ("", "").

    PHASE2_SKILL_SCRIPTS_DIR points at <skill>/scripts -- the benchmark loads
    replay_timing.py from there -- so the skill root is its parent. Taking it from
    config rather than a second setting is what keeps the agent's methodology and
    the replay gate's timing helper from drifting apart.

    Returns empty when the skill is absent instead of raising: the caller cannot
    fix it, and bootstrap_server --check reports it up front.
    """
    import config
    scripts = getattr(config, "PHASE2_SKILL_SCRIPTS_DIR", "")
    if not scripts:
        return "", ""
    root = Path(scripts).parent
    if not (root / "SKILL.md").is_file():
        logger.warning(
            "optimizer skill not found at %s; the agent will be told to use a "
            "skill it does not have and will refuse the round", root)
        return "", ""
    return str(root), getattr(config, "PHASE2_OPTIMIZER_SKILL", root.name)


def build_sandbox_validation_env() -> dict[str, str]:
    """The FUZZ_SOURCE_FOLDS_* validation contract, pointed at broker clients."""
    return {
        "FUZZ_SOURCE_FOLDS_VALIDATION_MODE": "wrapper",
        "FUZZ_SOURCE_FOLDS_BUILD_COMMAND": SANDBOX_BUILD_CMD,
        "FUZZ_SOURCE_FOLDS_SMOKE_COMMAND": SANDBOX_SMOKE_CMD,
        "FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND": SANDBOX_VALIDATE_CMD,
    }


def resolve_agent_cpus(explicit: str | None = None, *,
                       siblings: dict[int, frozenset[int]] | None = None) -> str:
    """The cpuset the agent container runs on (config.ONLINE_AGENT_CPUS), as a
    --cpuset-cpus string. Never empty: raises instead of letting the agent go
    unpinned.

    The broker pins the agent's builds/smokes/replays to its profile core, but the
    container itself -- the Claude CLI, plus anything the agent runs in it (the
    image has gcc) -- was unpinned, free to land on a trial core and steal the
    cycles the two arms are compared on, or on a profile core in the middle of a
    replay the gate is timing.

    Unset -> derived: one logical cpu per PHYSICAL core (the lowest of its
    hyperthreads, cpu*/topology/thread_siblings_list), minus every core that holds
    a trial cpu (ONLINE_TRIAL_CORES) or a profile cpu (ONLINE_OPTIMIZER_CORES) on
    either hyperthread. run_online_pertrial.sh's layout (trials 12-31, profile
    2-11, sibling of c is c+40) gives 0-1,32-39. The idle HT half stays idle.
    An explicit set is taken as given, except that touching a trial core or its
    sibling is an error (a profile core only warns: it skews gate timing, it does
    not bias the arms).
    """
    import config
    from lib.core_lock import format_cpuset, parse_cpuset, thread_siblings

    if explicit is None:
        explicit = str(getattr(config, "ONLINE_AGENT_CPUS", "") or "")
    sib = siblings if siblings is not None else thread_siblings()
    if not sib:
        # No topology (not Linux, /sys hidden): each logical cpu its own core.
        # Still never on a trial or profile cpu, but HT siblings are unknown.
        logger.warning("cpu topology unreadable; deriving the agent cpuset "
                       "without hyperthread siblings")
        sib = {c: frozenset({c}) for c in range(os.cpu_count() or 1)}

    def _cores(spec) -> set[int]:
        out: set[int] = set()
        for c in parse_cpuset(spec):
            out |= sib.get(c, frozenset({c}))
        return out

    trial = _cores(getattr(config, "ONLINE_TRIAL_CORES", ""))
    profile = _cores(getattr(config, "ONLINE_OPTIMIZER_CORES", ""))

    if explicit.strip():
        cpus = set(parse_cpuset(explicit))
        if cpus & trial:
            raise RuntimeError(
                f"ONLINE_AGENT_CPUS={explicit} overlaps the trial cores or their "
                f"hyperthread siblings ({format_cpuset(cpus & trial)}); the agent "
                "must never run on a trial core")
        if cpus & profile:
            logger.warning("ONLINE_AGENT_CPUS=%s overlaps optimizer profile cores "
                           "(%s): the agent can perturb replay timing there",
                           explicit, format_cpuset(cpus & profile))
        return format_cpuset(cpus)

    physical = {min(s) for s in sib.values()}
    cpus = {c for c in physical if not (sib.get(c, frozenset({c})) & (trial | profile))}
    if not cpus:
        raise RuntimeError(
            "no physical core is free for the agent container: trial cores "
            f"{getattr(config, 'ONLINE_TRIAL_CORES', '')} and optimizer cores "
            f"{getattr(config, 'ONLINE_OPTIMIZER_CORES', '')} (with hyperthread "
            "siblings) cover every core. Set ONLINE_AGENT_CPUS explicitly; "
            "refusing to run the agent unpinned.")
    return format_cpuset(cpus)


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


# docker states of a container that can no longer write anything. `created` is
# among them: `docker run` is create-then-start driven by the CLIENT, and every
# caller here asks only after that client has exited (subprocess.run returned,
# or killed and reaped it); no container this code starts has a restart policy
# (all are --rm). So nothing is left to start a created one -- and a start the
# dying client had already sent shows up within the retry loop, as running.
_STOPPED_STATES = frozenset({"created", "exited", "dead", "removing"})
_LIVE_STATES = frozenset({"running", "paused", "restarting"})


def _container_state(name: str) -> str:
    """'gone', 'live' (running, paused or restarting: it can still write),
    one of _STOPPED_STATES, or 'unknown' when docker could not be asked. Only
    a positive "No such container" is 'gone'."""
    try:
        r = subprocess.run(
            ["docker", "inspect", "--type", "container", "--format",
             "{{.State.Status}} {{.State.Running}} {{.State.Paused}} "
             "{{.State.Restarting}}", name],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if r.returncode != 0:
        return "gone" if "no such" in (r.stderr or "").lower() else "unknown"
    fields = (r.stdout or "").split()
    status = fields[0] if fields else ""
    if status in _LIVE_STATES or "true" in fields[1:4]:
        return "live"
    return status if status in _STOPPED_STATES else "unknown"


def remove_container(name: str, *, attempts: int = 10, delay: float = 1.0) -> bool:
    """`docker rm -f` ``name`` until it is gone. True when nothing of it can
    write any more: gone, or -- after ``attempts`` -- still listed but stopped
    for good (exited, dead, removing, created), which is logged. False, as an
    error, when it is still live or docker cannot say.

    Retried because `rm -f` on a container whose --rm removal is already under
    way returns at once while the container still exists. A stopped container
    docker cannot finish removing (`dead` after a device-busy error) must not
    count as a writer: that threw a finished round away, and a trial whose
    leftover stayed `dead` would have waited on it for the rest of the campaign.
    """
    state = "unknown"
    for i in range(attempts):
        try:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True,
                           timeout=120)
        except (OSError, subprocess.SubprocessError) as e:
            logger.warning("docker rm -f %s failed: %s", name, e)
        state = _container_state(name)
        if state == "gone":
            return True
        if i + 1 < attempts:
            time.sleep(delay)
    if state in _STOPPED_STATES:
        logger.warning(
            "container %s is stopped (%s) but docker could not remove it after %d "
            "attempts; it can no longer write. Remove it by hand (docker rm -f %s).",
            name, state, attempts, name)
        return True
    logger.error(
        "container %s is STILL PRESENT (%s) after %d removal attempts: it may still "
        "be editing the source tree and building through the broker. Remove it by "
        "hand (docker rm -f %s) before trusting anything this round left behind.",
        name, state, attempts, name)
    return False


def _labelled_containers(label_filter: str) -> list[dict] | None:
    """Containers in any state matching the docker filter ``label=<label_filter>``,
    as {id, name, launcher, role}; None when docker could not be asked."""
    fmt = "\t".join(["{{.ID}}", "{{.Names}}",
                     f'{{{{.Label "{LABEL_LAUNCHER}"}}}}', f'{{{{.Label "{LABEL_ROLE}"}}}}'])
    try:
        r = subprocess.run(
            ["docker", "ps", "-a", "--no-trunc", "--filter", f"label={label_filter}",
             "--format", fmt],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning("could not list sandbox containers: %s", e)
        return None
    if r.returncode != 0:
        logger.warning("could not list sandbox containers: %s", (r.stderr or "")[-200:])
        return None
    found = []
    for line in (r.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and parts[0]:
            found.append(dict(zip(("id", "name", "launcher", "role"), parts)))
    return found


def _force_remove_ids(ids: list[str]) -> None:
    try:
        subprocess.run(["docker", "rm", "-f", *ids], capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        logger.error("docker rm -f of %d sandbox container(s) failed: %s", len(ids), e)


def launcher_state(token: str) -> str:
    """'alive', 'dead' or 'unknown' for the launcher a LABEL_LAUNCHER value
    (<pid>:<start time>:<boot id>) names.

    Only 'dead' is ever acted on. 'unknown' -- a malformed value, or a live pid
    whose start time cannot be compared -- keeps the container: removing a live
    launcher's agent mid-round is the worse mistake.
    """
    pid_s, _, rest = (token or "").partition(":")
    start, _, boot = rest.partition(":")
    try:
        pid = int(pid_s)
    except ValueError:
        return "unknown"
    if pid <= 0:
        return "unknown"
    here = launch.boot_id()
    if boot and here and boot != here:
        return "dead"                       # started before this host last booted
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return "dead"
    except PermissionError:
        pass                                # exists, another user's process
    except OSError:
        return "unknown"
    if not start:
        return "unknown"
    now = launch.process_start_time(pid)
    if not now:
        return "unknown"
    return "alive" if now == start else "dead"    # dead: the pid was reused


def remove_launcher_containers(token: str | None = None) -> list[str]:
    """Force-remove every container labelled with this launcher (or ``token``);
    returns their names. Whatever is still listed afterwards is logged as an
    error."""
    token = token or launcher_token()
    found = _labelled_containers(f"{LABEL_LAUNCHER}={token}")
    if not found:
        return []
    _force_remove_ids([c["id"] for c in found])
    left = _labelled_containers(f"{LABEL_LAUNCHER}={token}") or []
    if left:
        logger.error("sandbox container(s) still present after removal: %s",
                     ", ".join(c["name"] for c in left))
    return [c["name"] for c in found]


def sweep_orphaned_containers() -> list[str]:
    """Remove agent and broker containers whose launcher is no longer running.

    Keyed on LABEL_LAUNCHER alone -- never on an image or a name -- and only a
    launcher proved dead (launcher_state) is swept. Another campaign on this
    host, still running or in its post-run phase, keeps every container it has;
    an unlabelled container (a manual run, a launcher older than the labels) is
    never even listed.
    """
    mine = launcher_token()
    dead = [c for c in (_labelled_containers(LABEL_LAUNCHER) or [])
            if c["launcher"] != mine and launcher_state(c["launcher"]) == "dead"]
    if not dead:
        return []
    logger.warning(
        "removing %d sandbox container(s) left by launchers that are no longer "
        "running: %s", len(dead),
        ", ".join(f"{c['name']} ({c['role'] or '?'}, launcher {c['launcher']})"
                  for c in dead))
    _force_remove_ids([c["id"] for c in dead])
    return [c["name"] for c in dead]


def _remove_live_secret_dirs() -> list[str]:
    with _LIVE_SECRET_LOCK:
        dirs = sorted(_LIVE_SECRET_DIRS)
        _LIVE_SECRET_DIRS.clear()
    for d in dirs:
        shutil.rmtree(d, ignore_errors=True)
    return dirs


def _launcher_teardown(why: str, *, resweep_after: float = 0.0) -> None:
    """Remove this launcher's containers -- twice, ``resweep_after`` seconds
    apart, when given -- and then, whatever that did, the credential dirs of
    sessions still running."""
    try:
        removed = remove_launcher_containers()
        if resweep_after:
            time.sleep(resweep_after)
            removed += remove_launcher_containers()
        if removed:
            logger.warning("%s: removed %d sandbox container(s): %s",
                           why, len(removed), ", ".join(removed))
    except Exception as e:                           # noqa: BLE001
        logger.error("%s: sandbox container cleanup failed: %s", why, e)
    finally:
        dirs = _remove_live_secret_dirs()
        if dirs:
            logger.warning("%s: removed %d live session credential dir(s)",
                           why, len(dirs))


def _cleanup_at_exit() -> None:
    launch.SHUTTING_DOWN.set()
    try:
        _launcher_teardown("launcher exit")
    except Exception:                                # noqa: BLE001
        pass                                         # never fail interpreter exit


def _on_launcher_signal(signum, frame, *, prev):
    launch.SHUTTING_DOWN.set()
    try:
        _launcher_teardown(f"signal {signum}", resweep_after=SIGNAL_RESWEEP_SECS)
    finally:
        # Whatever happened above -- a second Ctrl-C in the middle of a slow
        # docker call included -- the signal is handed on, or it is swallowed.
        if callable(prev):
            prev(signum, frame)                      # SIGINT: KeyboardInterrupt
        else:
            # SIG_DFL: die exactly as the signal would have killed us.
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)


def install_launcher_cleanup(experiment_id: str = "") -> None:
    """Launcher-level container hygiene. Call once from the launcher's main
    thread before any session starts; ``experiment_id`` goes on every label.

    * now: remove containers whose launcher is dead (sweep_orphaned_containers);
    * at exit, normal or by exception (atexit), and on SIGTERM/SIGINT: stop
      new sessions and broker containers (launch.SHUTTING_DOWN), remove every
      container this launcher labelled, and delete the credential dirs of
      sessions still running. The signal path sweeps twice, SIGNAL_RESWEEP_SECS
      apart, for a container a racing call started in between.

    A signal is then handed to whatever handled it before: SIGTERM still kills
    the process, SIGINT still raises KeyboardInterrupt, and a signal the
    launcher ignores (SIGINT under `nohup ... &`) stays ignored -- cleaning up
    and then running on would kill the agents of a launcher that keeps going.
    Anything that still slips through is left to the next launcher's sweep,
    which sees this launcher dead.
    """
    global _launcher_cleanup_installed
    launch.set_launcher_experiment(experiment_id)
    if _launcher_cleanup_installed:
        return
    _launcher_cleanup_installed = True
    try:
        sweep_orphaned_containers()
    except Exception as e:                           # noqa: BLE001
        logger.warning("start-up sweep of orphaned sandbox containers failed: %s", e)
    atexit.register(_cleanup_at_exit)
    if threading.current_thread() is not threading.main_thread():
        logger.warning("launcher cleanup installed off the main thread: no "
                       "SIGTERM/SIGINT handler, atexit only")
        return
    for signum in (signal.SIGTERM, signal.SIGINT):
        prev = signal.getsignal(signum)
        if prev is signal.SIG_IGN or prev is None:
            continue
        signal.signal(signum, functools.partial(_on_launcher_signal, prev=prev))


def run_sandboxed_optimizer(
    *, source_dir: str, profile_dir: str, out_dir: str, corpus_dir: str,
    image: str, fuzz_target: str, project: str, prompt: str,
    cpu: int = 0, timeout: int | None = None, audit_log: str = "",
    base_env: dict | None = None, harness: str = "", model: str = "",
    effort: str = "", ccache_dir: str = "", smoke_corpus_dir: str = "",
    agent_cpus: str | None = None,
) -> dict:
    """Run one optimizer session confined to a container.

    `image` is the pinned prework image the broker builds in -- NOT the image the
    agent runs in, which is AGENT_IMAGE and contains no project source at all.

    ``agent_cpus`` pins the agent container (--cpuset-cpus); None resolves it here
    (resolve_agent_cpus), so no caller can launch the agent unpinned. ``cpu`` is
    the broker's core, a different thing: where the agent's builds/replays run.

    The agent container must not outlive this call. On a timeout, on any
    exception, and on a normal return alike it is force-removed and confirmed
    gone, and the broker stopped with its in-flight containers, BEFORE the
    credential is harvested, the secret removed and the tree redacted. A timed-
    out `docker run` used to kill only the client: the agent went on editing the
    tree and building for up to 193 min, and once re-applied its edits after the
    harness had reset the tree, so the next round committed them as its baseline.

    When docker cannot confirm that, the result says so -- ``agent_removed``
    False, or ``broker_leftovers`` naming what still runs, with the agent's name
    in ``agent_container`` -- and the caller must not touch the tree.
    ``agent_removed`` is True for a container that is gone or stopped for good
    (remove_container): only a live one can still write.
    """
    if launch.SHUTTING_DOWN.is_set():
        raise RuntimeError("the launcher is shutting down; not starting an "
                           "optimizer session")
    assert_sandbox_available()
    # Before the broker or proxy start: a bad cpuset fails the round up front.
    agent_cpus = agent_cpus or resolve_agent_cpus()
    network = ensure_network()

    session_dir = Path(out_dir).parent / "sandbox"
    session_dir.mkdir(parents=True, exist_ok=True)

    # The socket does NOT live in session_dir. AF_UNIX caps sun_path at 108 bytes
    # and the natural path is
    #   <results>/<experiment>/<project>-<cve>/optimized/online/iter_NN/sandbox/broker.sock
    # which is 114 for a real experiment id -- the broker dies with "AF_UNIX path
    # too long", the agent loses build/smoke/replay, and every round is lost. It
    # fits only for short ids, so a shakedown passes (104) and the campaign it was
    # meant to de-risk does not.
    #
    # A short private dir also stops the host path carrying <project>-<cve>, which
    # the sandbox is otherwise careful never to expose.
    sock_dir = Path(tempfile.mkdtemp(prefix="bs-"))
    os.chmod(sock_dir, 0o700)
    sock_path = str(sock_dir / "b.sock")
    if len(sock_path.encode()) > 100:                 # leave headroom under 108
        raise RuntimeError(f"broker socket path too long: {sock_path}")

    # Drift-corrected replay timing: the broker snapshots the first built /out (the
    # pristine round-start binary) here, then brackets every candidate replay against
    # it so machine drift cancels. Off by setting FOLD_BRACKET_REPLAY=0.
    bracket = os.environ.get("FOLD_BRACKET_REPLAY", "1") != "0"
    baseline_ref_dir = str(session_dir / "baseline_ref") if bracket else ""
    # The round's ledger identity, read HERE on the round's own thread: the
    # broker serves from a new thread, which cannot see these thread-local tags.
    _tags = cpu_ledger.current_tags()
    # One id for the session, on the agent container and on every container the
    # broker starts for it, so each can be found and attributed (launch.LABEL_*).
    session_id = uuid.uuid4().hex[:12]
    session_labels = {LABEL_SESSION: session_id, LABEL_PROJECT: project,
                      LABEL_TRIAL: _tags["trial_id"], LABEL_ITER: _tags["iter"]}
    ctx = broker_mod.BrokerContext(
        image=image, source_dir=source_dir, out_dir=out_dir,
        corpus_dir=corpus_dir, fuzz_target=fuzz_target, project=project,
        cpu=cpu, audit_log=audit_log or str(session_dir / "broker_audit.log"),
        baseline_ref_dir=baseline_ref_dir,
        # Host-side only: the trial's ccache (FuzzBench, verified targets).
        ccache_dir=ccache_dir,
        # Online rounds: the crash-filtered mutation sample `smoke` runs on.
        smoke_corpus_dir=smoke_corpus_dir,
        # Every broker_* ledger row is charged to this optimizer and round.
        ledger_trial_id=_tags["trial_id"], ledger_iter=_tags["iter"],
        labels=session_labels,
    )

    def _serve():
        try:
            broker_mod.serve(sock_path, ctx)
        except Exception as e:                       # noqa: BLE001
            if not ctx.stop.is_set():
                logger.error("broker died: %s", e)

    t = threading.Thread(target=_serve, daemon=True)
    t.start()

    # Neutral on purpose: the agent network's DNS answers for container names.
    agent_name = f"agent-{os.getpid()}-{session_id}"
    agent_live = False                    # True from `docker run` until removal is tried
    # Outcome of each teardown step, once tried: agent confirmed gone (bool),
    # broker containers still running after the stop (names).
    removal: dict = {"agent": None, "broker": None}

    def _teardown() -> None:
        """Agent first, then the broker (with any chown a stopped build skipped).
        Each step is tried once: a teardown cut short by an exception is not
        re-run by the finally below, it goes straight on to the secret."""
        nonlocal agent_live
        if agent_live:
            agent_live = False
            removal["agent"] = remove_container(agent_name)
        if removal["broker"] is None:
            removal["broker"] = []
            removal["broker"] = broker_mod.stop_session(ctx)
            t.join(timeout=BROKER_JOIN_SECS)
            if t.is_alive():
                logger.warning("broker thread still busy %ds after its session "
                               "ended; it starts no new container", BROKER_JOIN_SECS)
            if not broker_mod.finish_ownership(ctx):
                logger.warning("the session's build output may still be root-owned "
                               "under %s", source_dir)

    # Read by the finally below, which also runs when setup fails before these
    # are resolved.
    cred_mode, secret, cred_id, secret_dir = "", "", "", None
    try:
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
        # The optimizer skill, if it is installed on this host. Derived from the same
        # config the benchmark loads replay_timing.py from, so the agent and the
        # replay gate can never end up on different versions of the methodology.
        # Empty per-run dir for the CLI's session transcript. Created before the
        # run so the bind mount does not have docker create it root-owned.
        transcripts_dir = session_dir / "transcripts"
        transcripts_dir.mkdir(parents=True, exist_ok=True)

        skill_dir, skill_name = _optimizer_skill_dir()
        cmd = build_agent_docker_command(
            image=AGENT_IMAGE, src=source_dir, profile=profile_dir, tools=tools,
            sock=sock_path, network=network, env=env,
            skill=skill_dir, skill_name=skill_name, harness=harness,
            transcripts=str(transcripts_dir),
            # Off the trial and profile cores (resolve_agent_cpus).
            cpus=agent_cpus,
            # So every exit path below can find and remove it.
            name=agent_name,
            labels={**launcher_labels(), LABEL_ROLE: "agent", **session_labels},
        )
        # Subscription OAuth: the credential is a FILE, mounted as a writable copy so
        # the CLI can refresh a short-lived access token without touching the host's.
        # Only the credential itself -- never ~/.claude, which holds prior-run
        # transcripts naming these bugs.
        insert = cmd.index("-w")
        # Fixed at launch: cswap may switch the host account while this session runs,
        # and the session keeps -- and the record names -- the credential it started
        # with.
        cred_mode, secret = egress.resolve_session_credential()
        cred_id = egress.credential_fingerprint(secret)
        logger.info("session credential: %s%s", cred_mode,
                    f" (id {cred_id})" if cred_id else "")
        if cred_mode != "oauth_file":
            # An API key, or a long-lived subscription token -- set explicitly,
            # mapped to the account cswap has active, or a setup-token in the host
            # file -- resolved anew for every session. None of them refreshes, so the
            # rotating store is never staged and ensure_fresh_host_credential (inside
            # stage_credentials) never forces a refresh that revokes running
            # sessions. stage_secret keeps it off every command line and out of the
            # results tree; secret_dir is removed in the finally below.
            secret_dir, secret_args = egress.stage_secret(cred_mode, secret)
            with _LIVE_SECRET_LOCK:
                _LIVE_SECRET_DIRS.add(str(secret_dir))
            cmd[insert:insert] = secret_args
            insert += len(secret_args)
        else:
            for spec in egress.stage_credentials(session_dir):
                cmd[insert:insert] = ["-v", spec]
                insert += 2
        # The prompt becomes the container's argv, which is readable from inside via
        # /proc/1/cmdline -- so it must carry nothing identifying about the target.
        # WebSearch/WebFetch execute SERVER-SIDE, inside the model API call, so the
        # egress proxy cannot see or block them: a search for the CVE leaves this
        # host looking exactly like ordinary traffic to api.anthropic.com. The whole
        # network allowlist is therefore bypassable by the agent simply asking the
        # model to look the bug up -- the CVE is public, ARVO-Meta is keyed by image
        # id, and upstream carries the fix commit. Refusing the tools at launch is
        # the only place this can be closed (leak-inventory item 5's sibling).
        cmd += ["claude", "-p", prompt, "--dangerously-skip-permissions",
                "--disallowedTools", "WebSearch", "WebFetch"]
        # Pin the model here or the CLI resolves its own account default inside
        # the container. This is the ONLY optimizer path that runs in production
        # (PHASE2_SANDBOX defaults on); the --model flag in phase2_setup lives on
        # the unconfined debug path, so without this the provenance record claims
        # a pin that never reached the CLI, and a model-comparison experiment
        # would silently run every arm on the same default.
        if model:
            cmd += ["--model", model]
        # Effort is a real CLI flag (low|medium|high|xhigh|max). Pin it: on GSO the
        # same model scored 33.33 at default and 41.18 at high, a swing bigger than
        # a model generation, so leaving it unset makes runs incomparable.
        if effort:
            cmd += ["--effort", effort]

        if launch.SHUTTING_DOWN.is_set():
            raise RuntimeError("the launcher is shutting down; not starting an "
                               "optimizer session")
        logger.info("launching sandboxed optimizer for %s (container %s)",
                    project, agent_name)
        agent_live = True
        timed_out = False
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            # Python killed the docker CLIENT; the container is still running.
            timed_out = True
        # Gone before anything reads what it wrote. A client that returned says
        # nothing about the container either (killed, or lost the daemon).
        _teardown()
        # What the caller must know before it touches the tree again: a
        # container still there may still be editing it (phase2_setup refuses
        # to go on; see AgentNotRemovedError).
        teardown = {
            "agent_container": agent_name,
            "agent_removed": bool(removal["agent"]),
            "broker_leftovers": list(removal["broker"] or []),
        }
        if timed_out:
            if teardown["agent_removed"]:
                logger.warning("sandboxed optimizer timed out after %ss; container "
                               "%s removed", timeout, agent_name)
            else:
                logger.error("sandboxed optimizer timed out after %ss and container "
                             "%s could NOT be confirmed removed", timeout, agent_name)
            return {
                "ok": False, "stdout": "", "stderr": "", "timed_out": True,
                "transcripts": sorted(str(f) for f in transcripts_dir.rglob("*.jsonl")),
                "model_requested": model or "",
                "effort_requested": effort or "",
                "agent_cpus": agent_cpus,
                "credential": cred_mode,
                "credential_id": cred_id,
                **teardown,
            }
        return {
            "ok": r.returncode == 0,
            # Saved verbatim by _save_agent_session_output and quoted in error
            # logs, so a credential the agent printed must not survive here.
            "stdout": egress.redact_text(r.stdout or "", secret),
            "stderr": egress.redact_text(r.stderr or "", secret),
            "timed_out": False,
            "transcripts": sorted(str(f) for f in transcripts_dir.rglob("*.jsonl")),
            "model_requested": model or "",
            "effort_requested": effort or "",
            "agent_cpus": agent_cpus,
            "credential": cred_mode,
            "credential_id": cred_id,
            **teardown,
        }
    finally:
        # Order matters. Until the agent is gone it can still write the tree, its
        # transcripts and its credential copy, and the broker can still build
        # for it; harvesting, removing the secret or redacting before that races
        # a live writer. An exception (KeyboardInterrupt included) inside
        # subprocess.run lands here with the container still up.
        #
        # And the secret goes whatever the teardown does: a Ctrl-C during a
        # slow stop_session must not leave a year-long token in TMPDIR.
        try:
            _teardown()
        finally:
            # Fold any token refresh the session performed back into the store.
            # Skipping this means re-seeding from a stale credential next time,
            # which under refresh-token rotation stops authenticating entirely.
            try:
                # Nothing to fold back under an API key or a long-lived token --
                # no credential was staged and none can have been refreshed.
                # Calling harvest anyway would re-seed the OAuth store from the
                # host on a run that deliberately is not using it.
                if cred_mode == "oauth_file":
                    egress.harvest_credentials(session_dir)
            except Exception as e:                   # noqa: BLE001
                logger.warning("credential harvest failed: %s", e)
            if secret_dir is not None:
                shutil.rmtree(secret_dir, ignore_errors=True)
                with _LIVE_SECRET_LOCK:
                    _LIVE_SECRET_DIRS.discard(str(secret_dir))
            if secret:
                # Wherever the session could have written: its transcripts,
                # broker log and egress log (session_dir) and the tree it edited.
                leaked = (egress.redact_tree(session_dir, secret)
                          + egress.redact_tree(source_dir, secret))
                if leaked:
                    logger.error(
                        "the session's credential (id %s) appeared in %d file(s); "
                        "redacted in place: %s", cred_id, len(leaked), leaked)
            try:
                os.unlink(sock_path)
            except OSError:
                pass
            try:
                os.rmdir(sock_dir)
            except OSError:
                pass
