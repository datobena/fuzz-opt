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
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib import cpu_ledger
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
    """
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
    )
    # Subscription OAuth: the credential is a FILE, mounted as a writable copy so
    # the CLI can refresh a short-lived access token without touching the host's.
    # Only the credential itself -- never ~/.claude, which holds prior-run
    # transcripts naming these bugs.
    insert = cmd.index("-w")
    key = egress.api_key()
    if key:
        # API key instead of the shared OAuth identity: no expiry, no refresh and
        # no rotation, so concurrent projects cannot invalidate each other's
        # credential mid-campaign (see egress.api_key). Passed by env rather than
        # mounted -- there is no file for the CLI to refresh, which is the point.
        cmd[insert:insert] = ["-e", f"{egress.API_KEY_ENV}={key}"]
        insert += 2
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
            "transcripts": sorted(str(f) for f in transcripts_dir.rglob("*.jsonl")),
            "model_requested": model or "",
            "effort_requested": effort or "",
            "agent_cpus": agent_cpus,
        }
    except subprocess.TimeoutExpired:
        logger.warning("sandboxed optimizer timed out after %ss", timeout)
        return {
            "ok": False, "stdout": "", "stderr": "", "timed_out": True,
            "transcripts": sorted(str(f) for f in transcripts_dir.rglob("*.jsonl")),
            "model_requested": model or "",
            "effort_requested": effort or "",
            "agent_cpus": agent_cpus,
        }
    finally:
        # Fold any token refresh the session performed back into the store.
        # Skipping this means re-seeding from a stale credential next time, which
        # under refresh-token rotation stops authenticating entirely.
        try:
            # Nothing to fold back under an API key -- no credential was staged
            # and none can have been refreshed. Calling harvest anyway would
            # re-seed the OAuth store from the host on a run that deliberately
            # is not using it.
            if not egress.api_key():
                egress.harvest_credentials(session_dir)
        except Exception as e:                       # noqa: BLE001
            logger.warning("credential harvest failed: %s", e)
        stop.set()
        try:
            os.unlink(sock_path)
        except OSError:
            pass
        try:
            os.rmdir(sock_dir)
        except OSError:
            pass
