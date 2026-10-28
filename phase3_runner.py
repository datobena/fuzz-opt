#!/usr/bin/env python3
"""Phase 3: Parallel Trial Execution (slot-based scheduler).

Runs fuzzing trials in Docker containers with CPU pinning,
monitors for crashes, and collects results.  Uses a slot-based
scheduler that fills freed CPU slots immediately instead of
waiting for entire waves to complete.
"""

import argparse
import json
import glob
import logging
import os
import random
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
from lib import afl, afl_launch, crash_classify, docker_util, provenance, swap_signal, trial_pause
from prework.build_image import image_tag

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class Trial:
    """Represents a single fuzzing trial."""
    project: str
    cve: str
    variant: str  # "baseline" or "optimized"
    trial_id: int
    seed: int
    # Manifest local_id, i.e. the ARVO id the prework image is tagged with. Carried
    # on the trial because the runtime image is derived from it and `cve` cannot
    # stand in: selinux's cve is "CVE-2021-36085" while its image is
    # bench-aflpp/selinux-arvo-42493454.
    local_id: int = 0
    # Per-trial binary directory. Set only for optimized trials under the
    # per-trial-optimizer design, where each trial runs a binary its own
    # optimizer produced. None means "use the shared <variant>/bin".
    bin_dir_override: str | None = None
    # The manifest entry this trial belongs to. Its "kind" selects the launch
    # flavour (FuzzBench vs ARVO, see lib/afl_launch.py) and the runtime image.
    # Optional: _trial_entry() falls back to a manifest lookup by project/cve.
    entry: dict | None = field(default=None, repr=False, compare=False)
    cpu: int = -1
    container_id: str = ""
    status: str = "pending"  # pending, running, completed, failed
    start_time: float = 0.0
    end_time: float = 0.0
    # The experiment this trial runs under. Set by _launch_container (the one
    # place every launch and relaunch goes through) and used ONLY to name the
    # docker container; results paths still come from get_trial_dirs.
    experiment_id: str = field(default="", compare=False)

    @property
    def name(self) -> str:
        return f"{self.project}-{self.cve}-{self.variant}-trial_{self.trial_id:02d}"

    @property
    def container_name(self) -> str:
        return trial_container_name(self.experiment_id, self.name)


# Docker accepts [a-zA-Z0-9][a-zA-Z0-9_.-]* for a container name.
_DOCKER_NAME_BAD = re.compile(r"[^a-zA-Z0-9_.-]")


def trial_container_name(experiment_id: str, trial_name: str) -> str:
    """Docker container name for one trial of one experiment.

    The experiment id is part of the name because _launch_container starts with
    `docker rm -f <name>`. Named by trial alone (bench_<project>-<cve>-<variant>-
    trial_NN), a second campaign on the same project -- a smoke run next to a
    24h run, or two EXP_PREFIXes -- force-removed the first campaign's live
    trials on its first launch, and that campaign's monitors then read the
    removal as the trial ending. Characters docker rejects become '_'.

    An empty experiment id gives the pre-fix name, which is also what
    tools/recover_online_harvest.py falls back to for campaigns launched
    before this change.
    """
    name = _DOCKER_NAME_BAD.sub("_", trial_name)
    exp = _DOCKER_NAME_BAD.sub("_", experiment_id or "")
    return f"bench_{exp}_{name}" if exp else f"bench_{name}"


def generate_trials(manifest: list[dict]) -> list[Trial]:
    """Generate all trial objects from manifest."""
    trials = []

    for entry in manifest:
        project = entry["project"]
        cve = entry["cve"]
        local_id = int(entry.get("local_id") or 0)

        for trial_id in range(config.NUM_TRIALS):
            # Baseline trial
            baseline_seed = (
                config.BASE_SEED
                + trial_id * config.SEED_MULTIPLIER
                + config.BASELINE_SEED_OFFSET
            )
            trials.append(Trial(
                project=project,
                cve=cve,
                local_id=local_id,
                entry=entry,
                variant="baseline",
                trial_id=trial_id,
                seed=baseline_seed,
            ))

            # Optimized trial
            optimized_seed = (
                config.BASE_SEED
                + trial_id * config.SEED_MULTIPLIER
                + config.OPTIMIZED_SEED_OFFSET
            )
            trials.append(Trial(
                project=project,
                cve=cve,
                local_id=local_id,
                entry=entry,
                variant="optimized",
                trial_id=trial_id,
                seed=optimized_seed,
            ))

    # Shuffle to interleave variants and avoid systematic bias
    rng = random.Random(config.SHUFFLE_SEED)
    rng.shuffle(trials)

    logger.info("Generated %d trials across %d CVEs", len(trials), len(manifest))
    return trials


def _trial_entry(trial) -> dict:
    """The manifest entry of a trial: the one it carries, else looked up by
    project/cve in config.MANIFEST_PATH. {} when neither is available, which
    selects the ARVO launch (the pre-existing behaviour)."""
    entry = getattr(trial, "entry", None)
    if entry:
        return entry
    try:
        with open(config.MANIFEST_PATH) as f:
            manifest = json.load(f)
    except (OSError, ValueError):
        return {}
    for e in manifest:
        if e.get("project") == trial.project and e.get("cve") == trial.cve:
            return e
    return {}


def get_trial_dirs(experiment_id: str, trial: Trial) -> dict[str, str]:
    """Get directory paths for a trial."""
    cve_dir = f"{trial.project}-{trial.cve}"
    base = os.path.join(
        config.RESULTS_DIR, experiment_id, cve_dir,
        trial.variant, f"trial_{trial.trial_id:02d}",
    )
    return {
        "base": base,
        "corpus": os.path.join(base, "corpus"),
        "crashes": os.path.join(base, "crashes"),
        # AFL owns its output tree (queue/, crashes/, fuzzer_stats, plot_data)
        # and needs it writable -- /out stays read-only.
        "afl_out": os.path.join(base, "afl_out"),
        # Live mutation capture (online arm only): the shim batches mutations
        # in memory and dumps here, so an optimization round reuses what the
        # trial already executed instead of re-fuzzing to regenerate it.
        "mutations": os.path.join(base, "mutations"),
        "log": os.path.join(base, "fuzzer.log"),
        "metadata": os.path.join(base, "metadata.json"),
        "crash_times": os.path.join(base, "crash_times.json"),
    }


def get_live_corpus_dir(experiment_id: str, trial: Trial) -> str:
    """Where the trial's ACCUMULATED corpus lives, for the online loop.

    Under libFuzzer this was the trial's corpus/ directory, which libFuzzer both
    read and appended to. AFL treats -i as read-only input and writes discovered
    inputs to <afl_out>/default/queue instead, so snapshotting corpus/ would hand
    the optimizer the unchanging SEED corpus every round -- the loop would look
    healthy while optimizing against inputs that never grow.
    """
    dirs = get_trial_dirs(experiment_id, trial)
    return os.path.join(dirs["afl_out"], "default", "queue")


def get_fuzzer_binary(experiment_id: str, trial: Trial) -> str:
    """Get path to the fuzzer binary for this trial."""
    cve_dir = f"{trial.project}-{trial.cve}"
    manifest_path = config.MANIFEST_PATH
    with open(manifest_path) as f:
        manifest = json.load(f)

    fuzz_target = ""
    for entry in manifest:
        if entry["project"] == trial.project and entry["cve"] == trial.cve:
            fuzz_target = entry["fuzz_target"]
            break

    if not fuzz_target:
        raise RuntimeError(f"No fuzz target found for {trial.project}/{trial.cve}")

    # Per-trial binary. Under the per-trial-optimizer design each optimized trial
    # owns its own binary (its own optimizer edited its own source tree), so the
    # trials no longer share optimized/bin. Baseline trials never set this and
    # keep the shared path, which is correct: they all run the same unmodified
    # build by construction.
    override = getattr(trial, "bin_dir_override", None)
    if override:
        return os.path.join(str(override), fuzz_target)

    return os.path.join(
        config.RESULTS_DIR, experiment_id, cve_dir,
        trial.variant, "bin", fuzz_target,
    )


def _dir_has_real_seeds(d: str) -> bool:
    """True if the dir has any non-fallback seed file (searched recursively)."""
    if not os.path.isdir(d):
        return False
    for _root, _dirs, files in os.walk(d):
        if any(not f.startswith("seed_fallback") for f in files):
            return True
    return False


def get_seed_corpus_dir(experiment_id: str, trial: Trial) -> str:
    """Path to the seed corpus phase-3 fuzzes from.

    Prefer ``merged/`` if it has real (non-fallback) seeds; otherwise use the
    bundled ``build/`` extraction (phase-2 unpacks the project's bundled
    <target>_seed_corpus.zip there) so fuzzing starts from the real bundled
    corpus, not the 1-byte fallback. Last resort: merged/ (fallback seed).
    """
    cve_dir = f"{trial.project}-{trial.cve}"
    base = os.path.join(config.RESULTS_DIR, experiment_id, cve_dir, "seed_corpus")
    merged = os.path.join(base, "merged")
    build = os.path.join(base, "build")
    if _dir_has_real_seeds(merged):
        return merged
    if _dir_has_real_seeds(build):
        return build
    return merged if os.path.isdir(merged) else base


def is_trial_completed(experiment_id: str, trial: Trial) -> bool:
    """Check if a trial has already been completed (for --resume)."""
    dirs = get_trial_dirs(experiment_id, trial)
    metadata_path = dirs["metadata"]
    if not os.path.exists(metadata_path):
        return False
    try:
        with open(metadata_path) as f:
            meta = json.load(f)
        return meta.get("duration_s", 0) > 0
    except (json.JSONDecodeError, KeyError):
        return False


def _ensure_executable(path: str) -> bool:
    """Make a fuzzer binary runnable, tolerating one produced inside a container.

    A bin dir written by an in-container `compile` through a bind mount is
    root-owned, and chmod by a non-root orchestrator raises EPERM even when the
    mode is already 0755 -- so an unconditional chmod kills the trial over a no-op.
    """
    try:
        os.chmod(path, 0o755)
        return True
    except OSError as e:
        if os.access(path, os.X_OK):
            return True
        logger.error("Fuzzer binary is not executable and chmod failed: %s", e)
        return False


def existing_afl_state(experiment_id: str, trial: Trial) -> Optional[str]:
    """First AFL-state path already in this trial's afl_out, or None.

    State = an instance dir (`default/`, or any -M/-S name) holding fuzzer_stats
    or queue/. That is what AFL_AUTORESUME=1 picks up: given one, afl-fuzz
    resumes the old queue and counters instead of starting from -i.
    """
    afl_out = get_trial_dirs(experiment_id, trial)["afl_out"]
    try:
        instances = sorted(os.listdir(afl_out))
    except OSError:
        return None
    for inst in instances:
        for marker in ("fuzzer_stats", "queue"):
            path = os.path.join(afl_out, inst, marker)
            if os.path.exists(path):
                return path
    return None


def stale_afl_state(experiment_id: str, trials) -> list[str]:
    """AFL state left in any of `trials`' afl_out dirs, logged as an error each.

    For the FRESH start of a campaign, checked before any trial starts. Every
    launch sets AFL_AUTORESUME=1 (relaunches need it) and start_trial wipes
    corpus/ and crashes/ but never afl_out/, so a reused experiment id silently
    resumed the previous campaign's queue, coverage and run_time: the new
    "trial" started hours in, on someone else's corpus, and nothing said so.
    Refusing is the only safe answer: wiping could destroy a result someone
    still wants, and resuming is exactly the silent failure.
    """
    found = []
    for t in trials:
        path = existing_afl_state(experiment_id, t)
        if path:
            logger.error(
                "Refusing to start %s: %s already holds AFL state from an "
                "earlier run of experiment %r, and AFL_AUTORESUME would resume "
                "it instead of starting fresh. Use a new experiment id "
                "(run_online_pertrial.sh dates them) or move the old results "
                "away.", t.name, path, experiment_id)
            found.append(path)
    return found


def start_trial(
    trial: Trial, experiment_id: str, duration: int = config.TRIAL_DURATION_SECS,
    *, allow_existing_afl_state: bool = False,
) -> bool:
    """Start a single fuzzing trial in a Docker container, from its seeds.

    A FRESH start: refuses (returns False) when afl_out already holds AFL
    state, see stale_afl_state. Relaunches inside a run go through
    relaunch_preserving_corpus, which resumes on purpose and never comes here.
    `allow_existing_afl_state` is for run_all_trials_slot(resume=True) only,
    which re-runs a trial interrupted in an earlier invocation.
    """
    dirs = get_trial_dirs(experiment_id, trial)

    if not allow_existing_afl_state and stale_afl_state(experiment_id, [trial]):
        trial.status = "failed"
        return False

    # Clean trial input/output dirs from any previous run, then recreate them.
    for d in [dirs["corpus"], dirs["crashes"]]:
        if os.path.isdir(d):
            shutil.rmtree(d)
        os.makedirs(d, exist_ok=True)

    # Copy seed corpus to trial corpus dir (recursively -- the bundled build/
    # extraction is nested, e.g. secilc/test/*.cil).
    seed_dir = get_seed_corpus_dir(experiment_id, trial)
    if os.path.isdir(seed_dir):
        for root, _dirs, files in os.walk(seed_dir):
            for fname in files:
                src = os.path.join(root, fname)
                if os.path.isfile(src):
                    shutil.copy2(src, dirs["corpus"])

    fuzzer_binary = get_fuzzer_binary(experiment_id, trial)
    if not os.path.isfile(fuzzer_binary):
        logger.error("Fuzzer binary not found: %s", fuzzer_binary)
        trial.status = "failed"
        return False

    if not _ensure_executable(fuzzer_binary):
        trial.status = "failed"
        return False

    bin_dir = os.path.dirname(fuzzer_binary)
    fuzz_target_name = os.path.basename(fuzzer_binary)

    # Determine the docker image. Shared with relaunch_preserving_corpus rather
    # than duplicated: the two lists had already drifted apart once, and a trial
    # that starts in one image and relaunches in another is not the same trial.
    docker_image = _resolve_trial_image(trial)
    if docker_image is None:
        logger.error("No suitable Docker image found for trial %s", trial.name)
        trial.status = "failed"
        return False

    trial._docker_image = docker_image
    trial._bin_dir = bin_dir
    trial._fuzz_target_name = fuzz_target_name
    trial._dirs = dirs

    if not _launch_container(trial, experiment_id, duration):
        return False
    return True


def _launch_container(
    trial: Trial, experiment_id: str, duration: int,
) -> bool:
    """Launch the Docker container for a trial."""
    # Name the container by experiment as well as trial (see
    # trial_container_name): the `docker rm -f` below must only ever hit this
    # campaign's own previous incarnation of this trial.
    trial.experiment_id = experiment_id
    container_name = trial.container_name
    docker_image = trial._docker_image
    bin_dir = trial._bin_dir
    fuzz_target_name = trial._fuzz_target_name
    dirs = trial._dirs
    seed = trial.seed

    # Experimental opt-in: callers attach a pause_control_dir to this trial.
    # Invalidate any old measurement before removing/relaunching its container.
    trial_pause.cancel_trial(trial, "trial relaunching")
    pause_dir = getattr(trial, "pause_control_dir", "")
    if pause_dir and getattr(trial, "pause_controller", None) is None:
        trial.pause_controller = trial_pause.TrialPause(pause_dir)

    # Clean up any leftover container with same name
    subprocess.run(
        ["docker", "rm", "-f", container_name],
        capture_output=True,
    )

    afl_out = dirs.get("afl_out") or os.path.join(dirs["base"], "afl_out")
    os.makedirs(afl_out, exist_ok=True)

    # AFL++ campaign. Differences from the libFuzzer command this replaces:
    #   -V <secs>   time-limited campaign; AFL keeps fuzzing PAST a crash, which
    #               is the whole point of the migration -- libFuzzer exited at
    #               the first one, truncating every trial at the measured event.
    #   -s <seed>   deterministic RNG, replacing libFuzzer's -seed
    #   -m none     ASAN reserves a huge address space; any memory cap kills it
    #   -t <ms>     fixed per-exec timeout (config.AFL_TIMEOUT_FLAG). No '+':
    #               since AFL++ 4.20c it auto-picks from the seeds with a 5 ms
    #               floor, which discarded 76% of bloaty's executions
    #   AFL_NO_AFFINITY  the container is already pinned via --cpuset-cpus, and
    #               AFL's own binding on top of that fails to find a free core
    #   ASAN/UBSAN_OPTIONS  FuzzBench's fuzz-run set (config.FUZZ_ASAN_OPTIONS);
    #               it carries abort_on_error=1, without which ASAN reports and
    #               exits cleanly and AFL never sees the crash
    # Live mutation capture. Only trials flagged for it carry the shim; see
    # capture_mutations_enabled(). The .so is compiled at launch rather than baked
    # into the prework image so the capture logic can change without rebuilding
    # four multi-GB images.
    capture = bool(getattr(trial, "capture_mutations", False))
    mutations_dir = dirs.get("mutations") or os.path.join(dirs["base"], "mutations")
    shim_src = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "mutation_dump_afl.c")
    if capture:
        os.makedirs(mutations_dir, exist_ok=True)

    # argv/env/cwd come from the one shared builder (lib/afl_launch.py): ARVO
    # trials get exactly the launch they always had, FuzzBench trials get
    # FuzzBench's aflplusplus runner launch (-w /out, its AFL_* env, -d,
    # -x afl++.dict, -c cmplog, options dict, trailing 2147483647).
    entry = _trial_entry(trial)
    try:
        launch = afl_launch.build_afl_launch(
            entry=entry, host_bin_dir=bin_dir, fuzz_target=fuzz_target_name,
            input_dir="/corpus", output_dir="/afl_out", duration=duration,
            seed=seed, autoresume=True, arvo_order=afl_launch.ARVO_ORDER_RUNNER)
    except ValueError as e:
        # FuzzBench semantics: a broken <t>.options dict= is fatal to the trial.
        logger.error("Cannot build afl-fuzz launch for %s: %s", trial.name, e)
        trial.status = "failed"
        return False
    trial._afl_launch = launch.record()

    cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "--privileged",
        "--cpuset-cpus", str(trial.cpu),
        "--memory", config.MEMORY_LIMIT,
        "--shm-size", config.DOCKER_SHM_SIZE,
        # A fuzzer's job is to crash the target, so the host's crash handling is
        # on the hot path. With kernel.core_pattern=core and RLIMIT_CORE
        # unlimited (the container default) every crash makes the kernel dump the
        # process image synchronously before it is reaped -- a per-crash I/O tax
        # paid by the fuzzer, and unbounded disk growth under afl_out. Nothing
        # here ever reads a core file: AFL takes the crash from waitpid and the
        # sanitizer report from stderr, both of which are unaffected.
        #
        # The related host setting is kernel.core_pattern. If it pipes to a
        # userspace handler (Ubuntu ships |/usr/share/apport/apport) the kernel
        # hands every crash to that helper instead: observed 2026-08-23 on
        # c-blosc2, whose 756 crashes in 10 min left 36 apport processes holding
        # ~8000% CPU while the 39 afl-fuzz processes shared 188%. AFL refuses to
        # start in that state; AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES below opts
        # out of the refusal, so the host must be set to `core` separately.
        "--ulimit", "core=0",
        # Run as the orchestrator's own uid. AFL creates <out>/default with mode
        # 0700, so as root it produces a tree the orchestrator cannot read -- and
        # every measurement this benchmark makes comes out of that tree: crash
        # files (time-to-bug), the queue (the corpus the optimizer snapshots), and
        # fuzzer_stats. It fails as silent absence, not as an error: no crashes
        # found, no corpus growth, a campaign that looks like it ran.
        "--user", f"{os.getuid()}:{os.getgid()}",
        # The prework image has no passwd entry for that uid, so HOME is unset and
        # anything that expands ~ writes to /.
        "-e", "HOME=/tmp",
        *launch.docker_env_args(),
        *launch.docker_workdir_args(),
        "-v", f"{bin_dir}:/out:ro",
        "-v", f"{dirs['corpus']}:/corpus",
        "-v", f"{afl_out}:/afl_out",
    ]
    if capture:
        cmd += [
            "-e", f"MUTATION_DUMP_DIR=/mutations",
            "-e", f"MUTATION_DUMP_CAP={int(getattr(config, 'PHASE2_MUTATION_CAP', 30000))}",
            "-e", f"MUTATION_DUMP_MODE={getattr(config, 'ONLINE_MUTATION_MODE', 'reservoir')}",
            "-e", f"MUTATION_DUMP_SEED={seed}",
            "-v", f"{mutations_dir}:/mutations",
            "-v", f"{shim_src}:/tmp/mutation_dump_afl.c:ro",
        ]
    if pause_dir:
        cmd += ["-v", f"{pause_dir}:/trial_pause",
                "-e", "TRIAL_PAUSE_DIR=/trial_pause"]
        if not capture:
            cmd += ["-v", f"{shim_src}:/tmp/mutation_dump_afl.c:ro"]
    cmd += [
        docker_image,
        "/bin/bash", "-c",
        (
            # Build the capture shim first when enabled. A failure here must NOT
            # take the trial down: losing mutation capture costs an optimization
            # round, losing the trial costs a data point.
            # The compiler must exist in the image: clang-18 in the ARVO prework
            # images, `clang` (clang-15) in the FuzzBench builder image.
            (f"{afl_launch.shim_compiler(entry)} -O2 -shared -fPIC "
             f"-o /tmp/mutdump.so /tmp/mutation_dump_afl.c 2>/tmp/shim_build.log "
             f"&& export AFL_CUSTOM_MUTATOR_LIBRARY=/tmp/mutdump.so "
             f"|| echo 'mutation shim build FAILED; continuing without capture';"
             if capture or pause_dir else "")
            + f" {launch.shell()}"
            f" 2>&1 | tee /tmp/fuzzer.log;"
            f" cp /tmp/fuzzer.log /afl_out/fuzzer.log 2>/dev/null || true"
        ),
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            logger.error(
                "Failed to start trial %s: %s", trial.name, result.stderr
            )
            trial.status = "failed"
            return False

        trial.container_id = result.stdout.strip()
        if pause_dir:
            trial.pause_controller.started(trial.container_id, deadline=time.time() + duration)
        trial.status = "running"
        trial.start_time = time.time()

        logger.info(
            "Started trial %s (container=%s, cpu=%d, seed=%d, duration=%ds)",
            trial.name, trial.container_id[:12], trial.cpu, seed, duration,
        )
        return True

    except subprocess.TimeoutExpired:
        logger.error("Timeout starting trial %s", trial.name)
        trial.status = "failed"
        return False


def _resolve_trial_image(trial: Trial) -> Optional[str]:
    """Pick the first locally-available runtime image for this trial.

    The pinned prework image comes FIRST. It is the only candidate that exists on
    a machine brought up by bootstrap_server.py: the gcr.io/oss-fuzz images below
    are byproducts of the legacy OSS-Fuzz path and are never pulled or built here,
    so without this entry every trial died with "No suitable Docker image found".

    It is also the correct image rather than merely an available one. The
    container only supplies the runtime around the binaries -- afl-fuzz and the
    target come from the bind-mounted bin dir -- and the prework image is the
    same clang-18 / AFL++ v5.02c environment those binaries were built in, which
    is what the mutation-capture shim is compiled against at launch.
    """
    candidate_images = []
    entry = _trial_entry(trial)
    if afl_launch.is_fuzzbench(entry):
        # FuzzBench builds are run in the image that built them
        # (fb-aflpp/<fuzzbench_dir>), never the old bench-aflpp/<p>-arvo-<id>
        # tag, which may still exist on the host from the pre-parity chain.
        from prework.prework_build import prework_image_for
        try:
            candidate_images.append(prework_image_for(entry))
        except (KeyError, ValueError) as e:
            logger.error("No prework image for fuzzbench trial %s: %s", trial.name, e)
            return None
        img = candidate_images[0]
        check = subprocess.run(["docker", "image", "inspect", img], capture_output=True)
        return img if check.returncode == 0 else None
    if trial.local_id:
        candidate_images.append(image_tag(trial.project, int(trial.local_id)))
    if trial.variant == "optimized":
        candidate_images.append(f"gcr.io/oss-fuzz/{trial.project}_opt")
    candidate_images.append(f"gcr.io/oss-fuzz/{trial.project}")
    candidate_images.append("gcr.io/oss-fuzz-base/base-runner")
    for img in candidate_images:
        check = subprocess.run(["docker", "image", "inspect", img], capture_output=True)
        if check.returncode == 0:
            return img
    return None


def relaunch_preserving_corpus(
    trial: Trial, experiment_id: str, duration: int,
) -> bool:
    """Relaunch a trial's container WITHOUT wiping its accumulated corpus/crashes.

    Unlike start_trial (which rmtree's corpus/ + crashes/ and re-copies the seed
    corpus), this keeps the grown corpus on disk and just relaunches the fuzzer against
    it with a new (remaining) time budget. Used by the online loop to hot-swap the
    binary: the orchestrator overwrites the shared optimized/bin/<target>, then each
    online trial is relaunched here against its own preserved corpus. The caller keeps
    trial.start_time stable so crash-elapsed timestamps stay cumulative across relaunches.
    """
    dirs = get_trial_dirs(experiment_id, trial)
    fuzzer_binary = get_fuzzer_binary(experiment_id, trial)
    if not os.path.isfile(fuzzer_binary):
        logger.error("Relaunch: fuzzer binary not found: %s", fuzzer_binary)
        trial.status = "failed"
        return False
    if not _ensure_executable(fuzzer_binary):
        trial.status = "failed"
        return False
    trial._bin_dir = os.path.dirname(fuzzer_binary)
    trial._fuzz_target_name = os.path.basename(fuzzer_binary)
    trial._dirs = dirs
    if getattr(trial, "_docker_image", None) is None:
        image = _resolve_trial_image(trial)
        if image is None:
            logger.error("Relaunch: no docker image for trial %s", trial.name)
            trial.status = "failed"
            return False
        trial._docker_image = image
    return _launch_container(trial, experiment_id, duration)


def _log_has_content(log_path: str, log_bytes: int, probe: int = 4096) -> bool:
    """Whether a trial log holds anything but whitespace.

    Only the head is read. The caller is the ghost-trial heuristic, which
    already requires a sub-5-second container, so any real output lands well
    inside the probe -- and reading the whole file would reintroduce the
    unbounded read this module just got rid of.
    """
    if not log_bytes:
        return False
    try:
        with open(log_path, "rb") as f:
            return bool(f.read(probe).strip())
    except OSError:
        return False


def _save_log_tail(container_id: str, dest: str, lines: int = 200) -> Optional[str]:
    """The last `lines` lines of a container's output, streamed to dest.

    Bounded by line count and never held in memory (see
    docker_util.write_container_logs). AFL's output goes through a pipe here,
    so it prints newline-terminated status lines, and its PROGRAM ABORT
    message -- the usual answer to "why did it die" -- is at the end.
    """
    try:
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "wb") as f:
            subprocess.run(["docker", "logs", "--tail", str(lines), container_id],
                           stdout=f, stderr=subprocess.STDOUT, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning("Could not save log tail of %s: %s", container_id[:12], e)
        return None
    return dest


def _early_death_record(trial: Trial, dirs: dict, n: int, *, at_s: float,
                        segment_s: float, remaining_s: float) -> dict:
    """What is known about a container that stopped before its budget.

    Taken BEFORE the relaunch, because the relaunch's `docker rm -f` destroys
    the container, and with it ExitCode, OOMKilled and the log. Docker's exit
    code alone says little: the container's shell ends in `cp ... || true`, so
    an AFL abort exits 0 and only a kill (137, OOM) shows up there.
    """
    state = docker_util.inspect_container_state(trial.container_id)
    if not isinstance(state, dict):
        state = {}
    tail = _save_log_tail(trial.container_id,
                          os.path.join(dirs["base"], f"early_death_{n:02d}.log"))
    return {
        "n": n,
        "container_id": (trial.container_id or "")[:12],
        "at_s": round(at_s, 1),            # since the trial's first launch
        "segment_s": round(segment_s, 1),  # how long this container was up
        "remaining_s": int(remaining_s),
        "exit_code": state.get("ExitCode"),
        "oom_killed": state.get("OOMKilled"),
        "docker_error": state.get("Error") or state.get("error") or None,
        "started_at": state.get("StartedAt"),
        "finished_at": state.get("FinishedAt"),
        "log_tail": tail,
        "action": None,
    }


def monitor_trial(
    trial: Trial, experiment_id: str,
    duration: int = config.TRIAL_DURATION_SECS,
) -> dict:
    """Monitor a running trial until its budget is spent, then harvest it.

    Used for the baseline arm of the online loop and for both arms of the
    plain (offline) phase 3. Three ways a container comes back up mid-trial,
    all through relaunch_preserving_corpus (same afl_out, AFL_AUTORESUME, the
    REMAINING budget as -V, trial start kept fixed so crash times stay
    cumulative):

      early death   the container stopped with more than
                    TRIAL_RELAUNCH_MIN_REMAINING_SECS of budget left. Every death
                    is recorded in metadata["early_deaths"] (time, exit code,
                    OOMKilled, docker error, a log tail). After
                    TRIAL_RELAUNCH_MAX_QUICK_DEATHS consecutive deaths within
                    TRIAL_RELAUNCH_QUICK_DEATH_SECS of launch it is a crash loop:
                    the trial is finalized short (end_reason "crash_loop").
      scheduled     BASELINE_RESTART_INTERVAL_SECS cadence (restart_arm only).
      mirrored      BASELINE_RESTART_MIRROR_SWAPS: once per hot swap of the
                    PAIRED optimized trial (per-trial mode) or of the shared
                    binary (legacy mode); see lib/swap_signal.

    Until early deaths were handled here, this docstring already promised a
    restart while the loop simply finalized: a baseline that died at 3h was
    scored as a 3h trial against optimized trials that the online monitor
    relaunched to the full 24h.
    """
    dirs = get_trial_dirs(experiment_id, trial)
    afl_out = dirs.get("afl_out") or os.path.join(dirs["base"], "afl_out")
    crashes_dir = os.path.join(afl_out, "default", "crashes")
    crash_times = []
    seen_crashes = set()
    overall_start = trial.start_time

    def scan_crashes():
        """Collect new AFL crash artifacts.

        Timing comes from the FILENAME (`time:<ms>`), not from when the poll
        happened to notice the file. Under libFuzzer the trial ended at the
        first crash so poll latency was bounded; AFL keeps running and can
        produce many crashes between polls, which would otherwise all be
        stamped with the same observation time.

        Every artifact is recorded as crash_type "crash"; deciding which one is
        the TARGET bug requires replaying it (see lib/afl_triage.py) and is
        deliberately not guessed from the filename.
        """
        for entry in afl.collect_crashes(crashes_dir):
            fname = entry["artifact"]
            if fname in seen_crashes:
                continue
            seen_crashes.add(fname)
            crash_times.append({
                "timestamp_s": entry["timestamp_s"],
                "artifact": fname,
                "crash_type": "crash",
            })
            logger.info(
                "Trial %s: crash at %.1fs (%s)",
                trial.name, entry["timestamp_s"], fname,
            )

    # Ramp the poll interval: short cadence during the first 30 seconds so
    # startup failures (ghost trials that die in <1s) are noticed promptly
    # and don't get their wall duration rounded up by a full 10s poll.
    # Periodic restart of the BASELINE arm, resuming from its own queue.
    #
    # The online arm is stopped and relaunched at every accepted fold; the
    # baseline never was, so "restarted" and "optimized" were confounded. A
    # restart is not free: AFL's in-memory dedup bitmap is not restored on
    # resume (which is why the online arm's raw crash-artifact counts inflate in
    # proportion to its swap count), and the queue is re-calibrated on start.
    # Restarting the baseline on a fixed cadence puts that cost on both arms.
    #
    # 0 disables. Note the cadence is independent of how often the online arm
    # actually swaps -- at 3h that is 8 restarts against the 2-3 an accepted-fold
    # schedule produced in b5, so the baseline takes MORE restart penalty, not
    # the same. That is a deliberate choice by the operator, not an oversight.
    restart_every = int(getattr(config, "BASELINE_RESTART_INTERVAL_SECS", 0) or 0)
    restart_arm = str(getattr(config, "BASELINE_RESTART_ARM", "baseline"))
    # Mirroring the online arm's swaps takes precedence over the fixed cadence:
    # the cadence cannot match a swap count that is not known in advance, and at
    # 3h it gave the b6 baseline 7 restarts against the online arm's 2.
    mirror_swaps = bool(getattr(config, "BASELINE_RESTART_MIRROR_SWAPS", False))
    restarts_done = 0
    next_restart = (overall_start + restart_every) if (restart_every and not mirror_swaps) else None
    # Start level with whatever has already happened, so a trial that begins
    # after a swap does not immediately fire a backlog of restarts.
    #
    # generation_for(trial_id), not the global generation: in per-trial mode
    # baseline trial k mirrors only optimized trial k's swaps (its seed pair);
    # in the legacy shared-binary mode it counts every shared swap, as before.
    seen_generation = (swap_signal.SIGNAL.generation_for(trial.trial_id)
                       if mirror_swaps else 0)

    # Early-death relaunch (see the docstring). Below min_left a relaunch would
    # spend its whole budget re-calibrating the queue, and the container ending
    # there is AFL's own -V expiring, i.e. the normal end of a trial.
    relaunch_min_left = float(getattr(config, "TRIAL_RELAUNCH_MIN_REMAINING_SECS", 60))
    quick_death_s = float(getattr(config, "TRIAL_RELAUNCH_QUICK_DEATH_SECS", 60))
    # 0 turns early-death relaunch off (the first death finalizes the trial).
    max_quick_deaths = int(getattr(config, "TRIAL_RELAUNCH_MAX_QUICK_DEATHS", 3))
    deaths: list[dict] = []
    quick_deaths = 0
    # When the CURRENT container was launched; trial.start_time is moved by
    # every relaunch, overall_start is not.
    segment_start = trial.start_time
    end_reason = "budget"

    while True:
        if not docker_util.container_is_running(trial.container_id):
            scan_crashes()
            now = time.time()
            remaining = duration - (now - overall_start)
            if remaining <= relaunch_min_left:
                break
            death = _early_death_record(trial, dirs, len(deaths) + 1,
                                        at_s=now - overall_start,
                                        segment_s=now - segment_start,
                                        remaining_s=remaining)
            quick_deaths = quick_deaths + 1 if death["segment_s"] < quick_death_s else 0
            crash_loop = 0 < max_quick_deaths <= quick_deaths
            if crash_loop or max_quick_deaths <= 0:
                death["action"] = "gave_up"
                deaths.append(death)
                end_reason = "crash_loop" if crash_loop else "died"
                logger.error(
                    "Trial %s: container died at %.2fh (exit %s, OOMKilled=%s; "
                    "%d death(s) in a row within %.0fs of launch) -- %s. "
                    "Finalized short with %ds of budget unused", trial.name,
                    death["at_s"] / 3600, death["exit_code"], death["oom_killed"],
                    quick_deaths, quick_death_s,
                    "crash loop, NOT relaunching" if crash_loop
                    else "early-death relaunch is disabled", int(remaining))
                break
            logger.warning(
                "Trial %s: container died early at %.2fh after %.0fs up (exit %s, "
                "OOMKilled=%s); relaunching on its own queue with %ds left "
                "(early death #%d)", trial.name, death["at_s"] / 3600,
                death["segment_s"], death["exit_code"], death["oom_killed"],
                int(remaining), death["n"])
            ok = relaunch_preserving_corpus(trial, experiment_id, int(remaining))
            death["action"] = "relaunched" if ok else "relaunch_failed"
            deaths.append(death)
            if not ok:
                end_reason = "relaunch_failed"
                logger.error("Trial %s: relaunch after early death FAILED; "
                             "finalizing short", trial.name)
                break
            segment_start = trial.start_time
            continue
        scan_crashes()
        now = time.time()
        elapsed_since_start = now - overall_start
        # A container that outlived the quick-death window breaks the streak.
        if quick_deaths and now - segment_start >= quick_death_s:
            quick_deaths = 0

        # Leave >5 min of budget, else a restart costs more than it measures.
        restart_due = False
        pending_generation = seen_generation
        if trial.variant == restart_arm and (duration - elapsed_since_start) > 300:
            if mirror_swaps:
                pending_generation = swap_signal.SIGNAL.generation_for(trial.trial_id)
                restart_due = pending_generation > seen_generation
            elif next_restart and now >= next_restart:
                restart_due = True

        if restart_due:
            remaining = int(duration - elapsed_since_start)
            logger.info(
                "Trial %s: %s restart #%d at %.2fh (resuming its queue, "
                "%ds budget left)", trial.name,
                f"swap-mirrored (gen {pending_generation})" if mirror_swaps
                else "scheduled",
                restarts_done + 1, elapsed_since_start / 3600, remaining)
            docker_util.remove_container(trial.container_id)
            if relaunch_preserving_corpus(trial, experiment_id, remaining):
                restarts_done += 1
                segment_start = trial.start_time
                if mirror_swaps:
                    # Advance to the generation we OBSERVED, not +1: if several
                    # swaps landed inside one poll the baseline restarts once,
                    # matching what a single relaunch can mirror.
                    seen_generation = pending_generation
                else:
                    next_restart = now + restart_every
            else:
                logger.error(
                    "Trial %s: scheduled restart FAILED; not retrying, the trial "
                    "is left stopped and will be harvested short", trial.name)
                end_reason = "restart_failed"
                break
            continue

        # Measured from the current container's launch, so a relaunch that dies
        # at once is noticed within 2s too, not only the first launch.
        poll_interval = 2 if (now - segment_start) < 30 else 10
        time.sleep(poll_interval)

    # Final scan after container exits
    scan_crashes()

    # The LAST container's lifetime. It is the whole trial only if nothing was
    # relaunched; see duration_s below.
    actual_duration = docker_util.get_container_duration_seconds(trial.container_id)

    # Collect logs. Streamed to disk, never held in memory -- see
    # docker_util.write_container_logs for what the buffered version cost.
    log_path = dirs["log"]
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    log_bytes = docker_util.write_container_logs(trial.container_id, log_path)

    # Capture post-exit docker state BEFORE removing the container.
    # This is the only place ExitCode / OOMKilled / Error are recoverable;
    # docker rm -f destroys them. Needed to diagnose ghost trials (<1s exits
    # with empty fuzzer.log) where stdout/stderr capture yields nothing.
    inspect_state = docker_util.inspect_container_state(trial.container_id)

    # Clean up container
    docker_util.remove_container(trial.container_id)

    trial.end_time = time.time()
    trial.status = "completed"

    final_stats = parse_fuzzer_stats(afl_out)

    observed_duration = round(trial.end_time - overall_start, 2)
    if not actual_duration or actual_duration <= 0:
        actual_duration = observed_duration
    last_container_s = actual_duration

    # Once the trial has been relaunched (early death, scheduled or mirrored
    # restart) the last container covers only the final segment, while AFL's
    # execs_done carries across resumes. Dividing one by the other overstated
    # exec/s by the share of the trial before the last relaunch -- 6x for a
    # death relaunched at 20h of 24h. Use wall time since the first launch,
    # which is what the online arm's _finalize_online_trial records too.
    death_relaunches = sum(1 for d in deaths if d.get("action") == "relaunched")
    relaunched = bool(restarts_done or death_relaunches)
    if relaunched:
        actual_duration = observed_duration

    if actual_duration > 0 and final_stats.get("total_execs"):
        final_stats["final_exec_s"] = round(
            float(final_stats["total_execs"]) / float(actual_duration), 2
        )

    with open(dirs["crash_times"], "w") as f:
        json.dump(crash_times, f, indent=2)

    # Persist raw docker state for post-mortem diagnosis.
    state_path = os.path.join(dirs["base"], "docker_state.json")
    try:
        with open(state_path, "w") as f:
            json.dump(inspect_state, f, indent=2)
    except OSError as e:
        logger.warning(
            "Failed to write docker_state.json for %s: %s", trial.name, e
        )

    # Heuristic flag: a "ghost" startup failure produces no log output, no
    # stats, and exits in under 5 seconds. Helps downstream reporting skip
    # these so they don't pollute baseline/optimized success ratios. Judged on
    # the last container, so a ghost relaunched into a crash loop still counts.
    failed_start = (
        last_container_s is not None
        and last_container_s > 0
        and last_container_s < 5
        and not final_stats
        and not crash_times
        and not _log_has_content(log_path, log_bytes)
    )

    metadata = {
        "trial_name": trial.name,
        "variant": trial.variant,
        "trial_id": trial.trial_id,
        "seed": trial.seed,
        "cpu": trial.cpu,
        "start_time": overall_start,
        "end_time": trial.end_time,
        "duration_s": actual_duration,
        "wall_duration_s": observed_duration,
        "duration_seconds": duration,
        "num_crashes": len(crash_times),
        # num_crashes counts ALL artifacts (slow-units/timeouts/OOMs too);
        # found_bug is the canonical "did the target bug reproduce?" flag.
        "found_bug": crash_classify.trial_found_bug(crash_times, duration),
        "time_to_bug_s": crash_classify.trial_time_to_bug(crash_times, duration),
        "final_stats": final_stats,
        "failed_start": failed_start,
        # What the run actually ran with, recorded while it ran.
        "sanitizer_options": _trial_env_record(trial),
        "toolchain": _trial_toolchain(trial),
        "crash_classification": _classify_trial_crashes(trial, crash_times, dirs),
        "failed_start_detail": failed_start,
        "docker_exit_code": (
            inspect_state.get("ExitCode")
            if isinstance(inspect_state, dict) else None
        ),
        "docker_oom_killed": (
            inspect_state.get("OOMKilled")
            if isinstance(inspect_state, dict) else None
        ),
        # Every early death in order, with what was done about it: "relaunched",
        # "gave_up" (crash loop) or "relaunch_failed". [] = no container of this
        # trial ever stopped before its budget except by schedule.
        "early_deaths": deaths,
        "death_relaunches": death_relaunches,
        "scheduled_restarts": restarts_done,
        # budget | crash_loop | relaunch_failed | restart_failed | died (relaunch
        # disabled). Anything but "budget" means the trial was harvested short
        # of duration_seconds.
        "end_reason": end_reason,
        "duration_source": ("wall_since_first_launch" if relaunched
                            else "container"),
    }
    with open(dirs["metadata"], "w") as f:
        json.dump(metadata, f, indent=2)

    logger.info(
        "Trial %s completed (%s): %d crashes in %.1f seconds, %d early "
        "death(s), %d scheduled restart(s)",
        trial.name, end_reason, len(crash_times), actual_duration,
        len(deaths), restarts_done,
    )

    return {
        "trial": trial.name,
        "crash_times": crash_times,
        "final_stats": final_stats,
        "max_total_time": duration,
    }


# AFL++ artifact naming: `id:000000,sig:06,src:000344,time:517045,...`. Both
# fields are required so a stray file in crashes/ (AFL's own README.txt) is not
# promoted to a crash.
_AFL_ARTIFACT_RE = re.compile(r"^id:\d+,.*\bsig:\d+")


def _classify_trial_crashes(trial, crash_times, dirs) -> dict:
    """Replay crash artifacts in timestamp order and record what they really are.

    crash_type in crash_times comes from classify_crash(), which reads the
    FILENAME -- every AFL `id:...` artifact is labelled "crash" without the file
    ever being executed. That is how 67% linkage artifacts and 31% assertion
    aborts all became "the target bug" for assimp, and why its recorded
    time_to_bug_s (0.19-4.8s) pointed the opposite way from the truth (10.7s
    baseline vs 103.9s optimized).

    Ordered by timestamp and capped, so the FIRST genuine sanitizer crash -- the
    only one time-to-bug needs -- is found without replaying tens of thousands of
    artifacts. Pinned to a reserved core so it never competes with a live fuzzer.
    Annotates crash_times in place and returns a summary.
    """
    if not (getattr(config, "PROVENANCE_CLASSIFY_CRASHES", True) and crash_times):
        return {}
    bin_dir = getattr(trial, "_bin_dir", None)
    image = getattr(trial, "_docker_image", None)
    target = getattr(trial, "_fuzz_target_name", None)
    if not (bin_dir and image and target):
        return {"skipped": "binary/image/target unknown"}
    crashes_dir = os.path.join(
        dirs.get("afl_out") or os.path.join(dirs["base"], "afl_out"), "default")
    cap = int(getattr(config, "PROVENANCE_CLASSIFY_MAX", 400))
    opts = getattr(config, "PROVENANCE_CLASSIFY_ASAN_OPTIONS",
                   "detect_leaks=0:alloc_dealloc_mismatch=0")
    # Reserved cores only (0..RESERVED_CORES-1): trials own everything above.
    cpu = max(int(getattr(config, "RESERVED_CORES", 1)) - 1, 0)
    counts = {"sanitizer": 0, "assert": 0, "abort": 0, "nocrash": 0, "infra": 0}
    # classify_artifact's UBSan default; recorded so the provenance names both.
    ubsan_opts = config.REPLAY_UBSAN_OPTIONS + ":symbolize=1"
    first_real = None
    ordered = sorted(crash_times, key=lambda e: e.get("timestamp_s") or 0)
    for entry in ordered[:cap]:
        art = next(iter(glob.glob(os.path.join(
            crashes_dir, "crashes*", glob.escape(entry.get("artifact", ""))))), None)
        if not art:
            continue
        res = provenance.classify_artifact(image, bin_dir, target, art,
                                           cpu=cpu, asan_options=opts,
                                           ubsan_options=ubsan_opts)
        entry["classified"] = res["class"]
        entry["sanitizer_kind"] = res["kind"]
        entry["crash_frame"] = res["frame"]
        counts[res["class"]] = counts.get(res["class"], 0) + 1
        if res["class"] == "sanitizer" and first_real is None:
            first_real = entry.get("timestamp_s")
    return {
        "classified": sum(counts.values()),
        "artifacts_total": len(crash_times),
        "capped_at": cap,
        "counts": counts,
        "asan_options": opts,
        "ubsan_options": ubsan_opts,
        # The honest time-to-bug: first artifact that is actually a sanitizer
        # crash, not merely the first file AFL wrote into crashes/.
        "time_to_first_sanitizer_crash_s": first_real,
    }


def _trial_env_record(trial=None) -> dict:
    """The sanitizer/AFL environment a trial actually ran under.

    ARVO's runner sets alloc_dealloc_mismatch=0 and this benchmark did not; that
    one difference accounts for 5845 assimp artifacts. It belongs next to the
    results it shaped, not only in the source that produced them.

    For a FuzzBench trial the record is the full launch (argv, env, cwd, which
    optional -x/-c flags were present) as built by lib/afl_launch, since that
    set varies per benchmark and per build.
    """
    launch = getattr(trial, "_afl_launch", None) if trial is not None else None
    if launch and launch.get("kind") == "fuzzbench":
        env = launch.get("env") or {}
        return {
            "ASAN_OPTIONS": env.get("ASAN_OPTIONS", config.FUZZ_ASAN_OPTIONS),
            "UBSAN_OPTIONS": env.get("UBSAN_OPTIONS", config.FUZZ_UBSAN_OPTIONS),
            "AFL_ENV": {k: v for k, v in env.items() if k.startswith("AFL_")},
            "afl_flags": launch.get("flags") or {},
            "launch": launch,
        }
    return {
        "ASAN_OPTIONS": config.FUZZ_ASAN_OPTIONS,
        "UBSAN_OPTIONS": config.FUZZ_UBSAN_OPTIONS,
        "AFL_ENV": {
            "AFL_NO_AFFINITY": "1", "AFL_SKIP_CPUFREQ": "1",
            "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1", "AFL_AUTORESUME": "1",
        },
        "afl_flags": {"-m": "none", "-t": config.AFL_TIMEOUT_FLAG},
    }


def _trial_toolchain(trial) -> dict:
    """Compiler + C++ runtime linkage of the binary this trial actually ran."""
    bin_dir = getattr(trial, "_bin_dir", None)
    image = getattr(trial, "_docker_image", None)
    target = getattr(trial, "_fuzz_target_name", None)
    if not (bin_dir and image and target):
        return {}
    try:
        fp = provenance.binary_fingerprint(image, bin_dir, target)
    except Exception as e:  # noqa: BLE001 - provenance must not kill a trial
        return {"error": f"{type(e).__name__}: {e}"}
    entry = _trial_entry(trial)
    if afl_launch.is_fuzzbench(entry) and isinstance(fp, dict):
        # binary_fingerprint reads CFLAGS from the image ENV, but FuzzBench sets
        # the real flags inside fuzzer.build(); record what actually applied.
        fp = dict(fp)
        fp["fuzzbench"] = {
            "benchmark_type": entry.get("type"),
            "fuzzbench_dir": entry.get("fuzzbench_dir"),
            "opt_level": afl_launch.fuzzbench_opt_level(entry),
            "build_opt_level_applied": False,
            "cmplog_present": os.path.isfile(os.path.join(bin_dir, "cmplog", target)),
            "aflpp_dict_present": os.path.isfile(os.path.join(bin_dir, "afl++.dict")),
        }
    return fp


def classify_crash(crash_path: str) -> str:
    """Try to classify a crash artifact type.

    Handles BOTH naming schemes. The prefix tests below are libFuzzer's; AFL++
    names every artifact `id:000000,sig:06,src:...,time:...` and puts timeouts
    in a separate hangs/ directory, so anything AFL writes into crashes/ is a
    real signal-terminated crash.

    Without the AFL branch this returned "unknown" for every AFL artifact, and
    crash_classify.is_target_bug_find drops anything whose crash_type is not
    "crash". Only the ONLINE arm calls this (phase3_online); the baseline arm
    hardcodes "crash". So the two arms disagreed on identical artifacts and the
    optimized arm scored found_bug=False on all 9 trials of b3r2 while holding
    126 sanitizer aborts -- the same arm-asymmetry class as the crashes-dir bug
    already documented in phase3_online._monitor_online_trial.
    """
    fname = os.path.basename(crash_path)
    if fname.startswith("crash-"):
        return "crash"
    if fname.startswith("oom-"):
        return "oom"
    if fname.startswith("timeout-"):
        return "timeout"
    if _AFL_ARTIFACT_RE.match(fname):
        return "crash"
    return "unknown"


def parse_fuzzer_stats(afl_out_dir: str) -> dict:
    """Read AFL++ campaign statistics from its output tree.

    Replaces the libFuzzer log-scraping this used to do. AFL writes structured
    files, so nothing has to be recovered from console text:
      fuzzer_stats  final counters (execs_done, execs_per_sec, edges_found)
      plot_data     the whole time series, which also gives coverage-over-time
                    for free and retires tools/run_covtime.py's ZIP-mtime method.

    Keys are normalized to the names phase 4 already consumes.
    """
    stats: dict = {}
    default_dir = os.path.join(afl_out_dir, "default")

    stats_path = os.path.join(default_dir, "fuzzer_stats")
    if os.path.isfile(stats_path):
        with open(stats_path, errors="replace") as f:
            raw = afl.parse_fuzzer_stats(f.read())
        stats.update({
            "total_execs": raw.get("execs_done"),
            "final_exec_s": raw.get("execs_per_sec"),
            "edges_found": raw.get("edges_found"),
            "corpus_size": raw.get("corpus_count"),
            "saved_crashes": raw.get("saved_crashes"),
            "run_time": raw.get("run_time"),
        })

    plot_path = os.path.join(default_dir, "plot_data")
    if os.path.isfile(plot_path):
        with open(plot_path, errors="replace") as f:
            rows = afl.parse_plot_data(f.read())
        if rows:
            stats["coverage_series"] = [
                {"t": r.get("relative_time"), "edges": r.get("edges_found")}
                for r in rows
            ]

    return {k: v for k, v in stats.items() if v is not None}


def save_partial_results(completed: list[dict], experiment_id: str):
    """Write intermediate results to disk."""
    results_path = os.path.join(
        config.RESULTS_DIR, experiment_id, "trial_results.json"
    )
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, "w") as f:
        json.dump(completed, f, indent=2)


def collect_all_trial_results(experiment_id: str) -> list[dict]:
    """Rebuild results from trial directories on disk.

    Useful for --resume or when in-memory results are incomplete.
    """
    results = []
    exp_dir = os.path.join(config.RESULTS_DIR, experiment_id)

    if not os.path.isdir(exp_dir):
        return results

    for cve_dir_name in sorted(os.listdir(exp_dir)):
        cve_path = os.path.join(exp_dir, cve_dir_name)
        if not os.path.isdir(cve_path) or cve_dir_name in ("report",):
            continue

        for variant in ["baseline", "optimized"]:
            variant_dir = os.path.join(cve_path, variant)
            if not os.path.isdir(variant_dir):
                continue

            for trial_name in sorted(os.listdir(variant_dir)):
                if not trial_name.startswith("trial_"):
                    continue

                trial_dir = os.path.join(variant_dir, trial_name)
                metadata_path = os.path.join(trial_dir, "metadata.json")
                crash_times_path = os.path.join(trial_dir, "crash_times.json")

                if not os.path.exists(metadata_path):
                    continue

                try:
                    with open(metadata_path) as f:
                        metadata = json.load(f)
                except (json.JSONDecodeError, OSError):
                    continue

                crash_times = []
                if os.path.exists(crash_times_path):
                    try:
                        with open(crash_times_path) as f:
                            crash_times = json.load(f)
                    except (json.JSONDecodeError, OSError):
                        pass

                results.append({
                    "trial": metadata.get("trial_name", trial_name),
                    "crash_times": crash_times,
                    "final_stats": metadata.get("final_stats", {}),
                    # cutoff for the canonical bug-find classifier (excludes the
                    # end-of-run boundary artifact); see lib/crash_classify.py
                    "max_total_time": (metadata.get("duration_seconds")
                                       or metadata.get("max_total_time")),
                })

    return results


def log_progress(
    running: dict, completed: list[dict], pending: deque,
    manifest: list[dict], start_time: float,
):
    """Log progress summary."""
    elapsed = time.time() - start_time
    hours = int(elapsed // 3600)
    mins = int((elapsed % 3600) // 60)
    secs = int(elapsed % 60)

    total = len(running) + len(completed) + len(pending)
    logger.info(
        "[%02d:%02d:%02d] Progress: %d/%d complete, %d running, %d pending",
        hours, mins, secs,
        len(completed), total, len(running), len(pending),
    )

    # Per-project summary
    project_stats = {}
    for entry in manifest:
        key = entry["project"]
        if key not in project_stats:
            project_stats[key] = {
                "bl_found": 0, "bl_total": 0,
                "opt_found": 0, "opt_total": 0,
            }

    for result in completed:
        trial_name = result.get("trial", "")
        # Canonical bug-find definition (real sanitizer crash before the cutoff),
        # NOT bool(crash_times) which also counts slow-units/timeouts/OOMs/boundary.
        has_crash = crash_classify.trial_found_bug(
            result.get("crash_times"), result.get("max_total_time"))

        # Parse project and variant from trial name
        # Format: project-CVE-XXXX-XXXXX-variant-trial_NN
        parts = trial_name.rsplit("-", 2)
        if len(parts) >= 2:
            variant = parts[-2] if "trial" in parts[-1] else ""
            # Extract project name (everything before the CVE)
            for entry in manifest:
                if entry["project"] in trial_name and entry["cve"] in trial_name:
                    key = entry["project"]
                    if key in project_stats:
                        if "baseline" in trial_name:
                            project_stats[key]["bl_total"] += 1
                            if has_crash:
                                project_stats[key]["bl_found"] += 1
                        elif "optimized" in trial_name:
                            project_stats[key]["opt_total"] += 1
                            if has_crash:
                                project_stats[key]["opt_found"] += 1
                    break

    header = f"{'Project':<16} | {'BL found':>10} | {'OPT found':>10}"
    logger.info(header)
    logger.info("-" * len(header))
    for proj, stats in project_stats.items():
        bl = f"{stats['bl_found']}/{stats['bl_total']}" if stats['bl_total'] else "—"
        opt = f"{stats['opt_found']}/{stats['opt_total']}" if stats['opt_total'] else "—"
        logger.info(f"{proj:<16} | {bl:>10} | {opt:>10}")


def run_all_trials_slot(
    manifest: list[dict],
    experiment_id: str,
    duration: int = config.TRIAL_DURATION_SECS,
    max_parallel: int = config.USABLE_CORES,
    resume: bool = False,
) -> list[dict]:
    """Run all trials using slot-based scheduling.

    Instead of running in waves, immediately fills freed CPU slots
    with pending trials for better utilization.
    """
    all_trials = generate_trials(manifest)

    # Filter out already-completed trials if resuming
    if resume:
        remaining = []
        skipped = 0
        for trial in all_trials:
            if is_trial_completed(experiment_id, trial):
                skipped += 1
            else:
                remaining.append(trial)
        logger.info("Resume: skipping %d completed trials, %d remaining",
                     skipped, len(remaining))
        all_trials = remaining

    if not all_trials:
        logger.info("No trials to run")
        return collect_all_trial_results(experiment_id)

    # A fresh campaign must not inherit AFL state (see stale_afl_state). Checked
    # for every trial BEFORE any starts, so a reused id fails whole rather than
    # half the trials starting fresh and half resuming. --resume re-runs the
    # trials an interrupted invocation left incomplete, so it is let through.
    if not resume:
        stale = stale_afl_state(experiment_id, all_trials)
        if stale:
            raise RuntimeError(
                f"experiment {experiment_id!r}: {len(stale)} trial afl_out dir(s) "
                f"already hold AFL state (first: {stale[0]}); refusing to start "
                f"a fresh campaign on top of them")

    pending = deque(all_trials)
    running = {}  # cpu -> (trial, future)
    completed_results = []
    available_cpus = deque(range(config.RESERVED_CORES, config.TOTAL_CORES))

    # Limit to max_parallel
    while len(available_cpus) > max_parallel:
        available_cpus.pop()

    total = len(all_trials)
    start_time = time.time()
    last_progress_time = 0

    logger.info(
        "Running %d trials with %d CPU slots (duration=%ds)",
        total, len(available_cpus), duration,
    )

    executor = ThreadPoolExecutor(max_workers=max_parallel)
    monitor_futures = {}  # future -> (cpu, trial)

    try:
        while pending or running:
            # Fill empty slots
            while pending and available_cpus:
                trial = pending.popleft()
                cpu = available_cpus.popleft()
                trial.cpu = cpu

                if start_trial(trial, experiment_id, duration,
                               allow_existing_afl_state=resume):
                    future = executor.submit(monitor_trial, trial, experiment_id, duration)
                    running[cpu] = trial
                    monitor_futures[future] = (cpu, trial)
                else:
                    # Trial failed to start, return CPU
                    available_cpus.append(cpu)
                    completed_results.append({
                        "trial": trial.name,
                        "crash_times": [],
                        "final_stats": {},
                        "error": "failed_to_start",
                    })

            # Check for completed futures (non-blocking)
            done_futures = []
            for future in list(monitor_futures.keys()):
                if future.done():
                    done_futures.append(future)

            for future in done_futures:
                cpu, trial = monitor_futures.pop(future)
                try:
                    result = future.result()
                    completed_results.append(result)
                except Exception as e:
                    logger.error("Trial %s failed: %s", trial.name, e)
                    completed_results.append({
                        "trial": trial.name,
                        "crash_times": [],
                        "final_stats": {},
                        "error": str(e),
                    })
                    if trial.container_id:
                        docker_util.stop_container(trial.container_id)
                        docker_util.remove_container(trial.container_id)

                if cpu in running:
                    del running[cpu]
                available_cpus.append(cpu)

                # Write intermediate results
                save_partial_results(completed_results, experiment_id)

            # Log progress periodically
            now = time.time()
            if now - last_progress_time >= config.MONITOR_INTERVAL:
                log_progress(
                    running, completed_results, pending, manifest, start_time
                )
                last_progress_time = now

            if pending or running:
                time.sleep(10)

    finally:
        executor.shutdown(wait=False)

    # Final save
    save_partial_results(completed_results, experiment_id)
    return completed_results


def main():
    parser = argparse.ArgumentParser(description="Phase 3: Trial Execution")
    parser.add_argument(
        "--manifest", default=config.MANIFEST_PATH,
        help="Path to manifest.json",
    )
    parser.add_argument(
        "--experiment-id", required=True,
        help="Experiment ID (from Phase 2)",
    )
    parser.add_argument(
        "--duration", type=int, default=config.TRIAL_DURATION_SECS,
        help=f"Trial duration in seconds (default: {config.TRIAL_DURATION_SECS})",
    )
    parser.add_argument(
        "--max-parallel", type=int, default=config.USABLE_CORES,
        help="Max parallel trials",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Resume from previous run, skipping completed trials",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Run a quick dry-run (1 trial, 5 minutes)",
    )
    parser.add_argument(
        "--project", default=None,
        help="Only run trials for a specific project",
    )
    args = parser.parse_args()

    with open(args.manifest) as f:
        manifest = json.load(f)

    if args.project:
        manifest = [e for e in manifest if e["project"] == args.project]

    if args.dry_run:
        logger.info("=== DRY RUN MODE ===")
        original_trials = config.NUM_TRIALS
        config.NUM_TRIALS = 1
        duration = 300
        max_parallel = min(args.max_parallel, 4)

        results = run_all_trials_slot(
            manifest, args.experiment_id, duration, max_parallel,
            resume=args.resume,
        )

        config.NUM_TRIALS = original_trials
    else:
        results = run_all_trials_slot(
            manifest, args.experiment_id, args.duration, args.max_parallel,
            resume=args.resume,
        )

    # If resuming, rebuild full results from disk
    if args.resume:
        results = collect_all_trial_results(args.experiment_id)

    # Save overall results
    results_path = os.path.join(
        config.RESULTS_DIR, args.experiment_id, "trial_results.json"
    )
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)

    logger.info("All trials complete. Results saved to %s", results_path)

    total = len(results)
    # Real target-bug finds only (not slow-units/timeouts/OOMs/boundary artifacts).
    with_crashes = sum(
        1 for r in results
        if crash_classify.trial_found_bug(r.get("crash_times"), r.get("max_total_time"))
    )
    print(f"\n=== Trial Summary ===")
    print(f"  Total completed: {total}")
    print(f"  Found target bug: {with_crashes}")
    print(f"  Results: {results_path}")
    print()


if __name__ == "__main__":
    main()
