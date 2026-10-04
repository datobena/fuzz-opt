"""Online (continuous) optimization during fuzzing — LOCAL Docker backend.

While the phase-3 fuzzer runs (10 baseline + 10 online trials for one target), a
sequential optimizer loop periodically snapshots one live online trial's accumulated
corpus, runs the phase-2 machinery on that snapshot (mutation capture -> profile ->
LLM folds -> PoC + replay-speedup gates) on a persistent cumulative source tree, and —
when a round is accepted — hot-swaps the new binary into all online trials without
wiping their corpora. Optimization compounds across the run and tracks the corpus as
it grows. Every intermediary binary + diff + profile is archived, and a soft per-target
attempt ledger steers the optimizer away from folds it already tried.

This module owns the swapped binary and the online-container lifecycle, which is what
makes the swap race-free. See the design in
docs/superpowers/specs / the approved plan for the full rationale.
"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import shutil
import subprocess
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

import config
import phase2_setup
from lib import swap_signal, provenance
import phase3_runner
from prework.prework_build import prework_image_for
from lib import afl
from lib import corpus as corpus_util
from lib import tracked_git
from lib import cpu_ledger, crash_classify, docker_util

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CPU pool parsing
# ---------------------------------------------------------------------------
def parse_cpu_range(spec: str) -> list[int]:
    """Parse a cpuset spec like '4-23', '4,7,9', or '4-6,10' into a list of ints."""
    cpus: list[int] = []
    for tok in str(spec).split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            a, b = tok.split("-", 1)
            cpus.extend(range(int(a), int(b) + 1))
        else:
            cpus.append(int(tok))
    return cpus


# ---------------------------------------------------------------------------
# Container-exit classification (bespoke online monitor)
# ---------------------------------------------------------------------------
def classify_exit(*, swap_requested: bool, found_bug: bool,
                  elapsed: float, duration: float) -> str:
    """Classify why an online trial's container exited.

    Priority (most-terminal first):
      - ``budget_done`` : the time budget is exhausted — terminal. This also wins over
                          a pending swap: a swap requested with no time left must not
                          relaunch.
      - ``swap``        : the orchestrator stopped the container to swap the binary —
                          park on relaunch_ready, then relaunch with the remaining time.
      - ``dead``        : a genuine early death (OOM/startup) with time left — relaunch
                          immediately with the remaining time.

    Finding the bug is NOT terminal. AFL keeps fuzzing past a crash, and running
    the full budget either way is the entire reason this benchmark left
    libFuzzer: under libFuzzer a trial died at its first crash, truncating every
    measurement at the event being measured. A ``bug_found`` state here would
    reimpose exactly that, and asymmetrically -- the baseline arm runs
    ``-V {duration}`` (phase3_runner) and never stops early, so the two arms
    would no longer be comparable on anything but time-to-bug.

    This branch was unreachable until ``classify_crash`` learned AFL's artifact
    naming: before that, ``trial_found_bug`` was False for every online trial and
    all nine ran the full budget. Fixing the classifier woke it up and truncated
    b3r3's yara arm at 2.7-12.6h against a 24h baseline. ``found_bug`` is kept in
    the signature so the caller's intent stays legible, and deliberately does not
    affect the result.
    """
    if elapsed >= duration:
        return "budget_done"
    if swap_requested:
        return "swap"
    return "dead"


# ---------------------------------------------------------------------------
# Attempt ledger — populating "which functions were tried" from a diff
# ---------------------------------------------------------------------------
_HUNK_RE = re.compile(r"^@@ .* @@\s*(.*)$")
_FUNC_RE = re.compile(r"([A-Za-z_]\w*)\s*\(")


def functions_from_diff(diff_text: str) -> list[str]:
    """Extract touched function names from a unified git diff's hunk-header context.

    A C hunk header carries the enclosing function signature after the second ``@@``
    (e.g. ``@@ -10,7 +10,9 @@ static int cil_resolve_ast(struct cil_db *db)``); we take
    the identifier immediately preceding the first ``(``. Hunks without a function
    context are skipped. Order-preserving and de-duplicated.
    """
    seen: list[str] = []
    for line in diff_text.splitlines():
        if not line.startswith("@@"):
            continue
        m = _HUNK_RE.match(line)
        if not m:
            continue
        fm = _FUNC_RE.search(m.group(1))
        if fm and fm.group(1) not in seen:
            seen.append(fm.group(1))
    return seen


# ---------------------------------------------------------------------------
# Live-corpus snapshot (the optimization input)
# ---------------------------------------------------------------------------
def snapshot_live_corpus(src_dir, dest_dir, *, now: float,
                         min_age_s: float = 2.0) -> dict:
    """Copy a corpus that is being written concurrently into ``dest_dir``, consistently.

    Both libFuzzer corpus units and AFL queue entries are write-once, so a
    stable-mtime/size filter yields a consistent set: skip any file whose mtime is
    within ``min_age_s`` of ``now`` (still in flight) or whose size changes during
    the copy. Returns
    {"file_count", "bytes", "skipped_in_flight", "taken_at"}.
    """
    src = Path(src_dir)
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    count = 0
    total = 0
    skipped = 0
    for p in sorted(src.rglob("*")):
        if not p.is_file():
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        if now - st.st_mtime < min_age_s:
            skipped += 1
            continue
        size_before = st.st_size
        target = dest / p.name
        try:
            shutil.copy2(p, target)
            if p.stat().st_size != size_before:  # grew mid-copy -> in flight
                target.unlink()
                skipped += 1
                continue
        except OSError:
            skipped += 1
            continue
        count += 1
        total += target.stat().st_size
    return {"file_count": count, "bytes": total,
            "skipped_in_flight": skipped, "taken_at": now}


# ---------------------------------------------------------------------------
# Live mutation capture
#
# Each round used to re-fuzz a corpus snapshot for PHASE2_MUTATION_DURATION_SECS
# purely to regenerate mutations the live trials had ALREADY executed -- roughly
# 4 hours of redundant fuzzing per target over a 24h run. The shim is a runtime
# .so, so the online trials carry it and a round consumes what they produced.
# ---------------------------------------------------------------------------
BATCH_MARKER = ".batch_complete"
DUMP_REQUEST = ".dump_now"


def request_mutation_dump(dump_dirs, *, timeout: float | None = None,
                          poll: float = 0.5) -> list[str]:
    """Ask every capture trial to write its batch, and wait for the markers.

    The shim samples continuously across the whole inter-round window and only
    writes when asked, so a round must REQUEST a dump rather than simply reading
    whatever is on disk. Requesting also stamps the window boundary: the shim
    resets and starts the next window as soon as it has written.

    Returns the dirs that produced a complete batch. A trial that does not answer
    in time is skipped rather than waited on -- a stalled or just-restarted trial
    must not hold up an optimization round.
    """
    if timeout is None:
        timeout = float(getattr(config, "ONLINE_MUTATION_DUMP_TIMEOUT_SECS", 300))
    pending = []
    for d in dump_dirs:
        p = Path(d)
        if not p.is_dir():
            continue
        # Clear any previous batch first so the marker we wait for is this one's.
        for f in p.iterdir():
            if f.name == BATCH_MARKER or f.name.startswith("mut_"):
                try:
                    f.unlink()
                except OSError:
                    pass
        try:
            (p / DUMP_REQUEST).write_text("")
            pending.append(p)
        except OSError:
            continue

    ready, deadline = [], time.time() + timeout
    while pending and time.time() < deadline:
        for p in list(pending):
            if (p / BATCH_MARKER).is_file():
                ready.append(str(p))
                pending.remove(p)
        if pending:
            time.sleep(poll)

    for p in pending:
        logger.warning("mutation dump not delivered within %.0fs by %s; skipping",
                       timeout, p)
        try:
            (p / DUMP_REQUEST).unlink()
        except OSError:
            pass
    return ready


def collect_round_mutations(dump_dirs, dest, *, cap: int, seed: int = 1337) -> int:
    """Sample up to `cap` mutations across every capture trial into `dest`.

    Pooled and sampled uniformly rather than taken per-trial in order, so no
    single trial dominates the profiling corpus.

    A dump without its completion marker is SKIPPED: the shim writes the marker
    last, so its absence means the batch is mid-write, and consuming it would
    silently profile a truncated set.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    pool: list[Path] = []
    for d in dump_dirs:
        p = Path(d)
        if not (p / BATCH_MARKER).is_file():
            logger.info("mutation dump %s has no completion marker; skipping", p)
            continue
        pool.extend(sorted(f for f in p.iterdir() if f.name.startswith("mut_")))

    if not pool:
        return 0
    rng = random.Random(seed)
    chosen = pool if len(pool) <= cap else rng.sample(pool, cap)
    written = 0
    for i, src in enumerate(chosen):
        try:
            shutil.copy2(src, dest / f"mut_{i:08d}")
            written += 1
        except OSError:
            continue
    return written


# ---------------------------------------------------------------------------
# Trial selection (which live trial's corpus feeds a round)
# ---------------------------------------------------------------------------
def select_snapshot_trial(trials, corpus_count_fn):
    """Pick the online trial whose corpus feeds the next round.

    Prefer the still-``running`` trial with the largest corpus (tie -> lowest
    trial_id). If none are running, fall back to the lowest-trial_id trial.
    """
    running = [t for t in trials if getattr(t, "state", None) == "running"]
    if running:
        return max(running, key=lambda t: (corpus_count_fn(t), -t.trial_id))
    return min(trials, key=lambda t: t.trial_id)


# ---------------------------------------------------------------------------
# Per-round env (reuse phase-2 with the corpus + replay-baseline overrides)
# ---------------------------------------------------------------------------
def build_round_env(*, experiment_dir, diff_dir, opt_bin_dir, snapshot_dir,
                    entry, previous_best_bin, profile_cpu: int | None = None) -> dict:
    """Env for one online round.

    Reuse phase-2's env builder but override the profiling corpus to the live
    snapshot (so mutations are captured from the *accumulated* corpus, not the bundled
    seeds) and anchor the replay-timing gate on the previous-best binary, giving
    cumulative "each fold must beat the previous best" semantics.

    Sampling: online rounds use PURE RESERVOIR sampling of the fuzzer's real (weighted)
    mutation stream and disable the guaranteed queue-pass pool. The queue pass mutates
    every seed queue_depth times UNCAPPED (Theta(seeds)); with a live trial's large,
    growing corpus that dominates the reservoir cap and balloons the profiling corpus
    round-over-round (it is what timed out round 3 at 140k files on the first 8h run).
    The reservoir alone is both what we want (a bounded, time-weighted sample of what
    the fuzzer actually executes) and constant-size regardless of corpus growth.

    Pinning: ``profile_cpu`` must be threaded through, not left to default.
    _make_phase2_profile_env falls back to RESERVED_CORES-1, which is a single
    fixed core for every project -- so two targets running concurrently would
    profile on the SAME core while their own ONLINE_PROFILE_CPU sat idle, and
    the timing-sensitive work each round depends on would be measured under
    contention from the other project.
    """
    env = phase2_setup._make_phase2_profile_env(
        experiment_dir, diff_dir, opt_bin_dir,
        corpus_dir=snapshot_dir, entry=entry, baseline_out_dir=previous_best_bin,
        profile_cpu=profile_cpu,
    )
    # Reservoir-only: turn OFF the uncapped guaranteed queue pass (reservoir stays on
    # via its own default). Only affects online rounds; offline phase-2 is unchanged.
    env["FUZZ_SOURCE_FOLDS_MUTATION_QUEUE_PASS"] = "0"
    return env


# ---------------------------------------------------------------------------
# Cumulative source-tree management (accept -> commit/tag, reject -> revert)
# ---------------------------------------------------------------------------
_GIT_ENV = {
    "GIT_AUTHOR_NAME": "benchmark", "GIT_AUTHOR_EMAIL": "bench@test",
    "GIT_COMMITTER_NAME": "benchmark", "GIT_COMMITTER_EMAIL": "bench@test",
}


def _commit_and_tag(source_tree, tag: str) -> None:
    """Commit the current (accepted) source state and (re)tag it as the new best."""
    cwd = str(source_tree)
    env = {**os.environ, **_GIT_ENV}
    g = tracked_git.git_cmd(source_tree)
    subprocess.run(g + ["add", "-A"], cwd=cwd, capture_output=True)
    subprocess.run(g + ["commit", "-m", f"online {tag}", "--allow-empty"],
                   cwd=cwd, capture_output=True, env=env)
    subprocess.run(g + ["tag", "-f", tag], cwd=cwd, capture_output=True)


def _revert_source_tree(source_tree, tag: str) -> None:
    """Reset the cumulative tree back to a tagged accepted state.

    Called when a round is REJECTED so the next round does not build on top of a
    rejected / bug-removing / non-speedup edit (the highest-severity correctness risk).
    """
    cwd = str(source_tree)
    g = tracked_git.git_cmd(source_tree)
    subprocess.run(g + ["reset", "--hard", tag], cwd=cwd, capture_output=True)
    subprocess.run(g + ["clean", "-fd"], cwd=cwd, capture_output=True)


def apply_round_outcome(accepted: bool, *, source_tree, iter_n: int, opt_bin_dir,
                        previous_best_bin, prev_tag: str):
    """Persist a round result and return the (possibly new) previous-best binary.

    Accepted -> commit + tag ``iter_NN`` and advance previous-best to this round's bin.
    Rejected -> revert the cumulative tree to ``prev_tag`` and keep previous-best.
    """
    if accepted:
        _commit_and_tag(source_tree, f"iter_{iter_n:02d}")
        return opt_bin_dir
    _revert_source_tree(source_tree, prev_tag)
    return previous_best_bin


# ---------------------------------------------------------------------------
# Hot-swap: stop ALL online containers before overwriting the shared binary
# ---------------------------------------------------------------------------
def _overwrite_binary(shared_bin_path, new_bin_path) -> None:
    shutil.copy2(str(new_bin_path), str(shared_bin_path))
    os.chmod(str(shared_bin_path), 0o755)


def _stop_all_and_overwrite(running_trials, shared_bin_path, new_bin_path, *,
                            poll_sleep: float = 0.5) -> None:
    """Stop every running online container, confirm each is down, THEN overwrite the
    single shared binary exactly once.

    Ordering is load-bearing: overwriting a file still mmap'd by a live libFuzzer
    process risks SIGBUS, so all online containers must be down before the write. All 10
    online trials bind-mount the same optimized/bin/<target>, so one overwrite serves all.
    """
    for t in running_trials:
        docker_util.stop_container(t.container_id)
        while docker_util.container_is_running(t.container_id):
            time.sleep(poll_sleep)
    _overwrite_binary(shared_bin_path, new_bin_path)


def _stop_one_and_overwrite(trial, bin_path, new_bin_path, *,
                            poll_sleep: float = 0.5) -> None:
    """Stop ONE online container, confirm it is down, then overwrite ITS binary.

    The per-trial analogue of _stop_all_and_overwrite. Same ordering constraint
    and same reason: overwriting a file still mmap'd by a live process risks
    SIGBUS, so the container must be confirmed down before the write. What
    changes is the blast radius -- each optimized trial bind-mounts its own
    bin_<tid>/, so one trial's swap cannot disturb the other nine.
    """
    docker_util.stop_container(trial.container_id)
    while docker_util.container_is_running(trial.container_id):
        time.sleep(poll_sleep)
    _overwrite_binary(bin_path, new_bin_path)


def hot_swap_one(ctx: RoundContext, state: OnlineState, new_bin_dir):
    """Swap an accepted round binary into THIS optimizer's own trial only.

    Deliberately takes no global lock. Under the per-trial design the ten
    optimizers are independent experiments that happen to share a host: trial 3
    accepting a fold is not an event for trial 7, and serialising the swaps
    would couple their timelines back together -- which is exactly the coupling
    this design exists to remove. The per-trial `relaunched` event is still used
    so this optimizer's own monitor cannot re-loop mid-swap.
    """
    trial = ctx.trial
    rec = state.trials.get(trial.trial_id, {})
    if rec.get("state") != "running":
        logger.info("trial_%02d round %d: trial already terminal, no swap",
                    trial.trial_id, ctx.iter_n)
        return
    gen = swap_signal.SIGNAL.record_swap(ctx.iter_n, 1)
    logger.info("trial_%02d round %d: HOT-SWAP (swap generation %d)",
                trial.trial_id, ctx.iter_n, gen)
    barrier = rec.setdefault("swap_barrier", threading.Event())
    ready = rec.setdefault("relaunch_ready", threading.Event())
    relaunched = rec.setdefault("relaunched", threading.Event())
    # Same ordering as the global swap: raise the barrier BEFORE tearing the
    # container down, so the monitor reads "this exit was a swap" rather than
    # "this trial died" and preserves the corpus instead of finalizing.
    barrier.set()
    ready.clear()
    relaunched.clear()
    bin_path = os.path.join(str(trial.bin_dir_override), ctx.fuzz_target)
    new_bin = os.path.join(str(new_bin_dir), ctx.fuzz_target)
    _stop_one_and_overwrite(trial, bin_path, new_bin)
    state.swap_timeline.append({
        "iter": ctx.iter_n, "ts": time.time(), "trial_id": trial.trial_id,
        "state_at_swap": _fuzzer_state(ctx.experiment_id, trial)})
    _write_json(ctx.swap_timeline_path, state.swap_timeline)
    ready.set()
    relaunched.wait(timeout=180)
    barrier.clear()
    logger.info("trial_%02d round %d: swap complete, relaunched on its own binary",
                trial.trial_id, ctx.iter_n)


# ---------------------------------------------------------------------------
# Sequential optimizer loop (convergence-terminated)
# ---------------------------------------------------------------------------
def run_optimizer_loop(*, run_round_fn, hot_swap_fn, convergence_k: int,
                       wait_fn, all_terminal_fn) -> int:
    """Drive sequential optimization rounds.

    Each iteration: wait the minimum inter-swap fuzz interval, stop if every online
    trial is already terminal, else run one round; on an accepted round hot-swap and
    reset the no-improvement counter, on a rejected round increment it and stop after
    ``convergence_k`` consecutive MEASURED rejects (infrastructure failures do not
    count -- see below). Returns the number of rounds attempted.
    Fuzzing continues to the end of the budget regardless (driven by the caller).

    ``convergence_k <= 0`` disables early stopping entirely: rounds keep running
    until the trials terminate, however many consecutive rejects accumulate. A
    run of rejects is weak evidence that the NEXT round will also reject -- the
    optimizer profiles a corpus that keeps growing, so a hotspot worth folding
    can surface on round 7 after six barren ones. Stopping early converts "found
    nothing yet" into "found nothing", and the online arm quietly finishes the
    campaign as a second baseline.
    """
    consecutive = 0
    iter_n = 0
    converge = convergence_k > 0
    while True:
        wait_fn()
        if all_terminal_fn():
            break
        iter_n += 1
        result = run_round_fn(iter_n)
        # A round may report a third element: whether its outcome is EVIDENCE
        # about the target (the optimizer measured and found no speedup) rather
        # than an infrastructure failure (a revoked credential, a dead broker, an
        # empty snapshot). Only evidence counts toward convergence -- otherwise a
        # transient outage three rounds running ends optimization for the whole
        # campaign and the online arm silently becomes a second baseline.
        accepted, new_bin, *rest = result
        measured = rest[0] if rest else True
        if accepted:
            hot_swap_fn(new_bin)
            consecutive = 0
        elif measured:
            consecutive += 1
            if converge and consecutive >= convergence_k:
                break
    return iter_n


# ===========================================================================
# Integration glue — trial construction, round assembly, monitor, hot-swap,
# and the top-level run_online orchestrator.
#
# The pure logic below the imports is unit-tested (test_phase3_online.py). The
# glue in this section composes those tested units and mirrors the proven
# setup_cve_arvo_image gate wiring; its threading / docker / LLM parts are
# exercised by the end-to-end smoke (a real target), not by unit tests.
# ===========================================================================
def _build_online_trials(entry: dict, experiment_dir: str | None = None):
    """Build the two arms for one target: 10 baseline + 10 online trials.

    Online trials use variant "optimized" so they write into the optimized/ dir that
    phase4_analysis.py already reads. Seeds follow the phase3_runner formula (baseline
    vs optimized offset). All 20 trials are pinned round-robin across ONLINE_TRIAL_CORES.

    Under ONLINE_PER_TRIAL_OPTIMIZER each optimized trial additionally gets its OWN
    binary directory (optimized/bin_<tid>), because its own optimizer edits its own
    source tree and replaces only its own binary. ``experiment_dir`` is required in
    that mode -- it is where those per-trial dirs live.
    """
    project, cve = entry["project"], entry["cve"]
    # Carries the prework image tag onto every trial; see phase3_runner.Trial.
    local_id = int(entry.get("local_id") or 0)
    trial_cores = parse_cpu_range(getattr(config, "ONLINE_TRIAL_CORES", "4-23"))
    baseline, online = [], []
    for tid in range(config.NUM_TRIALS):
        b_seed = (config.BASE_SEED + tid * config.SEED_MULTIPLIER
                  + config.BASELINE_SEED_OFFSET)
        o_seed = (config.BASE_SEED + tid * config.SEED_MULTIPLIER
                  + config.OPTIMIZED_SEED_OFFSET)
        baseline.append(phase3_runner.Trial(project=project, cve=cve, local_id=local_id,
                                             variant="baseline", trial_id=tid, seed=b_seed))
        o = phase3_runner.Trial(project=project, cve=cve, local_id=local_id,
                                variant="optimized", trial_id=tid, seed=o_seed)
        # Online trials carry the mutation-dump shim so rounds reuse mutations the
        # fuzzer already executed instead of re-fuzzing to regenerate them.
        #
        # NOTE this is an asymmetry between the arms: baseline trials do not carry
        # it. Chosen deliberately -- the shim batches in memory and goes idle once
        # its 20k are collected, so the cost is bounded to the fill window rather
        # than the whole campaign, and it measured as indistinguishable from noise.
        # Recorded here because it is the kind of difference that must be reported
        # alongside a TTB comparison, not discovered later.
        o.capture_mutations = getattr(config, "ONLINE_LIVE_MUTATION_CAPTURE", True)
        online.append(o)
    if getattr(config, "ONLINE_PER_TRIAL_OPTIMIZER", False):
        if not experiment_dir:
            raise ValueError("per-trial optimizer mode needs experiment_dir to place "
                             "each trial's own bin directory")
        for t in online:
            t.bin_dir_override = os.path.join(
                experiment_dir, "optimized", f"bin_{t.trial_id:02d}")
    for i, t in enumerate(baseline + online):
        t.cpu = trial_cores[i % len(trial_cores)]
    return baseline, online


def _is_n132_entry(entry: dict) -> bool:
    """True for an n132/arvo prebuilt-image entry; False for a classic gcr-ARVO one."""
    return "n132/arvo" in str(entry.get("image") or "")


def _online_target_strategy(entry: dict, fuzz_target: str, issue: dict | None = None,
                            profile_cpu: int | None = None):
    """Return (rebuild_fn, wrapper_env_fn) closures for this entry's backend.

    Under PHASE2_SANDBOX (the default) both closures go through the pinned prework
    image: rebuilds run there, and the agent's build/smoke commands become broker
    clients. Leaving the legacy branches in place would silently rebuild each
    online round with `arvo compile` -- i.e. FUZZING_ENGINE=libfuzzer -- so every
    hot-swapped binary would be a libFuzzer build dropped into an AFL campaign.

    ``profile_cpu`` pins the rebuild to the optimizer's core. Without it the
    rebuild ran UNPINNED, and OSS-Fuzz `compile` runs the project's build.sh with
    `make -j$(nproc)` -- so every round briefly saturated all 80 CPUs, including
    the cores running the very trials the round is measured against. The broker
    already pins the agent's own builds to one core (sandbox/broker.py); this
    makes the harness-side rebuild match, and it is also what lets the rebuild be
    charged as core-seconds rather than a number nobody can reconstruct.

    Legacy (PHASE2_SANDBOX=0): n132/arvo image -> ``arvo compile`` on the bundled
    image; classic ARVO (a bare ``local_id``, e.g. selinux) -> rebuild via
    ``gcr.io/oss-fuzz/<local_id>``. rebuild_fn(source_root, out_bin_dir) and
    wrapper_env_fn(source_root, state_dir) hide the backend from run_round.
    """
    if getattr(config, "PHASE2_SANDBOX", True):
        from prework.prework_build import rebuild_with_prework_image
        from sandbox.session import build_sandbox_validation_env

        def rebuild_fn(source_root, out_bin_dir):
            # source_root is the extracted /src ROOT (it holds build.sh, the
            # harness .cc, and the project dir side by side), but the image mounts
            # this over $SRC/<project> -- so passing it verbatim buries the tree
            # one level deep and build.sh compiles the copy baked into the image
            # instead of the optimizer's edits. The legacy branches below take the
            # root by design; only this one remounts. phase 2 resolves it the same
            # way (setup_cve_arvo_image's build_fn).
            return rebuild_with_prework_image(
                entry=entry,
                source_dir=str(phase2_setup._find_project_source(
                    Path(source_root), entry["project"])),
                out_dir=out_bin_dir, capture_log=True, cpu=profile_cpu)

        def wrapper_env_fn(source_root, state_dir):
            from prework.prework_build import prework_image_for
            env = build_sandbox_validation_env()
            env["PHASE2_PREWORK_IMAGE"] = prework_image_for(entry)
            env["FUZZ_TARGET"] = fuzz_target
            return env

        return rebuild_fn, wrapper_env_fn

    if _is_n132_entry(entry):
        image = str(entry["image"])

        def rebuild_fn(source_root, out_bin_dir):
            return phase2_setup.rebuild_with_modified_source_n132(
                image, Path(source_root), out_bin_dir, capture_log=True)

        def wrapper_env_fn(source_root, state_dir):
            return phase2_setup._make_n132_wrapper_validation_env(
                image=image, source_dir=Path(source_root),
                fuzz_target=fuzz_target, state_dir=Path(state_dir))

        return rebuild_fn, wrapper_env_fn

    local_id = int(entry["local_id"])

    def rebuild_fn(source_root, out_bin_dir):
        return phase2_setup.rebuild_with_modified_source_arvo(
            local_id, issue, Path(source_root), out_bin_dir, capture_log=True)

    def wrapper_env_fn(source_root, state_dir):
        return phase2_setup._make_arvo_wrapper_validation_env(
            local_id=local_id, issue=issue, source_dir=Path(source_root),
            fuzz_target=fuzz_target, state_dir=Path(state_dir))

    return rebuild_fn, wrapper_env_fn


@dataclass
class RoundContext:
    entry: dict
    experiment_id: str
    experiment_dir: str
    online_dir: str
    source_tree: str            # project source subdir the optimizer edits + git-tracks
    source_root: str            # extracted /src root for the rebuild + wrapper validation
    project: str
    image: str
    fuzz_target: str
    poc_path: str | None
    previous_best_bin: str      # replay-gate baseline = current best binary
    prev_tag: str
    optimized_bin_dir: str      # the LIVE shared binary dir (bind-mounted by trials)
    ledger_path: str
    swap_timeline_path: str
    profile_cpu: int
    rebuild_fn: object = None       # (source_root, out_bin_dir) -> bool|(bool, log)
    wrapper_env_fn: object = None   # (source_root, state_dir) -> dict[str,str]
    ledger: list = field(default_factory=list)
    last_profile: dict = field(default_factory=dict)
    online_trials: list = field(default_factory=list)
    iter_n: int = 0
    # --- per-trial-optimizer fields -------------------------------------
    # The single trial this optimizer owns. Set in per-trial mode; None in the
    # legacy shared-binary mode, where one optimizer served all online trials.
    trial: object = None
    # Trial i's mutations, harvested once and then held fixed for every round
    # this optimizer runs. None until the first successful harvest.
    fixed_mutations: str | None = None
    fixed_mutation_count: int = 0


@dataclass
class OnlineState:
    swap_barrier: threading.Event = field(default_factory=threading.Event)
    relaunch_ready: threading.Event = field(default_factory=threading.Event)
    swap_lock: threading.Lock = field(default_factory=threading.Lock)
    trials: dict = field(default_factory=dict)      # trial_id -> record
    swap_timeline: list = field(default_factory=list)


def _write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, default=str)


def _corpus_file_count(experiment_id, trial):
    # AFL's queue, not the read-only seed input dir -- see get_live_corpus_dir.
    cdir = phase3_runner.get_live_corpus_dir(experiment_id, trial)
    if not os.path.isdir(cdir):
        return 0
    return sum(1 for p in Path(cdir).rglob("*") if p.is_file())


def _parse_profile_ranks(profile_dir) -> dict:
    """Best-effort parse of the profile-once ranked hotspots (perf flat.txt).

    Returns {func: {"rank": int, "share": float}}. Defensive: any parse failure yields
    {} (which makes the ledger conservatively avoid all prior attempts — never a wrong
    re-open). Validate/tighten against a real flat.txt on the first live run.
    """
    flat = Path(profile_dir) / "flat.txt"
    ranks: dict = {}
    try:
        if not flat.is_file():
            return {}
        rank = 0
        for line in flat.read_text(errors="ignore").splitlines():
            # perf's flat report is: <pct>%  <Command>  <Shared Object>  [.] <Symbol>
            # Anchor on the [.]/[k] marker and take the WHOLE rest of the line as
            # the symbol. The old pattern assumed a single field before the marker
            # (perf emits two), so it never matched and the last-token fallback ran
            # instead -- which truncates every symbol containing a space. Measured
            # on a real profile: "__sanitizer::StackDepotBase<...StackDepotNode, 1,
            # 20>::Put" was recorded as "20>::Put", so the ledger's "already tried
            # this function" lookup could never match it again.
            m = re.match(r"^\s*(\d+\.\d+)%.*?\[[^\]]*\]\s+(.+?)\s*$", line)
            if not m:
                m = re.match(r"^\s*(\d+\.\d+)%.*\s(\S+)\s*$", line)
            if not m:
                continue
            func = m.group(2)
            if func in ranks:
                continue
            rank += 1
            ranks[func] = {"rank": rank, "share": float(m.group(1)) / 100.0}
        return ranks
    except Exception:  # noqa: BLE001
        return {}


def _git_init_baseline(tree):
    env = {**os.environ, **_GIT_ENV}
    g = tracked_git.git_cmd(tree)
    subprocess.run(g + ["init", "-q"], cwd=str(tree), capture_output=True)
    subprocess.run(g + ["add", "-A"], cwd=str(tree), capture_output=True)
    subprocess.run(g + ["commit", "-m", "online baseline", "--allow-empty"],
                   cwd=str(tree), capture_output=True, env=env)


def _write_cumulative_diff(tree, out_path):
    r = subprocess.run(tracked_git.git_cmd(tree) + ["diff", "iter_00", "HEAD"],
                       cwd=str(tree), capture_output=True, text=True)
    with open(out_path, "w") as f:
        f.write(r.stdout or "")


def _record_ledger(ctx: RoundContext, iter_n, diff_dir, outcome, speedup):
    diff_path = os.path.join(diff_dir, "optimization.diff")
    diff_text = ""
    if os.path.exists(diff_path):
        with open(diff_path) as f:
            diff_text = f.read()
    funcs = functions_from_diff(diff_text)
    ctx.ledger.append({
        "iter": iter_n,
        "corpus_snapshot_id": f"iter_{iter_n:02d}",
        "functions": funcs,
        "fold_pattern": "unknown",
        "outcome": outcome,
        "measured_speedup": speedup,
        "hotspot_rank": {f: ctx.last_profile.get(f, {}).get("rank") for f in funcs},
        "hotspot_share": {f: ctx.last_profile.get(f, {}).get("share") for f in funcs},
    })
    _write_json(ctx.ledger_path, ctx.ledger)


def _round_produced_evidence(diff_dir: str, build_ok: bool) -> bool:
    """True if this round's failure is informative about the target.

    ``build_ok`` alone conflates "the optimizer ran and kept nothing" with "the
    optimizer never ran". The saved agent report separates them: a session that
    died on authentication or was killed carries the marker, one that simply
    found no qualifying fold does not.
    """
    if build_ok:
        return True                        # ran, changed something, gate judged it
    try:
        reports = sorted(Path(diff_dir).glob("agent_attempt_*.txt"))
        if not reports:
            return False                   # no report at all -> never got going
        text = reports[-1].read_text(errors="replace")
    except OSError:
        return False
    if "[timed_out] True" in text:
        return False
    if phase2_setup._is_auth_failure(text, ""):
        return False
    if "[ok] False" in text and "NO source changes" not in text:
        return False                       # session failed for some other reason
    return True                            # ran to completion, kept nothing


def run_round(ctx: RoundContext, state: OnlineState, iter_n: int):
    """One online optimization round on the persistent cumulative source tree.

    Returns (accepted, iter_bin_dir). Mirrors setup_cve_arvo_image's gate wiring, but
    the profiling corpus is a live-trial snapshot and the replay baseline is the
    previous-best binary (cumulative). A rejected round reverts the tree to prev_tag so
    the next round never builds on a rejected edit.
    """
    ctx.iter_n = iter_n
    cpu_ledger.set_round(project=ctx.project, iter_n=iter_n)
    iter_dir = os.path.join(ctx.online_dir, f"iter_{iter_n:02d}")
    diff_dir = os.path.join(iter_dir, "source_diff")
    opt_bin_dir = os.path.join(iter_dir, "bin")
    os.makedirs(diff_dir, exist_ok=True)
    os.makedirs(opt_bin_dir, exist_ok=True)

    # 1. snapshot the live corpus this optimizer profiles against.
    #
    # Per-trial mode: always THIS optimizer's own trial. The old
    # select_snapshot_trial("largest") existed only because one optimizer served
    # ten trials and had to pick one; profiling trial 8's corpus and then
    # swapping the result into trials 0..9 meant nine trials ran a binary tuned
    # for a workload they never executed. Owning one trial removes the choice.
    if ctx.trial is not None:
        chosen = ctx.trial
    else:
        chosen = select_snapshot_trial(
            ctx.online_trials, lambda t: _corpus_file_count(ctx.experiment_id, t))
    src_corpus = phase3_runner.get_live_corpus_dir(ctx.experiment_id, chosen)
    snap_dir = os.path.join(iter_dir, "corpus_snapshot")
    with cpu_ledger.timed("corpus_snapshot", cores=1) as _info:
        meta = snapshot_live_corpus(src_corpus, snap_dir, now=time.time())
        _info["files"] = meta["file_count"]
    meta["trial_id"] = chosen.trial_id
    _write_json(os.path.join(iter_dir, "corpus_snapshot_meta.json"), meta)
    logger.info("online round %d: snapshot trial_%02d -> %d files (%d skipped in-flight)",
                iter_n, chosen.trial_id, meta["file_count"], meta["skipped_in_flight"])
    if meta["file_count"] == 0:
        logger.warning("online iter %d: empty corpus snapshot; skipping round", iter_n)
        _record_ledger(ctx, iter_n, diff_dir, "no-corpus", None)
        return (False, None, False)      # nothing was measured

    # 1b. Harvest the mutations the live trials already executed, and re-arm the
    # shim for the next round. This is what removes the redundant re-fuzz: phase 2
    # would otherwise spend PHASE2_MUTATION_DURATION_SECS regenerating mutations
    # these trials had already produced.
    #
    # If the harvest comes back empty the round FALLS BACK to phase 2's own
    # capture rather than profiling seeds alone -- seeds-only measures the wrong
    # workload, which is why mutation augmentation is mandatory.
    live_mutations = None
    # Fixed corpus: optimizer i profiles trial i's OWN mutations, harvested once
    # and reused for every round it runs. Re-harvesting each round made the
    # profiling workload move underneath the optimizer, so a round-to-round
    # speedup change confounded "this edit was better" with "the corpus grew".
    if (ctx.trial is not None
            and getattr(config, "ONLINE_FIXED_MUTATION_CORPUS", True)
            and ctx.fixed_mutations):
        live_mutations = ctx.fixed_mutations
        logger.info("trial_%02d round %d: reusing FIXED mutation corpus (%d mutations)",
                    ctx.trial.trial_id, iter_n, ctx.fixed_mutation_count)
        _write_json(os.path.join(iter_dir, "live_mutation_meta.json"),
                    {"harvested": ctx.fixed_mutation_count, "fixed": True,
                     "source_trial": ctx.trial.trial_id,
                     "corpus_dir": ctx.fixed_mutations})
    elif getattr(config, "ONLINE_LIVE_MUTATION_CAPTURE", True):
        # Per-trial mode harvests from THIS trial alone; legacy mode pools all.
        _mut_trials = [ctx.trial] if ctx.trial is not None else ctx.online_trials
        dump_dirs = [
            phase3_runner.get_trial_dirs(ctx.experiment_id, t)["mutations"]
            for t in _mut_trials
        ]
        # A fixed corpus lives at the optimizer's root, not under an iter dir --
        # it outlives the round that harvested it.
        harvest_dir = (os.path.join(ctx.online_dir, "fixed_mutations")
                       if ctx.trial is not None
                       else os.path.join(iter_dir, "live_mutations"))
        # Timed as one stage: the dump request blocks until every trial has
        # FLUSHED its batch to disk, so this is also the barrier that guarantees
        # the profiling corpus below is built from mutations that are already
        # written -- not from whatever happened to be on disk when the round woke.
        with cpu_ledger.timed("mutation_harvest", cores=1) as _info:
            ready = request_mutation_dump(dump_dirs)
            n = collect_round_mutations(
                ready, harvest_dir,
                cap=int(getattr(config, "PHASE2_MUTATION_CAP", 20000)),
                seed=config.BASE_SEED + iter_n)
            _info["trials_ready"] = len(ready)
            _info["mutations"] = n
        logger.info("online round %d: %d/%d trials delivered a batch, %d mutations",
                    iter_n, len(ready), len(dump_dirs), n)
        _write_json(os.path.join(iter_dir, "live_mutation_meta.json"),
                    {"harvested": n, "trials_ready": len(ready),
                     "dump_dirs": len(dump_dirs)})
        if not n and ctx.trial is not None:
            # RETRY rather than fall through. There is no usable fallback on the
            # AFL pipeline: phase 2's own capture is libFuzzer-based, and
            # _phase2_mutation_builder returns the sentinel "afl-custom-mutator"
            # that mutation_capture.py has no branch for -- it interpolates it
            # into a shell command, so the round dies with
            # "/bin/bash: afl-custom-mutator: command not found" reported
            # (misleadingly) as "shim build failed".
            #
            # A miss here is a TIMING failure, not a broken shim: the shim
            # answers in ~5s idle, and both trials that lost round 1 of
            # online-24h-c1 delivered in 5s when asked again a few minutes later.
            logger.warning("online round %d: no batch from trial_%02d; retrying "
                           "the dump request once", iter_n, ctx.trial.trial_id)
            ready = request_mutation_dump(dump_dirs)
            n = collect_round_mutations(
                ready, harvest_dir,
                cap=int(getattr(config, "PHASE2_MUTATION_CAP", 20000)),
                seed=config.BASE_SEED + iter_n)
            logger.info("online round %d: retry delivered %d mutations", iter_n, n)
        if n:
            live_mutations = harvest_dir
            if ctx.trial is not None and getattr(
                    config, "ONLINE_FIXED_MUTATION_CORPUS", True):
                ctx.fixed_mutations = harvest_dir
                ctx.fixed_mutation_count = n
                logger.info("trial_%02d: PINNED fixed mutation corpus of %d "
                            "mutations for all later rounds",
                            ctx.trial.trial_id, n)
        elif ctx.trial is not None:
            # Give up on THIS round rather than profile the wrong workload.
            # Recorded as non-evidence so it does not count toward convergence:
            # the target told us nothing, the plumbing did.
            logger.warning(
                "online round %d: trial_%02d delivered no mutation batch after a "
                "retry; skipping this round (a libFuzzer fallback would profile "
                "the wrong workload for an AFL campaign)",
                iter_n, ctx.trial.trial_id)
            _record_ledger(ctx, iter_n, diff_dir, "no-mutations", None)
            return (False, None, False)
        else:
            logger.warning(
                "online round %d: no completed mutation batch yet; falling back "
                "to phase-2 capture for this round", iter_n)

    # 2. env: profile the snapshot; anchor the replay gate on the previous best
    env = build_round_env(
        experiment_dir=ctx.experiment_dir, diff_dir=diff_dir,
        opt_bin_dir=os.path.join(iter_dir, "validation_out"),
        snapshot_dir=snap_dir, entry=ctx.entry,
        previous_best_bin=ctx.previous_best_bin, profile_cpu=ctx.profile_cpu)
    env.update(ctx.wrapper_env_fn(ctx.source_root, os.path.join(iter_dir, "validation")))
    if live_mutations:
        # Hand phase 2 the already-captured mutations; its own capture step sees
        # this and skips the re-fuzz.
        env["FUZZ_SOURCE_FOLDS_PREBUILT_MUTATIONS"] = live_mutations

    # No attempt-history block is injected into the optimizer prompt. A previous
    # design listed already-tried folds and told the agent to AVOID them unless a
    # hotspot's profile had shifted; it is deleted, not disabled, for three reasons
    # measured on the 264 real ledger entries under results/:
    #   - 71% of the avoid list was outcome "kept" -- it steered the agent away
    #     from the functions it had just proved had headroom;
    #   - fold_pattern was the literal string "unknown" in 264/264 entries, so the
    #     block never said what had actually been tried;
    #   - 68% of function mentions had no matching profile rank (ledger records C
    #     identifiers from diff hunks, the profile records perf symbols), so 28% of
    #     entries could never be re-opened at all -- and that failure was 100% on
    #     every C++ target (lcms, PcapPlusPlus, assimp) versus 0-6% on libxml2.
    #     A suppression whose strength depends on the target's symbol style is a
    #     systematic per-target difference inside the treatment arm.
    # Nothing skips a function now: the agent sees the current profile and may
    # retry anything, including folds it previously reverted. ledger.json is still
    # written as a record (see _record_ledger) but no longer feeds the prompt.

    def build_fn():
        # Pinned to ctx.profile_cpu by _online_target_strategy, so one core.
        with cpu_ledger.timed("rebuild", cores=1):
            return ctx.rebuild_fn(ctx.source_root, opt_bin_dir)

    try:
        build_ok = phase2_setup.optimize_and_build(
            ctx.source_tree, ctx.fuzz_target, diff_dir, project=ctx.project,
            build_fn=build_fn, codex_extra_env=env, use_wrapper_validation=True,
            extra_prompt_directives=None)
    except phase2_setup.MutationAugmentationError as exc:
        logger.warning("online iter %d: mutation augmentation failed: %s", iter_n, exc)
        ctx.previous_best_bin = apply_round_outcome(
            False, source_tree=ctx.source_tree, iter_n=iter_n, opt_bin_dir=opt_bin_dir,
            previous_best_bin=ctx.previous_best_bin, prev_tag=ctx.prev_tag)
        _record_ledger(ctx, iter_n, diff_dir, "augmentation-failed", None)
        return (False, None, False)      # nothing was measured

    # refresh the parsed profile (used to record attempt ranks + next round's re-open)
    ctx.last_profile = _parse_profile_ranks(os.path.join(diff_dir, "profiles", "profile_once"))

    opt_diff = os.path.join(diff_dir, "optimization.diff")
    opt_applied = os.path.exists(opt_diff) and bool(open(opt_diff).read().strip())
    optimization_ready = build_ok and opt_applied

    opt_crashes = False
    if optimization_ready and ctx.poc_path:
        with cpu_ledger.timed("poc_verify", cores=1):
            opt_crashes = phase2_setup.verify_poc_crash(
                opt_bin_dir, ctx.fuzz_target, ctx.poc_path, cpu=ctx.profile_cpu,
                image=prework_image_for(ctx.entry))

    opt_rej = None
    replay = None
    if optimization_ready:
        with cpu_ledger.timed("bug_survival_check", cores=1):
            optimization_ready, opt_rej = phase2_setup._reject_if_optimization_removed_bug(
                project=ctx.project, cve=ctx.entry["cve"],
                optimization_ready=optimization_ready,
                baseline_reproduced=bool(ctx.poc_path), opt_crashes=opt_crashes,
                baseline_bin_dir=ctx.previous_best_bin, optimized_bin_dir=opt_bin_dir)
    if optimization_ready:
        # The replay gate times both binaries on ctx.profile_cpu, one core each,
        # run sequentially -- so its core-seconds are its wall-seconds.
        with cpu_ledger.timed("replay_gate", cores=1):
            replay = phase2_setup.run_replay_speedup(
                diff_output_dir=diff_dir, baseline_bin_dir=ctx.previous_best_bin,
                optimized_bin_dir=opt_bin_dir, fuzz_target=ctx.fuzz_target,
                experiment_dir=ctx.experiment_dir, profile_cpu=ctx.profile_cpu,
                image=prework_image_for(ctx.entry))
        optimization_ready, replay_rej = phase2_setup._reject_if_no_replay_speedup(
            project=ctx.project, cve=ctx.entry["cve"],
            optimization_ready=optimization_ready, replay=replay,
            baseline_bin_dir=ctx.previous_best_bin, optimized_bin_dir=opt_bin_dir)
        opt_rej = opt_rej or replay_rej

    if optimization_ready:
        outcome = "kept"
    elif opt_rej and opt_rej.get("stage") == "optimized_poc_verify":
        outcome = "rejected-removed-bug"
    elif not opt_applied:
        # No diff was produced. Separate "the optimizer ran and found nothing
        # worth folding" -- evidence about the TARGET -- from "the session never
        # got going" -- evidence about the INFRASTRUCTURE. Both used to report
        # build-failed, which ALSO covered a third, unrelated case (a real diff
        # that did not compile), so a campaign's round table could not be read:
        # "build-failed" might mean the agent declined, the agent died, or the
        # compiler rejected an edit. _round_produced_evidence already draws the
        # line from the saved agent report; this just surfaces it in the label.
        outcome = ("no-fold" if _round_produced_evidence(diff_dir, False)
                   else "agent-failed")
    elif not build_ok:
        outcome = "build-failed"      # a diff WAS produced and did not compile
    else:
        outcome = "rejected-no-speedup"
    speedup = replay.get("replay_speedup") if replay else None
    # Bug survival belongs on the round line, not only in a WARNING and
    # setup_metadata.json. Survival is measured rather than enforced, so a fold
    # that DELETED the target bug is still reported outcome=kept -- and anyone
    # reading the log (or a progress report built from it) would see a healthy
    # accepted round with no hint the binary can no longer reproduce the PoC.
    # bug_survived is None when there was no PoC to check or the round never got
    # far enough to try, so "unknown" never masquerades as "survived".
    if not ctx.poc_path:
        bug_survived = "no-poc"
    elif not optimization_ready and outcome in (
            "build-failed", "no-fold", "agent-failed"):
        bug_survived = "unchecked"
    else:
        bug_survived = "yes" if opt_crashes else "NO"
    # Per-round provenance: what this round changed, what the gate measured, and
    # how noisy that measurement was. Written whatever the outcome -- a rejected
    # round is evidence about the target and is currently discarded.
    provenance.write_json(os.path.join(diff_dir, "..", "round_provenance.json"), {
        "iter": iter_n,
        "outcome": outcome,
        "speedup": speedup,
        "applied": opt_applied,
        "built": build_ok,
        "poc_reproduces": bug_survived,
        "attribution": provenance.diff_attribution(
            os.path.join(diff_dir, "optimization.diff")),
        "gate": {
            "baseline": (replay or {}).get("baseline"),
            "optimized": (replay or {}).get("optimized"),
            "corpus_file_count": (replay or {}).get("corpus_file_count"),
            "partial": (replay or {}).get("partial"),
        },
        "optimizer": phase2_setup.optimizer_provenance(),
    })
    logger.info(
        "online round %d: outcome=%s speedup=%s applied=%s built=%s "
        "poc_reproduces=%s",
        iter_n, outcome, speedup, opt_applied, build_ok, bug_survived)
    if bug_survived == "NO":
        logger.warning(
            "online round %d: the optimized binary NO LONGER reproduces the PoC "
            "-- the fold removed the target bug. Recorded, not reverted; any "
            "bug-finding number from this round onward is about a binary that "
            "no longer contains the bug.", iter_n)
    _record_ledger(ctx, iter_n, diff_dir, outcome, speedup)
    # Refresh after every round, so a campaign inspected mid-flight (or killed)
    # still has an up-to-date cpu_cost.json rather than only a raw JSONL.
    _write_cpu_cost_summary(ctx)

    phase2_setup._save_setup_metadata(
        ctx.entry, iter_dir, ctx.experiment_id, opt_applied, poc_path=ctx.poc_path,
        baseline_ok=True, optimized_ok=bool(optimization_ready and opt_crashes),
        failure=opt_rej, replay=replay)

    ctx.previous_best_bin = apply_round_outcome(
        optimization_ready, source_tree=ctx.source_tree, iter_n=iter_n,
        opt_bin_dir=opt_bin_dir, previous_best_bin=ctx.previous_best_bin,
        prev_tag=ctx.prev_tag)
    if optimization_ready:
        ctx.prev_tag = f"iter_{iter_n:02d}"
        _write_cumulative_diff(ctx.source_tree, os.path.join(diff_dir, "cumulative.diff"))
        return (True, opt_bin_dir, True)
    # Did this round tell us something about the TARGET, or only about the
    # plumbing? A gate rejection and a genuine "the agent found nothing worth
    # keeping" are both evidence of diminishing headroom and should count toward
    # convergence. A session that could not run at all -- revoked credential,
    # dead broker, timeout -- says nothing about the target, and counting it
    # ended optimization for a whole campaign after three transient outages.
    #
    # _round_produced_evidence reads the agent report the round just saved, so
    # the distinction is drawn from what actually happened rather than from a
    # boolean that conflates the two.
    return (False, None, _round_produced_evidence(diff_dir, build_ok))


_STATE_FIELDS = ("run_time", "execs_done", "corpus_count", "cycles_done",
                 "max_depth", "pending_total", "pending_favs", "saved_crashes",
                 "edges_found", "bitmap_cvg", "stability")


def _fuzzer_state(experiment_id: str, trial) -> dict:
    """A trial's AFL counters right now -- small, bounded, one row per event."""
    try:
        d = phase3_runner.get_trial_dirs(experiment_id, trial)
        f = Path(d.get("afl_out") or os.path.join(d["base"], "afl_out"))
        f = f / "default" / "fuzzer_stats"
        out = {}
        for line in f.read_text().splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                k = k.strip()
                if k in _STATE_FIELDS:
                    out[k] = v.strip()
        return out
    except Exception:  # noqa: BLE001
        return {}


def hot_swap(ctx: RoundContext, state: OnlineState, new_bin_dir):
    """Swap the accepted round binary into all online trials (stop-all -> overwrite ->
    relaunch), holding swap_lock. swap_barrier stays set until every swapped monitor has
    relaunched, which closes the re-loop race noted in the plan."""
    with state.swap_lock:
        running = [t for t in ctx.online_trials
                   if state.trials[t.trial_id]["state"] == "running"]
        logger.info("online round %d: HOT-SWAP into %d running online trials",
                    ctx.iter_n, len(running))
        # Signal BEFORE tearing the online trials down, so a baseline mirroring
        # this swap restarts inside the same window rather than one swap behind.
        # Swaps that reach zero trials are not recorded (see SwapSignal).
        gen = swap_signal.SIGNAL.record_swap(ctx.iter_n, len(running))
        if len(running):
            logger.info("online round %d: swap generation %d (baseline mirrors "
                        "this if BASELINE_RESTART_MIRROR_SWAPS)", ctx.iter_n, gen)
        state.swap_barrier.set()
        state.relaunch_ready.clear()
        for t in running:
            state.trials[t.trial_id]["relaunched"].clear()
        shared_bin = os.path.join(ctx.optimized_bin_dir, ctx.fuzz_target)
        new_bin = os.path.join(str(new_bin_dir), ctx.fuzz_target)
        _stop_all_and_overwrite(running, shared_bin, new_bin)
        # Snapshot each trial's fuzzing state at the swap. Without this the
        # effect of a restart can only be inferred from end-of-run totals -- the
        # assimp collapse (corpus depth 49 -> 20) took three refuted hypotheses
        # to pin down for exactly this reason.
        state.swap_timeline.append({
            "iter": ctx.iter_n, "ts": time.time(),
            "per_trial": {t.trial_id: {"relaunched": True,
                                       "state_at_swap": _fuzzer_state(
                                           ctx.experiment_id, t)}
                          for t in running}})
        _write_json(ctx.swap_timeline_path, state.swap_timeline)
        state.relaunch_ready.set()
        for t in running:
            state.trials[t.trial_id]["relaunched"].wait(timeout=180)
        state.swap_barrier.clear()
        logger.info("online round %d: swap complete, %d trials relaunched on new binary",
                    ctx.iter_n, len(running))


def _finalize_online_trial(trial, experiment_id, duration, overall_start, crash_times):
    dirs = phase3_runner.get_trial_dirs(experiment_id, trial)
    os.makedirs(dirs["base"], exist_ok=True)
    # Streamed, not buffered: all nine online trials finalize within the same
    # few minutes, so buffering these logs multiplies by nine (see
    # docker_util.write_container_logs).
    docker_util.write_container_logs(trial.container_id, dirs["log"])
    # parse_fuzzer_stats now reads AFL's structured output tree, not console
    # text -- passing `logs` here silently produced empty stats for every
    # online trial.
    final_stats = phase3_runner.parse_fuzzer_stats(dirs["afl_out"])
    with open(dirs["crash_times"], "w") as f:
        json.dump(crash_times, f, indent=2)
    actual = round(time.time() - overall_start, 2)
    meta = {
        "trial_name": trial.name, "variant": trial.variant, "trial_id": trial.trial_id,
        "seed": trial.seed, "cpu": trial.cpu, "start_time": overall_start,
        "end_time": time.time(), "duration_s": actual, "duration_seconds": duration,
        "num_crashes": len(crash_times),
        "found_bug": crash_classify.trial_found_bug(crash_times, duration),
        "time_to_bug_s": crash_classify.trial_time_to_bug(crash_times, duration),
        "final_stats": final_stats,
    }
    with open(dirs["metadata"], "w") as f:
        json.dump(meta, f, indent=2)


def _trial_online_dir(dirs: dict, trial) -> str:
    """Where THIS trial's iter_NN/bin snapshots live.

    Two bugs met here, so both are spelled out:

    1. The path was built with one dirname too many -- from
       ``<key>/optimized/trial_XX`` it produced ``<key>/online`` instead of
       ``<key>/optimized/online``. That directory has never existed, so
       live_binary returned None for EVERY crash in every campaign. The field
       exists precisely because joining swap timestamps to crash times after the
       fact mislabeled 918 PcapPlusPlus artifacts as non-reproducing.

    2. Under the per-trial design each optimizer keeps its own iter dirs at
       ``optimized/online/trials/trial_XX/``, so even the corrected campaign-level
       path would name another optimizer's binaries.
    """
    optimized = os.path.dirname(str(dirs["base"]))          # <key>/optimized
    campaign = os.path.join(optimized, "online")
    per_trial = os.path.join(campaign, "trials", f"trial_{trial.trial_id:02d}")
    return per_trial if os.path.isdir(per_trial) else campaign


def _monitor_online_trial(trial, experiment_id, duration, state: OnlineState):
    """Bespoke monitor: distinguishes budget/bug/swap/early-death on container exit and
    relaunches (preserving corpus) for swap/dead, finalizes for bug/budget."""
    dirs = phase3_runner.get_trial_dirs(experiment_id, trial)
    # AFL writes crashes to <afl_out>/default/crashes as "id:...,sig:06,...,time:MS".
    # dirs["crashes"] is the libFuzzer-era artifact dir and stays empty forever,
    # and the old prefix filter ("crash-"/"oom-"/"timeout-") is libFuzzer naming,
    # so this monitor could never see a crash. The baseline arm uses
    # phase3_runner.monitor_trial, which reads the AFL location -- so the two arms
    # disagreed and ONLY the online arm's time-to-bug was censored. That is the
    # measurement the whole benchmark exists to compare, and the failure direction
    # made optimization look like it destroyed bug-finding.
    afl_crashes_dir = os.path.join(
        dirs.get("afl_out") or os.path.join(dirs["base"], "afl_out"),
        "default", "crashes")
    rec = state.trials[trial.trial_id]
    overall_start = rec["overall_start"]
    crash_times = rec["crash_times"]
    seen = rec["seen_crashes"]

    def scan():
        # AFL's `time:` is already CAMPAIGN-cumulative across relaunches: with
        # AFL_AUTORESUME it restores the previous run_time rather than restarting
        # at zero. Verified on this campaign -- an online trial relaunched at
        # 07:46 reported run_time 25976s (7.2h) at 11:56, matching the
        # never-relaunched baseline's 26096s to within the swap downtime. So no
        # per-session offset is applied; adding one would overstate every online
        # crash by hours, which is the same bias as censoring, just inverted.
        for entry in afl.collect_crashes(afl_crashes_dir):
            fn = entry["artifact"]
            if fn in seen:
                continue
            seen.add(fn)
            # Which binary was live when this fired. Previously inferred by
            # joining swap_timeline timestamps against crash times at analysis
            # time; done naively that mislabels post-swap artifacts as
            # non-reproducible (918 of them on PcapPlusPlus b6). Record it.
            try:
                _live_dir, _live_id = V.live_binary(
                    _trial_online_dir(dirs, trial),
                    overall_start, entry["timestamp_s"],
                    os.path.join(os.path.dirname(os.path.dirname(dirs["base"])),
                                 "baseline", "bin"))
            except Exception:  # noqa: BLE001 - provenance must not kill a trial
                _live_id = None
            crash_times.append({
                "timestamp_s": entry["timestamp_s"],
                "artifact": fn,
                "crash_type": phase3_runner.classify_crash(
                    os.path.join(afl_crashes_dir, fn)),
                "live_binary": _live_id,
            })

    while True:
        while docker_util.container_is_running(trial.container_id):
            scan()
            time.sleep(2 if time.time() - overall_start < 30 else 10)
        scan()
        found_bug = crash_classify.trial_found_bug(crash_times, duration)
        elapsed = time.time() - overall_start
        # Per-trial swap signalling when this trial owns an optimizer; the
        # global pair otherwise. Reading the global barrier in per-trial mode
        # would let trial 3's swap make trial 7 believe it was being swapped.
        _barrier = rec.get("swap_barrier") or state.swap_barrier
        _ready = rec.get("relaunch_ready") or state.relaunch_ready
        cause = classify_exit(swap_requested=_barrier.is_set(),
                              found_bug=found_bug, elapsed=elapsed, duration=duration)
        if cause == "budget_done":
            rec["state"] = cause
            _finalize_online_trial(trial, experiment_id, duration, overall_start, crash_times)
            return
        if cause == "swap":
            _ready.wait()
        remaining = int(max(1, duration - (time.time() - overall_start)))
        ok = phase3_runner.relaunch_preserving_corpus(trial, experiment_id, remaining)
        if cause == "swap":
            rec["relaunched"].set()
        if not ok:
            rec["state"] = "dead"
            _finalize_online_trial(trial, experiment_id, duration, overall_start, crash_times)
            return


def _src_subtree_has_files(src_subdir: Path) -> bool:
    """True if an intercepted /src tree has real project source (not just engine dirs)."""
    return src_subdir.exists() and any(
        d.is_dir() and d.name not in ("afl", "aflplusplus", "libfuzzer", "honggfuzz")
        for d in src_subdir.iterdir())


def _extract_online_target(entry, source_tree_root, baseline_bin_dir, poc_dir,
                           fuzz_target, project):
    """Extract baseline bin + editable source + poc. Returns (crashed, poc_path, issue,
    source_root).

    n132 image entries use ``extract_n132_image`` (source at source_tree_root, issue=None).
    Classic gcr-ARVO entries (a bare ``local_id``, e.g. selinux) mirror setup_cve_arvo:
    fetch the ARVO issue, download the PoC, build the baseline via source-intercept
    (``gcr.io/oss-fuzz/<local_id>`` is a BUILD image with an empty /out — it must be
    compiled), fall back to image /src extraction if the intercept tree is empty, copy the
    built /out, and verify the baseline reproduces. The build's source_dir becomes the
    persistent source_root (NOT deleted — the online loop rebuilds from it each round).
    """
    if entry.get("kind") == "fuzzbench":
        from prework.prework_build import rebuild_with_prework_image
        image = prework_image_for(entry)
        src_root = Path(source_tree_root)
        src_root.mkdir(parents=True, exist_ok=True)
        if not phase2_setup.extract_source_from_image(image, str(src_root)):
            logger.error("online: fuzzbench source extract failed for %s", project)
            return False, None, None, source_tree_root
        proj_src = phase2_setup._find_project_source(src_root, project)
        built = rebuild_with_prework_image(
            entry=entry, source_dir=proj_src, out_dir=baseline_bin_dir,
            capture_log=True)
        ok = built[0] if isinstance(built, tuple) else built
        if not ok:
            logger.error("online: fuzzbench baseline build failed for %s", project)
            return False, None, None, source_tree_root
        # No injected bug: no crash, no PoC, no ARVO issue. Downstream gates treat a
        # missing poc_path as bug_survived == "no-poc" (throughput-only).
        logger.info("online: fuzzbench baseline built for %s (throughput-only, no PoC)",
                    project)
        return False, None, None, source_tree_root

    if _is_n132_entry(entry):
        crashed, _log = phase2_setup.extract_n132_image(
            str(entry["image"]), source_dir=Path(source_tree_root),
            baseline_bin_dir=baseline_bin_dir, poc_dir=poc_dir)
        poc = os.path.join(poc_dir, "poc_input")
        return crashed, (poc if os.path.exists(poc) else None), None, source_tree_root

    local_id = int(entry["local_id"])
    arvo_util = phase2_setup._lazy_import_arvo()
    issue = arvo_util.fetch_arvo_issue(local_id)
    if not issue:
        logger.error("online: fetch_arvo_issue failed for local_id %s", local_id)
        return False, None, None, source_tree_root
    os.makedirs(poc_dir, exist_ok=True)
    poc = arvo_util.download_arvo_poc(issue, poc_dir)
    poc_path = str(poc) if poc else None
    if not poc_path or not os.path.exists(poc_path):
        logger.error("online: PoC download failed for %s", entry["cve"])
        return False, None, issue, source_tree_root

    # Extract /src from the EXISTING gcr.io/oss-fuzz/<local_id> image (docker cp, no
    # image rebuild), then compile the unmodified source in that image to produce the
    # baseline binary. This deliberately avoids build_arvo_with_source_intercept, which
    # docker-builds the OSS-Fuzz image from scratch and fails here. Building the baseline
    # via the same compile path the online rounds use also proves the rebuild works.
    src_subdir = Path(source_tree_root) / "src"
    src_subdir.mkdir(parents=True, exist_ok=True)
    if not phase2_setup.extract_source_from_arvo_image(local_id, str(src_subdir)):
        logger.error("online: source extract from image failed for %s", entry["cve"])
        return False, poc_path, issue, source_tree_root
    built = phase2_setup.rebuild_with_modified_source_arvo(
        local_id, issue, Path(source_tree_root), baseline_bin_dir, capture_log=True)
    ok = built[0] if isinstance(built, tuple) else built
    if not ok:
        logger.error("online: baseline compile failed for %s", entry["cve"])
        return False, poc_path, issue, source_tree_root
    crashed = phase2_setup.verify_poc_crash(baseline_bin_dir, fuzz_target, poc_path)
    return crashed, poc_path, issue, source_tree_root


def _stage_online_seed_corpus(experiment_dir: str, bin_dir: str,
                              fuzz_target: str) -> int:
    """Unpack the target's bundled seed corpus into the layout phase 3 reads.

    The zip only exists for projects whose build.sh produces one (wolfssl and
    selinux here; libxml2 and libavc ship a dictionary instead), so the 1-byte
    fallback is a legitimate outcome rather than an error -- but an EMPTY
    directory is not: AFL aborts at startup on an empty -i.

    Deliberately reads the zip out of the extracted /out rather than going through
    phase2_setup.download_seed_corpus, whose ARVO branch needs the legacy arvo
    module and whose build branch needs an oss-fuzz checkout. Neither exists on a
    machine brought up by bootstrap_server.py; both would silently return zero
    seeds and leave the fallback as the only input.

    Returns the number of seed files staged.
    """
    corpus_root = os.path.join(experiment_dir, "seed_corpus")
    build_dir = os.path.join(corpus_root, "build")
    merged_dir = os.path.join(corpus_root, "merged")
    os.makedirs(build_dir, exist_ok=True)

    seed_zip = os.path.join(bin_dir, f"{fuzz_target}_seed_corpus.zip")
    if not os.path.isfile(seed_zip):
        # FuzzBench builds emit a generically-named seed_corpus.zip rather than
        # <target>_seed_corpus.zip. Without this fallback the target fuzzes from
        # the 1-byte seed and the queue never gets past shallow inputs -- which is
        # exactly what makes a profile/coverage run meaningless for those targets.
        alt = os.path.join(bin_dir, "seed_corpus.zip")
        if os.path.isfile(alt):
            seed_zip = alt
    if os.path.isfile(seed_zip):
        try:
            with zipfile.ZipFile(seed_zip) as zf:
                zf.extractall(build_dir)
        except (zipfile.BadZipFile, OSError) as e:
            logger.warning("online: could not unpack %s: %s", seed_zip, e)

    staged = sum(len(files) for _r, _d, files in os.walk(build_dir))
    if staged:
        corpus_util.merge_corpus_dirs([build_dir], merged_dir)
    corpus_util.ensure_fallback_seed(merged_dir)
    logger.info("online: seed corpus for %s: %d bundled file(s)%s",
                fuzz_target, staged, "" if staged else " (using 1-byte fallback)")
    return staged


def _build_afl_baseline(*, entry: dict, project_src_dir: str, baseline_bin_dir: str,
                        fuzz_target: str, poc_path: str | None,
                        profile_cpu: int | None) -> bool:
    """Replace the extracted historical /out with a pinned AFL++ build of it.

    Compiles the unmodified source in the prework image, which also drops
    afl-fuzz and afl-showmap into the bin dir (OSS-Fuzz's compile_afl copies
    ``afl-*`` into $OUT) -- the trials and the replay gate both run those from
    the mounted /out.

    Re-verifies the PoC afterwards. The `arvo` verdict from extraction only
    proves the bug is in the HISTORICAL binary; this proves it survived the
    toolchain change, which is the binary the campaign actually measures. A
    target that fails here is excluded rather than patched around.
    """
    from prework.prework_build import rebuild_with_prework_image

    project = entry["project"]
    # Wipe first: `compile` writes into a bind-mounted /out without clearing it,
    # so surviving libFuzzer siblings would sit next to the AFL build looking
    # equally legitimate to anything that globs the directory.
    shutil.rmtree(baseline_bin_dir, ignore_errors=True)
    os.makedirs(baseline_bin_dir, exist_ok=True)

    # counts=False: this build produces the binary BOTH arms start from, before
    # any fuzzing begins. It is setup, not a cost the online arm pays and the
    # baseline does not, so charging it as optimization CPU would overstate the
    # very number the coverage plot is meant to show. Still recorded, because
    # "how long before trials start" is worth being able to reconstruct.
    with cpu_ledger.timed("baseline_afl_build", cores=1, counts=False) as info:
        built = rebuild_with_prework_image(
            entry=entry, source_dir=project_src_dir, out_dir=baseline_bin_dir,
            capture_log=True, cpu=profile_cpu)
        ok, log = built if isinstance(built, tuple) else (built, "")
        info["ok"] = bool(ok)
    if not ok:
        logger.error("online: AFL baseline build failed for %s: %s",
                     project, log[-600:])
        return False
    if not os.path.isfile(os.path.join(baseline_bin_dir, fuzz_target)):
        logger.error("online: AFL baseline build produced no /out/%s for %s",
                     fuzz_target, project)
        return False

    if poc_path and os.path.isfile(poc_path):
        if not phase2_setup.verify_poc_crash(baseline_bin_dir, fuzz_target,
                                             poc_path, cpu=profile_cpu,
                                             image=prework_image_for(entry)):
            logger.error("online: PoC does not reproduce on the AFL baseline for "
                         "%s -- excluding this target", project)
            return False
        logger.info("online: AFL baseline reproduces the PoC for %s", project)

    # This build happens BEFORE the tree is git-initialised, so without a clean
    # its objects would land in the iter_00 commit and every later `git diff
    # iter_00 HEAD` would carry object-file churn alongside the optimizer's edits.
    phase2_setup._clean_build_artifacts(project_src_dir)
    return True


def _seed_corpus_provenance(experiment_dir: str) -> dict:
    """What seeds the campaign actually started from.

    A 1-byte fallback seed is a legitimate outcome (only some targets ship a
    corpus zip) but it is a materially different starting point from a real
    corpus, and today that distinction exists only in a log line.
    """
    merged = Path(experiment_dir) / "seed_corpus" / "merged"
    try:
        files = [f for f in merged.iterdir() if f.is_file()]
    except OSError:
        return {"staged": 0, "fallback_only": None}
    fallback = [f for f in files if f.name.startswith("seed_fallback")]
    return {
        "staged": len(files),
        "fallback_only": bool(files) and len(fallback) == len(files),
        "total_bytes": sum(f.stat().st_size for f in files),
    }


def _measure_noise_floor(*, ctx_entry, source_root, fuzz_target, online_dir,
                         profile_cpu, rounds: int) -> dict:
    """Rebuild unmodified source `rounds` times and replay-measure each.

    Uses the SAME rebuild and replay paths the gate uses, so the number is
    comparable to the speedups the gate reports -- a noise floor measured a
    different way would not be.
    """
    import functools
    import tempfile as _tf
    from lib import afl_replay
    from prework.prework_build import prework_image_for, rebuild_with_prework_image

    image = prework_image_for(ctx_entry)
    # <experiment_dir>/seed_corpus/merged -- online_dir is
    # <experiment_dir>/optimized/online, so this is TWO levels up, not one.
    # With one the path resolved to <experiment_dir>/optimized/seed_corpus/merged,
    # an empty directory that happens to exist, and afl-showmap aborted with
    # "could not read input testcases from /corpus" on every noise-floor round.
    #
    # Caveat that survives this fix: at setup time the only corpus available is
    # whatever _stage_online_seed_corpus harvested. For a target whose OSS-Fuzz
    # public corpus is missing that is a single 1-byte fallback seed, and a
    # variance estimate over one tiny input says little about the variance of a
    # real replay. The number is honest only when a real seed corpus exists.
    corpus = os.path.join(
        os.path.dirname(os.path.dirname(online_dir.rstrip("/"))),
        "seed_corpus", "merged")
    fixed = phase2_setup._phase2_fixed_corpus_dir(os.path.join(online_dir, "iter_00"))
    corpus_dir = fixed if phase2_setup._dir_has_files(fixed) else corpus
    workdirs = []

    def _rebuild():
        d = _tf.mkdtemp(prefix="noisefloor-", dir=online_dir)
        workdirs.append(d)
        ok = rebuild_with_prework_image(
            entry=ctx_entry, source_dir=str(source_root), out_dir=d,
            cpu=profile_cpu)
        # rebuild_with_prework_image has no fuzz_target parameter; the target
        # name comes from the image's own build.sh. Verify the binary landed
        # rather than trusting the return value alone.
        return d if (ok and os.path.isfile(os.path.join(d, fuzz_target))) else None

    # Same kwargs the real replay gate uses (phase2_setup.run_replay_speedup).
    # These three were missing, so every noise-floor measurement died with
    # "measure_binary() missing 3 required keyword-only arguments" and the
    # campaign recorded measured=false -- i.e. the accept threshold has been
    # read against no baseline variance at all since the feature landed.
    measure = functools.partial(
        afl_replay.measure_binary, image=image, corpus_dir=str(corpus_dir),
        fuzz_target=fuzz_target, cpu=profile_cpu,
        repeats=int(getattr(config, "PHASE2_REPLAY_REPEATS", 3)),
        seed=int(getattr(config, "BASE_SEED", 1337)),
        memory=getattr(config, "MEMORY_LIMIT", "4g"),
        shm_size=getattr(config, "DOCKER_SHM_SIZE", "2g"),
        run_timeout=int(getattr(config, "TRIAL_DURATION_SECS", 3600)))
    try:
        return provenance.noise_floor(_rebuild, lambda d: measure(out_dir=d),
                                      rounds=rounds)
    finally:
        for d in workdirs:
            shutil.rmtree(d, ignore_errors=True)


def run_online(entry: dict, experiment_id: str, duration: int | None = None) -> bool:
    """Top-level online-optimization run for ONE target (LOCAL backend).

    Extracts the n132 image once (baseline + source + poc), seeds the live optimized/bin
    from the baseline (iteration 0), starts 10 baseline + 10 online trials with the
    bespoke monitor, and drives the sequential optimizer loop (snapshot -> round ->
    hot-swap) to convergence while all trials fuzz to the end of the budget.
    """
    if duration is None:
        duration = getattr(config, "TRIAL_DURATION_SECS", 21600)
    project = entry["project"]
    fuzz_target = entry.get("fuzz_target", "")
    if not fuzz_target:
        logger.error("online: entry %s has no fuzz_target", entry.get("cve"))
        return False
    image = str(entry.get("image") or "")

    experiment_dir = phase2_setup.get_experiment_dir(experiment_id, entry)
    os.makedirs(experiment_dir, exist_ok=True)
    online_dir = os.path.join(experiment_dir, "optimized", "online")
    os.makedirs(online_dir, exist_ok=True)
    source_tree_root = os.path.join(online_dir, "source_tree")
    baseline_bin_dir = os.path.join(experiment_dir, "baseline", "bin")
    optimized_bin_dir = os.path.join(experiment_dir, "optimized", "bin")
    poc_dir = os.path.join(experiment_dir, "poc")

    _pcpu = os.environ.get("ONLINE_PROFILE_CPU") or getattr(config, "ONLINE_PROFILE_CPU", "")
    profile_cpu = int(_pcpu) if str(_pcpu).strip() else max(
        int(getattr(config, "RESERVED_CORES", 1)) - 1, 0)

    # Point every CPU-ledger writer at one file for this target. Set in the
    # environment (not passed down) because the broker serves the sandboxed agent
    # from a separate host process and phase 2 runs several layers below here;
    # both inherit it. Set before the baseline build rather than beside the
    # RoundContext below, because recording starts at the first thing worth
    # recording -- a ledger that only opens after setup silently drops it.
    cpu_ledger.set_ledger_path(os.path.join(online_dir, "cpu_ledger.jsonl"))
    cpu_ledger.set_round(project=project, iter_n=0)

    # 1. extract baseline bin + editable source + poc (n132 image OR classic gcr-ARVO)
    if os.path.isdir(source_tree_root):
        shutil.rmtree(source_tree_root, ignore_errors=True)
    os.makedirs(source_tree_root, exist_ok=True)
    crashed, poc_path, issue, source_root = _extract_online_target(
        entry, source_tree_root, baseline_bin_dir, poc_dir, fuzz_target, project)
    if not os.path.isfile(os.path.join(baseline_bin_dir, fuzz_target)):
        logger.error("online: extract did not yield baseline /out/%s for %s",
                     fuzz_target, entry["cve"])
        return False
    # The baseline-reproduces gate is PoC-specific: it guards ARVO targets whose
    # bug-survival signal is only meaningful once the freshly-built baseline is
    # confirmed to still crash on the known PoC. FuzzBench targets ship no PoC
    # (the fuzzer must FIND the bug), so `crashed` is always False there and this
    # gate would abort every fuzzbench run before a single trial. For them the
    # run is throughput-only and bug-survival is informational, so skip it.
    requires_poc = entry.get("kind") != "fuzzbench"
    if requires_poc and not crashed:
        logger.error("online: baseline did not reproduce for %s", entry["cve"])
        return False
    if not requires_poc:
        logger.info("online: fuzzbench target %s -- skipping PoC gate "
                    "(throughput-only, bug-survival informational)", entry["cve"])

    project_src_dir = str(phase2_setup._find_project_source(Path(source_root), project))

    # 1a. Delete the repositories the extracted tree ships, before anything reads
    # it. Two independent reasons, either sufficient:
    #   * LEAK. /work/src is bind-mounted writable into the agent. libxml2's tree
    #     carries origin/master 2308 commits PAST the vulnerable revision -- the
    #     fix itself -- plus CVE-named tags; wolfssl's is 619 MB / 22364 commits.
    #     The egress proxy blocks the network so the agent cannot look the bug up;
    #     leaving this in hands it `git diff HEAD origin/master` instead.
    #   * BUILD. wolfssl's autogen.sh sets WARNINGS="all,error" when it sees a
    #     .git, and clang 18 warns where clang 12 did not, so every rebuild fails.
    # Applied to the source ROOT: wolfssl's build copies sibling checkouts
    # (wolfssh, wolf-ssl-ssh-fuzzers, fuzzing-headers) into its build dir.
    tracked_git.strip_vcs_metadata(source_root)

    # 1b. Seeds, harvested from the extracted /out BEFORE the AFL rebuild replaces
    # it. Nothing else stages a seed corpus on this path, and AFL refuses to start
    # on an empty -i directory, so without this every trial dies at calibration.
    _stage_online_seed_corpus(experiment_dir, baseline_bin_dir, fuzz_target)

    # 1c. Rebuild the UNMODIFIED source through the pinned prework image.
    #
    # The extracted /out is the historical ARVO build: libFuzzer-instrumented,
    # built by whatever clang that target shipped, and carrying no afl-fuzz. The
    # trials run `/out/afl-fuzz -- /out/<target>` out of this very directory, so
    # keeping it would mean the baseline arm could not start at all -- and if it
    # somehow did, it would be measuring a different engine and a different
    # compiler from the online arm, which rebuilds through the prework image every
    # round. Both arms must come out of the same pinned AFL++ v5.02c / LLVM 18
    # toolchain or the comparison means nothing.
    if not _build_afl_baseline(entry=entry, project_src_dir=project_src_dir,
                               baseline_bin_dir=baseline_bin_dir,
                               fuzz_target=fuzz_target, poc_path=poc_path,
                               profile_cpu=profile_cpu):
        return False

    # Build-to-build noise floor, measured once here on UNMODIFIED source so the
    # gate's accept threshold can be read against the target's own variance.
    _nf_rounds = int(getattr(config, "PROVENANCE_NOISE_FLOOR", 0) or 0)
    if _nf_rounds >= 2:
        try:
            _nf = _measure_noise_floor(ctx_entry=entry, source_root=project_src_dir,
                                       fuzz_target=fuzz_target, online_dir=online_dir,
                                       profile_cpu=profile_cpu, rounds=_nf_rounds)
            logger.info("noise floor: spread=%s%% -> folds below %sx are inside "
                        "the target's own measurement noise",
                        _nf.get("spread_pct"), _nf.get("min_meaningful_speedup"))
            provenance.write_json(os.path.join(online_dir, "noise_floor.json"), _nf)
        except Exception as e:  # noqa: BLE001 - never block a campaign on this
            logger.warning("noise floor measurement failed: %s", e)

    # 2. build the two arms first -- per-trial mode needs each trial's identity
    #    (and its own bin dir) before any context can be constructed.
    baseline_trials, online_trials = _build_online_trials(entry, experiment_dir)
    state = OnlineState()
    per_trial = bool(getattr(config, "ONLINE_PER_TRIAL_OPTIMIZER", False))

    # 3. iteration 0 = original baseline; seed each optimizer's live binary and
    #    give each its own source tree, git-tagged iter_00.
    contexts = []
    if per_trial:
        opt_cores = parse_cpu_range(getattr(config, "ONLINE_OPTIMIZER_CORES", "24-39"))
        trials_root = os.path.join(online_dir, "trials")
        for t in online_trials:
            tdir = os.path.join(trials_root, f"trial_{t.trial_id:02d}")
            os.makedirs(tdir, exist_ok=True)
            # Independent source tree per optimizer. A shared tree would make the
            # ten optimizers edit, git-tag and revert the same working copy, so
            # trial 3's rejected round would revert trial 7's accepted one.
            t_src_root = os.path.join(tdir, "source_root")
            if os.path.isdir(t_src_root):
                shutil.rmtree(t_src_root, ignore_errors=True)
            shutil.copytree(source_root, t_src_root, symlinks=True)
            t_src = str(phase2_setup._find_project_source(Path(t_src_root), project))
            _git_init_baseline(t_src)
            _commit_and_tag(t_src, "iter_00")

            live_bin = str(t.bin_dir_override)
            os.makedirs(live_bin, exist_ok=True)
            shutil.copytree(baseline_bin_dir, live_bin, dirs_exist_ok=True)
            t_iter0 = os.path.join(tdir, "iter_00", "bin")
            os.makedirs(t_iter0, exist_ok=True)
            shutil.copytree(baseline_bin_dir, t_iter0, dirs_exist_ok=True)

            # One profiling core per optimizer, round-robin over the optimizer
            # pool. Kept off the trial cores so profiling never steals CPU from
            # the fuzzing it is measured against.
            t_cpu = opt_cores[t.trial_id % len(opt_cores)]
            t_rebuild, t_wrapper = _online_target_strategy(
                entry, fuzz_target, issue=issue, profile_cpu=t_cpu)
            tctx = RoundContext(
                entry=entry, experiment_id=experiment_id, experiment_dir=experiment_dir,
                online_dir=tdir, source_tree=t_src, source_root=t_src_root,
                project=project, image=image,
                fuzz_target=fuzz_target, poc_path=poc_path, previous_best_bin=t_iter0,
                prev_tag="iter_00", optimized_bin_dir=live_bin,
                ledger_path=os.path.join(tdir, "ledger.json"),
                swap_timeline_path=os.path.join(tdir, "swap_timeline.json"),
                profile_cpu=t_cpu, rebuild_fn=t_rebuild, wrapper_env_fn=t_wrapper,
                trial=t)
            tctx.online_trials = [t]
            contexts.append(tctx)
        logger.info("per-trial optimizers: %d contexts, profile cores %s",
                    len(contexts), sorted({c.profile_cpu for c in contexts}))
        ctx = contexts[0]        # representative, for the campaign-level summary
    else:
        os.makedirs(optimized_bin_dir, exist_ok=True)
        shutil.copytree(baseline_bin_dir, optimized_bin_dir, dirs_exist_ok=True)
        iter0_bin = os.path.join(online_dir, "iter_00", "bin")
        os.makedirs(iter0_bin, exist_ok=True)
        shutil.copytree(baseline_bin_dir, iter0_bin, dirs_exist_ok=True)
        _git_init_baseline(project_src_dir)
        _commit_and_tag(project_src_dir, "iter_00")
        rebuild_fn, wrapper_env_fn = _online_target_strategy(
            entry, fuzz_target, issue=issue, profile_cpu=profile_cpu)
        ctx = RoundContext(
            entry=entry, experiment_id=experiment_id, experiment_dir=experiment_dir,
            online_dir=online_dir, source_tree=project_src_dir, source_root=source_root,
            project=project, image=image,
            fuzz_target=fuzz_target, poc_path=poc_path, previous_best_bin=iter0_bin,
            prev_tag="iter_00", optimized_bin_dir=optimized_bin_dir,
            ledger_path=os.path.join(online_dir, "ledger.json"),
            swap_timeline_path=os.path.join(online_dir, "swap_timeline.json"),
            profile_cpu=profile_cpu, rebuild_fn=rebuild_fn, wrapper_env_fn=wrapper_env_fn)
        ctx.online_trials = online_trials
        contexts = [ctx]

    # Campaign provenance, written once, before any trial starts. Each field is
    # here because its absence previously cost an investigation: the host's
    # core_pattern (an apport storm held ~8000% CPU against fuzzers at 188%),
    # the orchestrator's peak RSS (a 239 GiB OOM killed a campaign leaving no
    # trace of the approach), the seed corpus actually staged (a 1-byte fallback
    # is legitimate but silently different from a real corpus), and the
    # optimizer's model (unrecoverable for every run b1..b6).
    _rss = provenance.PeakRSS().start()
    _campaign = {
        "experiment_id": experiment_id,
        "project": project,
        "cve": entry.get("cve"),
        "fuzz_target": fuzz_target,
        "started_at": time.time(),
        "duration_s": duration,
        "trials_per_arm": len(online_trials),
        "trial_cores": [t.cpu for t in baseline_trials + online_trials],
        "profile_cpu": profile_cpu,
        "host": provenance.host_environment(),
        "optimizer": phase2_setup.optimizer_provenance(),
        "seed_corpus": _seed_corpus_provenance(experiment_dir),
        "baseline_toolchain": provenance.binary_fingerprint(
            prework_image_for(entry), baseline_bin_dir, fuzz_target),
        # The experiment's SHAPE. b1..b6 ran one optimizer over a shared binary;
        # anything comparing across designs has to be able to tell which it was,
        # and that is not recoverable from the outputs alone.
        "design": {
            "per_trial_optimizer": per_trial,
            "optimizers": len(contexts),
            "fixed_mutation_corpus": bool(
                getattr(config, "ONLINE_FIXED_MUTATION_CORPUS", False)),
            "mutation_corpus_source": ("own-trial" if per_trial else "pooled"),
            "optimizer_stagger_s": int(
                getattr(config, "ONLINE_OPTIMIZER_STAGGER_SECS", 0) or 0),
            "swap_interval_s": int(getattr(config, "ONLINE_SWAP_INTERVAL_SECS", 0) or 0),
        },
        # -O level both arms were built at. "" means the OSS-Fuzz default (-O1).
        # A throughput number is only comparable to another run at the same level.
        "build_opt_level": str(getattr(config, "BUILD_OPT_LEVEL", "") or ""),
        "restart_policy": {
            "mirror_swaps": bool(getattr(config, "BASELINE_RESTART_MIRROR_SWAPS", False)),
            "interval_secs": int(getattr(config, "BASELINE_RESTART_INTERVAL_SECS", 0) or 0),
            "arm": str(getattr(config, "BASELINE_RESTART_ARM", "baseline")),
        },
    }
    provenance.write_json(os.path.join(online_dir, "campaign_provenance.json"),
                          _campaign)
    logger.info("campaign provenance: host core_pattern=%s, cxx_dynamic=%s, optimizer=%s",
                _campaign["host"].get("kernel_core_pattern"),
                _campaign["baseline_toolchain"].get("cxx_runtime_dynamically_linked"),
                _campaign["optimizer"].get("model"))

    # 4. start all trials + monitors (baseline reuses phase3_runner.monitor_trial)
    executor = ThreadPoolExecutor(max_workers=len(baseline_trials) + len(online_trials))
    futures = []
    for t in baseline_trials:
        if phase3_runner.start_trial(t, experiment_id, duration):
            futures.append(executor.submit(phase3_runner.monitor_trial, t, experiment_id, duration))
    for t in online_trials:
        if not phase3_runner.start_trial(t, experiment_id, duration):
            continue
        state.trials[t.trial_id] = {
            "overall_start": t.start_time or time.time(), "state": "running",
            "crash_times": [], "seen_crashes": set(),
            "relaunched": threading.Event(),
            # Per-trial swap signalling, created up front rather than lazily on
            # the first swap: the monitor reads these the moment its container
            # exits, and a record that does not yet carry them silently falls
            # back to the global barrier -- which in per-trial mode is never set,
            # so a genuine swap would be misread as the trial having died.
            **({"swap_barrier": threading.Event(),
                "relaunch_ready": threading.Event()} if per_trial else {})}
        futures.append(executor.submit(_monitor_online_trial, t, experiment_id, duration, state))

    # 5. optimizer loops (fuzzing continues to budget regardless).
    #
    # Per-trial mode runs ONE loop per optimized trial, concurrently. They share
    # nothing but the host: each has its own source tree, its own binary, its own
    # ledger, its own fixed mutation corpus and its own profiling core, so the
    # ten optimized trials are ten independent draws rather than ten copies of
    # one. Legacy mode keeps the single sequential loop over a shared binary.
    _conv_k = getattr(config, "ONLINE_CONVERGENCE_K", 2)
    _interval = getattr(config, "ONLINE_SWAP_INTERVAL_SECS", 3600)

    _stagger = int(getattr(config, "ONLINE_OPTIMIZER_STAGGER_SECS", 0) or 0)

    def _drive(c: RoundContext) -> int:
        tid = c.trial.trial_id if c.trial is not None else -1
        # Offset this optimizer from its siblings before its first round. See
        # ONLINE_OPTIMIZER_STAGGER_SECS: ten simultaneous agent sessions against
        # one account invite rate-limiting, and ten simultaneous rebuilds spike
        # the profile cores together.
        if _stagger and tid > 0:
            logger.info("trial_%02d optimizer: staggering first round by %ds",
                        tid, tid * _stagger)
            time.sleep(tid * _stagger)
        # Tag this thread's ledger rows; the environment tag is process-global
        # and would otherwise be overwritten by whichever optimizer ran last.
        cpu_ledger.set_thread_round(project=c.project, iter_n=0, trial_id=tid)
        try:
            return run_optimizer_loop(
                run_round_fn=lambda i: run_round(c, state, i),
                hot_swap_fn=lambda nb: (hot_swap_one(c, state, nb) if c.trial is not None
                                        else hot_swap(c, state, nb)),
                convergence_k=_conv_k,
                wait_fn=lambda: time.sleep(_interval),
                all_terminal_fn=(
                    (lambda: state.trials.get(tid, {}).get("state") != "running")
                    if c.trial is not None else
                    (lambda: all(state.trials.get(t.trial_id, {}).get("state") != "running"
                                 for t in online_trials))))
        except Exception:   # noqa: BLE001
            # One optimizer dying must not take the other nine (or the fuzzing)
            # with it. The trial keeps fuzzing whatever binary it currently has.
            logger.exception("optimizer for trial_%02d died; its trial keeps "
                             "fuzzing its current binary", tid)
            return c.iter_n

    if per_trial:
        opt_pool = ThreadPoolExecutor(max_workers=len(contexts),
                                      thread_name_prefix="opt")
        opt_futures = [opt_pool.submit(_drive, c) for c in contexts]
        for _f in as_completed(opt_futures):
            pass
        opt_pool.shutdown(wait=True)
    else:
        _drive(ctx)

    for _ in as_completed(futures):
        pass
    executor.shutdown(wait=True)
    for _c in contexts:
        _write_cpu_cost_summary(_c)
    # Campaign-level rollup. Every optimizer appends to ONE ledger (the path is
    # set process-wide before any of them start), so this is the whole campaign's
    # cost -- but _write_cpu_cost_summary writes it into each optimizer's OWN
    # dir, and analysis/plot_coverage_growth.py reads optimized/online/cpu_cost.json.
    # Without this the coverage plots silently lose CPU charging entirely.
    if per_trial:
        try:
            _agg = cpu_ledger.summarize(
                cpu_ledger.load(cpu_ledger.ledger_path()),
                trial_cores=len(online_trials) or None)
            _agg["project"] = project
            _agg["cve"] = entry.get("cve")
            _agg["optimizers"] = len(contexts)
            _agg["per_trial_optimizer"] = True
            _write_json(os.path.join(online_dir, "cpu_cost.json"), _agg)
            logger.info("campaign cpu cost: %s core-seconds (%.1fh of fuzzing "
                        "equivalent) across %d optimizers",
                        _agg.get("total_core_s"),
                        float(_agg.get("total_fuzz_seconds_equivalent") or 0) / 3600.0,
                        len(contexts))
        except Exception as e:  # noqa: BLE001 - accounting must never kill a run
            logger.warning("campaign cpu cost rollup failed: %s", e)
    _campaign["finished_at"] = time.time()
    _campaign["orchestrator"] = _rss.stop()
    _campaign["rounds_attempted"] = (
        {c.trial.trial_id: c.iter_n for c in contexts} if per_trial else ctx.iter_n)
    provenance.write_json(os.path.join(online_dir, "campaign_provenance.json"),
                          _campaign)
    logger.info("online: run complete for %s (rounds attempted: %s, orchestrator "
                "peak RSS %s MB)", entry["cve"], _campaign["rounds_attempted"],
                _campaign["orchestrator"].get("peak_rss_mb"))
    return True


def _write_cpu_cost_summary(ctx: RoundContext) -> dict | None:
    """Roll the raw ledger up into cpu_cost.json beside it.

    Written at campaign end, and again after every round so a run inspected (or
    killed) mid-campaign still has a readable summary. ``trial_cores`` is the
    online arm's core count, which is what converts core-seconds into the
    fuzzing wall-clock a coverage plot needs.
    """
    path = cpu_ledger.ledger_path()
    if not path or not os.path.exists(path):
        return None
    try:
        rows = cpu_ledger.load(path)
        # All ten optimizers append to ONE ledger (the path is process-wide), so
        # summarizing it unfiltered puts the WHOLE campaign's cost into each
        # optimizer's own cpu_cost.json -- a file under trials/trial_03/ that
        # actually reports all ten. Filter to this optimizer's rows; the
        # campaign-wide rollup is written separately at the end of run_online.
        if ctx.trial is not None:
            rows = [r for r in rows if r.get("trial_id") == ctx.trial.trial_id]
        summary = cpu_ledger.summarize(
            rows, trial_cores=len(ctx.online_trials) or None)
        if ctx.trial is not None:
            summary["trial_id"] = ctx.trial.trial_id
            summary["scope"] = "this optimizer only"
        summary["project"] = ctx.project
        summary["cve"] = ctx.entry.get("cve")
        summary["profile_cpu"] = ctx.profile_cpu
        _write_json(os.path.join(ctx.online_dir, "cpu_cost.json"), summary)
        return summary
    except Exception as e:  # noqa: BLE001 - accounting must never kill a run
        logger.warning("cpu cost summary failed: %s", e)
        return None
