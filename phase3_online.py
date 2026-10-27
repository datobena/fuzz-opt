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
from prework.prework_build import build_opt_provenance, prework_image_for
from prework import fb_ccache
from lib import afl
from lib import afl_launch
from lib import corpus as corpus_util
from lib import tracked_git
from lib import cpu_ledger, crash_classify, docker_util
from lib import afl_replay
from lib.live_binary import live_binary as _live_binary

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


def _copy_units(files, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for f in files:
        shutil.copy2(f, dest / f.name)


def _gate_replay_rate(experiment_dir) -> float | None:
    """Inputs/s the replay gate last measured on this target, or None."""
    try:
        d = json.loads(phase2_setup._replay_rate_path(experiment_dir).read_text())
        return float(d.get("units_per_s") or 0) or None
    except (OSError, ValueError, TypeError):
        return None


def prepare_round_corpus(*, mutations_dir, out_root, previous_best_bin, fuzz_target,
                         image, cpu, seed, replay_rate=None,
                         find_crashers_fn=None) -> dict | None:
    """Turn a round's harvested mutations into the sets the round uses.

    Only the inputs the round USES are crash-filtered -- a full pass over every
    harvested mutation costs ~7 min at 50 inputs/s for inputs nobody replays.

    1. smoke   -- ONLINE_SMOKE_FRACTION of the harvest: what the agent's smoke
                  runs. Filtered first; with no gate rate yet (round 1) that
                  pass also measures the replay speed used for sizing.
    2. tuning  -- capped to what one replay pass runs in PHASE2_REPLAY_BUDGET_SECS
                  at this target's speed. Used by the profile and every agent
                  replay. Speed is ``replay_rate`` (what the gate last measured)
                  when known, else the smoke filter pass's rate, which runs ~2x
                  faster than a timing pass (bloaty: 617 vs 308 inputs/s), so
                  round 1 may overshoot the budget.
    3. gate    -- what the final gate times: tuning-sized, a different sample
                  (overlaps tuning only when the harvest is too small for two
                  disjoint samples). Equal to tuning when nothing needs shrinking.
    4. checked -- tuning + gate + smoke: every input filtered, and what the
                  gate's crash check runs on the new build. With
                  ONLINE_GATE_FULL_SET=1 it is the whole harvest.

    Filtering drops every input that crashes the previous-best binary: the
    fuzzer runs a vulnerable binary and its sampled stream includes inputs that
    crash it; dropping them is what makes a later crash on the new build the
    agent's own doing. Samples are deterministic per round (``seed``). Returns
    None when a filter pass did not run over every input or nothing survived --
    the round must not go on to blame the agent for crashes the round-start
    binary already has.
    """
    find = find_crashers_fn or afl_replay.find_crashers
    mutations_dir, out_root = Path(mutations_dir), Path(out_root)
    harvest = sorted(p for p in mutations_dir.iterdir()
                     if p.is_file() and p.stat().st_size > 0)
    if not harvest:
        return None

    def stage(name, files):
        d = out_root / name
        if d.exists():
            shutil.rmtree(d)
        _copy_units(sorted(files), d)
        return d

    scanned, crashers, scan_secs = set(), set(), 0.0

    def scan(files, name):
        nonlocal scan_secs
        todo = [f for f in files if f.name not in scanned]
        if not todo:
            return 0.0
        d = stage(name, todo)
        r = find(out_dir=previous_best_bin, corpus_dir=d, fuzz_target=fuzz_target,
                 cpu=cpu, image=image)
        shutil.rmtree(d, ignore_errors=True)
        if not r["ok"]:
            logger.warning("crash filter did not cover the %s set (%s of %s inputs): %s",
                           name, r.get("scanned"), r.get("expected"),
                           (r.get("log") or "")[-400:])
            return None
        scanned.update(f.name for f in todo)
        crashers.update(set(r["crashers"]) & {f.name for f in todo})
        scan_secs += r.get("seconds") or 0.0
        return (r["scanned"] / r["seconds"]) if r.get("seconds") else 0.0

    frac = float(getattr(config, "ONLINE_SMOKE_FRACTION", 0.05))
    n_smoke = min(len(harvest), max(1, int(round(frac * len(harvest)))))
    smoke_files = random.Random(seed + 1).sample(harvest, n_smoke)
    filter_rate = scan(smoke_files, "scan_smoke")
    if filter_rate is None:
        return None

    rate = replay_rate or filter_rate
    budget = int(getattr(config, "PHASE2_REPLAY_BUDGET_SECS", 0))
    manual = int(getattr(config, "PHASE2_REPLAY_MAX_UNITS", 0))
    n_tune = len(harvest)
    if budget > 0 and rate > 0:
        n_tune = min(n_tune, max(1, int(budget * rate)))
    if manual > 0:
        n_tune = min(n_tune, manual)
    if n_tune < len(harvest):
        tuning_files = random.Random(seed).sample(harvest, n_tune)
        tuned = set(tuning_files)
        rest = [f for f in harvest if f not in tuned]
        pick = random.Random(seed + 2)
        if len(rest) >= n_tune:
            gate_files = pick.sample(rest, n_tune)
        else:
            gate_files = rest + pick.sample(tuning_files, n_tune - len(rest))
    else:
        tuning_files = gate_files = list(harvest)

    full_set = getattr(config, "ONLINE_GATE_FULL_SET", False)
    used = list(harvest) if full_set else list(
        {f.name: f for f in (*tuning_files, *gate_files, *smoke_files)}.values())
    if scan(used, "scan_rest") is None:
        return None

    keep = lambda fs: [f for f in fs if f.name not in crashers]
    tuning_files, gate_files = keep(tuning_files), keep(gate_files)
    smoke_files, used = keep(smoke_files), keep(used)
    if not used or not tuning_files:
        return None

    checked = stage("checked", used)
    if tuning_files == gate_files and len(tuning_files) == len(used):
        tuning = gate = checked          # nothing shrunk: one set for everything
    else:
        tuning, gate = stage("tuning", tuning_files), stage("gate", gate_files)
    smoke = stage("smoke", smoke_files) if smoke_files else checked
    gate_overlap = len({f.name for f in tuning_files} & {f.name for f in gate_files})

    return {
        "checked": str(checked), "tuning": str(tuning), "gate": str(gate),
        "smoke": str(smoke),
        "harvested": len(harvest), "crashers_removed": len(crashers),
        "crashers": sorted(crashers)[:50],
        "checked_count": len(used), "tuning_count": len(tuning_files),
        "gate_count": len(gate_files), "gate_overlap_with_tuning": gate_overlap,
        "smoke_count": len(smoke_files),
        "units_per_s": round(rate, 2),
        "rate_source": "gate" if replay_rate else "smoke-filter",
        "filter_units_per_s": round(filter_rate, 2), "budget_secs": budget,
        "filter_seconds": round(scan_secs, 2),
    }


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
def build_round_env(*, experiment_dir, diff_dir, opt_bin_dir, corpus_dir,
                    entry, previous_best_bin, profile_cpu: int | None = None) -> dict:
    """Env for one online round.

    Reuse phase-2's env builder but override the profiling corpus with
    ``corpus_dir`` -- the round's harvested mutations, or (re-fuzz fallback only)
    the live queue snapshot the re-fuzz seeds from, never the bundled seeds -- and
    anchor the replay-timing gate on the previous-best binary, giving cumulative
    "each fold must beat the previous best" semantics.

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
        corpus_dir=corpus_dir, entry=entry, baseline_out_dir=previous_best_bin,
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
def _overwrite_binary(shared_bin_path, new_bin_path, *, extra_files=()) -> None:
    """Replace the live binary with the round's binary.

    ``extra_files`` (FuzzBench only) names further files, relative to the bin
    dir, that belong to the same build and must be swapped with it: the CmpLog
    binary and afl++.dict (lib/afl_launch.fuzzbench_out_set) and the build's
    runtime shared libraries (afl_launch.fuzzbench_runtime_libs). Without them
    the relaunched trial would pair the new target with the baseline's cmplog
    binary, dictionary and libraries forever.

    The set is swapped "atomically enough": every file is first copied to a
    temporary name next to its destination -- the step that can fail (disk,
    permissions) -- and only when all copies exist are they renamed into
    place, so a failure leaves the old set intact rather than a mix. A file
    the new build lacks is removed from the live set, because the launch
    builder decides -x/-c from what is present.
    """
    if not extra_files:
        shutil.copy2(str(new_bin_path), str(shared_bin_path))
        os.chmod(str(shared_bin_path), 0o755)
        return
    dst_dir = os.path.dirname(str(shared_bin_path))
    src_dir = os.path.dirname(str(new_bin_path))
    pairs = [(str(new_bin_path), str(shared_bin_path), True)]
    for rel in extra_files:
        pairs.append((os.path.join(src_dir, rel), os.path.join(dst_dir, rel), False))
    staged, removals = [], []
    try:
        for src, dst, is_target in pairs:
            if not os.path.isfile(src):
                if is_target:
                    raise FileNotFoundError(src)
                removals.append(dst)
                continue
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            tmp = os.path.join(os.path.dirname(dst),
                               f".swap-{os.getpid()}-{os.path.basename(dst)}")
            shutil.copy2(src, tmp)
            if is_target or os.access(src, os.X_OK):
                os.chmod(tmp, 0o755)
            staged.append((tmp, dst))
    except BaseException:
        for tmp, _dst in staged:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise
    # Renames within one directory: atomic per file, and nothing between them
    # can fail short of the host dying. Target last, so a reader keyed on the
    # target's mtime never sees it ahead of its companions.
    staged.sort(key=lambda p: p[1] == str(shared_bin_path))
    for tmp, dst in staged:
        os.replace(tmp, dst)
    for dst in removals:
        try:
            os.unlink(dst)
        except FileNotFoundError:
            pass


def _swap_extra_files(entry, fuzz_target) -> tuple:
    """Companion files swapped with the target: FuzzBench's whole /out set
    minus the target itself; nothing for ARVO (unchanged single-file swap)."""
    if not afl_launch.is_fuzzbench(entry):
        return ()
    return tuple(afl_launch.fuzzbench_out_set(fuzz_target)[1:])


def _swap_runtime_libs(entry, new_bin_dir, live_bin_dir) -> tuple:
    """FuzzBench only: the build's runtime shared libraries under /out (main and
    cmplog), from the new build AND the live set -- so a library the new build
    no longer has is removed rather than left behind. Swapped together with the
    target (see afl_launch.fuzzbench_runtime_libs); nothing for ARVO."""
    if not afl_launch.is_fuzzbench(entry):
        return ()
    return tuple(sorted(set(afl_launch.fuzzbench_runtime_libs(str(new_bin_dir)))
                        | set(afl_launch.fuzzbench_runtime_libs(str(live_bin_dir)))))


def _overwrite(shared_bin_path, new_bin_path, extra_files) -> None:
    # Keep the ARVO call exactly two-positional (tests stub _overwrite_binary).
    if extra_files:
        _overwrite_binary(shared_bin_path, new_bin_path, extra_files=extra_files)
    else:
        _overwrite_binary(shared_bin_path, new_bin_path)


def _stop_all_and_overwrite(running_trials, shared_bin_path, new_bin_path, *,
                            poll_sleep: float = 0.5, extra_files=()) -> None:
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
    _overwrite(shared_bin_path, new_bin_path, extra_files)


def _stop_one_and_overwrite(trial, bin_path, new_bin_path, *,
                            poll_sleep: float = 0.5, extra_files=()) -> None:
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
    _overwrite(bin_path, new_bin_path, extra_files)


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
    # Recorded against THIS trial_id, not the shared counter: only baseline
    # trial_<tid> (same common-random-numbers pair) mirrors it under
    # BASELINE_RESTART_MIRROR_SWAPS. On the shared counter every baseline would
    # restart for every optimizer's swap -- ~10x the restarts of any one
    # optimized trial. Positional, so stubs written as `lambda *a` keep working.
    gen = swap_signal.SIGNAL.record_swap(ctx.iter_n, 1, trial.trial_id)
    logger.info("trial_%02d round %d: HOT-SWAP (trial swap generation %d; "
                "baseline trial_%02d mirrors it if BASELINE_RESTART_MIRROR_SWAPS)",
                trial.trial_id, ctx.iter_n, gen, trial.trial_id)
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
    _stop_one_and_overwrite(
        trial, bin_path, new_bin,
        extra_files=(_swap_extra_files(ctx.entry, ctx.fuzz_target)
                     + _swap_runtime_libs(ctx.entry, new_bin_dir,
                                          trial.bin_dir_override)))
    row = {"iter": ctx.iter_n, "ts": time.time(), "trial_id": trial.trial_id,
           "state_at_swap": _fuzzer_state(ctx.experiment_id, trial)}
    # The two clocks, for the plots' run_time -> wall conversion
    # (plot_coverage_growth.axis_windows). state_at_swap is AFL's last
    # PERIODIC stats write -- every 60 s, and the stop is a SIGKILL -- so its
    # run_time is up to a minute stale; stats_ts says which instant it is.
    stopped = _stats_clock(ctx.experiment_id, trial)
    if stopped:
        row["stats_ts"] = stopped[0]
    state.swap_timeline.append(row)
    _write_swap_timeline(ctx, state)
    ready.set()
    back = relaunched.wait(timeout=180)
    relaunch_ts = time.time() if back else None
    barrier.clear()
    logger.info("trial_%02d round %d: swap complete, relaunched on its own binary",
                trial.trial_id, ctx.iter_n)
    row = _amend_swap_row(state, row, relaunch_ts=relaunch_ts)
    _write_swap_timeline(ctx, state)
    # The relaunched AFL re-calibrates its whole queue before its run_time
    # resumes (minutes on bloaty/php). Its first stats write is that instant;
    # caught in the background so the swap takes no longer than it did.
    if stopped and back:
        threading.Thread(target=_record_resume, args=(ctx, state, row, stopped),
                         daemon=True, name=f"resume-{trial.trial_id:02d}").start()


def _amend_swap_row(state: OnlineState, row: dict, **fields) -> dict:
    """Add fields to a swap_timeline row WITHOUT mutating it in place.

    Every optimizer thread json.dumps the one shared list whenever it swaps,
    and a dict that grows under the encoder raises "dictionary changed size
    during iteration" -- in THAT thread's swap, with its trial stopped. The row
    is replaced by a new dict instead: one list store. Returns the new row.
    """
    new = {**row, **fields}
    for i, r in enumerate(state.swap_timeline):
        if r is row:
            state.swap_timeline[i] = new
            break
    return new


def _record_resume(ctx: RoundContext, state: OnlineState, row: dict, stopped,
                   *, poll: float = 5.0, timeout: float = 7200.0) -> None:
    """Record when a swapped trial's run_time clock restarted.

    Waits for the relaunched AFL's stats -- written after ``stopped`` (the
    (wall, run_time) of the write state_at_swap read), at a run_time no lower
    -- and stores them on the row as resumed_ts / resumed_run_time: an exact
    reading of the new segment's wall - run_time offset. Gives up when the
    trial stops running or after ``timeout``; the plots then measure that
    segment where it ends.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(poll)
        if state.trials.get(ctx.trial.trial_id, {}).get("state") != "running":
            return
        now = _stats_clock(ctx.experiment_id, ctx.trial)
        if now and now[0] > stopped[0] and now[1] >= stopped[1]:
            _amend_swap_row(state, row, resumed_ts=now[0], resumed_run_time=now[1])
            _write_swap_timeline(ctx, state)
            return


def _write_swap_timeline(ctx: RoundContext, state: OnlineState) -> None:
    """Write this trial's swap_timeline.json: serialised, atomic, best-effort.

    Two threads write the file: a swap, and the _record_resume a previous swap
    left running in the background. The trial record's lock orders them, and
    the snapshot is taken under it, so the last write is always the newest
    list. Each write goes to a temp file in the same directory, renamed over
    the target: no reader ever sees half a file. Provenance only -- a failure
    is logged, never raised. The swap it records has already happened, and an
    exception here would kill this trial's optimizer; the next write that
    succeeds carries the row anyway.
    """
    path = ctx.swap_timeline_path
    tid = ctx.trial.trial_id
    lock = state.trials.get(tid, {}).setdefault("swap_timeline_lock", threading.Lock())
    tmp = None
    try:
        with lock:
            snapshot = list(state.swap_timeline)
            d = os.path.dirname(path) or "."
            os.makedirs(d, exist_ok=True)
            tmp = os.path.join(d, f".{os.path.basename(path)}."
                                  f"{os.getpid()}-{threading.get_ident()}.tmp")
            with open(tmp, "w") as f:
                json.dump(snapshot, f, indent=2, default=str)
            os.replace(tmp, path)
            tmp = None
    except Exception as e:   # noqa: BLE001
        logger.warning("trial_%02d: could not write %s (%s); swap unaffected, "
                       "the next timeline write retries it", tid, path, e)
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Sequential optimizer loop (convergence-terminated)
# ---------------------------------------------------------------------------
def _inter_round_wait(interval: float, deadline: float | None, min_lead: float,
                      now: float | None = None) -> float:
    """Seconds to sleep before the next round: the interval, but never past the
    point where no further round may start (deadline - min_lead). Sleeping the
    full interval there only delays the campaign's end: the loop wakes, sees the
    lead rule, and exits -- up to 2h after the trials finished."""
    if deadline is None:
        return float(interval)
    now = time.time() if now is None else now
    return max(0.0, min(float(interval), deadline - float(min_lead) - now))


def run_optimizer_loop(*, run_round_fn, hot_swap_fn, convergence_k: int,
                       wait_fn, all_terminal_fn, deadline: float | None = None,
                       min_round_lead_s: float = 3600.0) -> int:
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
        # Do not START a round when the fuzzing budget is within min_round_lead_s
        # of ending (default 1h): a round begun now finishes after the trials
        # terminate, so its binary could never be swapped in -- pure agent/API
        # cost for no measured benefit. Once the deadline has passed this also
        # stops the loop (and the per-round agent timeout is capped to the
        # deadline, so an already-running round is killed at the budget end).
        if deadline is not None and (deadline - time.time()) <= min_round_lead_s:
            logger.info("optimizer: %.0fs left in budget (<= %ds round lead); "
                        "not starting another round",
                        max(deadline - time.time(), 0.0), int(min_round_lead_s))
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
        # Optional 4th element: this optimizer cannot make progress at all
        # (e.g. its prebuild fails the same deterministic way every round).
        if len(rest) > 1 and rest[1]:
            logger.error("optimizer: round %d asked to stop this optimizer; no "
                         "further rounds (its trial keeps fuzzing)", iter_n)
            break
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
                                             entry=entry, variant="baseline",
                                             trial_id=tid, seed=b_seed))
        o = phase3_runner.Trial(project=project, cve=cve, local_id=local_id,
                                entry=entry, variant="optimized", trial_id=tid,
                                seed=o_seed)
        # Online trials carry the mutation-dump shim so rounds reuse mutations the
        # fuzzer already executed instead of re-fuzzing to regenerate them.
        #
        # NOTE this is an asymmetry between the arms: baseline trials do not carry
        # it. Chosen deliberately -- the shim samples in memory (a few ns per exec)
        # and writes only when a round asks, and it measured as indistinguishable
        # from noise (php A/B 1.004x). AFL++ 4.21a's custom-mutator path is
        # behaviourally identical for a post_process-only mutator that returns the
        # input buffer unchanged (no custom stage, no RNG draws, same length clamp).
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
                            profile_cpu: int | None = None,
                            ccache_dir: str | None = None):
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

    ``ccache_dir`` (FuzzBench targets on the ccache verified list only): this
    optimizer's OWN ccache (main + cmplog builds). Both the harness rebuild and the broker's
    agent builds use it; nothing else does. See prework/fb_ccache.py.
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
                out_dir=out_bin_dir, capture_log=True, cpu=profile_cpu,
                **({"ccache_dir": ccache_dir} if ccache_dir else {}))

        def wrapper_env_fn(source_root, state_dir):
            from prework.prework_build import prework_image_for
            env = build_sandbox_validation_env()
            env["PHASE2_PREWORK_IMAGE"] = prework_image_for(entry)
            env["FUZZ_TARGET"] = fuzz_target
            if ccache_dir:
                env[fb_ccache.BROKER_ENV_KEY] = ccache_dir
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
    # Absolute wall-clock (time.time()) the fuzzing budget ends. Used to stop
    # starting rounds in the final hour and to cap an in-flight agent so it dies
    # at the budget end rather than running hours into the wind-down. None = no
    # deadline enforcement (legacy behaviour).
    deadline: float | None = None
    # --- per-trial-optimizer fields -------------------------------------
    # The single trial this optimizer owns. Set in per-trial mode; None in the
    # legacy shared-binary mode, where one optimizer served all online trials.
    trial: object = None
    # Trial i's mutations, harvested once and then held fixed for every round
    # this optimizer runs. None until the first successful harvest.
    fixed_mutations: str | None = None
    fixed_mutation_count: int = 0
    # Consecutive prebuild-failed rounds and the stage they failed at; reset by
    # any round whose prebuild succeeds (see _end_prebuild_failed_round).
    prebuild_fail_stage: str = ""
    prebuild_fail_streak: int = 0
    # Containers a session could not confirm removed (AgentNotRemovedError).
    # While any is present the tree is not the harness's: no round runs, and
    # the tree is neither reset nor committed. orphans_cleared names the ones
    # this round found gone before it started.
    orphan_containers: list = field(default_factory=list)
    orphans_cleared: list = field(default_factory=list)
    # Rounds that ran nothing while waiting for them (outcome
    # agent-not-removed-wait): not attempts, so the campaign record counts them
    # apart (rounds_attempted / rounds_waiting_for_orphans).
    orphan_wait_rounds: int = 0


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


def _reassert_edit_mtimes(source_tree) -> None:
    """Make every optimizer-edited file newer than the pristine baseline tree.

    A build's ``make`` regenerates a checked-in *generated* file -- re2c's
    ``zend_language_scanner.c``, bison's ``*_parser.c``, flex/gperf output, ... --
    whenever its *generator source* (``.l``/``.y``/...) is newer. Across rounds the
    cumulative tree's mtimes get flattened: the original prework extraction does not
    preserve the "generated committed after its source" ordering, and a rejected
    round's ``git reset --hard`` rewrites files in arbitrary order. So a generated
    file that an earlier accepted round hand-edited can end up OLDER than its
    pristine generator source, and this round's first build silently regenerates
    over it from the un-edited source -- discarding the fold. Observed on php-src:
    the ``lex_scan`` scanner folds vanished between iterations, erasing the single
    largest source of kept speedup.

    Restore the one invariant that is always correct: every file that differs from
    the pristine baseline (every file the optimizer has touched) is newer than every
    file it has not. An edited generated file is then never regenerated over; an
    edited generator source is still the newest of its pair, so the regeneration it
    intends still runs. Called just before the agent's first build of each round.
    Best-effort -- a build must never be blocked by mtime bookkeeping.
    """
    try:
        g = tracked_git.git_cmd(source_tree)
        root = subprocess.run(g + ["rev-list", "--max-parents=0", "HEAD"],
                              cwd=str(source_tree), capture_output=True, text=True)
        base = (root.stdout or "").split()
        if root.returncode != 0 or not base:
            return
        changed = subprocess.run(g + ["diff", "--name-only", base[-1]],
                                 cwd=str(source_tree), capture_output=True, text=True)
        if changed.returncode != 0:
            return
        now = time.time()
        root_path = Path(source_tree)
        bumped = 0
        for rel in (changed.stdout or "").splitlines():
            rel = rel.strip()
            if not rel:
                continue
            try:
                os.utime(root_path / rel, (now, now))
                bumped += 1
            except OSError:
                pass
        if bumped:
            logger.info("reasserted mtimes on %d optimizer-edited file(s) so a "
                        "generated-file rebuild cannot wipe a fold", bumped)
    except Exception:  # noqa: BLE001 -- never block a build on mtime bookkeeping
        return


def _carry_forward_agent_memory(online_dir: str, iter_n: int) -> bool:
    """Seed this round's agent memory dir from the previous round of the SAME trial.

    Every round runs a fresh agent container, and its ``~/.claude/projects`` is
    mounted per-iteration -- so the notes the agent writes for itself are thrown
    away when the round ends. That is why each round re-paid the same discoveries
    (e.g. that ZEND_DEBUG makes ``zend_never_inline`` expand to nothing, costing two
    ~17-minute builds), and why one trial re-tried the same regressing rewrite three
    rounds running.

    This copies the most recent previous round's memory directory into this round's,
    so the agent inherits ITS OWN notes. Nothing from outside the run is introduced
    and nothing crosses between trials -- each trial has its own ``online_dir`` -- so
    trial independence is unchanged. It is the carry-forward the cumulative source
    tree already provides, extended to the agent's notes. Carried after a rejected
    round too: "I tried X and it regressed" is the most useful note there is.
    """
    cur = Path(online_dir) / f"iter_{iter_n:02d}" / "sandbox" / "transcripts"
    for prev_n in range(iter_n - 1, -1, -1):
        prev = Path(online_dir) / f"iter_{prev_n:02d}" / "sandbox" / "transcripts"
        if not prev.is_dir():
            continue
        # The CLI names the project dir after the agent's cwd (/work/src ->
        # "-work-src"); glob rather than hardcode it.
        srcs = [p for p in prev.glob("*/memory")
                if p.is_dir() and any(p.iterdir())]
        if not srcs:
            continue
        carried = False
        for src in srcs:
            try:
                dest = cur / src.parent.name / "memory"
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(src, dest, dirs_exist_ok=True)
                carried = True
            except OSError as e:
                logger.warning("could not carry agent memory forward: %s", e)
        if carried:
            logger.info("carried agent memory forward from iter_%02d to iter_%02d",
                        prev_n, iter_n)
        return carried
    return False


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


# Outcome of a round whose harness prebuild (corpus freeze, baseline profile,
# hotspot table, target-source sample floor) failed. No agent runs for it.
PREBUILD_FAILED_OUTCOME = "prebuild-failed"
AGENT_NOT_REMOVED_OUTCOME = "agent-not-removed"
AGENT_NOT_REMOVED_WAIT_OUTCOME = "agent-not-removed-wait"


def _end_agent_not_removed_round(ctx: RoundContext, iter_n: int, *, diff_dir: str,
                                 containers: list) -> tuple:
    """Close a round whose session left containers docker could not remove.

    They may still be editing the tree, so it is NOT reset to prev_tag (that
    would race them) and nothing is committed; the trial's next round waits for
    them (_orphans_cleared). Not evidence about the target."""
    ctx.orphan_containers = list(containers)
    iter_dir = os.path.dirname(diff_dir)
    provenance.write_json(os.path.join(iter_dir, "round_provenance.json"), {
        "iter": iter_n,
        "outcome": AGENT_NOT_REMOVED_OUTCOME,
        "speedup": None,
        "applied": False,
        "built": False,
        "agent_started": True,
        "agent_containers_still_present": ctx.orphan_containers,
        "orphans_cleared": ctx.orphans_cleared or None,
        "optimizer": phase2_setup.optimizer_provenance(),
    })
    logger.error(
        "online round %d%s: the optimizer's container(s) %s could not be removed "
        "and may still be editing the source tree. Tree left as it is; no further "
        "round starts until they are gone (docker rm -f them by hand).",
        iter_n, (f" (trial_{ctx.trial.trial_id:02d})" if ctx.trial is not None else ""),
        ", ".join(ctx.orphan_containers))
    _record_ledger(ctx, iter_n, diff_dir, AGENT_NOT_REMOVED_OUTCOME, None)
    _write_cpu_cost_summary(ctx)
    return (False, None, False)


def _rounds_record(contexts: list, per_trial: bool) -> dict:
    """campaign_provenance's round counts. A round spent waiting for a leftover
    container ran nothing, so it is not an attempt: rounds_attempted leaves it
    out, and rounds_waiting_for_orphans (present only if any) counts it."""
    def per(f):
        return ({c.trial.trial_id: f(c) for c in contexts} if per_trial
                else f(contexts[0]))
    out = {"rounds_attempted": per(lambda c: c.iter_n - c.orphan_wait_rounds)}
    if any(c.orphan_wait_rounds for c in contexts):
        out["rounds_waiting_for_orphans"] = per(lambda c: c.orphan_wait_rounds)
    return out


def _orphans_cleared(ctx: RoundContext, iter_n: int) -> bool:
    """Before a round: are the containers an earlier session left behind gone?

    Tries to remove each once more; one that is gone or stopped for good can no
    longer write (sandbox.session.remove_container). All of them -> hand the
    tree back to the benchmark user, then reset it to prev_tag (they may have
    edited and built in it after the round ended) and let the round run. The
    chown comes first: a leftover ARVO build writes root-owned objects that
    `git clean -fd` cannot remove, and the next round would build on top of
    them. Any still live, or a chown that failed -> record a waiting round and
    run nothing; the next round tries again."""
    from sandbox import broker
    from sandbox.launch import LABEL_ITER, LABEL_TRIAL
    from sandbox.session import remove_container
    still = [n for n in ctx.orphan_containers if not remove_container(n, attempts=3)]
    owned = not still and broker.chown_back(
        prework_image_for(ctx.entry), [ctx.source_tree],
        labels={LABEL_TRIAL: ctx.trial.trial_id if ctx.trial is not None else None,
                LABEL_ITER: iter_n})
    if still or not owned:
        if still:
            ctx.orphan_containers = still
        ctx.orphan_wait_rounds += 1
        iter_dir = os.path.join(ctx.online_dir, f"iter_{iter_n:02d}")
        provenance.write_json(os.path.join(iter_dir, "round_provenance.json"), {
            "iter": iter_n,
            "outcome": AGENT_NOT_REMOVED_WAIT_OUTCOME,
            "speedup": None, "applied": False, "built": False,
            "agent_started": False,
            "agent_containers_still_present": still,
            "ownership_restored": None if still else False,
        })
        if still:
            logger.error("online round %d: container(s) %s from an earlier session "
                         "are STILL present; not starting this round",
                         iter_n, ", ".join(still))
        else:
            logger.error("online round %d: could not hand the source tree back from "
                         "root before resetting it; not starting this round", iter_n)
        return False
    logger.warning("online round %d: container(s) %s from an earlier session are "
                   "gone; ownership restored, resetting the source tree to %s before "
                   "the round", iter_n, ", ".join(ctx.orphan_containers), ctx.prev_tag)
    # Git alone cannot remove ignored or type-replaced paths from a live writer.
    from lib import source_scope
    source_scope.recover_pending(ctx.source_tree, writers_stopped=True)
    _revert_source_tree(ctx.source_tree, ctx.prev_tag)
    ctx.orphans_cleared, ctx.orphan_containers = list(ctx.orphan_containers), []
    return True


def _end_prebuild_failed_round(ctx: RoundContext, iter_n: int, *, diff_dir: str,
                               opt_bin_dir: str, reason: str, round_corpus,
                               carried_memory, stage: str = "") -> tuple:
    """Close a round whose prebuild failed: everything a measured round records
    (provenance, ledger, cpu cost, setup metadata, round line), with outcome
    ``prebuild-failed``. Returns the loop's (accepted, bin, measured, stop)
    tuple: not accepted, and NOT evidence -- the agent never ran, so the round
    says nothing about the target and must not count toward convergence. ``stop``
    is set once the prebuild has failed ONLINE_PREBUILD_FAIL_STOP rounds running
    at the same deterministic stage: it would fail the same way all campaign."""
    outcome = PREBUILD_FAILED_OUTCOME
    if stage and stage == ctx.prebuild_fail_stage:
        ctx.prebuild_fail_streak += 1
    else:
        ctx.prebuild_fail_stage, ctx.prebuild_fail_streak = stage, 1
    limit = int(getattr(config, "ONLINE_PREBUILD_FAIL_STOP", 3) or 0)
    stop = bool(limit and stage in phase2_setup.DETERMINISTIC_PREBUILD_STAGES
                and ctx.prebuild_fail_streak >= limit)
    iter_dir = os.path.dirname(diff_dir)
    # Nothing was edited (no agent ran); reverting keeps the invariant that a
    # rejected round always leaves the tree at prev_tag.
    ctx.previous_best_bin = apply_round_outcome(
        False, source_tree=ctx.source_tree, iter_n=iter_n, opt_bin_dir=opt_bin_dir,
        previous_best_bin=ctx.previous_best_bin, prev_tag=ctx.prev_tag)
    bug_survived = "no-poc" if not ctx.poc_path else "unchecked"
    provenance.write_json(os.path.join(iter_dir, "round_provenance.json"), {
        "iter": iter_n,
        "outcome": outcome,
        "speedup": None,
        "applied": False,
        "built": False,
        "poc_reproduces": bug_survived,
        "prebuild_failure": reason,
        "prebuild_stage": stage,
        "prebuild_fail_streak": ctx.prebuild_fail_streak,
        "optimizer_stopped": stop,
        "agent_started": False,
        "orphans_cleared": ctx.orphans_cleared or None,
        "attribution": None,
        "gate": {"baseline": None, "optimized": None,
                 "corpus_file_count": None, "partial": None},
        "optimizer": phase2_setup.optimizer_provenance(),
        "agent_memory_carried": carried_memory,
        "corpus": round_corpus,
        "crash_check": None,
        "ccache": None,
    })
    logger.error(
        "online round %d: outcome=%s speedup=None applied=False built=False "
        "poc_reproduces=%s -- no optimizer agent was started: %s",
        iter_n, outcome, bug_survived, reason)
    _record_ledger(ctx, iter_n, diff_dir, outcome, None)
    _write_cpu_cost_summary(ctx)
    phase2_setup._save_setup_metadata(
        ctx.entry, iter_dir, ctx.experiment_id, False, poc_path=ctx.poc_path,
        baseline_ok=True, optimized_ok=False,
        failure={"stage": "profile_prebuild", "reason": reason}, replay=None)
    if stop:
        logger.error(
            "online round %d: the prebuild failed at stage %r for %d rounds in a "
            "row -- deterministic, it will not recover. STOPPING this optimizer%s; "
            "its trial keeps fuzzing on the current binary. Last reason: %s",
            iter_n, stage, ctx.prebuild_fail_streak,
            (f" (trial_{ctx.trial.trial_id:02d})" if ctx.trial is not None else ""),
            reason)
    return (False, None, False, stop)


def run_round(ctx: RoundContext, state: OnlineState, iter_n: int):
    """One online optimization round on the persistent cumulative source tree.

    Returns (accepted, iter_bin_dir). Mirrors setup_cve_arvo_image's gate wiring, but
    the profiling corpus is the mutations the live trial executed and the replay
    baseline is the previous-best binary (cumulative). A rejected round reverts the tree to prev_tag so
    the next round never builds on a rejected edit.
    """
    ctx.iter_n = iter_n
    # Tag every ledger row this round writes with ITS trial and round, on this
    # thread. Thread-local beats the environment, and _drive tags the thread
    # iter=0 before the first round -- so the old set_round(env) here never took
    # effect in per-trial mode and every round's mutation_harvest / rebuild /
    # replay_gate / ... said iter 0 (php r2: 6 rounds, all iter 0). The session
    # snapshots these same tags for its broker (sandbox/session.py), so the
    # agent's builds and replays land on the right (trial, round) too. The
    # environment tag is kept for the legacy single-optimizer path only: in
    # per-trial mode it is one value shared by ten threads, i.e. wrong for nine.
    cpu_ledger.set_thread_round(
        project=ctx.project, iter_n=iter_n,
        trial_id=ctx.trial.trial_id if ctx.trial is not None else None)
    if ctx.trial is None:
        cpu_ledger.set_round(project=ctx.project, iter_n=iter_n)
    ctx.orphans_cleared = []
    if ctx.orphan_containers and not _orphans_cleared(ctx, iter_n):
        return (False, None, False)     # not measured: the tree is not ours yet
    iter_dir = os.path.join(ctx.online_dir, f"iter_{iter_n:02d}")
    diff_dir = os.path.join(iter_dir, "source_diff")
    opt_bin_dir = os.path.join(iter_dir, "bin")
    os.makedirs(diff_dir, exist_ok=True)
    os.makedirs(opt_bin_dir, exist_ok=True)

    # 1. Harvest the mutations the live trials already executed, and re-arm the
    # shim for the next round. This is what removes the redundant re-fuzz: phase 2
    # would otherwise spend PHASE2_MUTATION_DURATION_SECS regenerating mutations
    # these trials had already produced.
    #
    # If the harvest comes back empty the round FALLS BACK to phase 2's own
    # capture rather than profiling seeds alone -- seeds-only measures the wrong
    # workload, which is why mutation augmentation is mandatory.
    live_mutations = None
    # Optimizer i always profiles trial i's OWN mutations. Default
    # (ONLINE_FIXED_MUTATION_CORPUS=0): a fresh harvest every round, i.e. what the
    # current best binary executed since the last dump/restart. FIXED=1 pins the
    # first harvest for every later round (stationary workload, stale profile).
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
        # it outlives the round that harvested it. A per-round harvest gets its
        # own iter dir, so no earlier batch can leak into this round's corpus.
        _fixed = ctx.trial is not None and getattr(
            config, "ONLINE_FIXED_MUTATION_CORPUS", True)
        harvest_dir = (os.path.join(ctx.online_dir, "fixed_mutations")
                       if _fixed else os.path.join(iter_dir, "live_mutations"))
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

    # 2. The profiling corpus: the harvested mutations ALONE. The trial's queue
    # is not read at all -- see _augment_corpus_with_mutations for why it was
    # dropped. Only the fallback below (no harvest, so phase 2 re-fuzzes) still
    # snapshots the queue, and only as the seed that re-fuzz starts from.
    round_corpus = None
    if live_mutations:
        # Filter against the previous best, then size (see prepare_round_corpus).
        with cpu_ledger.timed("crash_filter", cores=1) as _info:
            round_corpus = prepare_round_corpus(
                mutations_dir=live_mutations, out_root=os.path.join(iter_dir, "corpus"),
                previous_best_bin=ctx.previous_best_bin, fuzz_target=ctx.fuzz_target,
                image=prework_image_for(ctx.entry), cpu=ctx.profile_cpu,
                seed=config.BASE_SEED + iter_n,
                replay_rate=_gate_replay_rate(ctx.experiment_dir))
            _info["ok"] = round_corpus is not None
        if round_corpus is None:
            logger.warning("online round %d: crash filter failed; skipping round "
                           "(the agent would be blamed for crashes the previous "
                           "best already has)", iter_n)
            _record_ledger(ctx, iter_n, diff_dir, "corpus-prep-failed", None)
            return (False, None, False)      # nothing was measured
        _write_json(os.path.join(iter_dir, "round_corpus_meta.json"), round_corpus)
        logger.info("online round %d: %d mutations, %d filtered (%d crash the previous "
                    "best) -> tuning %d (%.0f inputs/s, %ds budget), smoke %d",
                    iter_n, round_corpus["harvested"], round_corpus["checked_count"],
                    round_corpus["crashers_removed"], round_corpus["tuning_count"],
                    round_corpus["units_per_s"], round_corpus["budget_secs"],
                    round_corpus["smoke_count"])
        live_mutations = round_corpus["tuning"]
        corpus_dir = live_mutations
    else:
        # Per-trial mode: always THIS optimizer's own trial. The old
        # select_snapshot_trial("largest") existed only because one optimizer
        # served ten trials and had to pick one; profiling trial 8's corpus and
        # then swapping the result into trials 0..9 meant nine trials ran a
        # binary tuned for a workload they never executed.
        if ctx.trial is not None:
            chosen = ctx.trial
        else:
            chosen = select_snapshot_trial(
                ctx.online_trials, lambda t: _corpus_file_count(ctx.experiment_id, t))
        src_corpus = phase3_runner.get_live_corpus_dir(ctx.experiment_id, chosen)
        corpus_dir = os.path.join(iter_dir, "corpus_snapshot")
        with cpu_ledger.timed("corpus_snapshot", cores=1) as _info:
            meta = snapshot_live_corpus(src_corpus, corpus_dir, now=time.time())
            _info["files"] = meta["file_count"]
        meta["trial_id"] = chosen.trial_id
        _write_json(os.path.join(iter_dir, "corpus_snapshot_meta.json"), meta)
        logger.info("online round %d: snapshot trial_%02d -> %d files (%d skipped "
                    "in-flight) as the re-fuzz seed", iter_n, chosen.trial_id,
                    meta["file_count"], meta["skipped_in_flight"])
        if meta["file_count"] == 0:
            logger.warning("online iter %d: empty corpus snapshot; skipping round",
                           iter_n)
            _record_ledger(ctx, iter_n, diff_dir, "no-corpus", None)
            return (False, None, False)      # nothing was measured

    # 3. env: profile the corpus; anchor the replay gate on the previous best
    env = build_round_env(
        experiment_dir=ctx.experiment_dir, diff_dir=diff_dir,
        opt_bin_dir=os.path.join(iter_dir, "validation_out"),
        corpus_dir=corpus_dir, entry=ctx.entry,
        previous_best_bin=ctx.previous_best_bin, profile_cpu=ctx.profile_cpu)
    env.update(ctx.wrapper_env_fn(ctx.source_root, os.path.join(iter_dir, "validation")))
    if live_mutations:
        # Hand phase 2 the already-captured mutations; its own capture step sees
        # this and skips the re-fuzz.
        env["FUZZ_SOURCE_FOLDS_PREBUILT_MUTATIONS"] = live_mutations
    if round_corpus:
        # Host-side only (not on the agent env allowlist): the broker's smoke set.
        env["FUZZ_SOURCE_FOLDS_SMOKE_CORPUS_DIR"] = round_corpus["smoke"]

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

    last_build: dict = {}

    def build_fn():
        # Pinned to ctx.profile_cpu by _online_target_strategy, so one core.
        with cpu_ledger.timed("rebuild", cores=1) as info:
            r = ctx.rebuild_fn(ctx.source_root, opt_bin_dir)
            # Whether this round's binaries came from the trial's ccache (FuzzBench
            # only; main and cmplog are reported separately; None for a build log
            # without an FB_CCACHE_STATS line).
            if isinstance(r, tuple):
                st = fb_ccache.parse_stats(r[1])
                last_build["ccache"] = fb_ccache.slim_stats(st)
                if st:
                    info["ccache_hits"] = st.get("hits")
                    info["ccache_misses"] = st.get("misses")
                    for kind, b in (st.get("builds") or {}).items():
                        info[f"ccache_{kind}_hits"] = b.get("hits")
                        info[f"ccache_{kind}_misses"] = b.get("misses")
            return r

    # Guard against a generated-file rebuild (re2c/bison/...) silently wiping a
    # fold an earlier accepted round made to a checked-in generated file. Done
    # just before the agent's first build of this round. See _reassert_edit_mtimes.
    _reassert_edit_mtimes(ctx.source_tree)

    # Let this trial's agent inherit its OWN notes from the previous round, instead
    # of re-deriving them on a fresh container every time. See
    # _carry_forward_agent_memory.
    carried_memory = _carry_forward_agent_memory(ctx.online_dir, iter_n)

    try:
        build_ok = phase2_setup.optimize_and_build(
            ctx.source_tree, ctx.fuzz_target, diff_dir, project=ctx.project,
            build_fn=build_fn, codex_extra_env=env, use_wrapper_validation=True,
            extra_prompt_directives=None, deadline=ctx.deadline)
    except phase2_setup.MutationAugmentationError as exc:
        logger.warning("online iter %d: mutation augmentation failed: %s", iter_n, exc)
        ctx.previous_best_bin = apply_round_outcome(
            False, source_tree=ctx.source_tree, iter_n=iter_n, opt_bin_dir=opt_bin_dir,
            previous_best_bin=ctx.previous_best_bin, prev_tag=ctx.prev_tag)
        _record_ledger(ctx, iter_n, diff_dir, "augmentation-failed", None)
        return (False, None, False)      # nothing was measured
    except phase2_setup.source_scope.SourceScopeRecoveryRequired as exc:
        # No source-tree operation: a previous writer may still be alive.
        provenance.write_json(os.path.join(iter_dir, 'round_provenance.json'), {
            'iter': iter_n, 'outcome': 'source-scope-quarantined',
            'applied': False, 'built': False, 'reason': str(exc)})
        _record_ledger(ctx, iter_n, diff_dir, 'source-scope-quarantined', None)
        logger.error('online iter %d: %s; stopping this optimizer', iter_n, exc)
        return (False, None, False, True)
    except phase2_setup.AgentNotRemovedError as exc:
        return _end_agent_not_removed_round(ctx, iter_n, diff_dir=diff_dir,
                                            containers=exc.containers)
    except phase2_setup.PrebuildFailedError as exc:
        # The harness could not freeze the corpus or profile the baseline (or the
        # profile failed its sample-count sanity check). No agent ran -- it has no
        # fall-back that builds a corpus or profiles -- so nothing was measured:
        # an infrastructure failure, never counted toward convergence.
        return _end_prebuild_failed_round(
            ctx, iter_n, diff_dir=diff_dir, opt_bin_dir=opt_bin_dir,
            reason=str(exc), round_corpus=round_corpus,
            carried_memory=carried_memory, stage=getattr(exc, "stage", ""))
    # The prebuild got this round to an agent: any prebuild-failure streak ends.
    ctx.prebuild_fail_stage, ctx.prebuild_fail_streak = "", 0

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

    scope_report = os.path.join(diff_dir, 'source_scope_violation.json')
    opt_rej = ({'stage': 'source_scope', 'reason': 'host rejected out-of-scope edits',
                'report': scope_report} if os.path.exists(scope_report) else None)
    if opt_rej:
        optimization_ready = False
    replay = None
    if optimization_ready:
        with cpu_ledger.timed("bug_survival_check", cores=1):
            optimization_ready, opt_rej = phase2_setup._reject_if_optimization_removed_bug(
                project=ctx.project, cve=ctx.entry["cve"],
                optimization_ready=optimization_ready,
                baseline_reproduced=bool(ctx.poc_path), opt_crashes=opt_crashes,
                baseline_bin_dir=ctx.previous_best_bin, optimized_bin_dir=opt_bin_dir)
    crash_check = None
    if optimization_ready and round_corpus:
        # Every filtered input (tuning + gate + smoke), once, on the new build.
        # None of them crashes the previous best, so any crash here is the
        # round's edits -- the 5% smoke sample misses a fold that breaks only a
        # few inputs.
        with cpu_ledger.timed("crash_check", cores=1):
            scan = afl_replay.find_crashers(
                out_dir=opt_bin_dir, corpus_dir=round_corpus["checked"],
                fuzz_target=ctx.fuzz_target, cpu=ctx.profile_cpu,
                image=prework_image_for(ctx.entry))
        crash_check = {k: scan[k] for k in ("ok", "scanned", "expected")}
        crash_check["crashers"] = scan["crashers"][:50]
        crash_check["crash_count"] = len(scan["crashers"])
        if scan["crashers"]:
            report = afl_replay.crash_report(
                out_dir=opt_bin_dir, corpus_dir=round_corpus["checked"],
                fuzz_target=ctx.fuzz_target, cpu=ctx.profile_cpu,
                image=prework_image_for(ctx.entry), names=scan["crashers"])
            with open(os.path.join(diff_dir, "new_crashes.txt"), "w") as f:
                f.write(f"{len(scan['crashers'])} of {scan['expected']} inputs crash "
                        f"the new build and not the previous best:\n"
                        + "\n".join(scan["crashers"]) + "\n\n" + report)
            optimization_ready = False
            opt_rej = {"stage": "new_crashes",
                       "reason": f"{len(scan['crashers'])} inputs crash the new "
                                 f"build but not the previous best"}
        elif not scan["ok"]:
            optimization_ready = False
            opt_rej = {"stage": "crash_check_failed",
                       "reason": f"crash check ran {scan['scanned']} of "
                                 f"{scan['expected']} inputs"}
        logger.info("online round %d: crash check %s (%d of %d inputs crash)",
                    iter_n, "FAILED" if not optimization_ready else "passed",
                    crash_check["crash_count"], scan["expected"])
    if optimization_ready:
        # The replay gate times both binaries on ctx.profile_cpu, one core each,
        # run sequentially -- so its core-seconds are its wall-seconds.
        #
        # Online rounds already sized their corpus, so the gate never shrinks it
        # again (cap=False). It times the round's gate sample -- same size as
        # the set the agent tuned on, different inputs -- or, with
        # ONLINE_GATE_FULL_SET=1, the full filtered set.
        gate_corpus = None
        if round_corpus:
            gate_corpus = round_corpus[
                "checked" if getattr(config, "ONLINE_GATE_FULL_SET", False) else "gate"]
        with cpu_ledger.timed("replay_gate", cores=1):
            replay = phase2_setup.run_replay_speedup(
                diff_output_dir=diff_dir, baseline_bin_dir=ctx.previous_best_bin,
                optimized_bin_dir=opt_bin_dir, fuzz_target=ctx.fuzz_target,
                experiment_dir=ctx.experiment_dir, profile_cpu=ctx.profile_cpu,
                image=prework_image_for(ctx.entry),
                corpus_dir=gate_corpus, cap=not round_corpus)
        optimization_ready, replay_rej = phase2_setup._reject_if_no_replay_speedup(
            project=ctx.project, cve=ctx.entry["cve"],
            optimization_ready=optimization_ready, replay=replay,
            baseline_bin_dir=ctx.previous_best_bin, optimized_bin_dir=opt_bin_dir)
        opt_rej = opt_rej or replay_rej

    if optimization_ready:
        outcome = "kept"
    elif opt_rej and opt_rej.get("stage") == "source_scope":
        outcome = "rejected-source-scope"
    elif opt_rej and opt_rej.get("stage") == "optimized_poc_verify":
        outcome = "rejected-removed-bug"
    elif opt_rej and opt_rej.get("stage") == "new_crashes":
        outcome = "rejected-new-crashes"
    elif opt_rej and opt_rej.get("stage") == "crash_check_failed":
        outcome = "crash-check-failed"
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
        "agent_memory_carried": carried_memory,
        # Round corpus (crash filter + sizing) and the gate's crash check.
        "corpus": round_corpus,
        "crash_check": crash_check,
        # Last harness rebuild of this round (the binary the gate measured):
        # ccache use of its main and cmplog builds.
        "ccache": last_build.get("ccache"),
        # Leftover containers of an earlier session this round waited out, then
        # reset the tree after (_orphans_cleared).
        "orphans_cleared": ctx.orphans_cleared or None,
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
    return (False, None, False if outcome == 'rejected-source-scope'
            else _round_produced_evidence(diff_dir, build_ok))


_STATE_FIELDS = ("run_time", "execs_done", "corpus_count", "cycles_done",
                 "max_depth", "pending_total", "pending_favs", "saved_crashes",
                 "edges_found", "bitmap_cvg", "stability")


def _stats_path(experiment_id: str, trial) -> Path:
    d = phase3_runner.get_trial_dirs(experiment_id, trial)
    f = Path(d.get("afl_out") or os.path.join(d["base"], "afl_out"))
    return f / "default" / "fuzzer_stats"


def _stats_clock(experiment_id: str, trial):
    """(wall, run_time) of a trial's last fuzzer_stats write -- the file's
    mtime and the run_time AFL wrote into it, one instant of both clocks --
    or None."""
    try:
        f = _stats_path(experiment_id, trial)
        for line in f.read_text().splitlines():
            k, _, v = line.partition(":")
            if k.strip() == "run_time":
                return f.stat().st_mtime, float(v)
    except Exception:  # noqa: BLE001
        pass
    return None


def _fuzzer_state(experiment_id: str, trial) -> dict:
    """A trial's AFL counters right now -- small, bounded, one row per event."""
    try:
        f = _stats_path(experiment_id, trial)
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
        _stop_all_and_overwrite(
            running, shared_bin, new_bin,
            extra_files=(_swap_extra_files(ctx.entry, ctx.fuzz_target)
                         + _swap_runtime_libs(ctx.entry, new_bin_dir,
                                              ctx.optimized_bin_dir)))
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
    # docker_util.write_container_logs). check=True: the container is removed
    # below, and it is the only other copy of this log -- so a failed write
    # (docker error, full disk) must keep it, not destroy it. Not fatal: the
    # crash times and metadata below do not depend on the log.
    try:
        docker_util.write_container_logs(trial.container_id, dirs["log"], check=True)
        log_saved = True
    except Exception as e:  # noqa: BLE001 - keep finalizing; the container stays
        log_saved = False
        logger.error("%s: saving the console log failed (%s); keeping container "
                     "%s so it can be recovered with `docker logs`",
                     trial.name, e, trial.container_id)
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
        # The launch this trial actually ran (argv/env/cwd for FuzzBench).
        "sanitizer_options": phase3_runner._trial_env_record(trial),
        # False: fuzzer.log is missing or partial and the container was kept.
        "console_log_saved": log_saved,
    }
    with open(dirs["metadata"], "w") as f:
        json.dump(meta, f, indent=2)
    # Removed only once metadata.json exists, so tools/recover_online_harvest.py
    # still finds the container if the runner dies above. It used to linger
    # until the NEXT campaign on the project `docker rm -f`'d it by name; names
    # now carry the experiment id, so nothing else would ever remove it, and
    # each stopped container keeps its multi-GB console log on disk. Kept when
    # the log was not saved: removing it would destroy the only copy.
    if log_saved:
        docker_util.remove_container(trial.container_id)


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
                # (This called V.live_binary with V never imported, and with str
                # paths the function joined with "/": both raised, the except
                # below swallowed it, and every optimized crash record said None.)
                _live_dir, _live_id = _live_binary(
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
                           fuzz_target, project, cpu: int | None = None,
                           setup_cpus: int | str | None = None):
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
        image = prework_image_for(entry)
        src_root = Path(source_tree_root)
        src_root.mkdir(parents=True, exist_ok=True)
        if not phase2_setup.extract_source_from_image(image, str(src_root)):
            logger.error("online: fuzzbench source extract failed for %s", project)
            return False, None, None, source_tree_root
        proj_src = phase2_setup._find_project_source(src_root, project)
        # Strip the shipped repositories BEFORE this build, not after it: this
        # build is the campaign's baseline (run_online does not rebuild a
        # FuzzBench target), and every later rebuild compiles the stripped tree,
        # so a build that reads .git (version strings) must see the same tree
        # here. run_online strips again; that is a no-op.
        tracked_git.strip_vcs_metadata(src_root)
        # Pinned like every other harness build: unpinned, build.sh's
        # `make -j$(nproc)` spread over every host core, trials included. Setup
        # runs before any trial, so it gets the setup cpuset, not one core.
        ok, _log = _setup_build(entry=entry, source_dir=proj_src,
                                out_dir=baseline_bin_dir,
                                setup_cpus=setup_cpus if setup_cpus is not None else cpu,
                                profile_cpu=cpu, stage="baseline_afl_build",
                                counts=False)
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
                              fuzz_target: str, entry: dict | None = None) -> int:
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

    FuzzBench entries (``entry["kind"] == "fuzzbench"``) follow FuzzBench's
    runner instead (lib/corpus.stage_fuzzbench_seed_corpus): <bin>/seeds plus
    <t>_seed_corpus.zip only, 1 MiB limit, sha1 names, `default_seed` ("hi")
    when empty. That corpus lands in merged/ (what phase 3 fuzzes); build/
    gets the same real seeds without default_seed (what phase 2 profiles).
    """
    corpus_root = os.path.join(experiment_dir, "seed_corpus")
    build_dir = os.path.join(corpus_root, "build")
    merged_dir = os.path.join(corpus_root, "merged")

    if afl_launch.is_fuzzbench(entry):
        st = corpus_util.stage_fuzzbench_seed_corpus(bin_dir, fuzz_target, merged_dir)
        shutil.rmtree(build_dir, ignore_errors=True)
        os.makedirs(build_dir, exist_ok=True)
        if not st["default_seed"]:
            for f in os.listdir(merged_dir):
                shutil.copy2(os.path.join(merged_dir, f), os.path.join(build_dir, f))
        logger.info("online: fuzzbench seed corpus for %s: %d file(s)%s", fuzz_target,
                    st["staged"], " (default_seed only)" if st["default_seed"] else "")
        return st["staged"]

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


def _setup_cpus(profile_cpu: int | None) -> int | str | None:
    """Cpuset for campaign-setup builds: ONLINE_SETUP_BUILD_CPUS, else profile_cpu."""
    spec = (os.environ.get("ONLINE_SETUP_BUILD_CPUS")
            or getattr(config, "ONLINE_SETUP_BUILD_CPUS", "") or "")
    return spec.strip() if spec.strip() else profile_cpu


def _setup_build(*, entry: dict, source_dir: str, out_dir: str,
                 setup_cpus: int | str | None, profile_cpu: int | None,
                 stage: str | None = None, counts: bool = True,
                 ccache_dir: str | None = None) -> tuple[bool, str]:
    """One campaign-setup build on ``setup_cpus`` -> (ok, log).

    Setup builds run before any trial, so they may use every core the campaign
    owns; build.sh's `make -j$(nproc)` then sees all of them. A multi-core build
    that fails (not by timeout) is retried once on ``profile_cpu``: a few builds
    race under parallel make (woff2's dictionary.o). ``stage`` -> one CPU-ledger
    row per attempt, charged at the attempt's core count.
    """
    import contextlib
    from lib.core_lock import parse_cpuset
    from prework.prework_build import rebuild_with_prework_image

    attempts = [setup_cpus]
    if profile_cpu is not None and parse_cpuset(setup_cpus) != parse_cpuset(profile_cpu):
        attempts.append(profile_cpu)
    ok, log = False, ""
    for i, cpus in enumerate(attempts):
        timer = (cpu_ledger.timed(stage, cores=len(parse_cpuset(cpus)) or 1,
                                  counts=counts, cpus=str(cpus), retry=i > 0)
                 if stage else contextlib.nullcontext({}))
        with timer as info:
            built = rebuild_with_prework_image(
                entry=entry, source_dir=source_dir, out_dir=out_dir,
                capture_log=True, cpu=cpus, ccache_dir=ccache_dir)
            ok, log = built if isinstance(built, tuple) else (built, "")
            info["ok"] = bool(ok)
        if ok or i + 1 == len(attempts) or log.startswith("build timed out"):
            break
        logger.warning("online: setup build on cpus %s failed for %s; retrying on "
                       "core %s", cpus, entry["project"], profile_cpu)
    return bool(ok), log


def _build_afl_baseline(*, entry: dict, project_src_dir: str, baseline_bin_dir: str,
                        fuzz_target: str, poc_path: str | None,
                        profile_cpu: int | None,
                        setup_cpus: int | str | None = None) -> bool:
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
    project = entry["project"]
    # Wipe first: `compile` writes into a bind-mounted /out without clearing it,
    # so surviving libFuzzer siblings would sit next to the AFL build looking
    # equally legitimate to anything that globs the directory.
    shutil.rmtree(baseline_bin_dir, ignore_errors=True)
    os.makedirs(baseline_bin_dir, exist_ok=True)

    # Clean BEFORE building: _extract_online_target already compiled once to
    # produce the historical /out, leaving its build output in the tree. A
    # build.sh that does an out-of-source `mkdir build` (mbedtls's cmake step)
    # then aborts with "mkdir: cannot create directory 'build': File exists" on
    # this second compile. Starting from a clean tree avoids it; the after-clean
    # below still runs for the git-init hygiene it was added for.
    phase2_setup._clean_build_artifacts(project_src_dir)

    # counts=False: this build produces the binary BOTH arms start from, before
    # any fuzzing begins. It is setup, not a cost the online arm pays and the
    # baseline does not, so charging it as optimization CPU would overstate the
    # very number the coverage plot is meant to show. Still recorded, because
    # "how long before trials start" is worth being able to reconstruct.
    ok, log = _setup_build(
        entry=entry, source_dir=project_src_dir, out_dir=baseline_bin_dir,
        setup_cpus=setup_cpus if setup_cpus is not None else profile_cpu,
        profile_cpu=profile_cpu, stage="baseline_afl_build", counts=False)
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


def _prepare_fb_ccache_template(*, entry: dict, project_src_dir: str, online_dir: str,
                                baseline_bin_dir: str, fuzz_target: str,
                                profile_cpu: int | None,
                                setup_cpus: int | str | None = None) -> dict:
    """Fill the target-level ccache template (main + cmplog builds) with one extra
    pristine build.

    Only for a FuzzBench target on prework/fuzzbench_ccache_verified.txt. The
    baseline arm's binary was already built UNCACHED (_build_afl_baseline) and stays
    the reference; this build exists only to warm the cache, and its /out is
    compared with that baseline (main + cmplog + dictionary entry set) before the
    template is used:

      * a plain entry (equivalence verdict pass): byte-identical, strictly;
      * an entry marked pass_noise_masked (the build embeds a date / hostname):
        one more UNCACHED build of the same tree learns the build's own noise
        (baseline vs that build), and the cached build may differ from the
        baseline only inside it -- the same masked comparison the equivalence
        test uses (fb_ccache.compare_with_noise).

    Any mismatch or failure turns ccache off for the campaign: an optimized trial
    must never fuzz a binary that differs from an uncached build of the same tree.
    Both builds are charged to the optimized arm (counts=True), since the baseline
    arm would not need them.

    Returns a provenance record; ``record["template"]`` is the dir, or None.
    """
    rec: dict = {"enabled": False, "template": None}
    if setup_cpus is None:
        setup_cpus = profile_cpu
    if entry.get("kind") != "fuzzbench":
        return rec
    mode = fb_ccache.target_ccache_mode(entry)
    if mode is None:
        rec["reason"] = ("disabled" if not fb_ccache.ccache_globally_enabled()
                         else "not-verified")
        return rec
    rec["verified_mode"] = mode
    template = fb_ccache.template_dir(online_dir)
    shutil.rmtree(template, ignore_errors=True)
    os.makedirs(template, exist_ok=True)
    import tempfile as _tf
    out = _tf.mkdtemp(prefix="ccache-template-out-", dir=online_dir)
    noise_out = None
    try:
        ok, log = _setup_build(
            entry=entry, source_dir=project_src_dir, out_dir=out,
            setup_cpus=setup_cpus, profile_cpu=profile_cpu,
            stage="ccache_template_build", ccache_dir=template)
        rec["stats"] = fb_ccache.slim_stats(fb_ccache.parse_stats(log))
        rec["timings"] = fb_ccache.parse_build_timings(log)
        if not ok:
            rec["reason"] = "template-build-failed"
            logger.error("online: ccache template build failed for %s; rebuilds run "
                         "uncached: %s", entry["project"], log[-400:])
            return rec
        if not (rec["stats"] or {}).get("all_builds_enabled"):
            rec["reason"] = "cache-not-used:" + str((rec["stats"] or {}).get("reason")
                                                    or (rec["stats"] or {}).get("builds"))
            logger.error("online: ccache template build did not use the cache for "
                         "both builds (%s); rebuilds run uncached", rec["reason"])
            return rec
        if mode == fb_ccache.MODE_NOISE:
            # The extra uncached build that shows this target's own build noise.
            noise_out = _tf.mkdtemp(prefix="ccache-template-noise-", dir=online_dir)
            ok2, _log2 = _setup_build(
                entry=entry, source_dir=project_src_dir, out_dir=noise_out,
                setup_cpus=setup_cpus, profile_cpu=profile_cpu,
                stage="ccache_template_noise_build")
            if not ok2:
                rec["reason"] = "noise-build-failed"
                logger.error("online: uncached noise build failed for %s; rebuilds "
                             "run uncached", entry["project"])
                return rec
            cmp = fb_ccache.compare_with_noise(baseline_bin_dir, noise_out, out,
                                               fuzz_target)
            same = cmp["ok"]
        else:
            cmp = fb_ccache.compare_outs(baseline_bin_dir, out, fuzz_target)
            same = cmp["identical"]
        rec["matches_uncached_baseline"] = cmp
        if not same:
            rec["reason"] = "cold-cache-build-differs-from-uncached-baseline"
            logger.error("online: cold-cache build differs from the uncached baseline "
                         "for %s (%s, %s); rebuilds run uncached", entry["project"],
                         cmp["parts"], cmp.get("status"))
            return rec
        rec.update(enabled=True, template=template)
        logger.info("online: ccache template ready for %s (%s misses, check %s)",
                    entry["project"], (rec["stats"] or {}).get("misses"),
                    cmp.get("status", "identical"))
        return rec
    finally:
        shutil.rmtree(out, ignore_errors=True)
        if noise_out:
            shutil.rmtree(noise_out, ignore_errors=True)
        if not rec.get("enabled"):
            shutil.rmtree(template, ignore_errors=True)


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
    # seed_fallback_00 (ARVO) / default_seed (FuzzBench's empty-corpus seed).
    fallback = [f for f in files if f.name.startswith("seed_fallback")
                or f.name == getattr(config, "FUZZBENCH_DEFAULT_SEED_NAME", "default_seed")]
    return {
        "staged": len(files),
        "fallback_only": bool(files) and len(fallback) == len(files),
        "total_bytes": sum(f.stat().st_size for f in files),
    }


def _measure_noise_floor(*, ctx_entry, source_root, fuzz_target, online_dir,
                         profile_cpu, rounds: int, setup_cpus=None) -> dict:
    """Rebuild unmodified source `rounds` times and replay-measure each.

    Uses the SAME rebuild and replay paths the gate uses, so the number is
    comparable to the speedups the gate reports -- a noise floor measured a
    different way would not be.
    """
    import functools
    import tempfile as _tf
    from lib import afl_replay
    from prework.prework_build import prework_image_for

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
        # Built on the setup cpuset; measured below on profile_cpu alone.
        ok, _log = _setup_build(
            entry=ctx_entry, source_dir=str(source_root), out_dir=d,
            setup_cpus=setup_cpus if setup_cpus is not None else profile_cpu,
            profile_cpu=profile_cpu)
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


def _preflight_profile(*, entry: dict, baseline_bin_dir: str, experiment_dir: str,
                       project_src_dir: str, fuzz_target: str, online_dir: str,
                       profile_cpu: int) -> tuple[bool, str]:
    """Profile the baseline on the seed corpus and build its hotspot table, as a
    round would (phase2_setup.run_baseline_profile), before any trial starts.

    Fails ONLY on what would break every round: the hotspot table cannot be
    built (source-root mismatch, symbolizer failure, perf without dsoff, a
    truncated or mismatched dump), the profiler could not run, or perf recorded
    no sample at all in the build's own binary/libraries. A LOW target-source
    count is a warning, never a refusal: seeds can be one tiny "hi" input that
    exercises next to no project code (zlib's uncompress("hi") is ~1 us), and
    the rounds profile real mutations instead. Written to
    <online_dir>/preflight_profile/. 0 seconds disables the check.
    """
    secs = int(getattr(config, "ONLINE_PREFLIGHT_PROFILE_SECS", 30) or 0)
    if secs <= 0:
        return True, "disabled"
    corpus = os.path.join(experiment_dir, "seed_corpus", "merged")
    if not os.path.isdir(corpus) or not any(
            p.is_file() for p in Path(corpus).rglob("*")):
        return False, f"no seed corpus at {corpus} to profile"
    script = Path(getattr(config, "PHASE2_SKILL_SCRIPTS_DIR", "")) / "replay_fuzzer_profile.py"
    if not script.is_file():
        return False, f"profiler script missing: {script}"
    prof_dir = os.path.join(online_dir, "preflight_profile", "profile_once")
    env = phase2_setup.profile_layout_env(project_src_dir, fuzz_target)
    proc_env = dict(os.environ)
    proc_env["FUZZ_SOURCE_FOLDS_RUNNER_IMAGE"] = prework_image_for(entry)
    warn_below = int(getattr(config, "ONLINE_PREFLIGHT_WARN_TARGET_SAMPLES", 100))
    ok, stage, why = False, "", ""
    with cpu_ledger.timed("preflight_profile", cores=1) as _info:
        # A transient perf/docker failure gets one more try; anything else is
        # final at once.
        for attempt in (1, 2):
            try:
                ok, stage, why = phase2_setup.run_baseline_profile(
                    replay_profile=script, out_dir=baseline_bin_dir, corpus_dir=corpus,
                    profile_dir=prof_dir, fuzz_target=fuzz_target,
                    min_sample_seconds=secs, cpu=profile_cpu, env=env,
                    proc_env=proc_env, min_target_samples=0)
            except subprocess.TimeoutExpired as e:
                ok, stage, why = False, "timeout", str(e)
            except Exception as e:  # noqa: BLE001 - a crash here is a failed check
                ok, stage, why = False, "exception", repr(e)
            if ok or stage not in phase2_setup.TRANSIENT_PREBUILD_STAGES:
                break
        _info["ok"] = ok
    top, target_n, build_n = [], None, None
    if ok:
        try:
            hs = json.loads((Path(prof_dir) / "hotspots.json").read_text())
            target_n = int(hs["totals"]["target_attributed"]["samples"])
            build_n = int(hs["totals"]["build_dso_samples"])
            top = [f"{r['function']} {r['caused_pct']:.2f}%" for r in hs["functions"][:5]]
        except (OSError, ValueError, KeyError, TypeError) as e:
            ok, stage, why = False, "hotspots", f"hotspots.json unreadable: {e}"
    if ok and not build_n:
        ok, stage, why = False, "sanity", (
            f"perf recorded no sample at all in the build's own binary or libraries "
            f"({fuzz_target}): it is not sampling the target processes")
    if ok:
        if target_n < warn_below:
            logger.warning(
                "online: setup profile check: only %d samples attributed to %s's own "
                "source functions on the seeds (%d in the build's DSOs; warn below "
                "%d). Not refusing: seeds can barely exercise the project; the "
                "rounds profile real mutations.", target_n, fuzz_target, build_n,
                warn_below)
        logger.info("online: setup profile check passed (%s); top rows: %s", why,
                    "; ".join(top) or "-")
    provenance.write_json(os.path.join(online_dir, "preflight_profile.json"), {
        "ok": ok, "stage": stage, "reason": why, "seconds": secs,
        "target_source_samples": target_n, "build_dso_samples": build_n,
        "warn_below": warn_below, "corpus": corpus, "layout": env, "top_rows": top})
    return ok, f"{stage}: {why}"


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
    # A reused experiment id must fail HERE, before setup: every launch sets
    # AFL_AUTORESUME=1 and start_trial never wipes afl_out, so the "new" trials
    # would silently resume the old campaign's queues (and setup below would
    # first rmtree the old run's source tree). The trial list is pure; the real
    # one is built again below. start_trial re-checks per trial as a backstop.
    _stale = phase3_runner.stale_afl_state(
        experiment_id, [t for arm in _build_online_trials(entry, experiment_dir)
                        for t in arm])
    if _stale:
        logger.error("online: experiment %r already has AFL state in %d trial "
                     "dir(s) (first: %s); refusing to start a fresh campaign on "
                     "top of it", experiment_id, len(_stale), _stale[0])
        return False
    # The agent container's cpuset, resolved ONCE, here, before any setup. It used
    # to be resolved inside each optimizer's first session, so a bad
    # ONLINE_AGENT_CPUS (or a core layout leaving no core free) raised there,
    # _drive's per-optimizer catch-all swallowed it, and every optimizer died
    # while the trials fuzzed on for the full budget -- a campaign that silently
    # becomes two baseline arms. Pinned into config afterwards so every later
    # resolve_agent_cpus() (each round's launch and its optimizer_provenance())
    # takes the explicit path and returns this same set instead of re-deriving it.
    agent_cpus = None
    if getattr(config, "PHASE2_SANDBOX", True):
        from sandbox.session import resolve_agent_cpus
        try:
            agent_cpus = resolve_agent_cpus()
        except Exception as e:  # noqa: BLE001 - any failure here aborts the run
            logger.error("online: cannot place the agent containers (%s); refusing "
                         "to start a campaign whose optimizers would all die at "
                         "their first round", e)
            return False
        config.ONLINE_AGENT_CPUS = agent_cpus
        logger.info("online: agent containers pinned to cpus %s", agent_cpus)
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
    # Setup builds (everything up to the first trial) may use every core the
    # campaign owns; replays and PoC checks stay on profile_cpu.
    setup_cpus = _setup_cpus(profile_cpu)
    logger.info("online: setup builds on cpus %s, setup replays on core %s",
                setup_cpus, profile_cpu)
    crashed, poc_path, issue, source_root = _extract_online_target(
        entry, source_tree_root, baseline_bin_dir, poc_dir, fuzz_target, project,
        cpu=profile_cpu, setup_cpus=setup_cpus)
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
    _stage_online_seed_corpus(experiment_dir, baseline_bin_dir, fuzz_target, entry=entry)

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
    #
    # Not for FuzzBench: there the extraction above already built the AFL++
    # baseline through the same image, from the already-stripped tree (see
    # _extract_online_target), and there is no PoC to re-verify. Building it
    # again cost one full build (~1.5h on php at one core) for an identical /out.
    if entry.get("kind") != "fuzzbench" and not _build_afl_baseline(
                               entry=entry, project_src_dir=project_src_dir,
                               baseline_bin_dir=baseline_bin_dir,
                               fuzz_target=fuzz_target, poc_path=poc_path,
                               profile_cpu=profile_cpu, setup_cpus=setup_cpus):
        return False

    # 1c'. Setup-time profile check, before any trial launches: profile the
    # baseline on the seeds and build the hotspot table exactly the way every
    # round will. A profiler that cannot see the project's code -- code in a
    # shared library it misses, a source root that does not match the build, a
    # perf that cannot sample the target -- otherwise surfaces as 24 h of
    # prebuild-failed rounds and an online arm that is a second baseline.
    ok, why = _preflight_profile(
        entry=entry, baseline_bin_dir=baseline_bin_dir, experiment_dir=experiment_dir,
        project_src_dir=project_src_dir, fuzz_target=fuzz_target,
        online_dir=online_dir, profile_cpu=profile_cpu)
    if not ok:
        logger.error("online: setup profile check FAILED for %s: %s -- refusing to "
                     "start a campaign whose optimizer rounds could not run",
                     entry["cve"], why)
        return False

    # Build-to-build noise floor, measured once here on UNMODIFIED source so the
    # gate's accept threshold can be read against the target's own variance.
    _nf_rounds = int(getattr(config, "PROVENANCE_NOISE_FLOOR", 0) or 0)
    if _nf_rounds >= 2:
        try:
            _nf = _measure_noise_floor(ctx_entry=entry, source_root=project_src_dir,
                                       fuzz_target=fuzz_target, online_dir=online_dir,
                                       profile_cpu=profile_cpu, rounds=_nf_rounds,
                                       setup_cpus=setup_cpus)
            logger.info("noise floor: spread=%s%% -> folds below %sx are inside "
                        "the target's own measurement noise",
                        _nf.get("spread_pct"), _nf.get("min_meaningful_speedup"))
            provenance.write_json(os.path.join(online_dir, "noise_floor.json"), _nf)
        except Exception as e:  # noqa: BLE001 - never block a campaign on this
            logger.warning("noise floor measurement failed: %s", e)

    # 1d. FuzzBench targets on the ccache verified list: warm a template cache for
    #     the optimized arm's rebuilds, main + cmplog (the baseline above stays
    #     uncached).
    _ccache_rec = _prepare_fb_ccache_template(
        entry=entry, project_src_dir=project_src_dir, online_dir=online_dir,
        baseline_bin_dir=baseline_bin_dir, fuzz_target=fuzz_target,
        profile_cpu=profile_cpu, setup_cpus=setup_cpus)
    _ccache_template = _ccache_rec.get("template")

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
            # Own ccache per optimizer, copied from the template (never the
            # template itself): its builds compile this trial's agent-edited code.
            t_cache = (fb_ccache.seed_cache(_ccache_template, fb_ccache.trial_cache_dir(tdir))
                       if _ccache_template else None)
            t_rebuild, t_wrapper = _online_target_strategy(
                entry, fuzz_target, issue=issue, profile_cpu=t_cpu, ccache_dir=t_cache)
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
        _cache = (fb_ccache.seed_cache(_ccache_template,
                                       fb_ccache.trial_cache_dir(online_dir))
                  if _ccache_template else None)
        rebuild_fn, wrapper_env_fn = _online_target_strategy(
            entry, fuzz_target, issue=issue, profile_cpu=profile_cpu, ccache_dir=_cache)
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
        # The cpuset every agent container in this campaign runs on, resolved
        # once at the top of run_online (None: unsandboxed, no container).
        "agent_cpus": agent_cpus,
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
        # -O level both arms (and every agent build) were compiled at: the level
        # that RAN, not the raw BUILD_OPT_LEVEL string, whose default "" now means
        # "the benchmark's own build" rather than naming a level. ARVO: the image's
        # own CFLAGS level unless BUILD_OPT_LEVEL overrides it, exact CFLAGS under
        # "build_opt". FuzzBench builds ignore BUILD_OPT_LEVEL: their level is
        # fixed by benchmark type (fuzzers/utils.py: -O1 bug, -O3 coverage). A
        # throughput number is only comparable to another run at the same level.
        **build_opt_provenance(entry),
        # ccache (main + cmplog builds) for the optimized arm's rebuilds (FuzzBench,
        # verified targets). The baseline arm and the reference baseline are never
        # cached.
        "ccache": _ccache_rec,
        "restart_policy": {
            "mirror_swaps": bool(getattr(config, "BASELINE_RESTART_MIRROR_SWAPS", False)),
            "interval_secs": int(getattr(config, "BASELINE_RESTART_INTERVAL_SECS", 0) or 0),
            "arm": str(getattr(config, "BASELINE_RESTART_ARM", "baseline")),
            # Which swaps a mirroring baseline follows: its own trial_id pair's
            # (per-trial optimizers) or every shared swap. Campaigns before this
            # field mirrored EVERY optimizer's swap in per-trial mode.
            "mirror_pairing": "trial_id" if per_trial else "shared",
            # Early-death relaunch of baseline trials (phase3_runner.monitor_trial);
            # each death is in that trial's metadata.json "early_deaths".
            "early_death_relaunch": int(getattr(
                config, "TRIAL_RELAUNCH_MAX_QUICK_DEATHS", 3)) > 0,
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

    # Optimizer budget deadline = when the fuzzing trials end. Each trial runs
    # `-V duration` from its OWN start; use the earliest so the deadline never
    # sits past a trial's real end. No round starts within ONLINE_ROUND_MIN_LEAD_SECS
    # (default 1h) of it, and any in-flight agent is capped to it (see run_round ->
    # optimize_and_build(deadline=...)), so the optimizer stops at the budget end
    # instead of running hours into the wind-down.
    _min_lead = float(getattr(config, "ONLINE_ROUND_MIN_LEAD_SECS", 3600) or 0)
    _starts = [v.get("overall_start") for v in state.trials.values()
               if v.get("overall_start")]
    _opt_deadline = (min(_starts) if _starts else time.time()) + float(duration)
    for _c in contexts:
        _c.deadline = _opt_deadline
    logger.info("optimizer budget deadline in %.1fh; no new round within %.0fm of it",
                max(_opt_deadline - time.time(), 0.0) / 3600.0, _min_lead / 60.0)

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
                wait_fn=lambda: time.sleep(_inter_round_wait(
                    _interval, c.deadline, _min_lead)),
                deadline=c.deadline, min_round_lead_s=_min_lead,
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
    _campaign.update(_rounds_record(contexts, per_trial))
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
