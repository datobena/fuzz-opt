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
import re
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

import config
import phase2_setup
import phase3_runner
from lib import crash_classify, docker_util

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
      - ``bug_found``   : a real target bug reproduced (under AFL the run continues, so it
                          exits at the first crash) — terminal, never relaunch.
      - ``budget_done`` : the time budget is exhausted — terminal. This also wins over
                          a pending swap: a swap requested with no time left must not
                          relaunch.
      - ``swap``        : the orchestrator stopped the container to swap the binary —
                          park on relaunch_ready, then relaunch with the remaining time.
      - ``dead``        : a genuine early death (OOM/startup) with time left — relaunch
                          immediately with the remaining time.
    """
    if found_bug:
        return "bug_found"
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


def should_reopen(recorded_rank: int, recorded_share: float,
                  current_rank: int | None, current_share: float | None,
                  *, rank_delta: int | None = None,
                  share_rel: float | None = None) -> bool:
    """True if a tried hotspot's profile changed materially enough to retry it.

    Materially = current rank moved by >= ``rank_delta`` places, OR its self-time
    share changed by >= ``share_rel`` (relative). A function that dropped out of the
    current profile (current_rank/share None) is NOT re-opened — it is no longer hot.
    """
    if rank_delta is None:
        rank_delta = getattr(config, "ONLINE_LEDGER_REOPEN_RANK_DELTA", 3)
    if share_rel is None:
        share_rel = getattr(config, "ONLINE_LEDGER_REOPEN_SHARE_REL", 0.25)
    if current_rank is None or current_share is None:
        return False
    if abs(current_rank - recorded_rank) >= rank_delta:
        return True
    if recorded_share > 0 and abs(current_share - recorded_share) / recorded_share >= share_rel:
        return True
    return False


def build_ledger_summary(ledger: list[dict], current_profile: dict[str, dict]) -> str:
    """Build the 'already-attempted, avoid unless changed' prompt block.

    ``current_profile`` maps function -> {"rank": int, "share": float}. An entry is
    dropped from the avoid list (re-opened) if ANY of its functions changed materially
    vs the attempt. Returns "" when there is nothing to avoid.
    """
    avoided: list[dict] = []
    for entry in ledger:
        reopened = False
        for f in entry.get("functions", []):
            cur = current_profile.get(f)
            rec_rank = entry.get("hotspot_rank", {}).get(f)
            rec_share = entry.get("hotspot_share", {}).get(f)
            if rec_rank is None or rec_share is None:
                continue
            if should_reopen(rec_rank, rec_share,
                             cur.get("rank") if cur else None,
                             cur.get("share") if cur else None):
                reopened = True
                break
        if not reopened:
            avoided.append(entry)
    if not avoided:
        return ""
    lines = ["Already-attempted folds (AVOID re-attempting these unless a hotspot's "
             "profile changed materially):"]
    for e in avoided:
        funcs = ", ".join(e.get("functions", [])) or "(unknown)"
        lines.append(
            f"- {funcs} — {e.get('fold_pattern', '?')} — "
            f"{e.get('outcome', '?')} (replay speedup {e.get('measured_speedup', '?')})"
        )
    lines.append("You MAY re-open one only if its function's current profile rank or "
                 "self-time share differs materially from the attempt.")
    return "\n".join(lines)


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
                    entry, previous_best_bin) -> dict:
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
    """
    env = phase2_setup._make_phase2_profile_env(
        experiment_dir, diff_dir, opt_bin_dir,
        corpus_dir=snapshot_dir, entry=entry, baseline_out_dir=previous_best_bin,
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
    subprocess.run(["git", "add", "-A"], cwd=cwd, capture_output=True)
    subprocess.run(["git", "commit", "-m", f"online {tag}", "--allow-empty"],
                   cwd=cwd, capture_output=True, env=env)
    subprocess.run(["git", "tag", "-f", tag], cwd=cwd, capture_output=True)


def _revert_source_tree(source_tree, tag: str) -> None:
    """Reset the cumulative tree back to a tagged accepted state.

    Called when a round is REJECTED so the next round does not build on top of a
    rejected / bug-removing / non-speedup edit (the highest-severity correctness risk).
    """
    cwd = str(source_tree)
    subprocess.run(["git", "reset", "--hard", tag], cwd=cwd, capture_output=True)
    subprocess.run(["git", "clean", "-fd"], cwd=cwd, capture_output=True)


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


# ---------------------------------------------------------------------------
# Sequential optimizer loop (convergence-terminated)
# ---------------------------------------------------------------------------
def run_optimizer_loop(*, run_round_fn, hot_swap_fn, convergence_k: int,
                       wait_fn, all_terminal_fn) -> int:
    """Drive sequential optimization rounds.

    Each iteration: wait the minimum inter-swap fuzz interval, stop if every online
    trial is already terminal, else run one round; on an accepted round hot-swap and
    reset the no-improvement counter, on a rejected round increment it and stop after
    ``convergence_k`` consecutive rejects. Returns the number of rounds attempted.
    Fuzzing continues to the end of the budget regardless (driven by the caller).
    """
    consecutive = 0
    iter_n = 0
    while True:
        wait_fn()
        if all_terminal_fn():
            break
        iter_n += 1
        accepted, new_bin = run_round_fn(iter_n)
        if accepted:
            hot_swap_fn(new_bin)
            consecutive = 0
        else:
            consecutive += 1
            if consecutive >= convergence_k:
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
def _build_online_trials(entry: dict):
    """Build the two arms for one target: 10 baseline + 10 online trials.

    Online trials use variant "optimized" so they write into the optimized/ dir that
    phase4_analysis.py already reads. Seeds follow the phase3_runner formula (baseline
    vs optimized offset). All 20 trials are pinned round-robin across ONLINE_TRIAL_CORES.
    """
    project, cve = entry["project"], entry["cve"]
    trial_cores = parse_cpu_range(getattr(config, "ONLINE_TRIAL_CORES", "4-23"))
    baseline, online = [], []
    for tid in range(config.NUM_TRIALS):
        b_seed = (config.BASE_SEED + tid * config.SEED_MULTIPLIER
                  + config.BASELINE_SEED_OFFSET)
        o_seed = (config.BASE_SEED + tid * config.SEED_MULTIPLIER
                  + config.OPTIMIZED_SEED_OFFSET)
        baseline.append(phase3_runner.Trial(project=project, cve=cve,
                                             variant="baseline", trial_id=tid, seed=b_seed))
        online.append(phase3_runner.Trial(project=project, cve=cve,
                                          variant="optimized", trial_id=tid, seed=o_seed))
    for i, t in enumerate(baseline + online):
        t.cpu = trial_cores[i % len(trial_cores)]
    return baseline, online


def _is_n132_entry(entry: dict) -> bool:
    """True for an n132/arvo prebuilt-image entry; False for a classic gcr-ARVO one."""
    return "n132/arvo" in str(entry.get("image") or "")


def _online_target_strategy(entry: dict, fuzz_target: str, issue: dict | None = None):
    """Return (rebuild_fn, wrapper_env_fn) closures for this entry's backend.

    n132/arvo image -> ``arvo compile`` on the bundled image; classic ARVO (a bare
    ``local_id``, e.g. selinux) -> rebuild via the ``gcr.io/oss-fuzz/<local_id>`` image
    and the ARVO wrapper-validation commands. rebuild_fn(source_root, out_bin_dir) and
    wrapper_env_fn(source_root, state_dir) hide the backend from run_round.
    """
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
            m = re.match(r"^\s*(\d+\.\d+)%\s+\S+\s+\[[^\]]*\]\s+(\S+)", line)
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
    subprocess.run(["git", "init"], cwd=str(tree), capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=str(tree), capture_output=True)
    subprocess.run(["git", "commit", "-m", "online baseline", "--allow-empty"],
                   cwd=str(tree), capture_output=True, env=env)


def _write_cumulative_diff(tree, out_path):
    r = subprocess.run(["git", "diff", "iter_00", "HEAD"], cwd=str(tree),
                       capture_output=True, text=True)
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


def run_round(ctx: RoundContext, state: OnlineState, iter_n: int):
    """One online optimization round on the persistent cumulative source tree.

    Returns (accepted, iter_bin_dir). Mirrors setup_cve_arvo_image's gate wiring, but
    the profiling corpus is a live-trial snapshot and the replay baseline is the
    previous-best binary (cumulative). A rejected round reverts the tree to prev_tag so
    the next round never builds on a rejected edit.
    """
    ctx.iter_n = iter_n
    iter_dir = os.path.join(ctx.online_dir, f"iter_{iter_n:02d}")
    diff_dir = os.path.join(iter_dir, "source_diff")
    opt_bin_dir = os.path.join(iter_dir, "bin")
    os.makedirs(diff_dir, exist_ok=True)
    os.makedirs(opt_bin_dir, exist_ok=True)

    # 1. snapshot the chosen live trial's accumulated corpus (consistent copy)
    chosen = select_snapshot_trial(
        ctx.online_trials, lambda t: _corpus_file_count(ctx.experiment_id, t))
    src_corpus = phase3_runner.get_live_corpus_dir(ctx.experiment_id, chosen)
    snap_dir = os.path.join(iter_dir, "corpus_snapshot")
    meta = snapshot_live_corpus(src_corpus, snap_dir, now=time.time())
    meta["trial_id"] = chosen.trial_id
    _write_json(os.path.join(iter_dir, "corpus_snapshot_meta.json"), meta)
    logger.info("online round %d: snapshot trial_%02d -> %d files (%d skipped in-flight)",
                iter_n, chosen.trial_id, meta["file_count"], meta["skipped_in_flight"])
    if meta["file_count"] == 0:
        logger.warning("online iter %d: empty corpus snapshot; skipping round", iter_n)
        _record_ledger(ctx, iter_n, diff_dir, "build-failed", None)
        return (False, None)

    # 2. env: profile the snapshot; anchor the replay gate on the previous best
    env = build_round_env(
        experiment_dir=ctx.experiment_dir, diff_dir=diff_dir,
        opt_bin_dir=os.path.join(iter_dir, "validation_out"),
        snapshot_dir=snap_dir, entry=ctx.entry,
        previous_best_bin=ctx.previous_best_bin)
    env.update(ctx.wrapper_env_fn(ctx.source_root, os.path.join(iter_dir, "validation")))

    # 3. soft ledger -> optimizer prompt (avoid prior folds unless profile shifted)
    ledger_summary = build_ledger_summary(ctx.ledger, ctx.last_profile)

    def build_fn():
        return ctx.rebuild_fn(ctx.source_root, opt_bin_dir)

    try:
        build_ok = phase2_setup.optimize_and_build(
            ctx.source_tree, ctx.fuzz_target, diff_dir, project=ctx.project,
            build_fn=build_fn, codex_extra_env=env, use_wrapper_validation=True,
            extra_prompt_directives=ledger_summary or None)
    except phase2_setup.MutationAugmentationError as exc:
        logger.warning("online iter %d: mutation augmentation failed: %s", iter_n, exc)
        ctx.previous_best_bin = apply_round_outcome(
            False, source_tree=ctx.source_tree, iter_n=iter_n, opt_bin_dir=opt_bin_dir,
            previous_best_bin=ctx.previous_best_bin, prev_tag=ctx.prev_tag)
        _record_ledger(ctx, iter_n, diff_dir, "build-failed", None)
        return (False, None)

    # refresh the parsed profile (used to record attempt ranks + next round's re-open)
    ctx.last_profile = _parse_profile_ranks(os.path.join(diff_dir, "profiles", "profile_once"))

    opt_diff = os.path.join(diff_dir, "optimization.diff")
    opt_applied = os.path.exists(opt_diff) and bool(open(opt_diff).read().strip())
    optimization_ready = build_ok and opt_applied

    opt_crashes = False
    if optimization_ready and ctx.poc_path:
        opt_crashes = phase2_setup.verify_poc_crash(opt_bin_dir, ctx.fuzz_target, ctx.poc_path)

    opt_rej = None
    replay = None
    if optimization_ready:
        optimization_ready, opt_rej = phase2_setup._reject_if_optimization_removed_bug(
            project=ctx.project, cve=ctx.entry["cve"],
            optimization_ready=optimization_ready,
            baseline_reproduced=bool(ctx.poc_path), opt_crashes=opt_crashes,
            baseline_bin_dir=ctx.previous_best_bin, optimized_bin_dir=opt_bin_dir)
    if optimization_ready:
        replay = phase2_setup.run_replay_speedup(
            diff_output_dir=diff_dir, baseline_bin_dir=ctx.previous_best_bin,
            optimized_bin_dir=opt_bin_dir, fuzz_target=ctx.fuzz_target,
            experiment_dir=ctx.experiment_dir, profile_cpu=ctx.profile_cpu)
        optimization_ready, replay_rej = phase2_setup._reject_if_no_replay_speedup(
            project=ctx.project, cve=ctx.entry["cve"],
            optimization_ready=optimization_ready, replay=replay,
            baseline_bin_dir=ctx.previous_best_bin, optimized_bin_dir=opt_bin_dir)
        opt_rej = opt_rej or replay_rej

    if optimization_ready:
        outcome = "kept"
    elif opt_rej and opt_rej.get("stage") == "optimized_poc_verify":
        outcome = "rejected-removed-bug"
    elif not opt_applied or not build_ok:
        outcome = "build-failed"
    else:
        outcome = "rejected-no-speedup"
    speedup = replay.get("replay_speedup") if replay else None
    logger.info("online round %d: outcome=%s speedup=%s applied=%s built=%s",
                iter_n, outcome, speedup, opt_applied, build_ok)
    _record_ledger(ctx, iter_n, diff_dir, outcome, speedup)

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
        return (True, opt_bin_dir)
    return (False, None)


def hot_swap(ctx: RoundContext, state: OnlineState, new_bin_dir):
    """Swap the accepted round binary into all online trials (stop-all -> overwrite ->
    relaunch), holding swap_lock. swap_barrier stays set until every swapped monitor has
    relaunched, which closes the re-loop race noted in the plan."""
    with state.swap_lock:
        running = [t for t in ctx.online_trials
                   if state.trials[t.trial_id]["state"] == "running"]
        logger.info("online round %d: HOT-SWAP into %d running online trials",
                    ctx.iter_n, len(running))
        state.swap_barrier.set()
        state.relaunch_ready.clear()
        for t in running:
            state.trials[t.trial_id]["relaunched"].clear()
        shared_bin = os.path.join(ctx.optimized_bin_dir, ctx.fuzz_target)
        new_bin = os.path.join(str(new_bin_dir), ctx.fuzz_target)
        _stop_all_and_overwrite(running, shared_bin, new_bin)
        state.swap_timeline.append({
            "iter": ctx.iter_n, "ts": time.time(),
            "per_trial": {t.trial_id: {"relaunched": True} for t in running}})
        _write_json(ctx.swap_timeline_path, state.swap_timeline)
        state.relaunch_ready.set()
        for t in running:
            state.trials[t.trial_id]["relaunched"].wait(timeout=180)
        state.swap_barrier.clear()
        logger.info("online round %d: swap complete, %d trials relaunched on new binary",
                    ctx.iter_n, len(running))


def _finalize_online_trial(trial, experiment_id, duration, overall_start, crash_times):
    dirs = phase3_runner.get_trial_dirs(experiment_id, trial)
    logs = docker_util.get_container_logs(trial.container_id) or ""
    os.makedirs(dirs["base"], exist_ok=True)
    with open(dirs["log"], "w") as f:
        f.write(logs)
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


def _monitor_online_trial(trial, experiment_id, duration, state: OnlineState):
    """Bespoke monitor: distinguishes budget/bug/swap/early-death on container exit and
    relaunches (preserving corpus) for swap/dead, finalizes for bug/budget."""
    dirs = phase3_runner.get_trial_dirs(experiment_id, trial)
    crashes_dir = dirs["crashes"]
    rec = state.trials[trial.trial_id]
    overall_start = rec["overall_start"]
    crash_times = rec["crash_times"]
    seen = rec["seen_crashes"]

    def scan():
        if not os.path.isdir(crashes_dir):
            return
        for fn in os.listdir(crashes_dir):
            if fn in seen or not fn.startswith(("crash-", "oom-", "timeout-")):
                continue
            seen.add(fn)
            crash_times.append({
                "timestamp_s": round(time.time() - overall_start, 2),
                "artifact": fn,
                "crash_type": phase3_runner.classify_crash(os.path.join(crashes_dir, fn)),
            })

    while True:
        while docker_util.container_is_running(trial.container_id):
            scan()
            time.sleep(2 if time.time() - overall_start < 30 else 10)
        scan()
        found_bug = crash_classify.trial_found_bug(crash_times, duration)
        elapsed = time.time() - overall_start
        cause = classify_exit(swap_requested=state.swap_barrier.is_set(),
                              found_bug=found_bug, elapsed=elapsed, duration=duration)
        if cause in ("bug_found", "budget_done"):
            rec["state"] = cause
            _finalize_online_trial(trial, experiment_id, duration, overall_start, crash_times)
            return
        if cause == "swap":
            state.relaunch_ready.wait()
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
    if not crashed:
        logger.error("online: baseline did not reproduce for %s", entry["cve"])
        return False

    # 2. iteration 0 = original baseline; seed the LIVE shared binary from it
    os.makedirs(optimized_bin_dir, exist_ok=True)
    shutil.copytree(baseline_bin_dir, optimized_bin_dir, dirs_exist_ok=True)
    iter0_bin = os.path.join(online_dir, "iter_00", "bin")
    os.makedirs(iter0_bin, exist_ok=True)
    shutil.copytree(baseline_bin_dir, iter0_bin, dirs_exist_ok=True)

    # 3. persistent cumulative source tree: git init + tag iter_00
    project_src_dir = str(phase2_setup._find_project_source(Path(source_root), project))
    _git_init_baseline(project_src_dir)
    _commit_and_tag(project_src_dir, "iter_00")

    rebuild_fn, wrapper_env_fn = _online_target_strategy(entry, fuzz_target, issue=issue)
    _pcpu = os.environ.get("ONLINE_PROFILE_CPU") or getattr(config, "ONLINE_PROFILE_CPU", "")
    profile_cpu = int(_pcpu) if str(_pcpu).strip() else max(
        int(getattr(config, "RESERVED_CORES", 1)) - 1, 0)

    ctx = RoundContext(
        entry=entry, experiment_id=experiment_id, experiment_dir=experiment_dir,
        online_dir=online_dir, source_tree=project_src_dir, source_root=source_root,
        project=project, image=image,
        fuzz_target=fuzz_target, poc_path=poc_path, previous_best_bin=iter0_bin,
        prev_tag="iter_00", optimized_bin_dir=optimized_bin_dir,
        ledger_path=os.path.join(online_dir, "ledger.json"),
        swap_timeline_path=os.path.join(online_dir, "swap_timeline.json"),
        profile_cpu=profile_cpu, rebuild_fn=rebuild_fn, wrapper_env_fn=wrapper_env_fn)

    baseline_trials, online_trials = _build_online_trials(entry)
    ctx.online_trials = online_trials
    state = OnlineState()

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
            "relaunched": threading.Event()}
        futures.append(executor.submit(_monitor_online_trial, t, experiment_id, duration, state))

    # 5. sequential optimizer loop (fuzzing continues to budget regardless)
    def _all_terminal():
        return all(state.trials.get(t.trial_id, {}).get("state") != "running"
                   for t in online_trials)

    run_optimizer_loop(
        run_round_fn=lambda i: run_round(ctx, state, i),
        hot_swap_fn=lambda new_bin: hot_swap(ctx, state, new_bin),
        convergence_k=getattr(config, "ONLINE_CONVERGENCE_K", 2),
        wait_fn=lambda: time.sleep(getattr(config, "ONLINE_SWAP_INTERVAL_SECS", 3600)),
        all_terminal_fn=_all_terminal)

    for _ in as_completed(futures):
        pass
    executor.shutdown(wait=True)
    logger.info("online: run complete for %s (%d rounds attempted)", entry["cve"], ctx.iter_n)
    return True
