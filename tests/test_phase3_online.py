# test_phase3_online.py
import json
import os
import threading
import time
import types

import pytest

import config


# ---------------------------------------------------------------------------
# config knobs
# ---------------------------------------------------------------------------
def test_online_config_defaults():
    assert config.ONLINE_ENABLED is False
    assert config.ONLINE_SWAP_INTERVAL_SECS == 3600
    # 0 = never stop early. A run of rejects does not predict the next round:
    # the corpus the optimizer profiles keeps growing, so a foldable hotspot can
    # appear late. The old value of 3 ended lcms's optimization at round 4 of a
    # 24h campaign, leaving the online arm to finish as a second baseline.
    assert config.ONLINE_CONVERGENCE_K == 0
    assert config.ONLINE_TRIAL_CORES == "4-23"
    assert config.ONLINE_OPTIMIZER_CORES == "24-39"
    assert config.ONLINE_SNAPSHOT_TRIAL_SELECTOR == "largest"


import phase3_online


# ---------------------------------------------------------------------------
# parse_cpu_range
# ---------------------------------------------------------------------------
def test_parse_cpu_range_dash():
    assert phase3_online.parse_cpu_range("4-23") == list(range(4, 24))


def test_parse_cpu_range_list():
    assert phase3_online.parse_cpu_range("4,7,9") == [4, 7, 9]


def test_parse_cpu_range_mixed():
    assert phase3_online.parse_cpu_range("4-6,10") == [4, 5, 6, 10]


# ---------------------------------------------------------------------------
# classify_exit — the ambiguous-container-exit discriminator
# ---------------------------------------------------------------------------
def test_classify_exit_bug_is_not_terminal():
    """Finding the bug must NOT stop an online trial.

    AFL keeps fuzzing past a crash, and the baseline arm runs -V {duration} with
    no early exit -- so stopping the online arm at its first bug truncates the
    very measurement this benchmark exists to make, which is the libFuzzer
    behaviour the project migrated away from. A swap with time left still
    relaunches; finding the bug changes nothing.
    """
    assert phase3_online.classify_exit(
        swap_requested=True, found_bug=True, elapsed=10, duration=600
    ) == "swap"
    assert phase3_online.classify_exit(
        swap_requested=False, found_bug=True, elapsed=10, duration=600
    ) == "dead"
    assert phase3_online.classify_exit(
        swap_requested=False, found_bug=True, elapsed=600, duration=600
    ) == "budget_done"


def test_classify_exit_budget_when_time_up():
    assert phase3_online.classify_exit(
        swap_requested=False, found_bug=False, elapsed=600, duration=600
    ) == "budget_done"


def test_classify_exit_swap_requested_with_time_left():
    assert phase3_online.classify_exit(
        swap_requested=True, found_bug=False, elapsed=100, duration=600
    ) == "swap"


def test_classify_exit_swap_requested_but_no_time_left_is_budget():
    # A swap requested exactly as the budget runs out must NOT relaunch.
    assert phase3_online.classify_exit(
        swap_requested=True, found_bug=False, elapsed=600, duration=600
    ) == "budget_done"


def test_classify_exit_early_death_relaunches():
    assert phase3_online.classify_exit(
        swap_requested=False, found_bug=False, elapsed=42, duration=600
    ) == "dead"


# ---------------------------------------------------------------------------
# functions_from_diff — attempt-ledger population from a git diff
# ---------------------------------------------------------------------------
_DIFF = """diff --git a/secilc/cil.c b/secilc/cil.c
index abc1234..def5678 100644
--- a/secilc/cil.c
+++ b/secilc/cil.c
@@ -10,7 +10,9 @@ static int cil_resolve_ast(struct cil_db *db)
   int rc;
-  slow_path();
+  fast_path();
@@ -50,3 +52,5 @@ void cil_symtab_get_datum(struct cil_symtab *s)
   return s->datum;
@@ -1,3 +1,3 @@
   /* no enclosing function context here */
"""


def test_functions_from_diff_extracts_hunk_context_functions():
    fns = phase3_online.functions_from_diff(_DIFF)
    assert fns == ["cil_resolve_ast", "cil_symtab_get_datum"]


def test_functions_from_diff_empty():
    assert phase3_online.functions_from_diff("") == []


# ---------------------------------------------------------------------------
# (Removed) should_reopen / build_ledger_summary tests. The soft attempt ledger
# no longer exists: nothing skips or re-opens a function, and no attempt-history
# block is injected into the optimizer prompt. ledger.json is still written as a
# record by _record_ledger, which the round-outcome tests below still cover.
# ---------------------------------------------------------------------------
# snapshot_live_corpus — consistent copy of a corpus being written concurrently
# ---------------------------------------------------------------------------
def test_snapshot_live_corpus_skips_in_flight_files(tmp_path):
    src = tmp_path / "corpus"
    src.mkdir()
    now = 1_000_000.0
    # two settled units, one just-written (in-flight)
    for i, age in enumerate([100.0, 100.0, 0.5]):
        f = src / f"unit_{i}"
        f.write_bytes(b"x" * (i + 1))
        os.utime(f, (now - age, now - age))
    dest = tmp_path / "snap"

    meta = phase3_online.snapshot_live_corpus(src, dest, now=now, min_age_s=2.0)

    assert meta["file_count"] == 2
    assert meta["skipped_in_flight"] == 1
    assert meta["taken_at"] == now
    assert len(list(dest.iterdir())) == 2


# ---------------------------------------------------------------------------
# select_snapshot_trial — pick which live trial's corpus feeds the round
# ---------------------------------------------------------------------------
def _trial(tid, state):
    return types.SimpleNamespace(trial_id=tid, state=state, variant="online")


def test_select_snapshot_trial_picks_largest_running():
    trials = [_trial(0, "running"), _trial(1, "running"), _trial(2, "bug_found")]
    counts = {0: 5, 1: 9, 2: 20}
    chosen = phase3_online.select_snapshot_trial(trials, lambda t: counts[t.trial_id])
    assert chosen.trial_id == 1


def test_select_snapshot_trial_falls_back_when_none_running():
    trials = [_trial(0, "budget_done"), _trial(1, "bug_found")]
    counts = {0: 3, 1: 5}
    chosen = phase3_online.select_snapshot_trial(trials, lambda t: counts[t.trial_id])
    assert chosen.trial_id == 0  # lowest trial_id fallback


# ===========================================================================
# Wave 2 — docker / git / phase2-wiring seams
# ===========================================================================
import phase2_setup
import phase3_runner


# --- extra_prompt_directives threading through the phase-2 prompt builders ---
def test_extra_prompt_directives_appended_to_initial_prompt():
    p = phase2_setup._make_apply_fuzz_source_folds_prompt_with_mode(
        "harness.c", backend="claude",
        extra_prompt_directives="LEDGER-AVOID: cil_resolve_ast — lut")
    assert "LEDGER-AVOID: cil_resolve_ast" in p


def test_extra_prompt_directives_none_is_noop():
    p = phase2_setup._make_apply_fuzz_source_folds_prompt_with_mode(
        "harness.c", backend="claude")
    assert "LEDGER-AVOID" not in p


def test_retry_prompt_includes_directives():
    p = phase2_setup._make_retry_prompt(
        "tgt", "some build log", backend="claude",
        extra_prompt_directives="LEDGER-AVOID: bar")
    assert "LEDGER-AVOID: bar" in p


# --- relaunch_preserving_corpus must NOT wipe the accumulated corpus ---
def test_relaunch_preserving_corpus_keeps_corpus(monkeypatch, tmp_path):
    from pathlib import Path
    monkeypatch.setattr(config, "RESULTS_DIR", str(tmp_path))
    trial = phase3_runner.Trial(project="p", cve="c", variant="optimized",
                                trial_id=0, seed=1, cpu=5)
    dirs = phase3_runner.get_trial_dirs("exp", trial)
    os.makedirs(dirs["corpus"], exist_ok=True)
    keep = Path(dirs["corpus"]) / "unit_keep"
    keep.write_bytes(b"accumulated")
    bin_dir = Path(str(tmp_path)) / "exp" / "p-c" / "optimized" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "tgt").write_bytes(b"\x7fELFfake")
    monkeypatch.setattr(phase3_runner, "get_fuzzer_binary",
                        lambda e, t: str(bin_dir / "tgt"))
    trial._docker_image = "img"  # pre-set so no docker image resolution happens
    recorded = {}

    def fake_launch(t, e, d):
        recorded["duration"] = d
        t.container_id = "cid"
        t.status = "running"
        return True

    monkeypatch.setattr(phase3_runner, "_launch_container", fake_launch)

    ok = phase3_runner.relaunch_preserving_corpus(trial, "exp", 1234)

    assert ok is True
    assert recorded["duration"] == 1234
    assert keep.exists(), "relaunch must not wipe the accumulated corpus"
    assert keep.read_bytes() == b"accumulated"


# --- swap ordering: stop ALL online containers before overwriting the binary ---
def test_stop_all_before_overwrite(monkeypatch):
    calls = []
    trials = [types.SimpleNamespace(container_id=f"c{i}") for i in range(3)]
    monkeypatch.setattr(phase3_online.docker_util, "stop_container",
                        lambda cid, **k: calls.append(f"stop:{cid}"))
    monkeypatch.setattr(phase3_online.docker_util, "container_is_running",
                        lambda cid: False)
    monkeypatch.setattr(phase3_online, "_overwrite_binary",
                        lambda shared, new: calls.append("overwrite"))

    phase3_online._stop_all_and_overwrite(trials, "shared_bin", "new_bin",
                                          poll_sleep=0.0)

    assert calls == ["stop:c0", "stop:c1", "stop:c2", "overwrite"]


# --- build_round_env overrides the optimization corpus + replay baseline ---
def test_build_round_env_overrides_corpus_and_baseline(tmp_path):
    entry = {"project": "selinux", "cve": "arvo-1", "local_id": 1,
             "image": "n132/arvo:1-vul", "fuzz_target": "secilc-fuzzer"}
    snap = tmp_path / "snap"; snap.mkdir()
    prev = tmp_path / "prev_bin"; prev.mkdir()
    env = phase3_online.build_round_env(
        experiment_dir=tmp_path / "exp", diff_dir=tmp_path / "diff",
        opt_bin_dir=tmp_path / "optbin", corpus_dir=snap,
        entry=entry, previous_best_bin=prev)
    assert env["FUZZ_SOURCE_FOLDS_CORPUS_DIR"] == str(snap)
    assert env["FUZZ_SOURCE_FOLDS_BASELINE_OUT_DIR"] == str(prev)


def test_build_round_env_uses_pure_reservoir(tmp_path):
    # Online rounds sample the fuzzer's real mutation stream via reservoir only; the
    # uncapped guaranteed queue-pass pool (Theta(seeds)) must be OFF so the profiling
    # corpus stays bounded as the trial corpus grows over a long run.
    entry = {"project": "selinux", "cve": "arvo-1", "local_id": 1,
             "image": "n132/arvo:1-vul", "fuzz_target": "secilc-fuzzer"}
    snap = tmp_path / "snap"; snap.mkdir()
    env = phase3_online.build_round_env(
        experiment_dir=tmp_path / "exp", diff_dir=tmp_path / "diff",
        opt_bin_dir=tmp_path / "optbin", corpus_dir=snap,
        entry=entry, previous_best_bin=tmp_path / "prev")
    assert env["FUZZ_SOURCE_FOLDS_MUTATION_QUEUE_PASS"] == "0"
    # reservoir stays enabled (default) — do not disable it
    assert env.get("FUZZ_SOURCE_FOLDS_MUTATION_RESERVOIR", "1") != "0"


# --- backend strategy: n132 vs classic-ARVO (selinux) rebuild + validation wiring ---
def test_strategy_n132_wires_arvo_compile(monkeypatch):
    # Legacy backend. Under PHASE2_SANDBOX (the default) both strategies
    # route through the prework image instead -- see test_phase3_online_afl.
    monkeypatch.setattr(phase3_online.config, "PHASE2_SANDBOX", False)
    calls = {}
    def rec_rebuild(image, src, out, capture_log=False):
        calls["rebuild"] = (image, str(out)); return True
    def rec_wrap(**kw):
        calls["wrap"] = kw; return {"K": "V"}
    monkeypatch.setattr(phase2_setup, "rebuild_with_modified_source_n132", rec_rebuild)
    monkeypatch.setattr(phase2_setup, "_make_n132_wrapper_validation_env", rec_wrap)
    entry = {"project": "libxml2", "cve": "arvo-1972",
             "image": "n132/arvo:1972-vul", "local_id": 1972}
    rebuild_fn, wrap_fn = phase3_online._online_target_strategy(entry, "ft", issue=None)
    rebuild_fn("/root", "/out")
    env = wrap_fn("/root", "/state")
    assert calls["rebuild"] == ("n132/arvo:1972-vul", "/out")
    assert calls["wrap"]["image"] == "n132/arvo:1972-vul"
    assert env == {"K": "V"}


def test_strategy_classic_arvo_wires_gcr_rebuild(monkeypatch):
    # Legacy backend. Under PHASE2_SANDBOX (the default) both strategies
    # route through the prework image instead -- see test_phase3_online_afl.
    monkeypatch.setattr(phase3_online.config, "PHASE2_SANDBOX", False)
    calls = {}
    monkeypatch.setattr(phase2_setup, "rebuild_with_modified_source_arvo",
                        lambda lid, issue, src, out, capture_log=False: calls.setdefault("rebuild", (lid, str(out))) or True)
    monkeypatch.setattr(phase2_setup, "_make_arvo_wrapper_validation_env",
                        lambda **kw: calls.setdefault("wrap", kw) or {"K": "V"})
    entry = {"project": "selinux", "cve": "CVE-2021-36085",
             "image": None, "local_id": 42493454}
    issue = {"fuzz_target": "secilc-fuzzer"}
    rebuild_fn, wrap_fn = phase3_online._online_target_strategy(entry, "secilc-fuzzer", issue=issue)
    rebuild_fn("/root", "/out")
    wrap_fn("/root", "/state")
    assert calls["rebuild"] == (42493454, "/out")
    assert calls["wrap"]["local_id"] == 42493454
    assert calls["wrap"]["issue"] is issue


def test_is_n132_vs_classic_entry():
    assert phase3_online._is_n132_entry({"image": "n132/arvo:1972-vul"}) is True
    assert phase3_online._is_n132_entry({"image": None, "local_id": 42493454}) is False


# --- optimizer loop: converge after K consecutive rejected rounds ---
def test_optimizer_loop_stops_after_k_rejects():
    swaps = []
    n = phase3_online.run_optimizer_loop(
        run_round_fn=lambda i: (False, None),
        hot_swap_fn=lambda b: swaps.append(b),
        convergence_k=2, wait_fn=lambda: None, all_terminal_fn=lambda: False)
    assert n == 2
    assert swaps == []


def test_optimizer_loop_accept_resets_convergence():
    outcomes = iter([(True, "bin1"), (False, None), (False, None)])
    swaps = []
    n = phase3_online.run_optimizer_loop(
        run_round_fn=lambda i: next(outcomes),
        hot_swap_fn=lambda b: swaps.append(b),
        convergence_k=2, wait_fn=lambda: None, all_terminal_fn=lambda: False)
    assert n == 3
    assert swaps == ["bin1"]


def test_optimizer_loop_all_terminal_short_circuits():
    ran = []
    n = phase3_online.run_optimizer_loop(
        run_round_fn=lambda i: ran.append(i) or (False, None),
        hot_swap_fn=lambda b: None,
        convergence_k=2, wait_fn=lambda: None, all_terminal_fn=lambda: True)
    assert n == 0
    assert ran == []


# --- highest-severity risk: a rejected round must revert the cumulative tree ---
def test_apply_round_outcome_reject_reverts_source(monkeypatch):
    calls = []
    monkeypatch.setattr(phase3_online, "_revert_source_tree",
                        lambda tree, tag: calls.append(("revert", tree, tag)))
    monkeypatch.setattr(phase3_online, "_commit_and_tag",
                        lambda tree, tag: calls.append(("commit", tree, tag)))
    result = phase3_online.apply_round_outcome(
        False, source_tree="/tree", iter_n=3, opt_bin_dir="/iter3/bin",
        previous_best_bin="/iter2/bin", prev_tag="iter_02")
    assert ("revert", "/tree", "iter_02") in calls
    assert not any(c[0] == "commit" for c in calls)
    assert result == "/iter2/bin"  # previous best unchanged


def test_apply_round_outcome_accept_commits_and_advances(monkeypatch):
    calls = []
    monkeypatch.setattr(phase3_online, "_revert_source_tree",
                        lambda tree, tag: calls.append(("revert", tree, tag)))
    monkeypatch.setattr(phase3_online, "_commit_and_tag",
                        lambda tree, tag: calls.append(("commit", tree, tag)))
    result = phase3_online.apply_round_outcome(
        True, source_tree="/tree", iter_n=3, opt_bin_dir="/iter3/bin",
        previous_best_bin="/iter2/bin", prev_tag="iter_02")
    assert ("commit", "/tree", "iter_03") in calls
    assert not any(c[0] == "revert" for c in calls)
    assert result == "/iter3/bin"


# --- online trial construction: 10 baseline + 10 online, cores from the pool ---
def test_build_online_trials_two_arms_and_core_pinning(monkeypatch):
    monkeypatch.setattr(config, "NUM_TRIALS", 10)
    monkeypatch.setattr(config, "ONLINE_TRIAL_CORES", "4-23")
    monkeypatch.setattr(config, "ONLINE_PER_TRIAL_OPTIMIZER", False)
    entry = {"project": "selinux", "cve": "arvo-1", "fuzz_target": "secilc-fuzzer"}
    baseline, online = phase3_online._build_online_trials(entry)
    assert len(baseline) == 10 and len(online) == 10
    # legacy mode: every optimized trial shares the one optimized/bin
    assert all(t.bin_dir_override is None for t in online)
    assert all(t.variant == "baseline" for t in baseline)
    assert all(t.variant == "optimized" for t in online)
    pool = set(range(4, 24))
    assert all(t.cpu in pool for t in baseline + online)
    # seeds follow the phase3_runner formula (baseline vs optimized offset)
    assert baseline[0].seed == config.BASE_SEED + config.BASELINE_SEED_OFFSET
    assert online[0].seed == config.BASE_SEED + config.OPTIMIZED_SEED_OFFSET


# --- convergence must reflect the TARGET, not the infrastructure ------------
def test_infrastructure_failures_do_not_count_toward_convergence():
    """A revoked credential, a dead broker or an empty snapshot says nothing
    about whether the target still has headroom. Counting them ended
    optimization for a whole campaign after three transient outages, leaving the
    online arm as a second baseline for the remaining 20 hours."""
    rounds = []

    def run_round(i):
        rounds.append(i)
        if i <= 5:
            return (False, None, False)      # infra: not evidence
        return (False, None, True)           # measured: real reject

    n = phase3_online.run_optimizer_loop(
        run_round_fn=run_round, hot_swap_fn=lambda b: None, convergence_k=2,
        wait_fn=lambda: None,
        all_terminal_fn=lambda: len(rounds) >= 20)
    # 5 infra failures ignored, then 2 measured rejects stop it
    assert n == 7


def test_measured_rejects_still_converge():
    n = phase3_online.run_optimizer_loop(
        run_round_fn=lambda i: (False, None, True), hot_swap_fn=lambda b: None,
        convergence_k=3, wait_fn=lambda: None, all_terminal_fn=lambda: False)
    assert n == 3


def test_a_two_tuple_round_still_counts_as_measured():
    """Backward compatible: the older 2-tuple shape keeps its meaning."""
    n = phase3_online.run_optimizer_loop(
        run_round_fn=lambda i: (False, None), hot_swap_fn=lambda b: None,
        convergence_k=2, wait_fn=lambda: None, all_terminal_fn=lambda: False)
    assert n == 2


def test_an_accepted_round_resets_the_counter():
    seq = [(False, None, True), (True, "/bin", True), (False, None, True),
           (False, None, True)]
    n = phase3_online.run_optimizer_loop(
        run_round_fn=lambda i: seq[i - 1], hot_swap_fn=lambda b: None,
        convergence_k=2, wait_fn=lambda: None, all_terminal_fn=lambda: False)
    assert n == 4


# --- evidence vs infrastructure, drawn from the saved agent report ----------
def _report(tmp_path, body):
    (tmp_path / "agent_attempt_0.txt").write_text(body)
    return str(tmp_path)


def test_a_successful_build_is_always_evidence(tmp_path):
    assert phase3_online._round_produced_evidence(str(tmp_path), True) is True


def test_found_nothing_counts_as_evidence(tmp_path):
    d = _report(tmp_path, "[harness note] NO source changes\n[ok] True\ntried 3, reverted 3")
    assert phase3_online._round_produced_evidence(d, False) is True


def test_a_timeout_is_not_evidence(tmp_path):
    d = _report(tmp_path, "[ok] False  [timed_out] True\n")
    assert phase3_online._round_produced_evidence(d, False) is False


def test_an_auth_failure_is_not_evidence(tmp_path):
    d = _report(tmp_path, "[ok] False  [timed_out] False\n401 OAuth access token has expired")
    assert phase3_online._round_produced_evidence(d, False) is False


def test_a_missing_report_is_not_evidence(tmp_path):
    """No report means the session never got far enough to write one."""
    assert phase3_online._round_produced_evidence(str(tmp_path), False) is False


# ===========================================================================
# Per-trial optimizer design: 10 optimized trials = 10 INDEPENDENT optimizers.
# ===========================================================================
def test_per_trial_mode_gives_each_optimized_trial_its_own_binary(monkeypatch, tmp_path):
    """The shared-binary design made the optimized arm one sample dressed as ten:
    all 10 trials bind-mounted the same optimized/bin, so between-trial variance
    measured AFL's randomness alone. Each trial must own its binary directory."""
    monkeypatch.setattr(config, "NUM_TRIALS", 10)
    monkeypatch.setattr(config, "ONLINE_TRIAL_CORES", "4-23")
    monkeypatch.setattr(config, "ONLINE_PER_TRIAL_OPTIMIZER", True)
    entry = {"project": "libxml2", "cve": "arvo-1972", "fuzz_target": "x"}
    baseline, online = phase3_online._build_online_trials(entry, str(tmp_path))
    assert all(t.bin_dir_override is None for t in baseline), "baseline arm is shared"
    dirs = [t.bin_dir_override for t in online]
    assert len(set(dirs)) == 10, "every optimized trial needs a DISTINCT bin dir"
    for t in online:
        assert t.bin_dir_override.endswith(f"bin_{t.trial_id:02d}")


def test_per_trial_bin_dir_reaches_the_runner(monkeypatch, tmp_path):
    """The override is only useful if get_fuzzer_binary honours it -- that is the
    single place the container's /out mount is resolved from."""
    import phase3_runner
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps(
        [{"project": "libxml2", "cve": "arvo-1972", "fuzz_target": "xml"}]))
    monkeypatch.setattr(config, "MANIFEST_PATH", str(manifest))
    t = phase3_runner.Trial(project="libxml2", cve="arvo-1972",
                            variant="optimized", trial_id=7, seed=1)
    shared = phase3_runner.get_fuzzer_binary("exp", t)
    t.bin_dir_override = str(tmp_path / "bin_07")
    own = phase3_runner.get_fuzzer_binary("exp", t)
    assert own != shared
    assert own == str(tmp_path / "bin_07" / "xml")


def test_fixed_mutation_corpus_is_pinned_and_reused(monkeypatch, tmp_path):
    """Optimizer i profiles trial i's mutations, harvested ONCE. Re-harvesting
    every round moved the workload underneath the optimizer, so a round-to-round
    speedup change confounded 'this edit was better' with 'the corpus grew'."""
    ctx = phase3_online.RoundContext(
        entry={}, experiment_id="e", experiment_dir=str(tmp_path),
        online_dir=str(tmp_path), source_tree="", source_root="",
        project="libxml2", image="", fuzz_target="xml", poc_path=None,
        previous_best_bin="", prev_tag="iter_00", optimized_bin_dir="",
        ledger_path="", swap_timeline_path="", profile_cpu=1)
    assert ctx.fixed_mutations is None
    ctx.fixed_mutations = str(tmp_path / "fixed_mutations")
    ctx.fixed_mutation_count = 20000
    # A second round must reuse the pinned corpus rather than re-harvesting.
    assert ctx.fixed_mutations.endswith("fixed_mutations")
    assert ctx.fixed_mutation_count == 20000


def test_per_trial_swap_events_are_isolated():
    """Trial 3 swapping must not make trial 7's monitor believe it is being
    swapped -- that is what the shared swap_barrier would do."""
    state = phase3_online.OnlineState()
    for tid in (3, 7):
        state.trials[tid] = {"state": "running",
                             "swap_barrier": threading.Event(),
                             "relaunch_ready": threading.Event(),
                             "relaunched": threading.Event()}
    state.trials[3]["swap_barrier"].set()
    assert state.trials[3]["swap_barrier"].is_set()
    assert not state.trials[7]["swap_barrier"].is_set()
    assert not state.swap_barrier.is_set(), "global barrier must stay untouched"


# ===========================================================================
# "build-failed" used to cover three unrelated outcomes, so a campaign's round
# table could not be read: the agent declined, the agent died, or the compiler
# rejected a real edit all produced the same label.
# ===========================================================================
def _agent_report(tmp_path, text):
    d = tmp_path / "source_diff"
    d.mkdir(parents=True, exist_ok=True)
    (d / "agent_attempt_0.txt").write_text(text)
    return str(d)


def test_declined_round_is_evidence_but_dead_session_is_not(tmp_path):
    """The split hinges on _round_produced_evidence. A session that ran and kept
    nothing says something about the TARGET (no headroom found); one that timed
    out or failed auth says something about the INFRASTRUCTURE only."""
    declined = _agent_report(tmp_path / "a", "[ok] True\nNO source changes were needed\n")
    assert phase3_online._round_produced_evidence(declined, False) is True

    timed_out = _agent_report(tmp_path / "b", "[ok] False  [timed_out] True\n")
    assert phase3_online._round_produced_evidence(timed_out, False) is False

    never_ran = str(tmp_path / "c")          # no agent report at all
    os.makedirs(never_ran, exist_ok=True)
    assert phase3_online._round_produced_evidence(never_ran, False) is False


def test_evidence_split_maps_to_distinct_labels(tmp_path):
    """Mirrors run_round's classification for the no-diff case, which is the one
    that used to collapse into build-failed."""
    def label(diff_dir):
        return ("no-fold" if phase3_online._round_produced_evidence(diff_dir, False)
                else "agent-failed")

    assert label(_agent_report(tmp_path / "x", "[ok] True\nNO source changes needed\n")) == "no-fold"
    assert label(_agent_report(tmp_path / "y", "[ok] False  [timed_out] True\n")) == "agent-failed"
    # A real diff that fails to compile keeps the original label, and is only
    # reachable when opt_applied is True -- i.e. never through this path.


def test_mutation_dump_timeout_is_configurable_not_hardcoded(monkeypatch, tmp_path):
    """60s was hard-coded and too tight: a dump writes 20k small files while other
    optimizers snapshot 6k-file corpora onto the same disk. trials 00 and 01 of
    online-24h-c1 lost round 1 to it, then delivered in 5s when asked again."""
    monkeypatch.setattr(config, "ONLINE_MUTATION_DUMP_TIMEOUT_SECS", 1)
    d = tmp_path / "mutations"
    d.mkdir()
    t0 = time.time()
    # No shim is listening, so this must time out using the CONFIGURED value.
    assert phase3_online.request_mutation_dump([str(d)]) == []
    assert time.time() - t0 < 30, "did not honour the configured timeout"
    # and the stale request is cleaned up so the next round starts fresh
    assert not (d / phase3_online.DUMP_REQUEST).exists()


def test_dump_request_is_cleared_before_waiting(tmp_path):
    """The marker waited on must be THIS round's, not a leftover from the last."""
    d = tmp_path / "mutations"
    d.mkdir()
    (d / phase3_online.BATCH_MARKER).write_text("")
    (d / "mut_old_00000001").write_text("stale")
    import config as _c
    old = getattr(_c, "ONLINE_MUTATION_DUMP_TIMEOUT_SECS", 300)
    _c.ONLINE_MUTATION_DUMP_TIMEOUT_SECS = 1
    try:
        phase3_online.request_mutation_dump([str(d)])
    finally:
        _c.ONLINE_MUTATION_DUMP_TIMEOUT_SECS = old
    assert not (d / phase3_online.BATCH_MARKER).exists()
    assert not (d / "mut_old_00000001").exists()


# --- prepare_round_corpus: crash filter + speed cap + smoke sample ---------
from pathlib import Path


def _mutations(tmp_path, n):
    d = tmp_path / "muts"
    d.mkdir()
    for i in range(n):
        (d / f"mut_{i:08d}").write_bytes(b"m%d" % i)
    return d


def _fake_find(crashers, rate, seen=None):
    """find_crashers stand-in: ``rate`` inputs/s; reports only crashers it ran."""
    def find(*, out_dir, corpus_dir, fuzz_target, cpu, image):
        names = {p.name for p in Path(corpus_dir).iterdir()}
        if seen is not None:
            seen.append(names)
        return {"ok": True, "crashers": sorted(set(crashers) & names),
                "scanned": len(names), "expected": len(names),
                "seconds": len(names) / rate, "log": ""}
    return find


def _names(d):
    return {p.name for p in Path(d).iterdir()}


def _round(tmp_path, n, crashers=(), rate=10.0, seen=None, out="corpus", **kw):
    muts = tmp_path / "muts"
    if not muts.exists():
        muts = _mutations(tmp_path, n)
    return phase3_online.prepare_round_corpus(
        mutations_dir=muts, out_root=tmp_path / out, previous_best_bin="/b",
        fuzz_target="t", image="i", cpu=1, seed=7,
        find_crashers_fn=_fake_find(crashers, rate, seen), **kw)


def test_round_corpus_drops_inputs_that_crash_the_previous_best(tmp_path, monkeypatch):
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_BUDGET_SECS", 0)
    r = _round(tmp_path, 100, {"mut_00000003", "mut_00000050"})
    checked = _names(r["checked"])
    assert len(checked) == 98 and "mut_00000003" not in checked
    assert r["crashers_removed"] == 2
    assert not _names(r["tuning"]) & _names(r["gate"])
    assert _names(r["tuning"]) | _names(r["gate"]) == checked


def test_round_corpus_caps_the_tuning_set_by_measured_speed(tmp_path, monkeypatch):
    # The smoke filter pass measures 10 inputs/s; a 3s budget fits 30.
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_BUDGET_SECS", 3)
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_MAX_UNITS", 0)
    r = _round(tmp_path, 100)
    assert len(_names(r["tuning"])) == 30 and r["rate_source"] == "smoke-filter"


def test_round_corpus_filters_only_the_inputs_it_uses(tmp_path, monkeypatch):
    # 30 tuning + 30 gate + 5 smoke of 100: the other inputs are never run, and
    # no input is run twice (the smoke pass covers its share of the rest).
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_BUDGET_SECS", 3)
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_MAX_UNITS", 0)
    monkeypatch.setattr(phase3_online.config, "ONLINE_SMOKE_FRACTION", 0.05)
    seen = []
    r = _round(tmp_path, 100, seen=seen)
    ran = set().union(*seen)
    used = _names(r["tuning"]) | _names(r["gate"]) | _names(r["smoke"])
    assert ran == used == _names(r["checked"]) and len(ran) < 100
    assert sum(len(x) for x in seen) == len(ran)


def test_round_corpus_never_uses_an_unfiltered_crasher(tmp_path, monkeypatch):
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_BUDGET_SECS", 3)
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_MAX_UNITS", 0)
    bad = {f"mut_{i:08d}" for i in range(0, 100, 3)}
    r = _round(tmp_path, 100, bad)
    for k in ("tuning", "gate", "smoke", "checked"):
        assert not _names(r[k]) & bad, k


def test_round_corpus_full_set_gate_filters_the_whole_harvest(tmp_path, monkeypatch):
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_BUDGET_SECS", 3)
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_MAX_UNITS", 0)
    monkeypatch.setattr(phase3_online.config, "ONLINE_GATE_FULL_SET", True)
    r = _round(tmp_path, 100, {"mut_00000009"})
    # sampled before filtering, so a crasher in the sample leaves it one short
    assert len(_names(r["checked"])) == 99 and 29 <= len(_names(r["tuning"])) <= 30


def test_round_corpus_smoke_is_five_percent_of_tuning_partition(tmp_path, monkeypatch):
    monkeypatch.setattr(phase3_online.config, "ONLINE_SMOKE_FRACTION", 0.05)
    a = _round(tmp_path, 200, out="a")
    b = _round(tmp_path, 200, out="b")
    assert len(_names(a["smoke"])) == round(0.05 * 150)
    assert not _names(a["smoke"]) & _names(a["gate"])
    assert _names(a["smoke"]) == _names(b["smoke"])      # deterministic


def test_round_corpus_refuses_a_filter_that_did_not_run(tmp_path):
    muts = _mutations(tmp_path, 10)

    def broken(**_):
        return {"ok": False, "crashers": [], "scanned": 0, "expected": 10,
                "seconds": 0.5, "log": "SCANNED 0"}

    assert phase3_online.prepare_round_corpus(
        mutations_dir=muts, out_root=tmp_path / "corpus", previous_best_bin="/b",
        fuzz_target="t", image="i", cpu=1, seed=7, find_crashers_fn=broken) is None


def test_round_corpus_sizes_by_the_gate_rate_when_known(tmp_path, monkeypatch):
    # The filter pass runs ~2x faster than a timing pass, so the gate's own
    # measured rate wins: 5 inputs/s x 4s budget = 20, not the filter's 40.
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_BUDGET_SECS", 4)
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_MAX_UNITS", 0)
    r = _round(tmp_path, 100, replay_rate=5.0)
    assert r["tuning_count"] == 20 and r["rate_source"] == "gate"


def test_gate_sample_uses_same_fraction_of_heldout_partition(tmp_path, monkeypatch):
    # 10 inputs/s x 3s = 30 of 100: room for two disjoint samples.
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_BUDGET_SECS", 3)
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_MAX_UNITS", 0)
    r = _round(tmp_path, 100)
    tuning, gate = _names(r["tuning"]), _names(r["gate"])
    assert len(tuning) == 30 and len(gate) == 10
    assert r["sample_fraction"] == 0.4
    assert not gate & tuning and r["gate_overlap_with_tuning"] == 0


def test_gate_sample_never_overlaps_even_when_most_inputs_are_used(tmp_path, monkeypatch):
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_BUDGET_SECS", 7)
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_MAX_UNITS", 0)
    r = _round(tmp_path, 100)
    tuning, gate = _names(r["tuning"]), _names(r["gate"])
    assert len(tuning) == 70 and len(gate) == 23
    assert not gate & tuning


def test_gate_is_heldout_quarter_when_nothing_needs_shrinking(tmp_path, monkeypatch):
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_BUDGET_SECS", 0)
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_MAX_UNITS", 0)
    r = _round(tmp_path, 100)
    tuning, gate = _names(r["tuning"]), _names(r["gate"])
    assert len(tuning) == 75 and len(gate) == 25
    assert not gate & tuning and tuning | gate == _names(r["checked"])


@pytest.mark.parametrize("n", [2, 3, 4, 7, 101])
def test_round_split_manifest_matches_seeded_permutation_and_manual_scaling(tmp_path, monkeypatch, n):
    import random
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_BUDGET_SECS", 0)
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_MAX_UNITS", 2)
    r = _round(tmp_path, n)
    manifest = json.loads(Path(r["split_manifest"]).read_text())
    permutation = sorted(p.name for p in (tmp_path / "muts").iterdir())
    random.Random(7).shuffle(permutation)
    split = min(n - 1, max(1, 3 * n // 4))
    assert manifest["seed"] == 7
    assert manifest["tuning_partition"] == permutation[:split]
    assert manifest["gate_partition"] == permutation[split:]
    assert r["tuning_count"] == min(2, split)
    assert r["gate_count"] == max(1, round((n - split) * r["sample_fraction"]))
    assert _names(r["tuning"]) == set(manifest["tuning_inputs"])
    assert _names(r["gate"]) == set(manifest["gate_inputs"])
    assert not set(manifest["tuning_partition"]) & set(manifest["gate_partition"])


def test_round_split_refuses_single_input(tmp_path):
    assert _round(tmp_path, 1) is None


def test_crash_removal_never_moves_inputs_between_partitions(tmp_path, monkeypatch):
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_BUDGET_SECS", 0)
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_MAX_UNITS", 0)
    a = _round(tmp_path, 100, out="a")
    ma = json.loads(Path(a["split_manifest"]).read_text())
    b = _round(tmp_path, 100, {ma["tuning_inputs"][0], ma["gate_inputs"][0]}, out="b")
    mb = json.loads(Path(b["split_manifest"]).read_text())
    assert ma["tuning_partition"] == mb["tuning_partition"]
    assert ma["gate_partition"] == mb["gate_partition"]
    assert b["tuning_count"] == 74 and b["gate_count"] == 24


def test_round_refuses_empty_heldout_after_crash_filter(tmp_path, monkeypatch):
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_BUDGET_SECS", 0)
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_MAX_UNITS", 0)
    a = _round(tmp_path, 10, out="a")
    assert _round(tmp_path, 10, _names(a["gate"]), out="b") is None


# ===========================================================================
# Per-trial swap mirroring: optimizer k's hot swap signals ONLY baseline trial
# k. On the old single global generation every baseline restarted on every
# optimizer's swap, ~10x more than any one optimized trial.
# ===========================================================================
def test_hot_swap_one_signals_only_its_paired_baseline(monkeypatch, tmp_path):
    from lib import swap_signal
    sig = swap_signal.SwapSignal()
    monkeypatch.setattr(phase3_online.swap_signal, "SIGNAL", sig)
    monkeypatch.setattr(phase3_online, "_stop_one_and_overwrite", lambda *a, **k: None)
    monkeypatch.setattr(phase3_online, "_fuzzer_state", lambda e, t: {})
    monkeypatch.setattr(phase3_online, "_swap_extra_files", lambda e, f: ())
    trial = types.SimpleNamespace(trial_id=3, container_id="c",
                                  bin_dir_override=str(tmp_path / "bin_03"))
    ctx = types.SimpleNamespace(trial=trial, iter_n=2, fuzz_target="t", entry={},
                                experiment_id="e",
                                swap_timeline_path=str(tmp_path / "tl.json"))
    rel, ready = threading.Event(), threading.Event()
    threading.Thread(target=lambda: ready.wait(10) and rel.set(), daemon=True).start()
    state = types.SimpleNamespace(
        trials={3: {"state": "running", "relaunched": rel, "relaunch_ready": ready}},
        swap_timeline=[])
    phase3_online.hot_swap_one(ctx, state, str(tmp_path / "iter_02"))
    assert sig.generation_for(3) == 1
    assert all(sig.generation_for(t) == 0 for t in range(10) if t != 3)


# ===========================================================================
# The swap row reads both clocks, so the plots can convert run_time to
# wall-clock exactly: the stats write state_at_swap came from, the relaunch,
# and (in the background) when the relaunched AFL's run_time resumed.
# ===========================================================================
def _swap_ctx(monkeypatch, tmp_path):
    monkeypatch.setattr(phase3_online, "_stop_one_and_overwrite", lambda *a, **k: None)
    monkeypatch.setattr(phase3_online, "_fuzzer_state", lambda e, t: {"run_time": "980"})
    monkeypatch.setattr(phase3_online, "_swap_extra_files", lambda e, f: ())
    monkeypatch.setattr(phase3_online.swap_signal.SIGNAL, "record_swap", lambda *a: 1)
    trial = types.SimpleNamespace(trial_id=3, container_id="c",
                                  bin_dir_override=str(tmp_path / "bin_03"))
    ctx = types.SimpleNamespace(trial=trial, iter_n=2, fuzz_target="t", entry={},
                                experiment_id="e",
                                swap_timeline_path=str(tmp_path / "tl.json"))
    rel, ready = threading.Event(), threading.Event()
    threading.Thread(target=lambda: ready.wait(10) and rel.set(), daemon=True).start()
    other = {"iter": 1, "ts": 1.0, "trial_id": 7}
    state = types.SimpleNamespace(
        trials={3: {"state": "running", "relaunched": rel, "relaunch_ready": ready}},
        swap_timeline=[other])
    return ctx, state, other


def test_hot_swap_one_records_both_clocks(monkeypatch, tmp_path):
    ctx, state, other = _swap_ctx(monkeypatch, tmp_path)
    monkeypatch.setattr(phase3_online, "_stats_clock", lambda e, t: (500.0, 980.0))
    started = []
    monkeypatch.setattr(phase3_online, "_record_resume",
                        lambda *a, **k: started.append(a))
    phase3_online.hot_swap_one(ctx, state, str(tmp_path / "iter_02"))
    row = state.swap_timeline[1]
    assert row["stats_ts"] == 500.0 and row["state_at_swap"] == {"run_time": "980"}
    assert row["relaunch_ts"] >= row["ts"]
    assert state.swap_timeline[0] is other
    assert json.loads((tmp_path / "tl.json").read_text())[1]["relaunch_ts"] == row["relaunch_ts"]
    assert started and started[0][2] is row and started[0][3] == (500.0, 980.0)


def test_record_resume_waits_for_the_relaunched_afl(monkeypatch, tmp_path):
    ctx, state, _ = _swap_ctx(monkeypatch, tmp_path)
    row = {"iter": 2, "ts": 501.0, "trial_id": 3, "stats_ts": 500.0}
    state.swap_timeline.append(row)
    # The stopped trial's own file first, then a pre-load write of the new
    # process (run_time from 0), then the resumed one.
    reads = iter([(500.0, 980.0), (640.0, 3.0), (760.0, 980.0)])
    monkeypatch.setattr(phase3_online, "_stats_clock", lambda e, t: next(reads))
    phase3_online._record_resume(ctx, state, row, (500.0, 980.0), poll=0.0)
    new = state.swap_timeline[1]
    assert (new["resumed_ts"], new["resumed_run_time"]) == (760.0, 980.0)
    assert "resumed_ts" not in row          # replaced, never mutated in place
    assert json.loads((tmp_path / "tl.json").read_text())[1]["resumed_ts"] == 760.0


# ===========================================================================
# swap_timeline.json is provenance: a failed write must never kill the
# optimizer that just swapped, and the swap and the previous swap's background
# _record_resume must not interleave their writes of the one file.
# ===========================================================================
def test_hot_swap_one_survives_a_failed_timeline_write(monkeypatch, tmp_path, caplog):
    ctx, state, _ = _swap_ctx(monkeypatch, tmp_path)
    monkeypatch.setattr(phase3_online, "_stats_clock", lambda e, t: (500.0, 980.0))
    started = []
    monkeypatch.setattr(phase3_online, "_record_resume",
                        lambda *a, **k: started.append(a))

    def _full(src, dst):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(phase3_online.os, "replace", _full)
    phase3_online.hot_swap_one(ctx, state, str(tmp_path / "iter_02"))
    # The swap completed: row recorded in memory, resume watcher started.
    assert state.swap_timeline[1]["relaunch_ts"] >= state.swap_timeline[1]["ts"]
    assert started
    assert "No space left on device" in caplog.text
    assert os.listdir(tmp_path) == []        # no temp file left behind


def test_record_resume_survives_a_failed_timeline_write(monkeypatch, tmp_path):
    ctx, state, _ = _swap_ctx(monkeypatch, tmp_path)
    (tmp_path / "f").write_text("")
    ctx.swap_timeline_path = str(tmp_path / "f" / "tl.json")   # parent is a file
    row = {"iter": 2, "ts": 501.0, "trial_id": 3, "stats_ts": 500.0}
    state.swap_timeline.append(row)
    monkeypatch.setattr(phase3_online, "_stats_clock", lambda e, t: (760.0, 980.0))
    phase3_online._record_resume(ctx, state, row, (500.0, 980.0), poll=0.0)
    assert state.swap_timeline[1]["resumed_ts"] == 760.0


def test_concurrent_timeline_writes_stay_valid_json(monkeypatch, tmp_path):
    ctx, state, _ = _swap_ctx(monkeypatch, tmp_path)
    path = tmp_path / "tl.json"
    stop = threading.Event()
    bad = []

    def reader():
        while not stop.is_set():
            try:
                json.loads(path.read_text())
            except FileNotFoundError:
                pass
            except ValueError as e:
                bad.append(e)

    def writer(k):
        for i in range(40):
            state.swap_timeline.append({"iter": i, "ts": float(i), "trial_id": k,
                                        "pad": "x" * 500})
            phase3_online._write_swap_timeline(ctx, state)

    r = threading.Thread(target=reader)
    r.start()
    ws = [threading.Thread(target=writer, args=(k,)) for k in range(4)]
    for w in ws:
        w.start()
    for w in ws:
        w.join()
    stop.set()
    r.join()
    assert bad == []
    # Serialised: the last write carried the whole, newest list.
    assert json.loads(path.read_text()) == state.swap_timeline
    assert sorted(os.listdir(tmp_path)) == ["tl.json"]


# ===========================================================================
# A reused experiment id must be refused BEFORE setup: AFL_AUTORESUME would
# otherwise resume the previous campaign's queues in every "new" trial.
# ===========================================================================
def test_run_online_refuses_an_experiment_with_afl_state(monkeypatch, tmp_path, caplog):
    import phase3_runner
    from pathlib import Path
    monkeypatch.setattr(config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(config, "NUM_TRIALS", 2)
    monkeypatch.setattr(config, "ONLINE_PER_TRIAL_OPTIMIZER", True)
    entry = {"project": "libxml2", "cve": "arvo-1972", "fuzz_target": "xml"}
    stale = phase3_runner.Trial(project="libxml2", cve="arvo-1972",
                                variant="optimized", trial_id=1, seed=1)
    q = Path(phase3_runner.get_trial_dirs("exp", stale)["afl_out"]) / "default" / "queue"
    q.mkdir(parents=True)

    def setup_must_not_run(*a, **k):
        raise AssertionError("setup ran on a stale experiment")

    monkeypatch.setattr(phase3_online, "_extract_online_target", setup_must_not_run)
    monkeypatch.setattr(phase3_runner, "start_trial", setup_must_not_run)
    assert phase3_online.run_online(entry, "exp", duration=60) is False
    assert str(q) in caplog.text


# ===========================================================================
# The agent cpuset is resolved ONCE, before setup. Resolved per optimizer at its
# first round, a bad set raised inside _drive's catch-all and killed all ten
# optimizers while the trials fuzzed on: two baseline arms posing as a campaign.
# ===========================================================================
def _online_entry(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(config, "NUM_TRIALS", 2)
    monkeypatch.setattr(config, "ONLINE_PER_TRIAL_OPTIMIZER", True)
    monkeypatch.setattr(config, "PHASE2_SANDBOX", True)
    monkeypatch.setattr(config, "ONLINE_TRIAL_CORES", "12-31")
    monkeypatch.setattr(config, "ONLINE_OPTIMIZER_CORES", "2-11")
    monkeypatch.setattr(config, "ONLINE_AGENT_CPUS", "")
    return {"project": "libxml2", "cve": "arvo-1972", "fuzz_target": "xml"}


def test_run_online_aborts_before_setup_on_a_bad_agent_cpuset(monkeypatch, tmp_path, caplog):
    import phase3_runner
    entry = _online_entry(monkeypatch, tmp_path)
    monkeypatch.setattr(config, "ONLINE_AGENT_CPUS", "12")        # a trial core

    def setup_must_not_run(*a, **k):
        raise AssertionError("setup ran with an unplaceable agent")

    monkeypatch.setattr(phase3_online, "_extract_online_target", setup_must_not_run)
    monkeypatch.setattr(phase3_runner, "start_trial", setup_must_not_run)
    assert phase3_online.run_online(entry, "exp", duration=60) is False
    assert "agent containers" in caplog.text and "trial" in caplog.text
    assert not (tmp_path / "exp").exists(), "nothing may be created before the abort"


def test_run_online_pins_the_resolved_agent_cpuset_before_setup(monkeypatch, tmp_path):
    import sandbox.session as s
    entry = _online_entry(monkeypatch, tmp_path)
    calls = []
    monkeypatch.setattr(s, "resolve_agent_cpus",
                        lambda *a, **k: calls.append(1) or "0-1,32-39")
    monkeypatch.setattr(phase3_online.cpu_ledger, "set_ledger_path", lambda p: None)
    monkeypatch.setattr(phase3_online.cpu_ledger, "set_round", lambda **k: None)

    class _Setup(Exception):
        pass

    def setup(*a, **k):
        # Pinned BEFORE setup: every later round's resolve_agent_cpus() takes
        # the explicit path and returns this same set.
        assert config.ONLINE_AGENT_CPUS == "0-1,32-39"
        raise _Setup

    monkeypatch.setattr(phase3_online, "_extract_online_target", setup)
    with pytest.raises(_Setup):
        phase3_online.run_online(entry, "exp", duration=60)
    assert calls == [1]


# ===========================================================================
# A finished online trial's container is the only other copy of its console
# log: removed only when that log was actually saved.
# ===========================================================================
def _finalize(monkeypatch, tmp_path, write_logs):
    import phase3_runner
    monkeypatch.setattr(config, "RESULTS_DIR", str(tmp_path))
    trial = phase3_runner.Trial(project="libxml2", cve="arvo-1972",
                                variant="optimized", trial_id=1, seed=1)
    trial.container_id = "cid"
    removed = []
    monkeypatch.setattr(phase3_online.docker_util, "write_container_logs", write_logs)
    monkeypatch.setattr(phase3_online.docker_util, "remove_container", removed.append)
    phase3_online._finalize_online_trial(trial, "exp", 60, time.time() - 60, [])
    meta = json.loads(open(phase3_runner.get_trial_dirs("exp", trial)["metadata"]).read())
    return removed, meta


def test_finalize_removes_the_container_once_its_log_is_saved(monkeypatch, tmp_path):
    removed, meta = _finalize(monkeypatch, tmp_path, lambda cid, path, check=False: 10)
    assert removed == ["cid"] and meta["console_log_saved"] is True


def test_finalize_keeps_the_container_when_its_log_write_fails(monkeypatch, tmp_path, caplog):
    def fail(cid, path, check=False):
        assert check, "a caller that removes the container must ask for check=True"
        raise RuntimeError("docker logs cid exited 1")

    removed, meta = _finalize(monkeypatch, tmp_path, fail)
    assert removed == [], "removing it would destroy the only copy of the log"
    assert meta["console_log_saved"] is False
    assert "keeping container cid" in caplog.text


# ===========================================================================
# run_online_pertrial.sh: an existing log is refused before the launcher
# touches any file (EXP_ID or not); the pid file is per experiment, not project.
# ===========================================================================
_LAUNCHER = Path(__file__).resolve().parent.parent / "run_online_pertrial.sh"


def _launch(tmp_path, exp_id):
    import shutil
    import subprocess
    script = tmp_path / "run_online_pertrial.sh"
    shutil.copy(_LAUNCHER, script)
    env = {k: v for k, v in os.environ.items() if k not in ("EXP_ID", "EXP_PREFIX")}
    env["EXP_ID"] = exp_id
    return subprocess.run(["bash", str(script), "libxml2"], env=env,
                          capture_output=True, text=True, timeout=60)


def test_launcher_refuses_an_existing_log_without_touching_it(tmp_path):
    log = tmp_path / ".myexp.log"
    log.write_text("the old campaign's only log\n")
    r = _launch(tmp_path, "myexp")
    assert r.returncode == 5, r.stderr
    assert "already exists" in r.stderr
    assert log.read_text() == "the old campaign's only log\n"
    assert not list(tmp_path.glob(".online_pertrial_*.pid"))


def test_launcher_passes_the_log_guard_when_no_log_exists(tmp_path):
    # No log: the guard lets it through to the next check (the preflight, which
    # fails here because the copy has no bootstrap_server.py beside it).
    r = _launch(tmp_path, "freshexp")
    assert r.returncode != 5, r.stderr
    assert not (tmp_path / ".freshexp.log").exists()


def test_launcher_pid_file_is_named_by_experiment_id():
    text = _LAUNCHER.read_text()
    assert '.online_pertrial_${exp}.pid"' in text
    assert "online_pertrial_${PROJ}.pid" not in text


# --- prebuild failure: the round ends without an agent -------------------------
def _prebuild_round_ctx(tmp_path):
    online = tmp_path / "trial_02"
    ctx = phase3_online.RoundContext(
        entry={"cve": "x", "project": "libxml2"}, experiment_id="e",
        experiment_dir=str(tmp_path), online_dir=str(online), source_tree="",
        source_root="", project="libxml2", image="", fuzz_target="xml",
        poc_path=None, previous_best_bin=str(tmp_path / "iter_00_bin"),
        prev_tag="iter_00", optimized_bin_dir="",
        ledger_path=str(online / "ledger.json"), swap_timeline_path="",
        profile_cpu=1, wrapper_env_fn=lambda root, state: {})
    ctx.trial = types.SimpleNamespace(trial_id=2, project="libxml2", cve="x",
                                      variant="optimized")
    ctx.fixed_mutations = str(tmp_path / "fixed_mutations")
    ctx.fixed_mutation_count = 10
    return ctx


def test_prebuild_failure_ends_the_round_without_an_agent(monkeypatch, tmp_path):
    """optimize_and_build raises PrebuildFailedError before any agent session;
    run_round must record outcome prebuild-failed in every place a measured
    round records its outcome, and report it as NOT evidence."""
    monkeypatch.setattr(phase3_online.config, "ONLINE_FIXED_MUTATION_CORPUS", True)
    rc = {k: 1 for k in ("harvested", "checked_count", "crashers_removed",
                         "tuning_count", "units_per_s", "budget_secs", "smoke_count")}
    rc.update(tuning=str(tmp_path / "tuning"), smoke=str(tmp_path / "smoke"),
              checked=str(tmp_path / "checked"), gate=str(tmp_path / "gate"))
    monkeypatch.setattr(phase3_online, "prepare_round_corpus", lambda **k: rc)
    monkeypatch.setattr(phase3_online, "prework_image_for", lambda e: "img")
    monkeypatch.setattr(phase3_online, "_gate_replay_rate", lambda d: None)
    monkeypatch.setattr(phase3_online, "build_round_env", lambda **k: {"K": "v"})
    monkeypatch.setattr(phase3_online, "_reassert_edit_mtimes", lambda t: None)
    monkeypatch.setattr(phase3_online, "_carry_forward_agent_memory", lambda d, n: False)
    monkeypatch.setattr(phase2_setup, "optimizer_provenance", lambda: {"model": "m"})
    reverted, summaries = [], []
    monkeypatch.setattr(phase3_online, "apply_round_outcome",
                        lambda accepted, **k: reverted.append(accepted)
                        or k["previous_best_bin"])
    monkeypatch.setattr(phase3_online, "_write_cpu_cost_summary",
                        lambda ctx: summaries.append(ctx.iter_n))

    def no_prebuild(*a, **k):
        raise phase2_setup.PrebuildFailedError(
            "sanity: only 3 samples attributed to xml's own source functions")
    monkeypatch.setattr(phase2_setup, "optimize_and_build", no_prebuild)

    ctx = _prebuild_round_ctx(tmp_path)
    result = phase3_online.run_round(ctx, phase3_online.OnlineState(), 4)

    assert result == (False, None, False, False)  # rejected, not evidence, keep going
    assert reverted == [False]
    assert summaries == [4]
    iter_dir = tmp_path / "trial_02" / "iter_04"
    prov = json.loads((iter_dir / "round_provenance.json").read_text())
    assert prov["outcome"] == phase3_online.PREBUILD_FAILED_OUTCOME == "prebuild-failed"
    assert prov["agent_started"] is False and prov["speedup"] is None
    assert "only 3 samples" in prov["prebuild_failure"]
    assert prov["corpus"] == rc
    ledger = json.loads((tmp_path / "trial_02" / "ledger.json").read_text())
    assert ledger[-1]["outcome"] == "prebuild-failed" and ledger[-1]["iter"] == 4
    meta = json.loads((iter_dir / "setup_metadata.json").read_text())
    assert meta["failure"]["stage"] == "profile_prebuild"
    assert ctx.previous_best_bin == str(tmp_path / "iter_00_bin")


def test_prebuild_failed_rounds_never_converge_the_loop():
    """Prebuild failures are infrastructure: a run of them must not end
    optimization (the loop keeps scheduling rounds until the trials end)."""
    rounds = []

    def run_round(i):
        rounds.append(i)
        return (False, None, False)              # what a prebuild-failed round returns

    n = phase3_online.run_optimizer_loop(
        run_round_fn=run_round, hot_swap_fn=lambda b: None, convergence_k=2,
        wait_fn=lambda: None, all_terminal_fn=lambda: len(rounds) >= 6)
    assert n == 6


def _prebuild_failing_round(monkeypatch, tmp_path, stage):
    """run_round wired so optimize_and_build raises PrebuildFailedError(stage)."""
    monkeypatch.setattr(phase3_online.config, "ONLINE_FIXED_MUTATION_CORPUS", True)
    rc = {k: 1 for k in ("harvested", "checked_count", "crashers_removed",
                         "tuning_count", "units_per_s", "budget_secs", "smoke_count")}
    rc.update(tuning="t", smoke="s", checked="c", gate="g")
    monkeypatch.setattr(phase3_online, "prepare_round_corpus", lambda **k: rc)
    monkeypatch.setattr(phase3_online, "prework_image_for", lambda e: "img")
    monkeypatch.setattr(phase3_online, "_gate_replay_rate", lambda d: None)
    monkeypatch.setattr(phase3_online, "build_round_env", lambda **k: {"K": "v"})
    monkeypatch.setattr(phase3_online, "_reassert_edit_mtimes", lambda t: None)
    monkeypatch.setattr(phase3_online, "_carry_forward_agent_memory", lambda d, n: False)
    monkeypatch.setattr(phase2_setup, "optimizer_provenance", lambda: {})
    monkeypatch.setattr(phase3_online, "apply_round_outcome",
                        lambda accepted, **k: k["previous_best_bin"])
    monkeypatch.setattr(phase3_online, "_write_cpu_cost_summary", lambda ctx: None)
    stages = iter(stage) if isinstance(stage, list) else None

    def no_prebuild(*a, **k):
        st = next(stages) if stages else stage
        raise phase2_setup.PrebuildFailedError(f"{st}: nope", stage=st)
    monkeypatch.setattr(phase2_setup, "optimize_and_build", no_prebuild)
    return _prebuild_round_ctx(tmp_path)


def test_a_deterministic_prebuild_failure_stops_the_optimizer_after_three(monkeypatch, tmp_path):
    monkeypatch.setattr(phase3_online.config, "ONLINE_PREBUILD_FAIL_STOP", 3)
    ctx = _prebuild_failing_round(monkeypatch, tmp_path, "sanity")
    got = [phase3_online.run_round(ctx, phase3_online.OnlineState(), i)[3]
           for i in (1, 2, 3)]
    assert got == [False, False, True]
    prov = json.loads((tmp_path / "trial_02" / "iter_03" / "round_provenance.json").read_text())
    assert prov["optimizer_stopped"] is True and prov["prebuild_fail_streak"] == 3


def test_transient_or_changing_prebuild_failures_never_stop_it(monkeypatch, tmp_path):
    monkeypatch.setattr(phase3_online.config, "ONLINE_PREBUILD_FAIL_STOP", 3)
    ctx = _prebuild_failing_round(monkeypatch, tmp_path, "timeout")
    assert not any(phase3_online.run_round(ctx, phase3_online.OnlineState(), i)[3]
                   for i in range(1, 6))
    ctx = _prebuild_failing_round(monkeypatch, tmp_path / "b",
                                  ["sanity", "sanity", "profile", "sanity", "sanity"])
    assert not any(phase3_online.run_round(ctx, phase3_online.OnlineState(), i)[3]
                   for i in range(1, 6))


def test_the_loop_ends_when_a_round_asks_to_stop():
    rounds = []

    def run_round(i):
        rounds.append(i)
        return (False, None, False, i == 3)

    n = phase3_online.run_optimizer_loop(
        run_round_fn=run_round, hot_swap_fn=lambda b: None, convergence_k=0,
        wait_fn=lambda: None, all_terminal_fn=lambda: len(rounds) >= 10)
    assert n == 3


# --- setup-time profile check ---------------------------------------------------
def _preflight_dirs(tmp_path):
    exp = tmp_path / "exp"
    (exp / "seed_corpus" / "merged").mkdir(parents=True)
    (exp / "seed_corpus" / "merged" / "s0").write_bytes(b"hi")
    src = tmp_path / "src" / "demo"
    (src / "fuzz").mkdir(parents=True)
    (src / "fuzz" / "demo_fuzzer.c").write_text("int LLVMFuzzerTestOneInput(void){return 0;}")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "replay_fuzzer_profile.py").write_text("# stub")
    return exp, src, scripts


def _fake_hotspots(prof_dir, target_n, build_n):
    p = Path(prof_dir)
    p.mkdir(parents=True, exist_ok=True)
    (p / "hotspots.json").write_text(json.dumps({
        "totals": {"samples": 1000, "build_dso_samples": build_n,
                   "target_attributed": {"samples": target_n}},
        "functions": [{"function": "f", "caused_pct": 1.0}] if target_n else []}))


def _preflight_kw(tmp_path, exp, src):
    return dict(entry={"cve": "x"}, baseline_bin_dir=str(tmp_path / "bin"),
                experiment_dir=str(exp), project_src_dir=str(src),
                fuzz_target="demo_fuzzer", online_dir=str(tmp_path / "online"),
                profile_cpu=4)


@pytest.fixture
def preflight_env(monkeypatch, tmp_path):
    exp, src, scripts = _preflight_dirs(tmp_path)
    monkeypatch.setattr(phase3_online.config, "PHASE2_SKILL_SCRIPTS_DIR", str(scripts))
    monkeypatch.setattr(phase3_online.config, "ONLINE_PREFLIGHT_PROFILE_SECS", 30)
    monkeypatch.setattr(phase3_online.config, "ONLINE_PREFLIGHT_WARN_TARGET_SAMPLES", 100)
    monkeypatch.setattr(phase3_online, "prework_image_for", lambda e: "img")
    return exp, src


def test_preflight_profile_profiles_like_a_round(monkeypatch, tmp_path, preflight_env):
    exp, src = preflight_env
    seen = {}

    def fake_profile(**kw):
        seen.update(kw)
        _fake_hotspots(kw["profile_dir"], 5000, 9000)
        return True, "profile", "5000 of 9000"
    monkeypatch.setattr(phase2_setup, "run_baseline_profile", fake_profile)
    ok, why = phase3_online._preflight_profile(**_preflight_kw(tmp_path, exp, src))
    assert ok is True
    assert seen["env"]["PHASE2_PROFILE_SOURCE_ROOT"] == "/src/demo"
    assert seen["env"]["PHASE2_PROFILE_SOURCE_TREE"] == str(src.resolve())
    assert seen["corpus_dir"].endswith("seed_corpus/merged")
    assert seen["min_target_samples"] == 0          # the floor never refuses here
    assert seen["proc_env"]["FUZZ_SOURCE_FOLDS_RUNNER_IMAGE"] == "img"


def test_preflight_profile_only_warns_on_a_lone_tiny_seed(monkeypatch, tmp_path,
                                                         preflight_env, caplog):
    """zlib/re2/jsoncpp/libpcap get only the "hi" seed: almost no project code
    runs on it. That must not refuse a healthy campaign."""
    exp, src = preflight_env

    def fake_profile(**kw):
        _fake_hotspots(kw["profile_dir"], 3, 1800)
        return True, "profile", "3 of 26000"
    monkeypatch.setattr(phase2_setup, "run_baseline_profile", fake_profile)
    with caplog.at_level("WARNING"):
        ok, _ = phase3_online._preflight_profile(**_preflight_kw(tmp_path, exp, src))
    assert ok is True
    assert any("only 3 samples" in r.getMessage() for r in caplog.records
               if r.levelname == "WARNING")
    rec = json.loads((tmp_path / "online" / "preflight_profile.json").read_text())
    assert rec["ok"] is True and rec["target_source_samples"] == 3


def test_preflight_profile_refuses_only_what_breaks_every_round(monkeypatch, tmp_path,
                                                                preflight_env):
    exp, src = preflight_env
    kw = _preflight_kw(tmp_path, exp, src)
    # perf saw nothing of the build at all
    monkeypatch.setattr(phase2_setup, "run_baseline_profile", lambda **k: (
        _fake_hotspots(k["profile_dir"], 0, 0), (True, "profile", "0 of 26000"))[1])
    ok, why = phase3_online._preflight_profile(**kw)
    assert ok is False and "no sample at all" in why
    # the hotspot table could not be built (mismatch, symbolizer, dsoff, dump)
    monkeypatch.setattr(phase2_setup, "run_baseline_profile",
                        lambda **k: (False, "hotspots", "source-root mismatch: ..."))
    ok, why = phase3_online._preflight_profile(**kw)
    assert ok is False and why.startswith("hotspots: source-root mismatch")


def test_preflight_profile_retries_a_transient_perf_failure_once(monkeypatch, tmp_path,
                                                                preflight_env):
    exp, src = preflight_env
    calls = []

    def flaky(**kw):
        calls.append(1)
        if len(calls) == 1:
            return False, "profile-run", "perf replay-profile failed after 2 attempts"
        _fake_hotspots(kw["profile_dir"], 900, 1000)
        return True, "profile", "ok"
    monkeypatch.setattr(phase2_setup, "run_baseline_profile", flaky)
    assert phase3_online._preflight_profile(**_preflight_kw(tmp_path, exp, src))[0] is True
    assert len(calls) == 2


def test_preflight_profile_disables_and_needs_seeds(monkeypatch, tmp_path, preflight_env):
    exp, src = preflight_env
    kw = _preflight_kw(tmp_path, exp, src)
    monkeypatch.setattr(phase3_online.config, "ONLINE_PREFLIGHT_PROFILE_SECS", 0)
    assert phase3_online._preflight_profile(**kw) == (True, "disabled")
    monkeypatch.setattr(phase3_online.config, "ONLINE_PREFLIGHT_PROFILE_SECS", 30)
    (exp / "seed_corpus" / "merged" / "s0").unlink()
    ok, why = phase3_online._preflight_profile(**kw)
    assert ok is False and "no seed corpus" in why


# --- hot swap deploys the build's own shared libraries ---------------------------
def _fb_build(root, lib_bytes):
    for rel in ("t", "cmplog/t", "afl++.dict", "src/shared/libproj-shared-1.so",
                "cmplog/src/shared/libproj-shared-1.so", "modules/opcache.so",
                "afl-llvm-pass.so", "SanitizerCoveragePCGUARD.so"):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(lib_bytes if rel.endswith(".so") else b"bin-" + lib_bytes)


def test_runtime_libs_are_the_builds_own_shared_objects(tmp_path):
    from lib import afl_launch
    _fb_build(tmp_path, b"v1")
    assert afl_launch.fuzzbench_runtime_libs(str(tmp_path)) == [
        "cmplog/src/shared/libproj-shared-1.so", "modules/opcache.so",
        "src/shared/libproj-shared-1.so"]


def test_hot_swap_deploys_new_shared_libraries_and_drops_stale_ones(tmp_path):
    """A fold in /out/**/lib*.so is measured by the gate (the round's whole /out)
    and must reach the trial with the target: never a new binary on an old lib."""
    live, new = tmp_path / "live", tmp_path / "new"
    _fb_build(live, b"v1")
    (live / "src" / "shared" / "libgone.so").write_bytes(b"old")
    _fb_build(new, b"v2")
    entry = {"kind": "fuzzbench"}
    extra = (phase3_online._swap_extra_files(entry, "t")
             + phase3_online._swap_runtime_libs(entry, new, live))
    assert "src/shared/libgone.so" in extra and "afl-llvm-pass.so" not in extra
    phase3_online._overwrite_binary(str(live / "t"), str(new / "t"), extra_files=extra)
    assert (live / "t").read_bytes() == b"bin-v2"
    assert (live / "src/shared/libproj-shared-1.so").read_bytes() == b"v2"
    assert (live / "cmplog/src/shared/libproj-shared-1.so").read_bytes() == b"v2"
    assert (live / "modules/opcache.so").read_bytes() == b"v2"
    assert not (live / "src/shared/libgone.so").exists()
    assert (live / "afl-llvm-pass.so").read_bytes() == b"v1"   # tool plugin untouched
    assert phase3_online._swap_runtime_libs({"kind": "arvo"}, new, live) == ()


def test_run_online_checks_the_profile_before_any_trial_starts():
    import inspect
    src = inspect.getsource(phase3_online.run_online)
    assert src.index("_preflight_profile(") < src.index("_build_online_trials(entry, experiment_dir)\n    state")


def test_both_swap_paths_deploy_the_runtime_libraries():
    import inspect
    for fn in (phase3_online.hot_swap_one, phase3_online.hot_swap):
        assert "_swap_runtime_libs(" in inspect.getsource(fn), fn.__name__


# --- a session that could not remove its containers ---------------------------
#
# They may still be editing the tree: the round neither resets nor commits it,
# and the trial's next round waits until they are confirmed gone.

def _orphan_ctx(tmp_path):
    import types
    online = tmp_path / "trial_03"
    ctx = phase3_online.RoundContext(
        entry={"cve": "x"}, experiment_id="e", experiment_dir=str(tmp_path),
        online_dir=str(online), source_tree=str(tmp_path / "src"), source_root="",
        project="p", image="", fuzz_target="t", poc_path=None,
        previous_best_bin="/best", prev_tag="iter_02", optimized_bin_dir="",
        ledger_path=str(online / "ledger.json"), swap_timeline_path="",
        profile_cpu=1)
    ctx.trial = types.SimpleNamespace(trial_id=3)
    return ctx


def _no_tree_ops(monkeypatch):
    ops = []
    monkeypatch.setattr(phase3_online, "_revert_source_tree",
                        lambda tree, tag: ops.append(("revert", tag)))
    monkeypatch.setattr(phase3_online, "apply_round_outcome",
                        lambda *a, **k: ops.append(("outcome", a, k)))
    monkeypatch.setattr(phase3_online, "_write_cpu_cost_summary", lambda ctx: None)
    monkeypatch.setattr(phase3_online.phase2_setup, "optimizer_provenance", lambda: {})
    return ops


def test_a_round_whose_agent_was_not_removed_leaves_the_tree_alone(monkeypatch, tmp_path):
    ops = _no_tree_ops(monkeypatch)
    ctx = _orphan_ctx(tmp_path)
    diff_dir = tmp_path / "trial_03" / "iter_04" / "source_diff"
    diff_dir.mkdir(parents=True)
    r = phase3_online._end_agent_not_removed_round(
        ctx, 4, diff_dir=str(diff_dir), containers=["agent-1-x", "broker-1-2"])
    assert r == (False, None, False)              # not accepted, not evidence
    assert ops == [], "the tree was reset or committed under a live agent"
    assert ctx.orphan_containers == ["agent-1-x", "broker-1-2"]
    prov = json.loads((diff_dir.parent / "round_provenance.json").read_text())
    assert prov["outcome"] == phase3_online.AGENT_NOT_REMOVED_OUTCOME
    assert prov["agent_containers_still_present"] == ["agent-1-x", "broker-1-2"]
    assert ctx.previous_best_bin == "/best"


def test_the_next_round_waits_while_the_containers_are_still_there(monkeypatch, tmp_path):
    import sandbox.session as session
    ops = _no_tree_ops(monkeypatch)
    ctx = _orphan_ctx(tmp_path)
    ctx.orphan_containers = ["agent-1-x"]
    tried = []
    monkeypatch.setattr(session, "remove_container",
                        lambda name, attempts=10: tried.append(name) or False)
    from lib import cpu_ledger
    try:
        assert phase3_online.run_round(ctx, None, 5) == (False, None, False)
    finally:
        cpu_ledger.clear_thread_round()           # run_round tags this thread
    assert tried == ["agent-1-x"] and ops == []      # no chown either while live
    assert ctx.orphan_wait_rounds == 1
    prov = json.loads((tmp_path / "trial_03" / "iter_05" / "round_provenance.json")
                      .read_text())
    assert prov["outcome"] == phase3_online.AGENT_NOT_REMOVED_WAIT_OUTCOME
    assert not (tmp_path / "trial_03" / "iter_05" / "source_diff").exists()


def _chown(monkeypatch, ops, ok=True):
    import sandbox.broker as broker
    monkeypatch.setattr(phase3_online, "prework_image_for", lambda entry: "img")
    monkeypatch.setattr(broker, "chown_back", lambda image, paths, labels=None: (
        ops.append(("chown", image, paths, labels)) or ok))


def test_once_they_are_gone_the_tree_is_chowned_then_reset_before_the_round(monkeypatch, tmp_path):
    """A leftover ARVO build leaves root-owned objects `git clean` cannot
    remove: ownership comes back first, then the reset."""
    import sandbox.session as session
    from sandbox.launch import LABEL_ITER, LABEL_TRIAL
    ops = _no_tree_ops(monkeypatch)
    _chown(monkeypatch, ops)
    ctx = _orphan_ctx(tmp_path)
    ctx.orphan_containers = ["agent-1-x"]
    monkeypatch.setattr(session, "remove_container", lambda name, attempts=10: True)
    assert phase3_online._orphans_cleared(ctx, 6) is True
    assert ops == [("chown", "img", [ctx.source_tree], {LABEL_TRIAL: 3, LABEL_ITER: 6}),
                   ("revert", "iter_02")]
    assert ctx.orphan_containers == [] and ctx.orphans_cleared == ["agent-1-x"]
    assert ctx.orphan_wait_rounds == 0


def test_a_tree_that_cannot_be_chowned_is_not_reset_and_the_round_waits(monkeypatch, tmp_path):
    import sandbox.session as session
    ops = _no_tree_ops(monkeypatch)
    _chown(monkeypatch, ops, ok=False)
    ctx = _orphan_ctx(tmp_path)
    ctx.orphan_containers = ["agent-1-x"]
    monkeypatch.setattr(session, "remove_container", lambda name, attempts=10: True)
    assert phase3_online._orphans_cleared(ctx, 6) is False
    assert [o[0] for o in ops] == ["chown"], "reset without ownership restored"
    assert ctx.orphan_containers == ["agent-1-x"]     # checked again next round
    assert ctx.orphan_wait_rounds == 1
    prov = json.loads((tmp_path / "trial_03" / "iter_06" / "round_provenance.json")
                      .read_text())
    assert prov["outcome"] == phase3_online.AGENT_NOT_REMOVED_WAIT_OUTCOME
    assert prov["ownership_restored"] is False


def test_waiting_rounds_are_not_counted_as_attempts(tmp_path):
    a, b = _orphan_ctx(tmp_path), _orphan_ctx(tmp_path)
    b.trial = types.SimpleNamespace(trial_id=4)
    a.iter_n, b.iter_n, b.orphan_wait_rounds = 6, 9, 3
    assert phase3_online._rounds_record([a, b], per_trial=True) == {
        "rounds_attempted": {3: 6, 4: 6}, "rounds_waiting_for_orphans": {3: 0, 4: 3}}
    b.orphan_wait_rounds = 0
    assert phase3_online._rounds_record([a, b], per_trial=True) == {
        "rounds_attempted": {3: 6, 4: 9}}
    a.orphan_wait_rounds = 2
    assert phase3_online._rounds_record([a], per_trial=False) == {
        "rounds_attempted": 4, "rounds_waiting_for_orphans": 2}


@pytest.mark.parametrize('repair', [False, True])
@pytest.mark.parametrize('full_set', [False, True])
def test_online_scope_rejection_tracks_current_candidate_not_resolved_history(monkeypatch, tmp_path, repair, full_set):
    """A corrected broker build may still reach the ordinary acceptance gate."""
    from lib.source_scope import SourceScopeGuard, SourceScopeViolation
    from sandbox import broker

    monkeypatch.setattr(phase3_online.config, 'ONLINE_GATE_FULL_SET', full_set)
    ctx = _prebuild_round_ctx(tmp_path)
    tree = tmp_path / 'source'; (tree / 'fuzz').mkdir(parents=True)
    harness = tree / 'fuzz/target.c'; harness.write_text('int LLVMFuzzerTestOneInput(void) { return 0; }')
    (tree / 'library.c').write_text('int original;')
    ctx.source_tree = str(tree)
    ctx.source_root = str(tree)
    monkeypatch.setattr(phase3_online.config, 'ONLINE_FIXED_MUTATION_CORPUS', True)
    rc = {key: 1 for key in ('harvested', 'checked_count', 'crashers_removed',
                            'tuning_count', 'units_per_s', 'budget_secs', 'smoke_count')}
    rc.update(tuning='tuning', smoke='smoke', checked='checked', gate='gate')
    monkeypatch.setattr(phase3_online, 'prepare_round_corpus', lambda **kw: rc)
    monkeypatch.setattr(phase3_online, 'prework_image_for', lambda entry: 'img')
    monkeypatch.setattr(phase3_online, '_gate_replay_rate', lambda directory: None)
    def profile_env(**kwargs):
        assert kwargs['corpus_dir'] == 'tuning'
        return {'PROFILE_CORPUS': kwargs['corpus_dir']}
    monkeypatch.setattr(phase3_online, 'build_round_env', profile_env)
    monkeypatch.setattr(phase3_online, '_reassert_edit_mtimes', lambda tree: None)
    monkeypatch.setattr(phase3_online, '_carry_forward_agent_memory', lambda *a: False)
    monkeypatch.setattr(phase3_online, '_write_cpu_cost_summary', lambda c: None)
    monkeypatch.setattr(phase3_online, '_write_cumulative_diff', lambda *a: None)
    monkeypatch.setattr(phase2_setup, 'optimizer_provenance', lambda: {})
    monkeypatch.setattr(broker, '_run_build_snapshot', lambda candidate: (True, 'built'))
    accepted = []
    monkeypatch.setattr(phase3_online, 'apply_round_outcome', lambda ready, **kw:
        accepted.append(ready) or (kw['opt_bin_dir'] if ready else kw['previous_best_bin']))

    def optimize(source, target, diff_dir, **kwargs):
        env = kwargs['codex_extra_env']
        assert env['PROFILE_CORPUS'] == 'tuning'
        assert env['FUZZ_SOURCE_FOLDS_PREBUILT_MUTATIONS'] == 'tuning'
        assert env['FUZZ_SOURCE_FOLDS_SMOKE_CORPUS_DIR'] == 'smoke'
        assert 'gate' not in env.values() and 'checked' not in env.values()
        report = Path(diff_dir) / 'source_scope_violation.json'
        g = SourceScopeGuard(tree, harness='fuzz/target.c', report_path=report)
        original = harness.read_bytes()
        try:
            (tree / 'library.c').write_text('int faster;')
            harness.write_text('bad harness')
            candidate = broker.BrokerContext(image='img', source_dir=str(tree), out_dir='/out',
                corpus_dir='/corpus', fuzz_target='target', project='libxml2', cpu=0, source_guard=g)
            assert not broker._run_build(candidate)[0]
            if not repair:
                with pytest.raises(SourceScopeViolation): g.validate()
                g.restore()
                return False
            harness.write_bytes(original)
            metadata = g.entries['fuzz/target.c']
            os.utime(harness, ns=(harness.stat().st_atime_ns, metadata['mtime_ns']))
            assert broker._run_build(candidate)[0]
            g.validate()
            (Path(diff_dir) / 'optimization.diff').write_text('diff --git a/library.c b/library.c\n')
            assert not report.exists()
            assert list(report.parent.glob('source_scope_violation.resolved-*.json'))
            return True
        finally:
            g.close()
    monkeypatch.setattr(phase2_setup, 'optimize_and_build', optimize)
    monkeypatch.setattr(phase2_setup, '_reject_if_optimization_removed_bug', lambda **kw:
        (kw['optimization_ready'], None))
    monkeypatch.setattr(phase3_online.afl_replay, 'find_crashers', lambda **kw:
        {'ok': True, 'scanned': 1, 'expected': 1, 'crashers': []})
    gates = []
    def speed_gate(**kwargs):
        assert kwargs['corpus_dir'] == 'gate'
        assert kwargs['cap'] is False
        gates.append(True)
        return {'replay_speedup': 1.25, 'partial': False,
                'baseline': {'median_time_s': 10}, 'optimized': {'median_time_s': 8}}
    monkeypatch.setattr(phase2_setup, 'run_replay_speedup', speed_gate)
    monkeypatch.setattr(phase2_setup, '_reject_if_no_replay_speedup', lambda **kw:
        (kw['optimization_ready'], None))

    result = phase3_online.run_round(ctx, phase3_online.OnlineState(), 1)
    assert result[0] is repair and accepted == [repair]
    assert gates == ([True] if repair else [])
    prov = json.loads((Path(ctx.online_dir) / 'iter_01/round_provenance.json').read_text())
    assert prov['outcome'] == ('kept' if repair else 'rejected-source-scope')
    history = Path(ctx.online_dir) / 'iter_01/source_diff/source_scope_history.jsonl'
    assert history.exists()


def test_30k_snapshot_reserves_7500_inputs_for_final_gate(tmp_path, monkeypatch):
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_BUDGET_SECS", 0)
    monkeypatch.setattr(phase3_online.config, "PHASE2_REPLAY_MAX_UNITS", 0)
    r = _round(tmp_path, 30000)
    assert r["tuning_count"] == 22500
    assert r["gate_count"] == 7500
    assert not _names(r["tuning"]) & _names(r["gate"])
    assert not _names(r["smoke"]) & _names(r["gate"])


def test_fixed_snapshot_keeps_split_seed_across_rounds(monkeypatch, tmp_path):
    ctx = _prebuild_failing_round(monkeypatch, tmp_path, "profile")
    prepare = phase3_online.prepare_round_corpus
    seeds = []
    def remember(**kwargs):
        seeds.append(kwargs["seed"])
        return prepare(**kwargs)
    monkeypatch.setattr(phase3_online, "prepare_round_corpus", remember)
    phase3_online.run_round(ctx, phase3_online.OnlineState(), 1)
    phase3_online.run_round(ctx, phase3_online.OnlineState(), 2)
    assert seeds == [phase3_online.config.BASE_SEED] * 2


def test_online_round_without_snapshot_skips_before_agent(monkeypatch, tmp_path):
    ctx = _prebuild_round_ctx(tmp_path)
    ctx.fixed_mutations = None
    monkeypatch.setattr(phase3_online.config, "ONLINE_LIVE_MUTATION_CAPTURE", False)
    monkeypatch.setattr(phase2_setup, "optimize_and_build", lambda *a, **kw:
                        pytest.fail("agent cannot start without a held-out split"))
    assert phase3_online.run_round(ctx, phase3_online.OnlineState(), 1) == (False, None, False)
    assert ctx.ledger[-1]["outcome"] == "no-holdout-snapshot"
