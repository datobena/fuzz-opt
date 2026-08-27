# test_phase3_online.py
import os
import types

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
# should_reopen — soft-ledger re-open rule
# ---------------------------------------------------------------------------
def test_should_reopen_stable_hotspot_stays_avoided():
    assert phase3_online.should_reopen(1, 0.40, 1, 0.41) is False


def test_should_reopen_on_big_rank_shift():
    assert phase3_online.should_reopen(1, 0.40, 5, 0.40) is True


def test_should_reopen_on_big_share_shift():
    # rank barely moves but self-time share jumps 0.40 -> 0.60 (>25% relative)
    assert phase3_online.should_reopen(1, 0.40, 2, 0.60) is True


def test_should_reopen_dropped_out_of_profile_not_reopened():
    assert phase3_online.should_reopen(1, 0.40, None, None) is False


# ---------------------------------------------------------------------------
# build_ledger_summary — prompt block of already-tried folds to avoid
# ---------------------------------------------------------------------------
def _ledger_entry(func, rank, share, pattern="lut", outcome="rejected-no-speedup"):
    return {
        "functions": [func],
        "fold_pattern": pattern,
        "outcome": outcome,
        "measured_speedup": 1.0,
        "hotspot_rank": {func: rank},
        "hotspot_share": {func: share},
    }


def test_build_ledger_summary_lists_stable_attempts():
    ledger = [_ledger_entry("cil_resolve_ast", 1, 0.40)]
    profile = {"cil_resolve_ast": {"rank": 1, "share": 0.41}}
    summary = phase3_online.build_ledger_summary(ledger, profile)
    assert "cil_resolve_ast" in summary
    assert "lut" in summary


def test_build_ledger_summary_excludes_reopened_attempts():
    ledger = [_ledger_entry("cil_resolve_ast", 1, 0.40)]
    # profile now ranks it 6th -> materially changed -> re-opened -> not avoided
    profile = {"cil_resolve_ast": {"rank": 6, "share": 0.40}}
    summary = phase3_online.build_ledger_summary(ledger, profile)
    assert "cil_resolve_ast" not in summary


def test_build_ledger_summary_empty_when_nothing_to_avoid():
    assert phase3_online.build_ledger_summary([], {}) == ""


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
        opt_bin_dir=tmp_path / "optbin", snapshot_dir=snap,
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
        opt_bin_dir=tmp_path / "optbin", snapshot_dir=snap,
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
    entry = {"project": "selinux", "cve": "arvo-1", "fuzz_target": "secilc-fuzzer"}
    baseline, online = phase3_online._build_online_trials(entry)
    assert len(baseline) == 10 and len(online) == 10
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
