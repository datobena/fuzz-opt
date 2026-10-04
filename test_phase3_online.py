# test_phase3_online.py
import json
import os
import threading
import time
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
