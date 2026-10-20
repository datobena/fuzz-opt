import json

import pytest

import phase4_analysis


def test_load_trial_data_derives_execs_per_second_when_reported_value_is_zero(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(phase4_analysis.config, "RESULTS_DIR", str(tmp_path))

    exp_dir = (
        tmp_path
        / "exp"
        / "demo-CVE-0000-0001"
    )
    manifest = [{"project": "demo", "cve": "CVE-0000-0001", "crash_type": "crash"}]

    for variant in ["baseline", "optimized"]:
        trial_dir = exp_dir / variant / "trial_00"
        trial_dir.mkdir(parents=True)
        (trial_dir / "metadata.json").write_text(json.dumps({
            "duration_s": 10.0,
            "duration_seconds": 15,
            "final_stats": {
                "total_execs": 320,
                "final_exec_s": 0,
            },
        }))
        (trial_dir / "fuzzer.log").write_text(
            "stat::number_of_executed_units: 320\n"
            "stat::average_exec_per_sec:     0\n"
        )
        (trial_dir / "crash_times.json").write_text("[]")

    data = phase4_analysis.load_trial_data("exp", manifest)

    assert data["demo-CVE-0000-0001"]["baseline"]["exec_s"] == [32.0]
    assert data["demo-CVE-0000-0001"]["optimized"]["exec_s"] == [32.0]


def test_load_trial_data_attaches_replay_metric_from_setup_metadata(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(phase4_analysis.config, "RESULTS_DIR", str(tmp_path))

    key = "demo-CVE-0000-0002"
    exp_dir = tmp_path / "exp" / key
    manifest = [{"project": "demo", "cve": "CVE-0000-0002", "crash_type": "crash"}]

    for variant in ["baseline", "optimized"]:
        trial_dir = exp_dir / variant / "trial_00"
        trial_dir.mkdir(parents=True)
        (trial_dir / "metadata.json").write_text(json.dumps({
            "duration_s": 10.0,
            "final_stats": {"total_execs": 100, "final_exec_s": 10},
        }))
        (trial_dir / "crash_times.json").write_text("[]")

    (exp_dir / "setup_metadata.json").write_text(json.dumps({
        "replay": {
            "replay_speedup": 1.8,
            "baseline": {"median_time_s": 9.0},
            "optimized": {"median_time_s": 5.0},
            "corpus_file_count": 42,
        }
    }))

    data = phase4_analysis.load_trial_data("exp", manifest)
    result = phase4_analysis.analyze_cve(key, data[key], str(tmp_path / "report"))

    assert result["replay_speedup"] == 1.8
    assert result["replay_baseline_time_s"] == 9.0
    assert result["replay_optimized_time_s"] == 5.0
    assert result["replay_corpus_file_count"] == 42


def test_extract_execs_per_second_prefers_total_execs_over_bogus_reported_average(
    tmp_path
):
    trial_dir = tmp_path / "trial_00"
    trial_dir.mkdir()
    metadata = {
        "duration_s": 10.14,
        "final_stats": {
            "total_execs": 2835,
            "final_exec_s": 2835,
            "stat_avg_exec_s": 2835,
        },
    }
    (trial_dir / "fuzzer.log").write_text(
        "stat::number_of_executed_units: 2835\n"
        "stat::average_exec_per_sec:     2835\n"
    )

    exec_s = phase4_analysis.extract_execs_per_second(metadata, str(trial_dir))

    assert exec_s == pytest.approx(2835 / 10.14)


# --------------------------------------------------------------------------- #
# Trial duration = the time-to-bug censoring cutoff. It must come from what the
# trials recorded: a 6h default on a 24h campaign drops every late find.
# --------------------------------------------------------------------------- #

_KEY = "demo-CVE-0000-0003"
_MANIFEST = [{"project": "demo", "cve": "CVE-0000-0003", "crash_type": "crash"}]


def _write_trial(exp_dir, variant, trial, crash_ts=None, recorded=86400,
                 with_metadata=True):
    trial_dir = exp_dir / variant / f"trial_{trial:02d}"
    trial_dir.mkdir(parents=True)
    crash_times = []
    if crash_ts is not None:
        crash_times.append({
            "timestamp_s": crash_ts,
            "artifact": f"crash-{trial:040x}",
            "crash_type": "crash",
        })
    (trial_dir / "crash_times.json").write_text(json.dumps(crash_times))
    if with_metadata:
        meta = {"duration_s": 10.0,
                "final_stats": {"total_execs": 100, "final_exec_s": 10}}
        if recorded is not None:
            meta["duration_seconds"] = recorded
        (trial_dir / "metadata.json").write_text(json.dumps(meta))


@pytest.fixture
def results_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(phase4_analysis.config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(phase4_analysis.config, "TRIAL_DURATION_SECS", 21600)
    return tmp_path


def test_cli_duration_defaults_to_none_so_metadata_wins(monkeypatch):
    seen = {}

    def fake_load(experiment_id, manifest, duration=None):
        seen["duration"] = duration
        return {}

    monkeypatch.setattr(phase4_analysis, "load_trial_data", fake_load)
    monkeypatch.setattr(phase4_analysis.sys, "argv", [
        "phase4_analysis.py", "--experiment-id", "exp",
        "--manifest", "/dev/null",
    ])
    monkeypatch.setattr(phase4_analysis.json, "load", lambda f: [])
    with pytest.raises(SystemExit):        # no results -> exit(1)
        phase4_analysis.main()

    assert seen["duration"] is None


def test_24h_campaign_counts_finds_after_hour_6_by_default(results_dir):
    exp_dir = results_dir / "exp" / _KEY
    # Late finds (hour 10) in both arms, one early find, one censored trial.
    _write_trial(exp_dir, "baseline", 0, crash_ts=36000.0)
    _write_trial(exp_dir, "baseline", 1, crash_ts=None)
    _write_trial(exp_dir, "optimized", 0, crash_ts=36000.0)
    _write_trial(exp_dir, "optimized", 1, crash_ts=600.0)

    data = phase4_analysis.load_trial_data("exp", _MANIFEST)
    result = phase4_analysis.analyze_cve(_KEY, data[_KEY], str(results_dir / "r"))

    assert data[_KEY]["baseline"]["times"] == [36000.0, 86400.0]
    assert data[_KEY]["optimized"]["durations"] == [86400, 86400]
    assert result["baseline_found_bug"] == 1
    assert result["optimized_found_bug"] == 2
    assert result["trial_duration"] == 86400
    assert result["trial_durations"] == [86400]
    assert result["trial_duration_source"] == "trial metadata"


def test_explicit_duration_override_still_truncates(results_dir):
    exp_dir = results_dir / "exp" / _KEY
    _write_trial(exp_dir, "baseline", 0, crash_ts=36000.0)
    _write_trial(exp_dir, "optimized", 0, crash_ts=600.0)

    data = phase4_analysis.load_trial_data("exp", _MANIFEST, duration=21600)
    result = phase4_analysis.analyze_cve(
        _KEY, data[_KEY], str(results_dir / "r"), duration=21600,
    )

    assert data[_KEY]["baseline"]["times"] == [21600.0]
    assert result["baseline_found_bug"] == 0
    assert result["optimized_found_bug"] == 1
    assert result["trial_duration"] == 21600
    assert result["trial_duration_source"] == "--duration override"


def test_trial_without_recorded_duration_uses_experiment_max(results_dir):
    exp_dir = results_dir / "exp" / _KEY
    _write_trial(exp_dir, "baseline", 0, crash_ts=None)
    # Metadata present but no duration_seconds; another with no metadata at all.
    _write_trial(exp_dir, "baseline", 1, crash_ts=36000.0, recorded=None)
    _write_trial(exp_dir, "optimized", 0, crash_ts=36000.0, with_metadata=False)

    data = phase4_analysis.load_trial_data("exp", _MANIFEST)
    result = phase4_analysis.analyze_cve(_KEY, data[_KEY], str(results_dir / "r"))

    assert data[_KEY]["baseline"]["durations"] == [86400, 86400]
    assert data[_KEY]["optimized"]["durations"] == [86400]
    assert data[_KEY]["optimized"]["duration_sources"] == ["experiment_max"]
    assert result["baseline_found_bug"] == 1
    assert result["optimized_found_bug"] == 1
    assert "trial metadata (1 trials)" in result["trial_duration_source"]
    assert "max recorded" in result["trial_duration_source"]


def test_no_recorded_duration_falls_back_to_config_and_warns(results_dir, caplog):
    exp_dir = results_dir / "exp" / _KEY
    _write_trial(exp_dir, "baseline", 0, crash_ts=36000.0, recorded=None)
    _write_trial(exp_dir, "optimized", 0, crash_ts=None, with_metadata=False)

    with caplog.at_level("WARNING"):
        data = phase4_analysis.load_trial_data("exp", _MANIFEST)
    result = phase4_analysis.analyze_cve(_KEY, data[_KEY], str(results_dir / "r"))
    report_dir = results_dir / "r"
    phase4_analysis.generate_report([result], str(report_dir), "exp")

    assert data[_KEY]["baseline"]["times"] == [21600.0]
    assert result["trial_duration"] == 21600
    assert "NO trial metadata recorded a duration" in caplog.text
    report = (report_dir / "report.md").read_text()
    assert "**WARNING**" in report
    assert "config.TRIAL_DURATION_SECS default" in report


def test_mixed_durations_count_finds_against_each_trials_own_cutoff(results_dir):
    exp_dir = results_dir / "exp" / _KEY
    # A 6h trial censored at 21600 must not count as a find just because a
    # sibling ran 24h.
    _write_trial(exp_dir, "baseline", 0, crash_ts=None, recorded=21600)
    _write_trial(exp_dir, "baseline", 1, crash_ts=36000.0, recorded=86400)
    _write_trial(exp_dir, "optimized", 0, crash_ts=None, recorded=86400)

    data = phase4_analysis.load_trial_data("exp", _MANIFEST)
    result = phase4_analysis.analyze_cve(_KEY, data[_KEY], str(results_dir / "r"))

    assert data[_KEY]["baseline"]["times"] == [21600.0, 36000.0]
    assert result["baseline_found_bug"] == 1
    assert result["optimized_found_bug"] == 0
    assert result["trial_duration"] == 86400
    assert result["trial_durations"] == [21600, 86400]


def test_all_trials_finding_at_whole_second_is_not_miscounted(results_dir):
    # The old heuristic shrank the cutoff to the max time when that was an
    # integer, which dropped the latest find from the found count.
    exp_dir = results_dir / "exp" / _KEY
    _write_trial(exp_dir, "baseline", 0, crash_ts=5000.0)
    _write_trial(exp_dir, "optimized", 0, crash_ts=4000.0)

    data = phase4_analysis.load_trial_data("exp", _MANIFEST)
    result = phase4_analysis.analyze_cve(_KEY, data[_KEY], str(results_dir / "r"))

    assert result["baseline_found_bug"] == 1
    assert result["optimized_found_bug"] == 1


def test_report_states_duration_and_source(results_dir):
    exp_dir = results_dir / "exp" / _KEY
    _write_trial(exp_dir, "baseline", 0, crash_ts=None)
    _write_trial(exp_dir, "optimized", 0, crash_ts=None)

    data = phase4_analysis.load_trial_data("exp", _MANIFEST)
    result = phase4_analysis.analyze_cve(_KEY, data[_KEY], str(results_dir / "r"))
    phase4_analysis.generate_report([result], str(results_dir / "r"), "exp")

    report = (results_dir / "r" / "report.md").read_text()
    assert ("**Duration per trial**: 24.0 hours (86400s, from trial metadata)"
            in report)
    assert "**WARNING**" not in report


def test_zero_duration_override_is_rejected_not_turned_into_6h(results_dir):
    exp_dir = results_dir / "exp" / _KEY
    _write_trial(exp_dir, "baseline", 0, crash_ts=36000.0)
    _write_trial(exp_dir, "optimized", 0, crash_ts=600.0)

    for bad in (0, -1):
        with pytest.raises(ValueError):
            phase4_analysis.load_trial_data("exp", _MANIFEST, duration=bad)
        with pytest.raises(ValueError):
            phase4_analysis.find_time_to_target_bug([], "crash", "",
                                                    trial_duration=bad)
    data = phase4_analysis.load_trial_data("exp", _MANIFEST)
    with pytest.raises(ValueError):
        phase4_analysis.analyze_cve(_KEY, data[_KEY], str(results_dir / "r"),
                                    duration=0)


def test_find_time_to_target_bug_without_duration_uses_config(results_dir):
    assert phase4_analysis.find_time_to_target_bug([], "crash", "") == 21600.0


def test_cli_rejects_zero_duration(monkeypatch):
    monkeypatch.setattr(phase4_analysis.sys, "argv", [
        "phase4_analysis.py", "--experiment-id", "exp", "--duration", "0",
    ])
    with pytest.raises(SystemExit) as exc:
        phase4_analysis.main()
    assert exc.value.code == 2
