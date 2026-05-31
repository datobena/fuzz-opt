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
