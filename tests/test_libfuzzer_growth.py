"""Historical libFuzzer curves must use common coverage and honest clocks."""
import json
from pathlib import Path
import sys
import warnings

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analysis"))
from libfuzzer_growth import parse_control, throughput
from plot_coverage_growth import band


def test_merge_edges_accumulate_in_discovery_order():
    control = ["3", "0", "/corpus/a", "/corpus/b", "/corpus/c",
               "STARTED 0 10", "FT 0 42 43", "COV 0 10 20",
               "STARTED 1 10", "FT 1 44", "COV 1 20 30",
               "STARTED 2 10", "FT 2"]
    assert parse_control(control, [0, 30, 60]) == [
        (0, 0, 0), (0, 1, 2), (30, 2, 3), (60, 3, 3)]


def test_crash_skipped_input_is_not_silently_treated_as_complete():
    control = ["2", "0", "/corpus/a", "/corpus/b",
               "STARTED 0 10", "FT 0 42", "COV 0 10", "STARTED 1 10"]
    with pytest.raises(ValueError, match="Incomplete baseline replay"):
        parse_control(control, [0, 30])


def test_control_must_match_original_corpus():
    with pytest.raises(ValueError, match="header"):
        parse_control(["1", "1", "/corpus/a", "FT 0"], [0])


def test_throughput_uses_log_order_and_measured_endpoint(tmp_path):
    (tmp_path / "metadata.json").write_text(json.dumps({
        "duration_s": 100, "final_stats": {"total_execs": 2000}}))
    (tmp_path / "fuzzer.log").write_text(
        "#2 INITED cov: 7 exec/s: 0\n"
        "#100 NEW cov: 9 exec/s: 10\n"
        "#110 NEW cov: 10 exec/s: 20\n"  # clock regression: discard
        "#900 pulse cov: 11 exec/s: 20\n"
        "#2000 DONE cov: 11 exec/s: 19\n")  # beyond actual duration
    xs, ys = throughput(tmp_path)
    np.testing.assert_allclose(xs, [100 / 10.5, 900 / 20.5, 100])
    np.testing.assert_allclose(ys, [10, 20, 20])


def test_band_keeps_missing_times_unknown_without_warnings():
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        mean, lo, hi, n = band([np.array([np.nan, 1., 2.]),
                                np.array([np.nan, np.nan, 4.])], gridded=True)
    assert n == 2
    assert np.isnan(mean[0]) and np.isnan(lo[0]) and np.isnan(hi[0])
    assert mean[1] == lo[1] == hi[1] == 1
    assert mean[2] == 3 and lo[2] < 3 < hi[2]
