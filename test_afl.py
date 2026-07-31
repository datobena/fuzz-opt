"""Tests for lib/afl.py — parsing AFL++ campaign output.

Every TTB number in the study comes from crash_time_secs, so the units matter
more than anything else here. The millisecond assumption is validated against a
real afl-fuzz run (see the plan's Task 5 Step 5), not taken on faith.
"""
import pytest

from lib.afl import (
    crash_time_secs,
    collect_crashes,
    parse_fuzzer_stats,
    parse_plot_data,
)


def test_crash_time_is_parsed_from_the_filename_in_seconds():
    """AFL++ writes time: as MILLISECONDS since campaign start."""
    n = "id:000003,sig:06,src:000001,time:45231,execs:99112,op:havoc,rep:4"
    assert crash_time_secs(n) == pytest.approx(45.231)


def test_crash_time_handles_a_leading_time_field():
    assert crash_time_secs("id:000000,time:1000,execs:5") == pytest.approx(1.0)


def test_crash_time_handles_a_trailing_time_field():
    assert crash_time_secs("id:000000,execs:5,time:2500") == pytest.approx(2.5)


def test_crash_time_returns_none_without_a_time_field():
    assert crash_time_secs("README.txt") is None


def test_crash_time_ignores_a_substring_field():
    """'+cov' and other fields must not be mistaken for time."""
    assert crash_time_secs("id:1,runtime:99,execs:5") is None


def test_parse_fuzzer_stats_reads_key_colon_value():
    text = ("start_time        : 1656000000\n"
            "execs_done        : 1234567\n"
            "execs_per_sec     : 1234.56\n"
            "edges_found       : 4321\n"
            "saved_crashes     : 3\n")
    s = parse_fuzzer_stats(text)
    assert s["execs_done"] == 1234567
    assert s["execs_per_sec"] == pytest.approx(1234.56)
    assert s["edges_found"] == 4321
    assert s["saved_crashes"] == 3


def test_parse_fuzzer_stats_keeps_non_numeric_values_as_strings():
    s = parse_fuzzer_stats("command_line : /out/afl-fuzz -V 120\nafl_banner : x\n")
    assert s["afl_banner"] == "x"
    assert "afl-fuzz" in s["command_line"]


def test_parse_fuzzer_stats_tolerates_junk():
    assert parse_fuzzer_stats("") == {}
    assert parse_fuzzer_stats("no colon here\n") == {}


def test_parse_plot_data_yields_time_series_rows():
    text = ("# relative_time, cycles_done, cur_item, corpus_count, pending_total, "
            "pending_favs, map_size, saved_crashes, saved_hangs, max_depth, "
            "execs_per_sec, total_execs, edges_found\n"
            "10, 0, 5, 12, 3, 1, 4.5%, 0, 0, 2, 900.1, 9001, 150\n"
            "20, 1, 9, 20, 2, 0, 5.1%, 1, 0, 3, 950.0, 19000, 210\n")
    rows = parse_plot_data(text)
    assert len(rows) == 2
    assert rows[0]["relative_time"] == 10
    assert rows[1]["edges_found"] == 210
    assert rows[1]["saved_crashes"] == 1


def test_parse_plot_data_uses_the_header_not_fixed_positions():
    """AFL++ has reordered these columns between releases."""
    text = ("# relative_time, edges_found, execs_per_sec\n"
            "5, 42, 100.0\n")
    rows = parse_plot_data(text)
    assert rows[0]["edges_found"] == 42
    assert rows[0]["execs_per_sec"] == pytest.approx(100.0)


def test_parse_plot_data_without_a_header_returns_nothing():
    """Guessing column meaning from position is how silent corruption starts."""
    assert parse_plot_data("5, 42, 100.0\n") == []


def test_collect_crashes_skips_the_readme(tmp_path):
    """AFL drops a README.txt into crashes/; it is not a finding."""
    d = tmp_path / "crashes"
    d.mkdir()
    (d / "README.txt").write_text("afl notes\n")
    (d / "id:000000,sig:06,src:000000,time:1500,execs:10,op:havoc").write_bytes(b"x")

    got = collect_crashes(d)
    assert len(got) == 1
    assert got[0]["timestamp_s"] == pytest.approx(1.5)
    assert got[0]["artifact"].startswith("id:000000")


def test_collect_crashes_is_sorted_by_time(tmp_path):
    d = tmp_path / "crashes"
    d.mkdir()
    for t in (5000, 1000, 3000):
        (d / f"id:00000{t},sig:06,time:{t},execs:1").write_bytes(b"x")
    times = [c["timestamp_s"] for c in collect_crashes(d)]
    assert times == sorted(times)


def test_collect_crashes_on_missing_dir_is_empty(tmp_path):
    assert collect_crashes(tmp_path / "nope") == []


# --- Regression tests built from a REAL afl-fuzz v5.02c run on libxml2 --------
#
# Captured 2026-07-31: 120s campaign, run_time=120, max queue time:=119719.
# That ratio is the proof that time: is milliseconds -- the single assumption
# every TTB number in the study rests on.

REAL_FUZZER_STATS = """start_time        : 1785495385
last_update       : 1785495505
run_time          : 120
execs_done        : 852047
execs_per_sec     : 7097.02
corpus_count      : 1986
saved_crashes     : 0
edges_found       : 2826
command_line      : /out/afl-fuzz -V 120 -m none -i /tmp/in -o /aflout
"""

# NOTE: 15 columns. AFL++ v5.02c appends total_crashes and servers_count beyond
# the 13 columns older releases documented -- which is exactly why parse_plot_data
# keys off the header instead of fixed positions.
REAL_PLOT_DATA = """# relative_time, cycles_done, cur_item, corpus_count, pending_total, pending_favs, map_size, saved_crashes, saved_hangs, max_depth, execs_per_sec, total_execs, edges_found, total_crashes, servers_count
10, 0, 180, 512, 400, 12, 2.10%, 0, 0, 5, 6900.10, 70000, 1200, 0, 0
120, 0, 1956, 1986, 1634, 31, 5.30%, 0, 0, 11, 5400.95, 852047, 2826, 0, 0
"""


def test_time_field_is_milliseconds_against_a_real_run():
    """119719 ms over a run_time of 120 s. If time: were seconds this would be
    119719 s -- a thousand-fold TTB error in every reported result."""
    stats = parse_fuzzer_stats(REAL_FUZZER_STATS)
    max_queue_time = crash_time_secs("id:001985,src:000010,time:119719,execs:850000")
    assert max_queue_time <= stats["run_time"] + 1


def test_parses_the_real_fifteen_column_plot_data():
    rows = parse_plot_data(REAL_PLOT_DATA)
    assert len(rows) == 2
    assert len(rows[0]) == 15
    assert rows[-1]["edges_found"] == 2826
    assert rows[-1]["total_execs"] == 852047
    assert rows[-1]["total_crashes"] == 0
    assert rows[-1]["map_size"] == pytest.approx(5.30)   # '%' stripped


def test_parses_the_real_fuzzer_stats():
    s = parse_fuzzer_stats(REAL_FUZZER_STATS)
    assert s["run_time"] == 120
    assert s["execs_done"] == 852047
    assert s["execs_per_sec"] == pytest.approx(7097.02)
    assert isinstance(s["command_line"], str)
