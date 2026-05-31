import warnings

from lib import stats_util


def test_plot_time_to_bug_boxplot_emits_no_ticklabel_warning(tmp_path):
    output_path = tmp_path / "time_to_bug_boxplot.png"

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        stats_util.plot_time_to_bug_boxplot(
            optimized=[3600.0, 5400.0, 7200.0],
            baseline=[7200.0, 9000.0, 10800.0],
            title="Time to Bug",
            output_path=str(output_path),
            duration_secs=14400,
        )

    assert output_path.exists()
    assert not [w for w in caught if "set_ticklabels()" in str(w.message)]
