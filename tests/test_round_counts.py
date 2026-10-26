"""Round counts in the analysis scripts.

A round that only waited for a container an earlier session could not remove
(outcome agent-not-removed-wait) ran nothing: it is never an attempt, and is
shown apart. The round that left the container (agent-not-removed) ran its
agent and is one. analyze_c1 used to read a fixed range of iterations.
"""
from __future__ import annotations

import ast
import json
import os
import re
import sys
from pathlib import Path

import phase3_online

ANALYSIS = Path(__file__).resolve().parent.parent / "analysis"
sys.path.insert(0, str(ANALYSIS))
import plot_bug_campaign_summary as summary  # noqa: E402


def _analyze_c1_helpers() -> dict:
    """round_provenances and WAIT_OUTCOME from analyze_c1, which runs its whole
    analysis at import and so cannot be imported here."""
    tree = ast.parse((ANALYSIS / "analyze_c1.py").read_text())
    keep = [n for n in tree.body
            if (isinstance(n, ast.FunctionDef) and n.name == "round_provenances")
            or (isinstance(n, ast.Assign)
                and any(getattr(t, "id", "") == "WAIT_OUTCOME" for t in n.targets))]
    ns = {"json": json, "os": os, "re": re}
    exec(compile(ast.Module(body=keep, type_ignores=[]), "analyze_c1", "exec"), ns)
    return ns


def test_every_script_names_the_waiting_outcome_the_loop_writes():
    assert summary.WAIT_OUTCOME == phase3_online.AGENT_NOT_REMOVED_WAIT_OUTCOME
    assert _analyze_c1_helpers()["WAIT_OUTCOME"] == phase3_online.AGENT_NOT_REMOVED_WAIT_OUTCOME


def test_summary_counts_waiting_rounds_apart():
    rr = [{"outcome": o} for o in ("kept", "rejected", "agent-not-removed",
                                   "agent-not-removed-wait", "agent-not-removed-wait",
                                   "kept")]
    assert summary.round_counts(rr) == {
        "rounds_attempted": 4, "rounds_kept": 2,
        "rounds_by_outcome": {"agent-not-removed": 1, "kept": 2, "rejected": 1},
        "rounds_waiting_for_orphans": 2}
    assert "rounds_waiting_for_orphans" not in summary.round_counts(rr[:3])


def test_analyze_c1_reads_the_rounds_that_exist(tmp_path):
    for it, outcome in ((0, "baseline"), (1, "kept"), (3, "rejected"), (12, "kept"),
                        (14, "agent-not-removed-wait")):
        d = tmp_path / f"iter_{it:02d}"
        d.mkdir()
        (d / "round_provenance.json").write_text(json.dumps({"outcome": outcome}))
    (tmp_path / "iter_05").mkdir()                   # unfinished: no provenance
    (tmp_path / "iter_x").mkdir()
    got = _analyze_c1_helpers()["round_provenances"](str(tmp_path))
    # iter_12 is past the old fixed range(1, 12); iter_00 is the baseline copy.
    assert [it for it, _ in got] == [1, 3, 12, 14]
    assert _analyze_c1_helpers()["round_provenances"](str(tmp_path / "none")) == []
