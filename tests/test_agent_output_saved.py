"""Every optimizer round must leave a record of what the agent did.

A round that tries ten folds and reverts all ten produces an empty diff, and the
attempt ledger derives its function list from that diff -- so the round left no
trace at all. Four consecutive wolfssl rounds reported "No changes made" with
nothing on disk explaining why.
"""
from __future__ import annotations

import phase2_setup as ps


def _result(**kw):
    base = {"ok": True, "stdout": "tried fold A, reverted: 0.4% < 2%",
            "stderr": "", "timed_out": False}
    base.update(kw)
    return base


def test_output_is_written(tmp_path):
    ps._save_agent_session_output(str(tmp_path), 0, _result())
    f = tmp_path / "agent_attempt_0.txt"
    assert f.is_file()
    body = f.read_text()
    assert "tried fold A" in body
    assert "[ok] True" in body


def test_stderr_and_flags_are_captured(tmp_path):
    ps._save_agent_session_output(
        str(tmp_path), 2, _result(ok=False, timed_out=True, stderr="401 revoked"))
    body = (tmp_path / "agent_attempt_2.txt").read_text()
    assert "401 revoked" in body
    assert "[timed_out] True" in body


def test_a_harness_note_is_recorded(tmp_path):
    """So "no changes" is distinguishable from "never ran" months later."""
    ps._save_agent_session_output(str(tmp_path), 0, _result(), note="NO source changes")
    assert "NO source changes" in (tmp_path / "agent_attempt_0.txt").read_text()


def test_attempts_do_not_overwrite_each_other(tmp_path):
    ps._save_agent_session_output(str(tmp_path), 0, _result(stdout="first"))
    ps._save_agent_session_output(str(tmp_path), 1, _result(stdout="second"))
    assert "first" in (tmp_path / "agent_attempt_0.txt").read_text()
    assert "second" in (tmp_path / "agent_attempt_1.txt").read_text()


def test_an_unwritable_directory_does_not_kill_the_round(tmp_path):
    """Diagnostics must never be able to fail the optimization itself."""
    blocker = tmp_path / "file"
    blocker.write_text("x")
    ps._save_agent_session_output(str(blocker / "sub"), 0, _result())   # no raise
