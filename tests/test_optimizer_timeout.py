"""The optimizer session runs to completion unless a positive cap is set.

A cap is destructive here: the diff is only written once the agent RETURNS, so
killing it discards the entire round including folds it had already built,
smoked and validated. Overrunning the swap interval is harmless by comparison --
run_optimizer_loop waits the interval BETWEEN rounds, so the next round simply
starts later and profiles whatever mutations have accumulated by then.
"""
from __future__ import annotations

import importlib

import config
import phase2_setup


def _with_env(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("PHASE2_OPTIMIZER_TIMEOUT_SECS", raising=False)
    else:
        monkeypatch.setenv("PHASE2_OPTIMIZER_TIMEOUT_SECS", value)
    importlib.reload(config)
    importlib.reload(phase2_setup)
    return phase2_setup._optimizer_timeout()


def test_zero_means_no_cap(monkeypatch):
    assert _with_env(monkeypatch, "0") is None


def test_negative_means_no_cap(monkeypatch):
    assert _with_env(monkeypatch, "-1") is None


def test_a_positive_value_is_honoured(monkeypatch):
    assert _with_env(monkeypatch, "5400") == 5400


def test_an_empty_value_falls_back_instead_of_crashing_at_import(monkeypatch):
    """`FOO= python3 ...` sets an empty string, not an unset variable. A bare
    int() on that raises at config-import time, before any logging exists."""
    assert _with_env(monkeypatch, "") == 18000


def test_garbage_falls_back_instead_of_crashing(monkeypatch):
    assert _with_env(monkeypatch, "abc") == 18000


def test_unset_uses_the_default(monkeypatch):
    assert _with_env(monkeypatch, None) == 18000


def test_the_prompt_carries_no_deadline(monkeypatch):
    """The agent is not told to stop early; it works until it is done."""
    _with_env(monkeypatch, None)
    p = phase2_setup._make_apply_fuzz_source_folds_prompt_with_mode(
        "h.c", use_wrapper_validation=True, backend="claude")
    for word in ("TIME BUDGET", "deadline", "hard-killed"):
        assert word not in p
