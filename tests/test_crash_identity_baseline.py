"""Bug identity keyed on the baseline replay, and the per-trial cross-check.

php's assert at zend_compile.c:9852 reports 9855/9857 on folded binaries whose
agent edited that file; keyed on the live binary that split one bug into three.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "analysis"))

from lib import crash_classify  # noqa: E402


def _assert_out(line: int) -> str:
    return (f"php-fuzz-parser: /src/php-src/Zend/zend_compile.c:{line}: "
            "void zend_compile_const_expr_magic_const(zend_ast **): "
            "Assertion `CG(active_class_entry)' failed.\n"
            "==1==ERROR: AddressSanitizer: ABRT on unknown address 0x1\n"
            "    #0 0x7f in raise (/lib/x86_64-linux-gnu/libc.so.6+0x4300b)\n")


ASAN_OUT = ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
            "    #0 0x5 in fold_copy /src/a.c:3\n"
            "    #1 0x6 in parse_thing /src/a.c:9\n")


def test_assert_site():
    assert crash_classify.assert_site(_assert_out(9857)) == "zend_compile.c:9857"
    assert crash_classify.assert_site("x: Assertion `a' failed.") == "<libc-assert>"
    assert crash_classify.assert_site(ASAN_OUT) is None
    assert crash_classify.assert_site("") is None


def _fake_replay(outputs):
    """V.replay stand-in: output chosen by the bin dir's name."""
    def replay(image, bin_dir, target, testcase, cpu, timeout=90):
        return outputs[Path(bin_dir).name]
    return replay


def test_dedup_keys_on_baseline_replay(monkeypatch, tmp_path):
    import dedup_crashes as D
    art = tmp_path / "id:000000,sig:06"
    art.write_bytes(b"<?php")
    (tmp_path / "own").mkdir()
    (tmp_path / "base").mkdir()
    monkeypatch.setattr(D.V, "replay", _fake_replay(
        {"own": _assert_out(9857), "base": _assert_out(9852)}))
    r = D.one(("optimized", "trial_08", str(art), 10, "img", "t",
               str(tmp_path / "own"), str(tmp_path / "base"), 1, 1))
    assert r[5:] == ("assert", ["zend_compile.c:9852"], "assert", ["zend_compile.c:9857"])


def test_dedup_crash_only_on_folded_binary_is_introduced(monkeypatch, tmp_path):
    import dedup_crashes as D
    art = tmp_path / "a"
    art.write_bytes(b"x")
    (tmp_path / "own").mkdir()
    (tmp_path / "base").mkdir()
    monkeypatch.setattr(D.V, "replay", _fake_replay({"own": ASAN_OUT, "base": ""}))
    r = D.one(("optimized", "trial_01", str(art), 10, "img", "t",
               str(tmp_path / "own"), str(tmp_path / "base"), 1, 2))
    assert r[5] is None and r[7] == "heap-buffer-overflow"
    # fold_ frames are the optimizer's own; the nearest real frame is the key.
    assert r[8][:1] == ["parse_thing"]


def test_dedup_non_reproducer_skips_baseline(monkeypatch, tmp_path):
    import dedup_crashes as D
    art = tmp_path / "a"
    art.write_bytes(b"x")
    calls = []

    def replay(image, bin_dir, target, testcase, cpu, timeout=90):
        calls.append(Path(bin_dir).name)
        return ""
    monkeypatch.setattr(D.V, "replay", replay)
    r = D.one(("optimized", "trial_01", str(art), 10, "img", "t",
               str(tmp_path / "own"), str(tmp_path / "base"), 1, 2))
    assert r[5] is None and r[7] is None
    assert calls == ["own", "own"]


def test_cross_check_identifies_asserts(monkeypatch, tmp_path):
    import cross_check_bugs as X
    monkeypatch.setattr(X.V, "replay", lambda *a, **k: _assert_out(9852))
    assert X.crashes("img", tmp_path, "t", tmp_path / "a", 1, 1) == "assert:zend_compile.c:9852"


def test_deployed_binaries_per_trial(tmp_path):
    import cross_check_bugs as X
    online = tmp_path / "online"
    rows = [{"iter": 1, "ts": 1, "trial_id": 0}, {"iter": 2, "ts": 2, "trial_id": 1},
            {"iter": 3, "ts": 3, "trial_id": 0}]
    for t in ("trial_00", "trial_01"):
        d = online / "trials" / t
        d.mkdir(parents=True)
        (d / "swap_timeline.json").write_text(json.dumps(rows))
        for it in range(4):
            b = d / f"iter_{it:02d}" / "bin"
            b.mkdir(parents=True)
            if it != 3:                     # trial_00's iter_03 left empty
                (b / "fuzzer").write_text("x")
    got = [lab for _, lab in X.deployed_binaries(online)]
    # only each trial's own swaps; iter_00 (baseline copy) and empty bins left out
    assert got == ["trial_00/iter_01", "trial_01/iter_02"]


def test_deployed_binaries_legacy_layout(tmp_path):
    import cross_check_bugs as X
    online = tmp_path / "online"
    online.mkdir()
    (online / "swap_timeline.json").write_text(json.dumps(
        [{"iter": 1, "per_trial": {"0": 1}}, {"iter": 2, "per_trial": {}}]))
    for it in (1, 2):
        b = online / f"iter_{it:02d}" / "bin"
        b.mkdir(parents=True)
        (b / "fuzzer").write_text("x")
    assert [lab for _, lab in X.deployed_binaries(online)] == ["iter_01"]


def test_assert_site_expression_with_quotes():
    out = _assert_out(9852).replace("CG(active_class_entry)", "*p == '&'")
    assert crash_classify.assert_site(out) == "zend_compile.c:9852"


def test_assert_text_without_abort_is_not_a_crash():
    printed = "log: a.c:3: f: Assertion `x' failed.\n"   # no ASan ABRT report
    assert crash_classify.assert_site(printed) == "a.c:3"
    assert crash_classify.assert_crash_site(printed) is None
    assert crash_classify.assert_crash_site(_assert_out(5)) == "zend_compile.c:5"


def _seq_replay(script):
    """V.replay stand-in: per bin dir name, pop outputs in order (last repeats)."""
    def replay(image, bin_dir, target, testcase, cpu, timeout=90):
        q = script[Path(bin_dir).name]
        return q.pop(0) if len(q) > 1 else q[0]
    return replay


def test_confirm_gap_verdicts(monkeypatch, tmp_path):
    import cross_check_bugs as X
    for name, script, want in (
            ("gap", {"hit": [ASAN_OUT], "miss": [""]}, "gap"),
            ("both", {"hit": [ASAN_OUT], "miss": ["", "", ASAN_OUT]}, "both"),
            ("flaky", {"hit": [""], "miss": [""]}, "flaky")):
        monkeypatch.setattr(X.V, "replay", _seq_replay(script))
        assert X.confirm_gap("img", "t", tmp_path / "a", tmp_path / "hit",
                             tmp_path / "miss", 1, 1) == want, name


def test_dedup_flaky_artifact_is_not_introduced(monkeypatch, tmp_path):
    import dedup_crashes as D
    art = tmp_path / "a"
    art.write_bytes(b"x")
    # crashes once on its own binary, then never again on either
    monkeypatch.setattr(D.V, "replay", _seq_replay({"own": [ASAN_OUT, ""], "base": [""]}))
    r = D.one(("optimized", "trial_01", str(art), 10, "img", "t",
               str(tmp_path / "own"), str(tmp_path / "base"), 1, 1))
    assert r[5] is None and r[7] is None


def test_line_moved_only():
    import cross_check_bugs as X
    assert X.line_moved_only("assert:zend_compile.c:9857", "assert:zend_compile.c:9852")
    assert not X.line_moved_only("assert:zend_compile.c:1200", "assert:zend_compile.c:9852")
    assert not X.line_moved_only("assert:a.c:3", "assert:b.c:3")
    assert not X.line_moved_only("heap-buffer-overflow:f", "heap-buffer-overflow:f")


def test_split_signature():
    import dedup_crashes as D
    assert D.split_signature("assert:zend_compile.c:9852") == ("assert", ["zend_compile.c:9852"])
    assert D.split_signature("ubsan:null:/src/Zend/zend_ast.c:697") == (
        "ubsan:null", ["/src/Zend/zend_ast.c:697"])
    assert D.split_signature("SEGV") == ("SEGV", [])


def test_dedup_flaky_baseline_keys_on_baseline_signature(monkeypatch, tmp_path):
    import dedup_crashes as D
    art = tmp_path / "a"
    art.write_bytes(b"x")
    # baseline misses the first identify (1 try) then crashes once in confirm_gap,
    # then misses the re-identify: key must still be the BASELINE line.
    monkeypatch.setattr(D.V, "replay", _seq_replay(
        {"own": [_assert_out(9857)], "base": ["", _assert_out(9852), ""]}))
    r = D.one(("optimized", "trial_08", str(art), 10, "img", "t",
               str(tmp_path / "own"), str(tmp_path / "base"), 1, 1))
    assert r[5:7] == ("assert", ["zend_compile.c:9852"])
