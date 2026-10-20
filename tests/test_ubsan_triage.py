"""UBSan-aware crash classification, against REAL sanitizer output.

Fixtures in tests/fixtures/sanitizer/ were captured from ub.c / as.c compiled
with base-builder clang 15 (gcr.io/oss-fuzz-base/base-builder@sha256:87ca1e9e...)
and FuzzBench's type:bug flags:

    clang -fsanitize=address -fsanitize=<16 UBSan checks>
          -fno-sanitize-recover=<same list> -O1 -gline-tables-only ub.c

  ubsan_signed_overflow_fuzzopts.txt   ./ub in_ubsan under config.FUZZ_UBSAN_OPTIONS
                                       (print_stacktrace=0, abort_on_error=1); rc 134
  ubsan_signed_overflow_stacktrace.txt same + print_stacktrace=1:symbolize=1
  asan_heap_overflow_fuzzopts.txt      ./ub in_asan under FUZZ_ASAN/UBSAN_OPTIONS
                                       (symbolize=0: no function names)
  asan_heap_overflow_classify.txt      ASAN_OPTIONS=detect_leaks=0:alloc_dealloc_mismatch=0
                                       UBSAN_OPTIONS=<FUZZ_UBSAN_OPTIONS>:symbolize=1
  assert_handle_abort.txt              as.c (-fsanitize=address) assert() under the
                                       classification env: handle_abort=2 makes the
                                       assert print an ASan ABRT report
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "analysis"))

import config  # noqa: E402
from lib import afl_triage, crash_classify, provenance  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "sanitizer"


def fx(name: str) -> str:
    return (FIX / name).read_text()


UBSAN = "ubsan_signed_overflow_fuzzopts.txt"
UBSAN_STACK = "ubsan_signed_overflow_stacktrace.txt"
ASAN = "asan_heap_overflow_classify.txt"
ASAN_NOSYM = "asan_heap_overflow_fuzzopts.txt"
ASSERT = "assert_handle_abort.txt"


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
def test_fixture_is_the_exact_fuzzbench_ubsan_report():
    assert fx(UBSAN) == (
        "ub.c:8:12: runtime error: signed integer overflow: 2147483646 + 6 "
        "cannot be represented in type 'int'\n"
        "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ub.c:8:12 in \n")
    # No ASan ERROR line and no stack: why the old analysers missed it.
    assert "ERROR:" not in fx(UBSAN) and "#0" not in fx(UBSAN)


@pytest.mark.parametrize("name", [UBSAN, UBSAN_STACK])
def test_ubsan_identity_is_check_plus_file_line(name):
    ident = crash_classify.ubsan_identity(fx(name))
    assert ident["check"] == "signed-integer-overflow"
    assert ident["kind"] == "ubsan:signed-integer-overflow"
    assert (ident["file"], ident["line"], ident["col"]) == ("ub.c", 8, 12)
    assert ident["location"] == "ub.c:8"
    # Same signature with and without a stack: it never depends on print_stacktrace.
    assert ident["signature"] == "ubsan:signed-integer-overflow:ub.c:8"


def test_ubsan_signature_ignores_operand_values():
    a = "x.c:3:5: runtime error: signed integer overflow: 1 + 2147483647 cannot be represented in type 'int'\n"
    b = "x.c:3:5: runtime error: signed integer overflow: 9 + 2147483645 cannot be represented in type 'int'\n"
    assert crash_classify.ubsan_identity(a)["signature"] == \
        crash_classify.ubsan_identity(b)["signature"]


# Verbatim messages captured from ub2.c with the same flags/options.
@pytest.mark.parametrize("line,check", [
    ("ub2.c:5:59: runtime error: shift exponent 40 is too large for 32-bit type 'int'", "shift-exponent"),
    ("ub2.c:6:59: runtime error: division by zero", "integer-divide-by-zero"),
    ("ub2.c:7:59: runtime error: member access within null pointer of type 'struct S'", "null"),
    ("ub2.c:8:74: runtime error: index 5 out of bounds for type 'int[4]'", "array-bounds"),
    ("ub2.c:9:97: runtime error: load of value 7, which is not a valid value for type 'bool'", "bool"),
    # compiler-rt wording for the rest of the FuzzBench list
    ("a.c:1:1: runtime error: left shift of negative value -1", "shift-base"),
    ("a.c:1:1: runtime error: load of value 9, which is not a valid value for type 'enum E'", "enum"),
    ("a.cc:1:1: runtime error: downcast of address 0x1 which does not point to an object of type 'B'", "vptr"),
    ("a.c:1:1: runtime error: execution reached an unreachable program point", "unreachable"),
    ("a.c:1:1: runtime error: null pointer returned from function declared to never return null", "returns-nonnull-attribute"),
    ("a.c:1:1: runtime error: variable length array bound evaluates to non-positive value 0", "vla-bound"),
    ("a.c:1:1: runtime error: passing zero to ctz(), which is not a valid argument", "builtin"),
    ("a.c:1:1: runtime error: applying zero offset to null pointer", "pointer-overflow"),
    ("a.c:1:1: runtime error: negation of -2147483648 cannot be represented in type 'int'", "signed-integer-overflow"),
])
def test_ubsan_check_names(line, check):
    assert crash_classify.ubsan_identity(line + "\n")["check"] == check


def test_asan_report_wins_and_is_not_ubsan():
    ident = crash_classify.sanitizer_identity(fx(ASAN))
    assert ident == {"sanitizer": "AddressSanitizer", "kind": "heap-buffer-overflow",
                     "deadly_signal": False}
    assert crash_classify.ubsan_identity(fx(ASAN)) is None


def test_deadly_signal_kinds_are_recognised():
    seg = "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000\n"
    assert crash_classify.sanitizer_identity(seg)["kind"] == "SEGV"


def test_ubsan_signature_matching():
    ident = crash_classify.ubsan_identity(fx(UBSAN))
    for exp in ("undefined-behavior", "signed-integer-overflow",
                "ubsan:signed-integer-overflow", "ub.c:8",
                "ubsan:signed-integer-overflow:ub.c:8"):
        assert crash_classify.ubsan_signature_matches(ident, exp), exp
    assert not crash_classify.ubsan_signature_matches(ident, "heap-buffer-overflow")
    assert not crash_classify.ubsan_signature_matches(ident, "")


# --------------------------------------------------------------------------- #
# replay environment
# --------------------------------------------------------------------------- #
def test_replay_env_uses_fuzzbench_ubsan_options_plus_symbolize():
    env = crash_classify.replay_sanitizer_env("detect_leaks=0")
    assert env["ASAN_OPTIONS"] == "detect_leaks=0"
    assert env["UBSAN_OPTIONS"].startswith(config.REPLAY_UBSAN_OPTIONS)
    # The LAST occurrence wins in sanitizer flag parsing.
    assert env["UBSAN_OPTIONS"].endswith(":symbolize=1")
    assert "print_stacktrace=0" in env["UBSAN_OPTIONS"]


def test_symbolize_override_is_needed_for_asan_frame_names():
    # Under FuzzBench's UBSAN_OPTIONS (symbolize=0) the ASan frames lose names.
    assert provenance.classify_replay_output(fx(ASAN_NOSYM), 134)["frame"] is None
    assert provenance.classify_replay_output(fx(ASAN), 134)["frame"] == "heap_read"


# --------------------------------------------------------------------------- #
# provenance.classify_artifact (-> time_to_first_sanitizer_crash_s)
# --------------------------------------------------------------------------- #
def test_classify_ubsan_is_sanitizer():
    assert provenance.classify_replay_output(fx(UBSAN), 134) == {
        "class": "sanitizer", "kind": "ubsan:signed-integer-overflow",
        "frame": "ub.c:8", "exit_code": 134}


def test_classify_ubsan_that_recovered_is_not_a_crash():
    assert provenance.classify_replay_output(fx(UBSAN), 0)["class"] == "nocrash"


def test_classify_asan_unchanged():
    assert provenance.classify_replay_output(fx(ASAN), 134) == {
        "class": "sanitizer", "kind": "heap-buffer-overflow",
        "frame": "heap_read", "exit_code": 134}


def test_classify_assert_under_handle_abort_stays_assert():
    assert provenance.classify_replay_output(fx(ASSERT), 134)["class"] == "assert"


def test_classify_plain_abort_is_abort_not_sanitizer():
    out = ("AddressSanitizer:DEADLYSIGNAL\n==1==ERROR: AddressSanitizer: ABRT on "
           "unknown address 0x1 (pc 0x2 bp 0x3 sp 0x4 T0)\n"
           "    #0 0x7f in raise (/lib/x86_64-linux-gnu/libc.so.6+0x4300b)\n"
           "    #1 0x7f in abort (/lib/x86_64-linux-gnu/libc.so.6+0x22859)\n"
           "    #2 0x4d in parse_thing /src/p/x.c:9:3\n")
    assert provenance.classify_replay_output(out, 134) == {
        "class": "abort", "kind": "ABRT", "frame": "parse_thing", "exit_code": 134}


def test_classify_artifact_passes_ubsan_options(monkeypatch, tmp_path):
    art = tmp_path / "id:000000,sig:06"
    art.write_bytes(b"U1")
    seen = {}

    def fake_run(cmd, timeout=60):
        seen["cmd"] = cmd
        # stdout, then bash's stderr notice for the abort (abort_on_error=1)
        return fx(UBSAN) + "__RC=134\nbash: line 1:     7 Aborted   timeout 65 /out/t /tc/tc\n", 0
    monkeypatch.setattr(provenance, "_run", fake_run)
    res = provenance.classify_artifact("fb-aflpp/x", tmp_path, "t", art, cpu=3,
                                       asan_options="detect_leaks=0:alloc_dealloc_mismatch=0")
    assert res["class"] == "sanitizer" and res["kind"] == "ubsan:signed-integer-overflow"
    assert res["exit_code"] == 134
    cmd = seen["cmd"]
    assert "ASAN_OPTIONS=detect_leaks=0:alloc_dealloc_mismatch=0" in cmd
    ub = [c for c in cmd if c.startswith("UBSAN_OPTIONS=")]
    assert ub == [f"UBSAN_OPTIONS={config.REPLAY_UBSAN_OPTIONS}:symbolize=1"]


# --------------------------------------------------------------------------- #
# lib/afl_triage and lib/crash_classify gold tier
# --------------------------------------------------------------------------- #
def test_afl_triage_ubsan_verdict():
    ctx = afl_triage._Ctx("img", "/out", "t", "undefined-behavior")
    assert afl_triage._verdict(fx(UBSAN), 0, ctx) == (
        "poc_crash", "ubsan:signed-integer-overflow:ub.c:8")
    ctx = afl_triage._Ctx("img", "/out", "t", "heap-buffer-overflow")
    assert afl_triage._verdict(fx(UBSAN), 0, ctx)[0] == "other_crash"


def test_afl_triage_asan_verdict_unchanged():
    ctx = afl_triage._Ctx("img", "/out", "t", "heap-buffer-overflow READ 1")
    assert afl_triage._verdict(fx(ASAN), 0, ctx) == ("poc_crash", "heap-buffer-overflow")


class _R:
    def __init__(self, out, rc=0):
        self.stdout, self.stderr, self.returncode = out, "", rc


def test_afl_triage_replay_passes_ubsan_options(monkeypatch, tmp_path):
    art = tmp_path / "a"
    art.write_bytes(b"x")
    seen = {}

    def fake(cmd, **kw):
        seen["cmd"] = cmd
        return _R(fx(UBSAN))
    monkeypatch.setattr(afl_triage.subprocess, "run", fake)
    ctx = afl_triage._Ctx("img", str(tmp_path), "t", "signed-integer-overflow")
    assert afl_triage._replay(ctx, art)[0] == "poc_crash"
    assert any(c.startswith("UBSAN_OPTIONS=") for c in seen["cmd"])


def test_verify_crash_reproduces_ubsan(monkeypatch, tmp_path):
    art = tmp_path / "a"
    art.write_bytes(b"x")
    seen = {}

    def fake(cmd, **kw):
        seen["cmd"] = cmd
        return _R(fx(UBSAN), 134)
    monkeypatch.setattr(crash_classify.subprocess, "run", fake)
    ok, sig = crash_classify.verify_crash_reproduces(str(art), str(tmp_path), "t")
    assert ok and sig == "ubsan:signed-integer-overflow:ub.c:8"
    ok, _ = crash_classify.verify_crash_reproduces(
        str(art), str(tmp_path), "t", expected_signature="heap-buffer-overflow")
    assert not ok
    assert any(c.startswith("UBSAN_OPTIONS=") for c in seen["cmd"])


# --------------------------------------------------------------------------- #
# analysis/ signatures
# --------------------------------------------------------------------------- #
def test_verify_crash_signatures_signature():
    import verify_crash_signatures as V
    assert V.signature(fx(UBSAN)) == "ubsan:signed-integer-overflow:ub.c:8"
    assert V.signature(fx(ASAN)) == "heap-buffer-overflow:heap_read"
    assert V.signature("==1==ERROR: AddressSanitizer: SEGV on unknown address 0x0\n"
                       "    #0 0x4d in cil_fill_ipaddr x.c:1\n") == "SEGV:cil_fill_ipaddr"
    # asserts are not signatures here (they were not before either)
    assert V.signature(fx(ASSERT)) is None


def test_verify_crash_signatures_replay_passes_ubsan_options(monkeypatch, tmp_path):
    import verify_crash_signatures as V
    art = tmp_path / "a"
    art.write_bytes(b"x")
    seen = {}

    def fake(cmd, **kw):
        seen["cmd"] = cmd
        return _R(fx(UBSAN), 0)
    monkeypatch.setattr(V.subprocess, "run", fake)
    assert V.replay("img", tmp_path, "t", art, 3) == fx(UBSAN)
    assert any(c.startswith("UBSAN_OPTIONS=") and c.endswith(":symbolize=1")
               for c in seen["cmd"])


def test_dedup_and_cross_check_identity():
    import cross_check_bugs
    import dedup_crashes
    assert dedup_crashes.report_identity(fx(UBSAN)) == (
        "ubsan:signed-integer-overflow", ["ub.c:8"])
    kind, frames = dedup_crashes.report_identity(fx(ASAN))
    assert (kind, frames[:2]) == ("heap-buffer-overflow", ["heap_read", "main"])
    assert dedup_crashes.abort_identity(fx(ASSERT)) == ("assert", ["as.c:3"])
    assert dedup_crashes.report_identity(fx(ASSERT)) == (None, [])
    assert cross_check_bugs.normalize("ubsan:signed-integer-overflow:ub.c:8") == \
        "ubsan:signed-integer-overflow:ub.c:8"


def test_bug_discovery_curve_identity():
    import bug_discovery_curve as B
    assert B._identity(fx(UBSAN)) == "ubsan:signed-integer-overflow:ub.c:8"
    assert B._identity(fx(ASAN)) == "heap-use-after-free:heap_read"   # existing alias
    assert B._identity(fx(ASSERT)) is None


def test_assert_abort_is_not_a_crash(monkeypatch, tmp_path):
    """handle_abort=2 makes assert() print an ASan ABRT report; asserts stay non-bugs."""
    from prework import verify
    art = tmp_path / "a"
    art.write_bytes(b"x")
    monkeypatch.setattr(crash_classify.subprocess, "run",
                        lambda cmd, **kw: _R(fx(ASSERT), 134))
    ok, _ = crash_classify.verify_crash_reproduces(str(art), str(tmp_path), "t")
    assert not ok
    assert verify.classify_run(fx(ASSERT), 134, "heap-buffer-overflow") not in (
        "poc_crash", "other_crash")
    monkeypatch.setattr(afl_triage.subprocess, "run", lambda cmd, **kw: _R(fx(ASSERT), 134))
    ctx = afl_triage._Ctx("img", str(tmp_path), "t", "heap-buffer-overflow")
    assert afl_triage._replay(ctx, art)[0] not in ("poc_crash", "other_crash")
