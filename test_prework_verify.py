"""Tests for prework/verify.py — AFL build command and PoC signature matching."""
from prework.verify import compile_command, signature_matches


def test_compile_command_selects_afl_and_asan():
    cmd = compile_command("bench-aflpp/libxml2-arvo-1972", "/tmp/out")
    joined = " ".join(cmd)
    assert "FUZZING_ENGINE=afl" in joined
    assert "SANITIZER=address" in joined
    assert "ARCHITECTURE=x86_64" in joined
    assert cmd[-1] == "compile", "must invoke OSS-Fuzz compile"
    # The `arvo` wrapper exports FUZZING_ENGINE=libfuzzer unconditionally, so it
    # must never be the command verb. Checked per-argument: the image tag
    # legitimately contains "arvo" (bench-aflpp/<project>-arvo-<id>).
    assert "arvo" not in cmd, "the arvo wrapper hardcodes FUZZING_ENGINE=libfuzzer"


def test_signature_matches_ignores_access_and_size_suffixes():
    assert signature_matches("stack-buffer-overflow", "Stack-buffer-overflow WRITE {*}")
    assert signature_matches("heap-buffer-overflow READ 8", "Heap-buffer-overflow READ 1")


def test_signature_mismatch_is_not_the_target_bug():
    """A fold can introduce a DIFFERENT crash; that is not the bug reproducing."""
    assert not signature_matches("heap-use-after-free", "Stack-buffer-overflow WRITE {*}")


def test_signature_matches_requires_a_detection():
    """No SUMMARY line means no sanitizer report -- never treat that as a repro."""
    assert not signature_matches("", "Stack-buffer-overflow WRITE {*}")


# --- classify_run: never let broken plumbing masquerade as "bug removed" -----
#
# The benchmark's headline result is a bug-SURVIVAL rate, so a target that
# failed to execute must never be scored the same as one that ran cleanly.
# aflpp_driver prints "Execution successful." after each input it runs, which is
# the positive proof-of-execution signal.

from prework.verify import classify_run


def test_crash_with_matching_signature_is_reproduced():
    blob = (
        "Reading 2889 bytes from /testcase\n"
        "==10==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f8f\n"
        "SUMMARY: AddressSanitizer: stack-buffer-overflow /src/libxml2/valid.c:1279:3 in xmlSnprintfElementContent\n"
    )
    assert classify_run(blob, 1, "Stack-buffer-overflow WRITE {*}") == "reproduced"


def test_clean_execution_without_a_crash_is_no_crash():
    """Ran to completion, did not crash -- the bug is genuinely gone."""
    blob = "Reading 2889 bytes from /testcase\nExecution successful.\n"
    assert classify_run(blob, 0, "Stack-buffer-overflow WRITE {*}") == "no_crash"


def test_loader_failure_is_did_not_run_not_no_crash():
    """The regression that produced a false 'dropped' verdict for libxml2."""
    blob = (
        "/out/libxml2_xml_read_memory_fuzzer: error while loading shared "
        "libraries: libc++.so.1: cannot open shared object file\n"
    )
    assert classify_run(blob, 127, "Stack-buffer-overflow WRITE {*}") == "did_not_run"


def test_empty_output_is_did_not_run():
    """No execution marker and no crash report proves nothing; refuse to guess."""
    assert classify_run("", 1, "Stack-buffer-overflow WRITE {*}") == "did_not_run"


def test_crash_with_a_different_signature_is_wrong_crash():
    """A different bug is not the target bug, and is not 'no crash' either."""
    blob = (
        "Reading 10 bytes from /testcase\n"
        "SUMMARY: AddressSanitizer: heap-use-after-free /src/p/foo.c:12:5 in bar\n"
    )
    assert classify_run(blob, 1, "Stack-buffer-overflow WRITE {*}") == "wrong_crash"


def test_signature_capture_is_not_polluted_by_a_relative_path():
    """A relative path in SUMMARY must not be absorbed into the bug class."""
    blob = (
        "Reading 5 bytes from /testcase\n"
        "SUMMARY: AddressSanitizer: stack-buffer-overflow valid.c:1279 in xmlSnprintf\n"
    )
    assert classify_run(blob, 1, "Stack-buffer-overflow WRITE {*}") == "reproduced"
