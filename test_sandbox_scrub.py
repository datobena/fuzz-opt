"""Tests for sandbox/scrub.py — build output filtering before it reaches the agent."""
from sandbox.scrub import WITHHELD, scrub

ASAN_TRACE = """==10==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f8f
WRITE of size 37 at 0x7f8fb45c5c08 thread T0
SCARINESS: 60 (multi-byte-write-stack-buffer-overflow)
    #0 0x48ac56 in strcat asan_interceptors.cpp:378:7
    #1 0x64b872 in xmlSnprintfElementContent /src/libxml2/valid.c:1279:3
SUMMARY: AddressSanitizer: stack-buffer-overflow /src/libxml2/valid.c:1279:3 in xmlSnprintf
"""


def test_keeps_compiler_errors():
    log = "valid.c:120:5: error: use of undeclared identifier 'foo'\n"
    assert "use of undeclared identifier" in scrub(log)


def test_keeps_linker_errors():
    log = "/usr/bin/ld: xzlib.o: undefined reference to `inflate'\n"
    assert "undefined reference" in scrub(log)


def test_drops_sanitizer_frames_naming_the_bug():
    out = scrub(ASAN_TRACE)
    for leak in ("xmlSnprintfElementContent", "valid.c", "stack-buffer-overflow",
                 "SCARINESS", "SUMMARY"):
        assert leak not in out, f"{leak!r} leaked the bug location"


def test_fails_closed_when_a_trace_rides_along_with_compiler_output():
    """A trace mixed into an otherwise-normal build log must withhold everything."""
    log = "valid.c:120:5: error: something\n" + ASAN_TRACE
    assert scrub(log) == WITHHELD


def test_empty_log_is_empty():
    assert scrub("") == ""


def test_drops_stack_frames_even_without_a_summary_line():
    """A truncated trace has no SUMMARY, but its frames still name the bug."""
    log = (
        "    #1 0x64b872 in xmlSnprintfElementContent /src/libxml2/valid.c:1279:3\n"
        "    #2 0x64b899 in xmlSnprintfElementContent /src/libxml2/valid.c\n"
    )
    assert "xmlSnprintfElementContent" not in scrub(log)


def test_drops_the_crashing_input_path():
    """Artifact paths let the agent fetch and replay the crashing input."""
    log = "Test unit written to /crashes/crash-da39a3ee5e6b4b0d3255bfef95601890\n"
    assert "crash-" not in scrub(log)


def test_a_normal_ossfuzz_build_log_is_not_withheld():
    """Every OSS-Fuzz build echoes -fsanitize=address; that must not trip the
    fail-closed path, or the optimizer never sees a compiler error again."""
    log = (
        "CFLAGS=-O1 -fno-omit-frame-pointer -fsanitize=address "
        "-fsanitize-address-use-after-scope\n"
        "SANITIZER_FLAGS_address=-fsanitize=address\n"
        "valid.c:120:5: error: use of undeclared identifier 'foo'\n"
    )
    out = scrub(log)
    assert out != WITHHELD, "a clean build log must not be withheld"
    assert "use of undeclared identifier" in out


def test_ubsan_runtime_error_is_withheld():
    log = "/src/libxml2/valid.c:1279:3: runtime error: signed integer overflow\n"
    assert scrub(log) == WITHHELD


def test_make_bookkeeping_is_dropped_but_make_errors_survive():
    """On a real build, directory chatter buried the actual errors."""
    log = (
        "make[1]: Entering directory '/src/libxml2/include'\n"
        "make[2]: Leaving directory '/src/libxml2'\n"
        "make[4]: *** [Makefile:632: libxml.lo] Error 1\n"
    )
    out = scrub(log)
    assert "Entering directory" not in out
    assert "Leaving directory" not in out
    assert "Error 1" in out
