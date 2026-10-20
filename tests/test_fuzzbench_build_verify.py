"""prework/verify.py shares lib/crash_classify's ASan+UBSan parsing.

ASan verdicts (all ARVO results) must not move; UBSan findings from FuzzBench
bug builds get a real identity instead of the generic "undefined-behavior".
"""
from prework.verify import classify_run, matches_reference, report_identity

ASAN = """==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602 at pc 0x1
READ of size 4 at 0x602 thread T0
    #0 0x4d1 in __asan_memcpy
    #1 0x4d2 in parse_box /src/p/box.c:10:3
    #2 0x4d3 in read_file /src/p/file.c:20:5
    #3 0x4d4 in LLVMFuzzerTestOneInput /src/fuzz.c:5:1
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/p/box.c:10:3 in parse_box
"""
SEGV = """==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x4d2 in deref /src/p/a.c:3:1
    #1 0x4d3 in LLVMFuzzerTestOneInput /src/fuzz.c:5:1
SUMMARY: AddressSanitizer: SEGV /src/p/a.c:3:1 in deref
"""
UBSAN = """/src/mruby/src/vm.c:1234:9: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/mruby/src/vm.c:1234:9 in
"""


def test_asan_identity_and_verdicts_unchanged():
    assert report_identity(ASAN) == ("heap-buffer-overflow",
                                     ["parse_box", "read_file", "LLVMFuzzerTestOneInput"])
    assert classify_run(ASAN, 1, "Heap-buffer-overflow READ 4") == "poc_crash"
    assert classify_run(ASAN, 1, "stack-buffer-overflow") == "other_crash"
    assert classify_run(ASAN, 1, "x", reference=ASAN) == "poc_crash"


def test_uppercase_deadly_signal_kind_is_recognised():
    assert report_identity(SEGV) == ("SEGV", ["deref", "LLVMFuzzerTestOneInput"])
    assert matches_reference(SEGV, SEGV)[0]


def test_ubsan_gets_check_and_location_identity():
    kind, frames = report_identity(UBSAN)
    assert kind == "ubsan:signed-integer-overflow"
    assert frames == ["/src/mruby/src/vm.c:1234"]
    assert classify_run(UBSAN, 1, "signed-integer-overflow") == "poc_crash"
    assert classify_run(UBSAN, 1, "undefined-behavior") == "poc_crash"
    assert classify_run(UBSAN, 1, "ubsan:signed-integer-overflow:/src/mruby/src/vm.c:1234") \
        == "poc_crash"
    assert classify_run(UBSAN, 1, "integer-divide-by-zero") == "other_crash"
    other_line = UBSAN.replace("1234", "99")
    assert matches_reference(UBSAN, UBSAN)[0]
    assert not matches_reference(other_line, UBSAN)[0]


def test_asan_report_wins_over_a_ubsan_line():
    blob = UBSAN.replace("SUMMARY: UndefinedBehaviorSanitizer", "note") + ASAN
    assert report_identity(blob)[0] == "heap-buffer-overflow"
    assert classify_run(blob, 1, "heap-buffer-overflow") == "poc_crash"
