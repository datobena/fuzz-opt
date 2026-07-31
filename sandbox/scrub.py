"""Filter build output before it reaches the sandboxed optimizer.

The agent needs compiler diagnostics to fix its own broken edits, but must never
see a sanitizer report -- an ASAN trace names the bug's file, line, and function
outright (leak inventory items 1 and 11 in
docs/superpowers/specs/2026-07-30-aflpp-migration-sandboxed-optimizer-design.md).

Implemented as a WHITELIST, not a blocklist: only lines positively recognized as
compiler/linker diagnostics survive. Sanitizer frames ("#1 0x... in func file.c")
never match that shape, so a report format we have not seen before cannot leak by
going unrecognized. A blocklist would fail the other way -- silently, and in the
direction that destroys the experiment.
"""
from __future__ import annotations

import re

WITHHELD = "<build output withheld>"

COMPILER_DIAG_RE = re.compile(
    # file:line[:col]: error|warning|note:
    r"^\s*\S+:\d+:(?:\d+:)?\s+(?:fatal\s+)?(?:error|warning|note):"
    # tool-prefixed diagnostics
    r"|^\s*(?:clang|clang\+\+|gcc|g\+\+|ld|ar|make|configure|collect2)"
    r"(?:\[\d+\])?:\s"
    # link failures
    r"|undefined reference to"
    # Generic error/fatal lines. Build systems emit plenty of real failures that
    # match no file:line: shape ("fatal build error", "Error 1"), and dropping
    # them leaves the agent unable to fix a break it caused. This is safe only
    # because REPORT_RE runs FIRST on the raw log: if any sanitizer report is
    # present, the whole log is withheld before this pattern is ever consulted.
    r"|(?i:\berror\b|\bfatal\b|\bcannot find\b|\bno such file\b)"
)

# Structural markers of an actual sanitizer/fuzzer REPORT, checked against the
# RAW log. If a report happened at all, withhold everything -- even the compiler
# diagnostics, because "your edit produced a crash in this build" is itself a
# signal the agent could bisect against to localize the bug.
#
# Matched on structure, not on the word "sanitizer": every OSS-Fuzz build echoes
# `-fsanitize=address` and `SANITIZER_FLAGS_*` in its CFLAGS, so a substring
# check would withhold on every successful build and starve the optimizer.
REPORT_RE = re.compile(
    r"==\d+==\s*ERROR:\s*\w*Sanitizer"      # ==10==ERROR: AddressSanitizer: ...
    r"|SUMMARY:\s*\w*Sanitizer"             # SUMMARY: AddressSanitizer: ...
    r"|^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s"    # stack frame: "#1 0x64b872 in func"
    r"|DEDUP_TOKEN"
    r"|SCARINESS"
    r"|ERROR:\s*libFuzzer"
    r"|Test unit written to"
    r"|runtime error:",                     # UBSan
    re.MULTILINE,
)

# Second layer, applied after filtering, in case a report line is ever shaped
# like a compiler diagnostic.
SANITIZER_MARKERS = (
    "Sanitizer:", "SUMMARY:", "DEDUP_TOKEN", "SCARINESS",
    "ERROR: libFuzzer", "Test unit written to",
)


# Tool-prefixed bookkeeping that matches COMPILER_DIAG_RE but carries no
# diagnostic value. On a real libxml2 build these were 90% of what survived,
# burying the actual errors the agent needs to act on.
NOISE_RE = re.compile(
    r"Entering directory|Leaving directory|Nothing to be done"
    r"|creating \./config\.status|is up to date"
)


def scrub(log: str) -> str:
    """Return only compiler/linker diagnostics; withhold all output if unsure."""
    if not log:
        return ""
    if REPORT_RE.search(log):
        return WITHHELD
    kept = [
        ln for ln in log.splitlines()
        if COMPILER_DIAG_RE.search(ln) and not NOISE_RE.search(ln)
    ]
    joined = "\n".join(kept)
    if any(m in joined for m in SANITIZER_MARKERS):
        return WITHHELD
    return joined
