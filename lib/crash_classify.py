"""Canonical definition of "did this fuzzing trial find the TARGET bug?".

This module exists because the pipeline previously had NO single definition of a
bug find, so every analysis (the phase-3 summary, phase-4 TTB, ad-hoc recovery
scripts) re-invented it and silently miscounted. Two real incidents:

  * `phase3_runner` counted `has_crash = bool(crash_times)` — i.e. ANY artifact,
    including slow-units, timeouts, OOMs, and the end-of-run boundary artifact.
  * The `mut-8h` recovery counted pod-log `outcome=finding`, which the runner
    sets for crash | timeout | out-of-memory | leak alike.

Both massively over-count. A libFuzzer run drops several kinds of artifact into
the crashes dir, and only one of them means "the target bug reproduced":

  ┌────────────────┬───────────────┬──────────────────────────────────────────┐
  │ artifact prefix│ crash_type    │ is it the target bug?                      │
  ├────────────────┼───────────────┼──────────────────────────────────────────┤
  │ crash-<sha1>   │ "crash"       │ YES — a sanitizer/deadly-signal crash …    │
  │                │               │   …UNLESS it's the empty-input boundary    │
  │                │               │   artifact or occurs at the run cutoff     │
  │ slow-unit-<..> │ "unknown"     │ no — an input that ran too slow            │
  │ timeout-<..>   │ "timeout"     │ no — a per-unit timeout                    │
  │ oom-<..>       │ "oom"         │ no — out of memory                         │
  └────────────────┴───────────────┴──────────────────────────────────────────┘

The "boundary artifact" is a spurious `crash-` of the EMPTY input (sha1
da39a3ee…) written at t ≈ max_total_time as the run shuts down; it is not a real
find and must be excluded (libxml2's entire "10/10 crashes" were this).

Two tiers of classification:

  * `trial_found_bug` / `trial_time_to_bug` — CHEAP, metadata-only. Uses
    crash_type + timestamp + the empty-input exclusion. This is what the
    summaries and TTB use; it removes the slow-unit / timeout / OOM / boundary
    contamination. Use this everywhere by default.

  * `verify_crash_reproduces` — GOLD STANDARD. Replays a crash artifact on the
    target binary and confirms it actually crashes under the sanitizer, and
    (optionally) that the reported signature matches the manifest's expected
    crash type. This additionally catches (a) fold-induced FALSE-POSITIVE
    crashes that are not the target bug, and (b) NON-REPRODUCIBLE / flaky
    crashes (e.g. libavc's multithreaded decoder, where most recorded crashes
    don't replay). Run it when you need a fully trustworthy count.
"""
from __future__ import annotations

import os
import logging
import re
import tempfile
import shutil
import subprocess

# sha1("") — the empty input. libFuzzer writes crash-<this> at shutdown as a
# boundary artifact on some targets; it is never a real find.
EMPTY_INPUT_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

logger = logging.getLogger(__name__)

RUNNER_IMAGE = "gcr.io/oss-fuzz-base/base-runner"

# Exit codes that mean the TOOLING failed, not the target. 125 = docker usage
# error (bad -v spec, unknown flag); 126 = not executable; 127 = command or
# shared library not found.
_INFRA_EXIT_CODES = (125, 126, 127)

# Replay options. alloc_dealloc_mismatch is OFF because our rebuilt targets link
# libc++/libc++abi DYNAMICALLY while the upstream ARVO builds link them
# statically. Dynamically there are two copies of the exception-teardown code:
# libc++.so.1 allocates std::runtime_error's message with `operator new` and
# libc++abi.so.1 frees it with `free`, so ASan reports alloc-dealloc-mismatch on
# every caught C++ exception. It is a property of our linkage, not of the target
# -- verified on assimp, where disabling this single option reconciles our build
# with the upstream reference on 3042/3042 artifacts. OSS-Fuzz's own runner
# (/bin/arvo) disables it for the same reason.
ASAN_REPLAY_OPTIONS = "detect_leaks=0:alloc_dealloc_mismatch=0"

# A sanitizer abort that produced no SUMMARY line (truncated output, or a
# non-ASan abort such as an assertion). Distinguishes a real abort from a docker
# failure, which prints neither.
_SANITIZER_ABORT_RE = re.compile(
    r"ERROR: \w*Sanitizer|libFuzzer: deadly signal|AddressSanitizer:DEADLYSIGNAL")


# --------------------------------------------------------------------------- #
# Sanitizer report parsing: ASan AND UBSan
# --------------------------------------------------------------------------- #
# FuzzBench type:bug builds compile with ASan plus 16 UBSan checks under
# -fno-sanitize-recover, and fuzz/replay with UBSAN_OPTIONS print_stacktrace=0.
# A UBSan finding then prints NO "ERROR: ...Sanitizer:" line and NO stack, only
#
#   /src/mruby/src/vm.c:1234:9: runtime error: signed integer overflow: ...
#   SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/mruby/src/vm.c:1234:9 in
#
# and aborts (abort_on_error=1). Every analyser that keyed on "ERROR:
# AddressSanitizer" scored that as "did not crash". The UBSan identity below is
#
#   kind      "ubsan:<check>"   check derived from the runtime-error message
#   location  "<file>:<line>"   exactly as printed (column kept separately)
#   signature "ubsan:<check>:<file>:<line>"
#
# The location is compiled into the check itself, so it is present with
# symbolize=0 and print_stacktrace=0 and does not depend on llvm-symbolizer.
# It is stable for ONE binary. Caveat: an optimizer edit to the same file shifts
# line numbers, so the same UBSan bug can carry different lines on the two arms;
# cross-arm identity must come from replaying the artifact on the other arm's
# binary (cross_check_bugs), not from comparing these strings.
UBSAN_SUMMARY_RE = re.compile(
    r"SUMMARY: UndefinedBehaviorSanitizer: ([A-Za-z0-9_\-]+)(?:[ \t]+(\S+))?")
UBSAN_RUNTIME_ERROR_RE = re.compile(
    r"^(?P<file>[^\s:]+):(?P<line>\d+):(?P<col>\d+): runtime error: (?P<msg>[^\n]*)",
    re.M)
# Same line when UBSan had no source location ("<unknown>", or a module+offset).
_UBSAN_RUNTIME_ERROR_ANY_RE = re.compile(r"^(?P<where>\S*): runtime error: (?P<msg>[^\n]*)", re.M)
# "ERROR: <San>: <kind>". Kinds are lowercase classes (heap-buffer-overflow) OR
# upper-case deadly signals (SEGV, BUS, FPE, ILL, ABRT): "[a-z-]+" alone missed
# every "AddressSanitizer: SEGV on unknown address".
SANITIZER_ERROR_RE = re.compile(r"ERROR: (\w*Sanitizer): ([A-Za-z][A-Za-z0-9_\-]*)")
DEADLY_SIGNAL_KINDS = frozenset({"SEGV", "BUS", "FPE", "ILL", "ABRT", "TRAP"})

# runtime-error message -> UBSan check name (compiler-rt ubsan_handlers.cpp
# wording, LLVM 15-18). First match wins, so specific phrases come first.
_UBSAN_CHECKS = (
    ("pointer-overflow", re.compile(r"offset to null pointer|pointer index expression|"
                                    r"(addition|subtraction) of unsigned offset")),
    ("signed-integer-overflow", re.compile(r"^signed integer overflow|^negation of|"
                                           r"^division of .* by -1 cannot be represented")),
    ("unsigned-integer-overflow", re.compile(r"^unsigned integer overflow")),
    ("integer-divide-by-zero", re.compile(r"^division by zero|^remainder by zero")),
    ("shift-exponent", re.compile(r"^shift exponent")),
    ("shift-base", re.compile(r"^left shift of")),
    ("array-bounds", re.compile(r"^index .* out of bounds")),
    ("vptr", re.compile(r"which does not point to an object of type|"
                        r"^(downcast|upcast|cast to virtual base) of")),
    ("object-size", re.compile(r"insufficient space for an object")),
    ("alignment", re.compile(r"misaligned address|^assumption of .* alignment")),
    ("null", re.compile(r"null pointer")),
    ("bool", re.compile(r"not a valid value for type '(?:_Bool|bool)'")),
    ("enum", re.compile(r"not a valid value for type")),
    ("function", re.compile(r"through pointer to incorrect function type")),
    ("return", re.compile(r"end of a value-returning function")),
    ("unreachable", re.compile(r"unreachable program point|__builtin_unreachable")),
    ("vla-bound", re.compile(r"variable length array bound")),
    ("builtin", re.compile(r"^passing zero to (?:ctz|clz)|which is not a valid argument")),
    ("float-cast-overflow", re.compile(r"outside the range of representable values")),
    ("implicit-conversion", re.compile(r"^implicit conversion")),
)


def ubsan_check(message: str) -> str:
    """UBSan check name for one runtime-error message ('runtime error: ' stripped)."""
    msg = (message or "").strip()
    for name, rx in _UBSAN_CHECKS:
        if rx.search(msg):
            # returns-nonnull-attribute / nonnull-attribute share "null pointer"
            # wording with -fsanitize=null; separate them here.
            if name == "null" and "declared to never" in msg:
                return ("returns-nonnull-attribute" if "returned from function" in msg
                        else "nonnull-attribute")
            return name
    # Unknown wording: a stable slug of the message's leading words, digits and
    # quoted values removed, so different operand values map to one kind.
    words = re.sub(r"'[^']*'|\b0x[0-9a-f]+\b|-?\d+", " ", msg.lower())
    words = re.findall(r"[a-z]+", words)[:4]
    return "-".join(words) or "unknown"


def ubsan_identity(blob: str) -> dict | None:
    """Identity of the FIRST UBSan finding in a report, or None.

    Requires a "runtime error:" line. The SUMMARY line confirms it when present
    (print_summary defaults to 1). Fields: check, kind, file, line, col, message,
    location ("file:line") and signature ("ubsan:<check>:<file>:<line>").
    """
    if not blob:
        return None
    m = UBSAN_RUNTIME_ERROR_RE.search(blob)
    anyloc = None if m else _UBSAN_RUNTIME_ERROR_ANY_RE.search(blob)
    if anyloc:
        file, line, col = anyloc.group("where") or "?", None, None
        message = anyloc.group("msg").strip()
        check = ubsan_check(message)
    elif not m:
        s = UBSAN_SUMMARY_RE.search(blob)
        if not s:
            return None
        # SUMMARY without the runtime-error line (truncated log): location only.
        loc = s.group(2) or ""
        lm = re.match(r"(.+?):(\d+)(?::(\d+))?$", loc)
        file, line, col = (lm.group(1), int(lm.group(2)),
                           int(lm.group(3)) if lm.group(3) else None) if lm else (loc or "?", None, None)
        check, message = s.group(1), ""
    else:
        file, line, col = m.group("file"), int(m.group("line")), int(m.group("col"))
        message = m.group("msg").strip()
        check = ubsan_check(message)
    if file.startswith("./"):
        file = file[2:]
    location = f"{file}:{line}" if line is not None else file
    return {
        "sanitizer": "UndefinedBehaviorSanitizer",
        "check": check,
        "kind": f"ubsan:{check}",
        "file": file, "line": line, "col": col,
        "message": message,
        "location": location,
        "signature": f"ubsan:{check}:{location}",
    }


def is_abort_report(blob: str) -> bool:
    """True for an ASan "ABRT" deadly-signal report (assert/abort, not a bug).

    FuzzBench's UBSAN_OPTIONS carry handle_abort=2, and ASan reads the common
    flags from UBSAN_OPTIONS too, so every assert() / abort() now prints an
    ASan ABRT report. Before, it aborted silently. Asserts are not counted as
    bugs anywhere in triage, so callers treat this as "no sanitizer report".
    """
    ident = sanitizer_identity(blob or "")
    return bool(ident and ident.get("sanitizer") == "AddressSanitizer"
                and ident.get("kind") == "ABRT")


# "assertion failure in <file>(<line>)" -- non-glibc assert macros.
_ASSERT_PAREN_RE = re.compile(r"assert(?:ion)?[^\n]*?failure[^\n]*?in\s+(\S+?)\((\d+)\)", re.I)
# Greedy to the last "' failed." on the line: the expression itself may hold
# quotes (ZEND_ASSERT(*p == '&')), which a [^']* class could not cross.
_ASSERT_GLIBC_RE = re.compile(r"Assertion\s+`[^\n]*\'\s+failed\.", re.I)
# glibc's message: "<prog>: <file>:<line>: <func>: Assertion `...' failed."
_ASSERT_SITE_RE = re.compile(r"(\S+?):(\d+): [^\n]*?Assertion\s+`")


def assert_site(blob: str) -> str | None:
    """"<file>:<line>" of a failed assert(), "<libc-assert>" without a site, else None.

    The site is the identity of an assert crash: it has no sanitizer kind and,
    under handle_abort=2, its ASan ABRT stack starts in libc's abort path. The
    line moves when an optimizer edit touches the same file, so compare sites
    from replays on ONE binary (dedup_crashes keys on the baseline replay).
    """
    if not blob:
        return None
    m = _ASSERT_PAREN_RE.search(blob)
    if m:
        return f"{os.path.basename(m.group(1))}:{m.group(2)}"
    if _ASSERT_GLIBC_RE.search(blob):
        s = _ASSERT_SITE_RE.search(blob)
        return f"{os.path.basename(s.group(1))}:{s.group(2)}" if s else "<libc-assert>"
    return None


def assert_crash_site(blob: str) -> str | None:
    """assert_site(), but only when the run actually aborted.

    Every classification replay runs with handle_abort=2 (replay_sanitizer_env),
    so a real assert crash also prints an ASan ABRT report. Requiring it keeps
    assert-shaped text a target merely printed -- a logged, non-fatal check, an
    echoed input -- from reading as a crash.
    """
    return assert_site(blob) if is_abort_report(blob) else None


def sanitizer_identity(blob: str) -> dict | None:
    """The sanitizer finding a replay produced: ASan-family report or UBSan.

    An "ERROR: <San>:" report wins when both are present: it is always fatal,
    whereas a UBSan line before it could only come from a recoverable check.
    Returns {"sanitizer", "kind", ...} or None. For ERROR reports "kind" is the
    printed class ("heap-buffer-overflow", "SEGV"); for UBSan see ubsan_identity.
    """
    if not blob:
        return None
    e = SANITIZER_ERROR_RE.search(blob)
    if e:
        return {"sanitizer": e.group(1), "kind": e.group(2),
                "deadly_signal": e.group(2) in DEADLY_SIGNAL_KINDS}
    return ubsan_identity(blob)


def ubsan_signature_matches(ident: dict | None, expected: str | None) -> bool:
    """True iff an expected signature names this UBSan finding.

    Accepts the full signature, "ubsan:<check>", the bare check name, the
    location ("file:line"), or OSS-Fuzz's generic "undefined-behavior" label.
    """
    if not ident or not expected:
        return False
    e = expected.strip()
    el = e.lower()
    if el in ("undefined-behavior", "undefined behavior", "ubsan"):
        return True
    return e in (ident["signature"], ident["kind"], ident["location"]) or \
        normalize_signature(e) == normalize_signature(ident["check"])


def replay_sanitizer_env(asan_options: str, *, symbolize: bool = True,
                         ubsan_options: str | None = None) -> dict:
    """ASAN_OPTIONS/UBSAN_OPTIONS for a CLASSIFICATION replay.

    UBSAN_OPTIONS is config.REPLAY_UBSAN_OPTIONS (FuzzBench's set) so a UBSan
    finding aborts and reports exactly as it did under afl-fuzz. ``symbolize``
    appends symbolize=1 to it, because in ANY clang ASan binary -- ASan-only
    ARVO builds included -- the ASan runtime also parses UBSAN_OPTIONS for the
    common flags, and FuzzBench's symbolize=0 there silently strips the
    function names from every ASan frame (verified on base-builder clang 15:
    "#0 0x4d862a in heap_read ub.c:14" becomes "#0 0x4d862a (/w/ub+0x4d862a)").
    Every frame-keyed identity in this repo needs those names. The UBSan
    identity itself does not depend on symbolization.
    """
    if ubsan_options is None:
        try:
            import config  # noqa: PLC0415 - lib/ is importable without config
            ubsan_options = getattr(config, "REPLAY_UBSAN_OPTIONS", "") or ""
        except Exception:  # noqa: BLE001
            ubsan_options = ""
        if not ubsan_options:
            ubsan_options = ("abort_on_error=1:print_stacktrace=0:"
                             "symbolize=0:symbolize_inline_frames=0")
    if symbolize:
        ubsan_options = f"{ubsan_options}:symbolize=1" if ubsan_options else "symbolize=1"
    return {"ASAN_OPTIONS": asan_options, "UBSAN_OPTIONS": ubsan_options}


def docker_env_args(env: dict) -> list[str]:
    """["-e", "K=V", ...] for a docker run."""
    out: list[str] = []
    for k, v in env.items():
        out += ["-e", f"{k}={v}"]
    return out


# --------------------------------------------------------------------------- #
# Tier 1 — cheap, metadata-only classification (no docker, no binary)
# --------------------------------------------------------------------------- #
def is_target_bug_find(entry: dict, max_total_time: float | int | None = None) -> bool:
    """True iff one crash_times entry is a genuine target-bug crash.

    Excludes slow-units (crash_type "unknown"), timeouts, OOMs, the empty-input
    boundary artifact, and any crash at/after the run cutoff.

    `entry` is one element of a trial's crash_times list:
        {"timestamp_s": float, "artifact": "crash-<sha1>", "crash_type": "crash"}
    `max_total_time` is the trial's -max_total_time (seconds). When None, only
    the cutoff check is skipped; crash_type + empty-input exclusion still apply.
    """
    if not isinstance(entry, dict):
        return False
    if entry.get("crash_type") != "crash":            # only real sanitizer crashes
        return False
    artifact = entry.get("artifact") or ""
    if EMPTY_INPUT_SHA1 in artifact:                  # empty-input boundary artifact
        return False
    ts = entry.get("timestamp_s")
    if ts is None:
        return False
    if max_total_time is not None and float(ts) >= float(max_total_time):
        return False                                  # end-of-run boundary artifact
    return True


def trial_time_to_bug(
    crash_times: list | None, max_total_time: float | int | None = None
) -> float | None:
    """Earliest genuine target-bug crash time for a trial, or None if not found
    (i.e. the trial is censored at max_total_time)."""
    hits = [
        float(e["timestamp_s"])
        for e in (crash_times or [])
        if is_target_bug_find(e, max_total_time)
    ]
    return min(hits) if hits else None


def trial_found_bug(
    crash_times: list | None, max_total_time: float | int | None = None
) -> bool:
    """True iff the trial found the target bug (a real, non-boundary crash)."""
    return trial_time_to_bug(crash_times, max_total_time) is not None


def summarize_trials(
    results: list[dict],
    max_total_time: float | int | None = None,
    time_key: str = "crash_times",
    cutoff_key: str = "max_total_time",
) -> dict:
    """Aggregate a list of trial-result dicts into found/total + TTBs.

    Each result may carry its own cutoff under `cutoff_key`; otherwise the
    `max_total_time` argument is used. Returns {found, total, ttbs:[...]}.
    """
    found, ttbs = 0, []
    for r in results:
        cutoff = r.get(cutoff_key) if isinstance(r, dict) else None
        if cutoff is None:
            cutoff = max_total_time
        t = trial_time_to_bug(r.get(time_key), cutoff)
        if t is not None:
            found += 1
            ttbs.append(t)
    return {"found": found, "total": len(results), "ttbs": ttbs}


# --------------------------------------------------------------------------- #
# Tier 2 — gold-standard: replay the artifact and confirm it reproduces
# --------------------------------------------------------------------------- #
# Bug classes are lowercase-hyphenated single tokens ("stack-buffer-overflow").
# The character class deliberately EXCLUDES spaces: an ASAN SUMMARY reads
# "SUMMARY: <San>: <class> <path>:<line> in <func>", so allowing spaces swallows
# the location whenever the path is relative -- yielding "stack-buffer-overflow
# valid" and a silent signature MISMATCH, i.e. a real crash scored as "not the
# target bug". READ/WRITE and size suffixes live on the manifest side and are
# handled by normalize_signature.
_SUMMARY_RE = re.compile(r"SUMMARY:\s*\w*Sanitizer:\s*([a-zA-Z0-9_\-]+)")


def normalize_signature(sig: str) -> str:
    """Normalize an ASan signature / manifest crash_type for comparison.

    "Heap-use-after-free READ 8" and "heap-use-after-free" both -> a common core.
    Keeps only the leading bug-class tokens (drops READ/WRITE/size/{*}).
    """
    if not sig:
        return ""
    s = sig.lower().replace("_", "-").replace(" ", "-")
    s = re.sub(r"-(read|write|\d+|\{\*\}|\*).*$", "", s)  # drop access/size suffix
    return s.strip("-")


def verify_crash_reproduces(
    artifact_path: str,
    out_dir: str,
    fuzz_target: str,
    expected_signature: str | None = None,
    timeout: int = 120,
    image: str = RUNNER_IMAGE,
) -> tuple[bool, str]:
    """Replay one crash artifact on the target binary; confirm it really crashes.

    Returns (reproduced, detected_signature). `reproduced` is True only if the
    binary aborts under the sanitizer on this input AND — when
    `expected_signature` (e.g. the manifest crash_type) is given — the detected
    ASan bug-class matches it. This is the strongest "is it the target bug?"
    signal: it rejects fold-induced false positives and non-reproducible flakes.

    Requires docker, the built target in `out_dir`, and the artifact file.
    """
    if not (os.path.isfile(artifact_path) and os.path.isdir(out_dir)):
        return False, ""
    # Stage the artifact under a neutral name. AFL writes `id:000000,sig:06,...`
    # and archives crash dirs as `crashes.<ts>` with colons in the timestamp;
    # docker parses colons in a -v spec as field separators, so mounting either
    # the file OR its parent fails with "too many colons", exit 125 -- before the
    # container is even created. Mounting a clean temp dir is the only safe form.
    with tempfile.TemporaryDirectory(prefix="verifycrash-") as _tmp:
        staged = os.path.join(_tmp, "testcase")
        shutil.copyfile(artifact_path, staged)
        # UBSAN_OPTIONS travels as a docker -e (not an inline export): the
        # FuzzBench set contains no shell metacharacters, but -e needs no quoting.
        env = replay_sanitizer_env(ASAN_REPLAY_OPTIONS)
        cmd = [
            "docker", "run", "--rm", "--privileged",
            "-e", f"UBSAN_OPTIONS={env['UBSAN_OPTIONS']}",
            "-v", f"{os.path.abspath(out_dir)}:/out:ro",
            "-v", f"{_tmp}:/tc:ro",
            image, "/bin/bash", "-lc",
            f"export ASAN_OPTIONS={ASAN_REPLAY_OPTIONS}; /out/{fuzz_target} /tc/testcase",
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               errors="replace", timeout=timeout)
        except subprocess.TimeoutExpired:
            return False, "timeout"
    blob = (r.stdout or "") + (r.stderr or "")
    m = _SUMMARY_RE.search(blob)
    detected = m.group(1).strip() if m else ""
    ident = sanitizer_identity(blob)
    ubsan = ident if ident and ident.get("sanitizer") == "UndefinedBehaviorSanitizer" else None
    if ubsan:
        # SUMMARY says only "undefined-behavior" for every UBSan check; report
        # the stable identity instead (see ubsan_identity).
        detected = ubsan["signature"]
    # A non-zero exit is NOT evidence of a crash: this subprocess is `docker`,
    # not the target. Docker's own usage errors (125), a missing image (125/127),
    # and a binary that cannot load its shared libs (127 -- base-runner has no
    # libc++.so.1, which every rebuilt target needs) all exit non-zero without
    # ever running the input. Treating those as "reproduced" made this function
    # return True for ANY artifact, which is worse than returning nothing: it is
    # the gold-standard tier, so it silently rubber-stamped whatever it was fed.
    # Fail CLOSED -- require positive evidence the sanitizer fired.
    if r.returncode in _INFRA_EXIT_CODES and not detected:
        logger.warning(
            "verify_crash_reproduces: infrastructure failure (exit %s), not a crash: %s",
            r.returncode, blob.strip().splitlines()[0][:160] if blob.strip() else "no output")
        return False, ""
    crashed = bool(detected) or _SANITIZER_ABORT_RE.search(blob) is not None
    if is_abort_report(blob):
        crashed = False   # assert/abort, not a bug (see is_abort_report)
    if not crashed:
        return False, detected
    if expected_signature:
        if ubsan:
            return ubsan_signature_matches(ubsan, expected_signature), detected
        return normalize_signature(detected) == normalize_signature(expected_signature), detected
    return True, detected
