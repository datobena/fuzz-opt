"""Build a prework image's target and check the ARVO bug still reproduces.

This is the migration's decision gate. The bugs are from 2016-2021 and are being
rebuilt on a modern toolchain: different inlining and stack layout can stop ASAN
catching a stack overflow, and a newer clang can optimize away UB the bug relied
on. Per the spec, a target whose PoC no longer reproduces is DROPPED rather than
patched around, so the benchmark only ever measures bugs that demonstrably exist
in the binary under test.
"""
from __future__ import annotations

import logging
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib.crash_classify import normalize_signature

logger = logging.getLogger(__name__)

RUNNER_IMAGE = "gcr.io/oss-fuzz-base/base-runner"
# Bug classes are lowercase-hyphenated single tokens ("stack-buffer-overflow").
# Deliberately EXCLUDES the space that lib/crash_classify.py's copy allows: ASAN
# SUMMARY lines are "SUMMARY: <San>: <class> <path>:<line> in <func>", so a class
# allowing spaces swallows the location whenever the path is relative, yielding
# "stack-buffer-overflow valid" and a silent signature mismatch. READ/WRITE and
# size suffixes live on the manifest side and are handled by normalize_signature.
_SUMMARY_RE = re.compile(r"SUMMARY:\s*\w*Sanitizer:\s*([a-zA-Z0-9_\-]+)")


@dataclass
class VerifyResult:
    reproduced: bool
    detected_signature: str
    log: str
    status: str = "did_not_run"


# aflpp_driver prints this after each input it runs to completion. It is the
# only POSITIVE proof that the target actually executed, which is what separates
# "ran and did not crash" from "never got off the ground".
EXECUTION_MARKER = "Execution successful."

# Loader/exec failures. Without these, a broken run scores identically to a
# clean one -- and in a benchmark whose headline result is a bug-SURVIVAL rate,
# that silently converts infrastructure breakage into "optimization removed the
# bug". This exact case bit us: a missing libc++.so.1 produced status=dropped.
_DID_NOT_RUN_MARKERS = (
    "error while loading shared libraries",
    "cannot open shared object file",
    "No such file or directory",
    "cannot execute binary file",
    "Permission denied",
)


def classify_run(blob: str, returncode: int, expected_signature: str) -> str:
    """Classify one PoC replay into a four-state verdict.

    Returns one of:
      "reproduced"   the target bug fired (SUMMARY matches expected_signature)
      "wrong_crash"  a sanitizer fired, but a DIFFERENT bug class
      "no_crash"     the target provably ran to completion and did not crash
      "did_not_run"  no proof of execution -- treat as an error, never as a result

    Deliberately biased toward "did_not_run": guessing "no_crash" from silence
    is what corrupts a survival-rate measurement.
    """
    m = _SUMMARY_RE.search(blob)
    detected = m.group(1).strip() if m else ""
    if detected:
        return "reproduced" if signature_matches(detected, expected_signature) else "wrong_crash"
    if any(marker in blob for marker in _DID_NOT_RUN_MARKERS):
        return "did_not_run"
    if EXECUTION_MARKER in blob:
        return "no_crash"
    return "did_not_run"


def compile_command(tag: str, out_dir: str | Path) -> list[str]:
    """Run OSS-Fuzz `compile` with the AFL engine.

    Deliberately calls `compile` and not `arvo compile`: the arvo wrapper exports
    FUZZING_ENGINE=libfuzzer unconditionally, which is exactly what we are
    migrating away from.
    """
    return [
        "docker", "run", "--rm", "--privileged",
        "-e", "FUZZING_ENGINE=afl",
        "-e", "SANITIZER=address",
        "-e", "ARCHITECTURE=x86_64",
        "-e", "FUZZING_LANGUAGE=c++",
        "-v", f"{Path(out_dir).absolute()}:/out",
        tag, "compile",
    ]


def signature_matches(detected: str, expected: str) -> bool:
    """True iff a detected ASAN signature is the manifest's expected bug class.

    normalize_signature strips the access/size suffix, so "Heap-buffer-overflow
    READ 8" and "heap-buffer-overflow READ 1" are the same bug class.
    """
    if not detected:
        return False
    return normalize_signature(detected) == normalize_signature(expected)


def verify_poc(
    tag: str, out_dir: str | Path, fuzz_target: str, poc: str | Path,
    expected_signature: str, *, timeout: int = 300,
) -> VerifyResult:
    """Replay the PoC on the freshly built AFL++/ASAN binary.

    aflpp_driver's ExecuteFilesOnyByOne runs file arguments once each, so the
    libFuzzer-style `<target> <file>` invocation still works on an AFL build.

    Runs in the PREWORK image, not base-runner. The target links the pinned
    LLVM's shared libc++, which base-runner does not carry -- and using the
    pinned image end-to-end keeps a second, unpinned environment out of the
    experiment.
    """
    cmd = [
        "docker", "run", "--rm", "--privileged",
        "-v", f"{Path(out_dir).absolute()}:/out:ro",
        "-v", f"{Path(poc).absolute()}:/testcase:ro",
        "--entrypoint", "/bin/bash", tag, "-lc",
        f"export ASAN_OPTIONS=detect_leaks=0; /out/{fuzz_target} /testcase",
    ]
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return VerifyResult(False, "", "timeout", status="did_not_run")

    blob = (r.stdout or "") + (r.stderr or "")
    m = _SUMMARY_RE.search(blob)
    detected = m.group(1).strip() if m else ""
    status = classify_run(blob, r.returncode, expected_signature)
    return VerifyResult(
        reproduced=(status == "reproduced"),
        detected_signature=detected,
        log=blob,
        status=status,
    )
