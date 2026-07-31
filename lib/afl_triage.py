"""Decide which of a trial's crashes is the TARGET bug.

Under libFuzzer a trial ended at its first crash, so "did it crash" and "did it
find the target bug" were nearly the same question -- the only contamination was
slow-units, timeouts, OOMs, and the empty-input boundary artifact, which
lib/crash_classify.py filters by metadata alone.

AFL keeps fuzzing past a crash. A trial now yields many DISTINCT real crashes,
and only some are the bug under study. Two ways to get this wrong:

  * counting every artifact inflates the find rate
  * taking the earliest corrupts TTB, because the first crash is usually a
    shallower, unrelated bug

So each artifact is replayed and matched against the manifest's crash_type. This
is the same gold-standard check crash_classify.verify_crash_reproduces performs,
reusing prework.verify.classify_run so the four-state discipline is identical:
an artifact that fails to EXECUTE is an error, never "not the target bug".
"""
from __future__ import annotations

import logging
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib.afl import collect_crashes
from prework.verify import classify_run

logger = logging.getLogger(__name__)

# Shared with prework/verify.py and lib/crash_classify.py: no space in the
# class, or a relative path in the SUMMARY gets absorbed into the signature.
_SUMMARY_RE = re.compile(r"SUMMARY:\s*\w*Sanitizer:\s*([a-zA-Z0-9_\-]+)")


@dataclass
class _Ctx:
    image: str
    out_dir: str
    fuzz_target: str
    expected_signature: str
    timeout: int = 120


def _replay(ctx: _Ctx, path: Path) -> tuple[str, str]:
    """Replay one artifact. Returns (verdict, detected_signature).

    Runs in the prework image rather than base-runner: the target links the
    pinned LLVM's shared libc++, which base-runner does not carry.
    """
    cmd = [
        "docker", "run", "--rm", "--privileged",
        "-v", f"{Path(ctx.out_dir).absolute()}:/out:ro",
        "-v", f"{path.absolute()}:/testcase:ro",
        "--entrypoint", "/bin/bash", ctx.image, "-lc",
        f"export ASAN_OPTIONS=detect_leaks=0; /out/{ctx.fuzz_target} /testcase",
    ]
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=ctx.timeout,
        )
    except subprocess.TimeoutExpired:
        return "did_not_run", ""
    blob = (r.stdout or "") + (r.stderr or "")
    verdict = classify_run(blob, r.returncode, ctx.expected_signature)
    m = _SUMMARY_RE.search(blob)
    return verdict, (m.group(1).strip() if m else "")


def triage_trial(
    crashes_dir: str | Path, *, image: str, out_dir: str, fuzz_target: str,
    expected_signature: str, timeout: int = 120,
) -> list[dict]:
    """Replay every crash artifact and classify it. Earliest first."""
    ctx = _Ctx(image, out_dir, fuzz_target, expected_signature, timeout)
    crashes_dir = Path(crashes_dir)
    results: list[dict] = []
    for entry in collect_crashes(crashes_dir):
        path = crashes_dir / entry["artifact"]
        verdict, detected = _replay(ctx, path)
        if verdict == "did_not_run":
            logger.warning(
                "triage: %s did not execute -- infrastructure problem, not a "
                "statement about the bug", entry["artifact"],
            )
        results.append({
            "artifact": entry["artifact"],
            "timestamp_s": entry["timestamp_s"],
            "verdict": verdict,
            "detected_signature": detected,
        })
    return results


def target_bug_ttb(triaged: list[dict]) -> float | None:
    """Earliest crash that actually reproduced the target bug, in seconds."""
    hits = [t["timestamp_s"] for t in triaged if t.get("verdict") == "reproduced"]
    return min(hits) if hits else None


def summarize_triage(triaged: list[dict]) -> dict:
    """Counts by verdict. `errors` must stay at zero in a healthy campaign."""
    return {
        "total": len(triaged),
        "target_bug": sum(1 for t in triaged if t.get("verdict") == "reproduced"),
        "other_bugs": sum(1 for t in triaged if t.get("verdict") == "wrong_crash"),
        "errors": sum(1 for t in triaged if t.get("verdict") == "did_not_run"),
    }
