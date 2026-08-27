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
import shutil
import subprocess
import sys
import tempfile
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
    # ARVO's own reproducer output for this target's PoC (its repro.log). When
    # present it OUTRANKS expected_signature, because the sanitizer label is a
    # property of the harness, not of the bug: the same invalid read lands in a
    # heap redzone under libFuzzer ("heap-buffer-overflow") and in the
    # shared-memory redzone under AFL++ persistent mode ("use-after-poison").
    # prework.verify.matches_reference documents this on yara and c-blosc2 with
    # frame-for-frame identical stacks. Matching the manifest label instead
    # scores every AFL replay wrong_crash -- including the verified PoC itself.
    reference: str = ""


def _replay(ctx: _Ctx, path: Path) -> tuple[str, str]:
    """Replay one artifact. Returns (verdict, detected_signature).

    Runs in the prework image rather than base-runner: the target links the
    pinned LLVM's shared libc++, which base-runner does not carry.
    """
    # AFL names every artifact `id:000000,sig:06,src:...` -- and `docker -v`
    # parses host:container:mode on colons, so mounting the artifact by its own
    # path dies with "invalid spec: too many colons" and EVERY replay returned
    # did_not_run. That silently disabled this entire gold-standard tier for as
    # long as AFL has been the backend. Stage the artifact under a colon-free
    # name instead; the bytes are what matter, not the filename.
    with tempfile.TemporaryDirectory(prefix="triage-") as td:
        staged = Path(td) / "testcase"
        try:
            shutil.copyfile(path, staged)
        except OSError as e:
            logger.warning("triage: cannot stage %s: %s", path.name, e)
            return "did_not_run", ""
        cmd = [
            "docker", "run", "--rm", "--privileged",
            "-v", f"{Path(ctx.out_dir).absolute()}:/out:ro",
            "-v", f"{staged}:/testcase:ro",
            "--entrypoint", "/bin/bash", ctx.image, "-lc",
            f"export ASAN_OPTIONS=detect_leaks=0; /out/{ctx.fuzz_target} /testcase",
        ]
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, errors="replace",
                timeout=ctx.timeout,
            )
        except subprocess.TimeoutExpired:
            return "did_not_run", ""
    blob = (r.stdout or "") + (r.stderr or "")
    verdict = classify_run(blob, r.returncode, ctx.expected_signature,
                           reference=ctx.reference or None)
    m = _SUMMARY_RE.search(blob)
    return verdict, (m.group(1).strip() if m else "")


def triage_trial(
    crashes_dir: str | Path, *, image: str, out_dir: str, fuzz_target: str,
    expected_signature: str, timeout: int = 120, reference: str = "",
) -> list[dict]:
    """Replay every crash artifact and classify it. Earliest first.

    Pass ``reference`` (the PoC's repro.log) whenever it exists: identity then
    comes from the crash LOCATION rather than the sanitizer label. See _Ctx.
    """
    ctx = _Ctx(image, out_dir, fuzz_target, expected_signature, timeout, reference)
    crashes_dir = Path(crashes_dir)

    # collect_crashes also reads the crashes.<timestamp> archives AFL creates on
    # every resume, so an artifact is frequently NOT in crashes_dir itself --
    # `crashes_dir / artifact` then points at a file that does not exist and the
    # replay reports did_not_run for a perfectly good crash. Index the same
    # search set by filename and resolve against that instead.
    index: dict[str, Path] = {}
    for d in [crashes_dir] + sorted(
        p for p in crashes_dir.parent.glob(crashes_dir.name + ".*") if p.is_dir()
    ):
        if not d.is_dir():
            continue
        for f in d.iterdir():
            if f.is_file():
                index.setdefault(f.name, f)

    results: list[dict] = []
    for entry in collect_crashes(crashes_dir):
        path = index.get(entry["artifact"], crashes_dir / entry["artifact"])
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
    """Earliest crash that actually reproduced the PoC's bug, in seconds.

    Only ``poc_crash`` counts. ``other_crash`` is a real crash at a different
    location -- on yara that is pe_parse_exports, which is found earlier and more
    often than the target and would halve the measured time-to-bug if counted.
    """
    hits = [t["timestamp_s"] for t in triaged if t.get("verdict") == "poc_crash"]
    return min(hits) if hits else None


def summarize_triage(triaged: list[dict]) -> dict:
    """Counts by verdict. `errors` must stay at zero in a healthy campaign."""
    return {
        "total": len(triaged),
        "poc_crash": sum(1 for t in triaged if t.get("verdict") == "poc_crash"),
        "other_crash": sum(1 for t in triaged if t.get("verdict") == "other_crash"),
        "errors": sum(1 for t in triaged if t.get("verdict") == "did_not_run"),
    }
