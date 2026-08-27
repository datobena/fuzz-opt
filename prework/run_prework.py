"""Drive the full prework for one target: extract -> build -> compile -> verify.

Writes prework_result.json next to the extracted artifacts. A target whose PoC
does not reproduce on the modern toolchain is reported as dropped; nothing
downstream should use it.
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from prework.build_image import build_image, image_tag, load_meta
from prework.extract import extract_arvo, extract_source_only
from prework.verify import compile_command, verify_poc

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_ARVO_UNUSABLE = 2
EXIT_IMAGE_BUILD_FAILED = 3
EXIT_COMPILE_FAILED = 4
EXIT_BUG_GONE = 5
EXIT_VERIFY_INFRA_FAILURE = 6


def main() -> int:
    ap = argparse.ArgumentParser(description="Prework for one ARVO target")
    ap.add_argument("--target", required=True, help="prework/targets/<name>")
    ap.add_argument("--work", default="/tmp/prework", help="artifact root")
    ap.add_argument(
        "--skip-extract", action="store_true",
        help="reuse an existing extraction under --work (skips the ARVO pull)",
    )
    args = ap.parse_args()

    target_dir = Path(args.target)
    meta = load_meta(target_dir)
    work = Path(args.work) / f"{meta['project']}-arvo-{meta['arvo_id']}"
    tag = image_tag(meta["project"], meta["arvo_id"])

    if args.skip_extract:
        source_dir = work / "src"
        poc_path = work / "poc" / "poc_input"
        if not (source_dir.is_dir() and poc_path.is_file()):
            logger.error("--skip-extract but no prior extraction under %s", work)
            return EXIT_ARVO_UNUSABLE
        logger.info("[1/4] reusing extraction at %s", work)
    else:
        logger.info("[1/4] extracting from %s", meta["arvo_image"])
        # Two ARVO image shapes: n132/arvo:<id>-vul bakes a reproducer, while a
        # plain gcr.io/oss-fuzz/<local_id> builder has neither `arvo` nor
        # /tmp/poc. The latter needs an externally supplied PoC.
        if meta.get("poc_source"):
            # Resolve relative to the target dir so a fresh clone works from any
            # cwd, and so the PoC can live beside the target under version control.
            poc_source = Path(meta["poc_source"])
            if not poc_source.is_absolute():
                poc_source = target_dir / poc_source
            extracted = extract_source_only(
                meta["arvo_image"], meta["project"], work,
                poc_source=poc_source,
            )
        else:
            extracted = extract_arvo(meta["arvo_image"], meta["project"], work)
            if not extracted.baseline_crashed:
                logger.error("ARVO image itself does not reproduce; target unusable")
                return EXIT_ARVO_UNUSABLE
        if extracted.poc_path is None:
            logger.error("no PoC extracted; cannot verify")
            return EXIT_ARVO_UNUSABLE
        source_dir, poc_path = extracted.source_dir, extracted.poc_path

    logger.info("[2/4] building %s", tag)
    ok, build_log = build_image(target_dir, source_dir, tag)
    if not ok:
        (work / "build.log").write_text(build_log)
        logger.error("image build failed; see %s", work / "build.log")
        return EXIT_IMAGE_BUILD_FAILED

    logger.info("[3/4] compiling target with FUZZING_ENGINE=afl")
    out_dir = work / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    c = subprocess.run(
        compile_command(tag, out_dir), capture_output=True, text=True,
        errors="replace", check=False,
    )
    (work / "compile.log").write_text((c.stdout or "") + (c.stderr or ""))
    if c.returncode != 0:
        logger.error("compile failed; see %s", work / "compile.log")
        return EXIT_COMPILE_FAILED

    logger.info("[4/4] verifying the PoC still reproduces")
    # ARVO's own reproducer output for this same PoC, when the image baked one.
    # It identifies the bug by WHERE it fires, which survives the harness change
    # that renames the sanitizer check (see verify.matches_reference).
    reference_log = Path(poc_path).parent / "repro.log"
    v = verify_poc(tag, out_dir, meta["fuzz_target"], poc_path, meta["crash_type"],
                   reference_log=reference_log if reference_log.is_file() else None)
    # Four-state, because "the binary would not load" must never be recorded as
    # "the bug is gone" -- that would corrupt the bug-survival rate the study
    # reports. Only a PROVEN clean execution counts as attrition.
    status_map = {
        "poc_crash": "ready",
        "no_crash": "dropped_bug_gone",
        "other_crash": "dropped_wrong_bug",
        "did_not_run": "error_did_not_run",
    }
    result = {
        "target": target_dir.name,
        "image": tag,
        "fuzz_target": meta["fuzz_target"],
        "expected_signature": meta["crash_type"],
        "detected_signature": v.detected_signature,
        "verdict": v.status,
        "poc_crash": v.reproduced,
        "status": status_map.get(v.status, "error_did_not_run"),
        "deviations": meta.get("deviations", []),
    }
    (work / "prework_result.json").write_text(json.dumps(result, indent=2))
    (work / "verify.log").write_text(v.log)
    print(json.dumps(result, indent=2))

    if v.status == "poc_crash":
        return EXIT_OK
    if v.status == "did_not_run":
        logger.error(
            "PoC replay never executed -- this is an INFRASTRUCTURE failure, not "
            "evidence about the bug. See %s", work / "verify.log",
        )
        return EXIT_VERIFY_INFRA_FAILURE
    return EXIT_BUG_GONE


if __name__ == "__main__":
    raise SystemExit(main())
