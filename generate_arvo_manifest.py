#!/usr/bin/env python3
"""Generate ARVO-based manifest.

Fetches metadata for a set of ARVO local IDs and writes manifest.json
with fuzz_target and crash_type populated from the issue tracker.

Usage:
    python generate_arvo_manifest.py
    python generate_arvo_manifest.py --input cves.txt --output manifest.json
"""

import argparse
import json
import logging
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
from lib.arvo import fetch_arvo_issue, get_arvo_fuzz_target, get_arvo_crash_type

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


def parse_cves_file(path: str) -> list[dict]:
    """Parse a cves.txt file into (cve, local_id) entries.

    Deduplicates by CVE, keeping the first (lowest) local_id per CVE.
    """
    cve_to_lid = {}
    with open(path) as f:
        for line in f:
            m = re.match(r"cve='(CVE-[^']+)': localId=(\d+)", line.strip())
            if not m:
                continue
            cve, lid = m.group(1), int(m.group(2))
            if cve not in cve_to_lid:
                cve_to_lid[cve] = lid

    return [{"cve": cve, "local_id": lid} for cve, lid in sorted(cve_to_lid.items())]


def generate_manifest(output_path: str, input_entries: list[dict]) -> bool:
    """Fetch ARVO metadata and write manifest.json.

    Returns True if all entries were populated successfully.
    """
    manifest = []
    failures = []

    for entry in input_entries:
        local_id = entry["local_id"]
        cve = entry["cve"]
        logger.info("Fetching metadata for %s (local_id=%d)...", cve, local_id)

        issue = fetch_arvo_issue(local_id)
        if not issue:
            logger.error("Failed to fetch issue for %s", cve)
            failures.append(cve)
            continue

        job_type = issue.get("job_type", "")
        if job_type.startswith("afl_"):
            logger.info("Skipping %s (AFL engine: %s) — benchmark requires libfuzzer",
                        cve, job_type)
            continue
        # Reject 32-bit i386 builds: the host's perf cannot symbolize 32-bit
        # ASAN-instrumented binaries reliably, so the agent's profile-guided
        # optimization stage degrades to source-tree heuristics. Empirically
        # both i386 CVEs in codex-4 (file, qt) ended with no measurable
        # optimization benefit. Keep only x86_64 builds.
        if "_i386" in job_type:
            logger.info("Skipping %s (32-bit i386: %s) — benchmark requires x86_64",
                        cve, job_type)
            continue

        project = issue.get("project", "")
        fuzz_target = get_arvo_fuzz_target(issue)
        crash_type = get_arvo_crash_type(issue) or ""

        if not project:
            logger.error("No project name for %s (local_id=%d)", cve, local_id)
            failures.append(cve)
            continue

        if not fuzz_target:
            logger.warning("No fuzz_target for %s (local_id=%d)", cve, local_id)

        manifest_entry = {
            "project": project,
            "cve": cve,
            "local_id": local_id,
            "fuzz_target": fuzz_target,
            "crash_type": crash_type,
        }
        manifest.append(manifest_entry)
        logger.info(
            "  %s: project=%s, fuzz_target=%s, crash_type=%s",
            cve, project, fuzz_target, crash_type,
        )

    # Write manifest
    with open(output_path, "w") as f:
        json.dump(manifest, f, indent=2)
    logger.info(
        "Wrote manifest with %d entries to %s (%d failures)",
        len(manifest), output_path, len(failures),
    )

    if failures:
        logger.warning("Failed entries: %s", failures)
        return False

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Generate ARVO-based manifest for benchmark"
    )
    parser.add_argument(
        "--input", default=os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "data", "arvo", "cves.txt"
        ),
        help="Input CVE file (default: data/arvo/cves.txt)",
    )
    parser.add_argument(
        "--output", default=config.MANIFEST_PATH,
        help="Output manifest path (default: manifest.json)",
    )
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: input file not found: {args.input}")
        sys.exit(1)

    entries = parse_cves_file(args.input)
    logger.info("Parsed %d unique CVEs from %s", len(entries), args.input)

    success = generate_manifest(args.output, entries)
    if success:
        print(f"\nManifest generated successfully: {args.output}")
        print(f"  {len(entries)} CVEs")
    else:
        print(f"\nManifest generated with some failures: {args.output}")
        sys.exit(1)


if __name__ == "__main__":
    main()
