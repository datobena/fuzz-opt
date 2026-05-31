#!/usr/bin/env python3
"""Phase 1: CVE Selection.

Discovers CVEs from oss-fuzz-vulns repo, filters by criteria
(C/C++, libFuzzer, crash-type, buildable), and outputs manifest.json.
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime

import yaml
from tqdm import tqdm

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
from lib import osv

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# Preferred project domains for diversity
DOMAIN_TAGS = {
    "openssl": "crypto",
    "boringssl": "crypto",
    "mbedtls": "crypto",
    "libxml2": "parser",
    "expat": "parser",
    "json-c": "parser",
    "cjson": "parser",
    "jansson": "parser",
    "libpng": "media",
    "libjpeg-turbo": "media",
    "libwebp": "media",
    "libtiff": "media",
    "ffmpeg": "media",
    "curl": "networking",
    "nghttp2": "networking",
    "wget": "networking",
    "zlib": "compression",
    "lz4": "compression",
    "zstd": "compression",
    "sqlite3": "database",
    "hdf5": "data-format",
    "freetype2": "fonts",
    "harfbuzz": "fonts",
    "re2": "regex",
    "pcre2": "regex",
    "systemd": "system",
    "util-linux": "system",
}


def ensure_repos_cloned():
    """Ensure oss-fuzz and oss-fuzz-vulns repos are cloned."""
    if not os.path.isdir(config.OSS_FUZZ_DIR):
        logger.error("oss-fuzz repo not found at %s", config.OSS_FUZZ_DIR)
        sys.exit(1)

    if not os.path.isdir(config.OSS_FUZZ_VULNS_DIR):
        logger.info("Cloning oss-fuzz-vulns...")
        subprocess.run(
            ["git", "clone", "--depth=1",
             "https://github.com/google/oss-fuzz-vulns.git",
             config.OSS_FUZZ_VULNS_DIR],
            check=True,
        )
    else:
        logger.info("Updating oss-fuzz-vulns...")
        subprocess.run(
            ["git", "-C", config.OSS_FUZZ_VULNS_DIR, "pull", "--ff-only"],
            capture_output=True,
        )


def find_vulnerable_commit(repo_url: str, fixed_commit: str) -> str:
    """Find the vulnerable commit (parent of fix).

    Uses git log to find the commit just before the fix.
    """
    # We'll resolve this during phase 2 when we have the repo cloned.
    # For now, return a marker that phase 2 will resolve.
    return f"PARENT_OF:{fixed_commit}"


def find_oss_fuzz_project_commit(
    project_name: str, vulnerable_commit_date: str
) -> str:
    """Find the oss-fuzz project configuration commit at the time of the vulnerability.

    Uses: git log --before=<date> -n1 --format=%H -- projects/<name>
    """
    projects_dir = os.path.join("projects", project_name)
    result = subprocess.run(
        ["git", "log", f"--before={vulnerable_commit_date}",
         "-n1", "--format=%H", "--", projects_dir],
        cwd=config.OSS_FUZZ_DIR,
        capture_output=True,
        text=True,
    )
    commit = result.stdout.strip()
    if not commit:
        # Fall back to latest commit for the project
        result = subprocess.run(
            ["git", "log", "-n1", "--format=%H", "--", projects_dir],
            cwd=config.OSS_FUZZ_DIR,
            capture_output=True,
            text=True,
        )
        commit = result.stdout.strip()
    return commit


def identify_fuzz_target(
    project_name: str, references: list[dict], crash_type: str
) -> str:
    """Try to identify the fuzz target that found the bug.

    Checks build.sh for fuzz target names and returns best guess.
    """
    targets = osv.get_fuzz_targets(project_name)

    # Check references for Monorail issue links that might name the target
    for ref in references:
        url = ref.get("url", "")
        # Parse fuzz target name from issue title/body if available
        if "bugs.chromium.org" in url or "monorail" in url:
            # We can't easily fetch these programmatically without auth
            pass

    if len(targets) == 1:
        return targets[0]

    # Return empty if we can't determine — phase 2 will need manual input
    if targets:
        logger.info("Multiple targets for %s: %s", project_name, targets)
        return targets[0]  # Best guess: first target

    return ""


def filter_candidates(vulns: list[dict]) -> list[dict]:
    """Apply selection criteria to vulnerability entries."""
    candidates = []
    # Cache project metadata to avoid re-reading yaml files
    lang_cache = {}
    engine_cache = {}

    for v in tqdm(vulns, desc="Filtering candidates", unit="vuln"):
        project = v["project"]

        # Check language (C/C++ only)
        if project not in lang_cache:
            lang_cache[project] = osv.get_project_language(project)
        if lang_cache[project] not in ("c", "c++"):
            continue

        # Check engine support
        if project not in engine_cache:
            engine_cache[project] = osv.get_project_engines(project)
        if "libfuzzer" not in engine_cache[project]:
            continue

        # Check crash type
        if not osv.is_crash_type(v["crash_type"]):
            continue

        # Must have both introduced and fixed commits
        if not v["introduced_commit"] or not v["fixed_commit"]:
            continue

        candidates.append(v)

    logger.info(
        "Filtered %d vulns down to %d candidates", len(vulns), len(candidates)
    )
    return candidates


def select_diverse_cves(
    candidates: list[dict], target_count: int = config.TARGET_CVE_COUNT
) -> list[dict]:
    """Select diverse set of CVEs (one per project, different domains).

    Prioritizes:
    1. Projects from different domains
    2. CVEs with clear crash types
    3. More recent CVEs (more likely to build)
    """
    # Group by project
    by_project = defaultdict(list)
    for c in candidates:
        by_project[c["project"]].append(c)

    # Score and rank projects
    project_scores = []
    for project, project_vulns in by_project.items():
        domain = DOMAIN_TAGS.get(project, "other")
        # Prefer projects with known domains
        domain_score = 1 if domain != "other" else 0
        # Prefer projects with fewer vulns (cleaner codebases)
        vuln_count_score = -len(project_vulns)
        # Pick the "best" vuln per project (clearest crash type)
        best_vuln = max(
            project_vulns,
            key=lambda v: (
                len(v["crash_type"]) > 0,  # Has crash type
                len(v.get("cves", [])) > 0,  # Has CVE ID
                v["osv_id"],  # Tiebreak by ID
            ),
        )
        project_scores.append((domain_score, vuln_count_score, project, best_vuln, domain))

    project_scores.sort(reverse=True)

    # Select diverse set
    selected = []
    used_domains = set()

    # First pass: one per domain
    for _, _, project, vuln, domain in project_scores:
        if len(selected) >= target_count:
            break
        if domain in used_domains and domain != "other":
            continue
        used_domains.add(domain)
        selected.append(vuln)

    # Second pass: fill remaining slots
    if len(selected) < target_count:
        for _, _, project, vuln, domain in project_scores:
            if len(selected) >= target_count:
                break
            if vuln not in selected:
                selected.append(vuln)

    return selected


def build_manifest_entry(vuln: dict) -> dict:
    """Build a manifest entry from a vulnerability record."""
    project = vuln["project"]

    # Determine fuzz target
    fuzz_target = identify_fuzz_target(
        project, vuln.get("references", []), vuln["crash_type"]
    )

    # Get CVE ID
    cve = vuln["cves"][0] if vuln.get("cves") else vuln["osv_id"]

    # The vulnerable commit is the parent of the fix
    vulnerable_commit = find_vulnerable_commit(
        vuln["repo_url"], vuln["fixed_commit"]
    )

    return {
        "project": project,
        "osv_id": vuln["osv_id"],
        "cve": cve,
        "repo_url": vuln["repo_url"],
        "vulnerable_commit": vulnerable_commit,
        "fixed_commit": vuln["fixed_commit"],
        "introduced_commit": vuln["introduced_commit"],
        "fuzz_target": fuzz_target,
        "crash_type": vuln["crash_type"],
        "oss_fuzz_project_commit": "",  # Resolved in phase 2
    }


def validate_build(project_name: str, pbar=None) -> bool:
    """Quick check if project can build (image build only, no fuzzers).

    Streams Docker build output directly to the terminal so progress is visible.
    Returns True if the Docker image builds successfully.
    """
    if pbar is not None:
        pbar.set_postfix_str(project_name)
        # Write a newline so streamed output doesn't collide with tqdm bar
        tqdm.write(f"--- Building image: {project_name} ---")

    logger.info("Validating build for %s...", project_name)
    # Don't capture output — let Docker print directly to terminal.
    # Pipe "n\n" to stdin to auto-decline the "pull base images?" prompt.
    try:
        result = subprocess.run(
            ["python3", os.path.join(config.OSS_FUZZ_DIR, "infra", "helper.py"),
             "build_image", "--no-pull", project_name],
            cwd=config.OSS_FUZZ_DIR,
            input="n\n",
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        logger.warning("Build validation timed out for %s", project_name)
        return False

    success = result.returncode == 0
    if not success:
        logger.warning("Build validation failed for %s", project_name)
    else:
        if pbar is not None:
            tqdm.write(f"--- {project_name}: OK ---")
    return success


def main():
    parser = argparse.ArgumentParser(description="Phase 1: CVE Selection")
    parser.add_argument(
        "--target-count", type=int, default=config.TARGET_CVE_COUNT,
        help="Number of CVEs to select",
    )
    parser.add_argument(
        "--skip-build-check", action="store_true",
        help="Skip build validation (faster, less reliable)",
    )
    parser.add_argument(
        "--output", default=config.MANIFEST_PATH,
        help="Output manifest file path",
    )
    args = parser.parse_args()

    ensure_repos_cloned()

    # Load all vulnerabilities
    logger.info("Loading vulnerabilities from oss-fuzz-vulns...")
    vulns = osv.load_all_vulns()
    logger.info("Loaded %d vulnerability entries", len(vulns))

    # Filter by criteria
    candidates = filter_candidates(vulns)

    # Select diverse set
    selected = select_diverse_cves(candidates, args.target_count)
    logger.info("Selected %d CVEs for benchmarking", len(selected))

    # Optionally validate builds
    if not args.skip_build_check:
        validated = []
        pbar = tqdm(selected, desc="Validating builds", unit="project")
        for vuln in pbar:
            if validate_build(vuln["project"], pbar=pbar):
                validated.append(vuln)
            else:
                logger.warning(
                    "Skipping %s/%s — build failed", vuln["project"], vuln["osv_id"]
                )
        pbar.close()
        selected = validated

    if len(selected) < config.MIN_CVE_COUNT:
        logger.error(
            "Only %d CVEs passed validation (need at least %d)",
            len(selected), config.MIN_CVE_COUNT,
        )
        sys.exit(1)

    # Build manifest
    manifest = [build_manifest_entry(v) for v in selected]

    # Write manifest
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(manifest, f, indent=2)

    logger.info("Wrote manifest with %d entries to %s", len(manifest), args.output)

    # Print summary
    print("\n=== Selected CVEs ===")
    for entry in manifest:
        print(f"  {entry['project']}: {entry['cve']} ({entry['crash_type']})")
        print(f"    Target: {entry['fuzz_target'] or 'TBD'}")
        print(f"    Repo: {entry['repo_url']}")
    print()


if __name__ == "__main__":
    main()
