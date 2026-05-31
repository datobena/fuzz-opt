"""OSV vulnerability data client.

Parses OSV YAML files from the google/oss-fuzz-vulns repository to extract
CVE information including affected commit ranges, crash types, and project metadata.
"""

import glob
import os
import re
from typing import Optional

import yaml

import config


def parse_osv_yaml(filepath: str) -> Optional[dict]:
    """Parse a single OSV YAML file and extract relevant fields.

    Returns None if the entry doesn't meet basic criteria (missing commits, etc).
    """
    with open(filepath) as f:
        data = yaml.safe_load(f)

    if not data:
        return None

    osv_id = data.get("id", "")
    aliases = data.get("aliases", [])
    cves = [a for a in aliases if a.startswith("CVE-")]

    summary = data.get("summary", "")
    details = data.get("details", "")
    crash_type = _extract_crash_type(summary, details)

    affected = data.get("affected", [])
    if not affected:
        return None

    entry = affected[0]
    package = entry.get("package", {})
    ecosystem = package.get("ecosystem", "")
    project_name = package.get("name", "")

    if ecosystem != "OSS-Fuzz":
        return None

    # Extract commit range
    introduced = None
    fixed = None
    repo_url = None
    for r in entry.get("ranges", []):
        if r.get("type") != "GIT":
            continue
        repo_url = r.get("repo", "")
        for event in r.get("events", []):
            if "introduced" in event:
                introduced = event["introduced"]
            if "fixed" in event:
                fixed = event["fixed"]

    if not introduced or not fixed or not repo_url:
        return None

    # Extract references for issue links
    references = []
    for ref in data.get("references", []):
        references.append({
            "type": ref.get("type", ""),
            "url": ref.get("url", ""),
        })

    return {
        "osv_id": osv_id,
        "cves": cves,
        "project": project_name,
        "repo_url": repo_url,
        "introduced_commit": introduced,
        "fixed_commit": fixed,
        "crash_type": crash_type,
        "summary": summary,
        "references": references,
    }


def _extract_crash_type(summary: str, details: str) -> str:
    """Extract crash type from summary/details text."""
    text = f"{summary} {details}".lower()
    for ct in config.CRASH_TYPES:
        if ct.lower().replace("-", " ") in text.replace("-", " "):
            return ct
        if ct.lower().replace("-", "-") in text:
            return ct
    # Try to find common patterns
    patterns = [
        (r"heap-buffer-overflow", "heap-buffer-overflow"),
        (r"heap-use-after-free", "heap-use-after-free"),
        (r"stack-buffer-overflow", "stack-buffer-overflow"),
        (r"use-after-free", "use-after-free"),
        (r"null.?deref", "null-dereference"),
        (r"double.?free", "double-free"),
        (r"out.of.bounds", "out-of-bounds"),
        (r"integer.overflow", "integer-overflow"),
        (r"buffer.overflow", "buffer-overflow"),
        (r"divide.by.zero", "divide-by-zero"),
    ]
    for pattern, name in patterns:
        if re.search(pattern, text):
            return name
    return ""


def is_crash_type(crash_type: str) -> bool:
    """Check if crash_type is a valid crash (not timeout/OOM/leak)."""
    if not crash_type:
        return False
    excluded = {"timeout", "oom", "out-of-memory", "memory-leak", "leak"}
    return crash_type.lower() not in excluded


def load_all_vulns(vulns_dir: Optional[str] = None) -> list[dict]:
    """Load all OSV vulnerability entries from oss-fuzz-vulns repo.

    Args:
        vulns_dir: Path to the vulns/ directory in oss-fuzz-vulns repo.
                   Defaults to config.OSS_FUZZ_VULNS_DIR/vulns.
    """
    if vulns_dir is None:
        vulns_dir = os.path.join(config.OSS_FUZZ_VULNS_DIR, "vulns")

    results = []
    yaml_files = glob.glob(os.path.join(vulns_dir, "*", "OSV-*.yaml"))

    try:
        from tqdm import tqdm
        iter_files = tqdm(yaml_files, desc="Loading OSV YAMLs", unit="file")
    except ImportError:
        iter_files = yaml_files

    for filepath in iter_files:
        entry = parse_osv_yaml(filepath)
        if entry is not None:
            results.append(entry)

    return results


def get_project_language(project_name: str) -> str:
    """Get project language from oss-fuzz project.yaml."""
    project_yaml = os.path.join(
        config.OSS_FUZZ_DIR, "projects", project_name, "project.yaml"
    )
    if not os.path.exists(project_yaml):
        return ""
    with open(project_yaml) as f:
        data = yaml.safe_load(f)
    return (data or {}).get("language", "").lower()


def get_project_engines(project_name: str) -> list[str]:
    """Get supported fuzzing engines from oss-fuzz project.yaml."""
    project_yaml = os.path.join(
        config.OSS_FUZZ_DIR, "projects", project_name, "project.yaml"
    )
    if not os.path.exists(project_yaml):
        return []
    with open(project_yaml) as f:
        data = yaml.safe_load(f)
    engines = (data or {}).get("fuzzing_engines", [])
    if isinstance(engines, str):
        return [engines]
    return engines


def get_fuzz_targets(project_name: str) -> list[str]:
    """Get list of fuzz targets from oss-fuzz project directory and build output."""
    targets = []

    # Method 1: Parse build.sh for $OUT/<target> patterns
    build_sh = os.path.join(
        config.OSS_FUZZ_DIR, "projects", project_name, "build.sh"
    )
    if os.path.exists(build_sh):
        with open(build_sh) as f:
            content = f.read()
        for match in re.finditer(r'\$OUT/(\w+)', content):
            target = match.group(1)
            if target not in targets:
                targets.append(target)

    # Method 2: Check actual build output directory for ELF binaries
    build_out = os.path.join(config.OSS_FUZZ_DIR, "build", "out", project_name)
    if os.path.isdir(build_out):
        for fname in sorted(os.listdir(build_out)):
            fpath = os.path.join(build_out, fname)
            if (os.path.isfile(fpath)
                    and os.access(fpath, os.X_OK)
                    and not fname.startswith("llvm-")
                    and not fname.endswith((".zip", ".dict", ".options", ".cfg"))
                    and fname not in targets):
                targets.append(fname)

    return targets
