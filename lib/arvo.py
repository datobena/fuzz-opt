"""ARVO integration module.

Wraps the ARVO reproducer to fetch issue metadata, download PoCs,
and build vulnerable versions of fuzz targets.
"""

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# Import force_remove from phase2_setup (avoids sudo password prompts)
# Lazy import to avoid circular deps — define a local fallback
def _force_remove(path):
    path = str(path)
    if not os.path.exists(path):
        return
    try:
        shutil.rmtree(path)
        return
    except PermissionError:
        pass
    subprocess.run(
        ["docker", "run", "--rm",
         "-v", f"{path}:/cleanup",
         "alpine:3.19",
         "rm", "-rf", "/cleanup"],
        capture_output=True, timeout=120,
    )
    try:
        os.rmdir(path)
    except OSError:
        pass

# Add ARVO reproducer to sys.path so we can import its modules
sys.path.insert(0, config.ARVO_REPRODUCER_DIR)

import arvo_reproducer
from arvo_utils import OSS_OUT

logger = logging.getLogger(__name__)


def fetch_arvo_issue(
    local_id: int | str, retries: int = 3, delay: int = 10
) -> dict[str, Any] | bool:
    """Fetch issue metadata from OSS-Fuzz via ARVO.

    Returns dict with keys: project, job_type, crash_type, reproducer,
    regressed, verified_fixed, fuzz_target, etc.  Returns False on failure.

    The upstream parse_oss_fuzz_report() calls exit(1) on parse failure
    (including rate-limit 429 responses), so we catch SystemExit and retry.
    """
    logger.info("Fetching ARVO issue %s...", local_id)

    import time as _time

    for attempt in range(retries):
        try:
            issue = arvo_reproducer.fetch_issue(int(local_id))
        except SystemExit:
            # arvo_reproducer.parse_oss_fuzz_report calls exit(1) on failure
            logger.warning(
                "ARVO fetch_issue(%s) called exit — attempt %d/%d, "
                "retrying in %ds...",
                local_id, attempt + 1, retries, delay,
            )
            _time.sleep(delay)
            delay *= 2  # exponential backoff
            continue
        except Exception as e:
            logger.error("ARVO fetch_issue(%s) raised %s: %s",
                         local_id, type(e).__name__, e)
            return False

        if issue:
            break
    else:
        logger.error("Failed to fetch issue %s after %d retries",
                     local_id, retries)
        return False

    if not issue:
        logger.error("Failed to fetch issue %s", local_id)
        return False

    # Ensure project field exists (early issues may lack it)
    if "project" not in issue:
        try:
            issue["project"] = issue["fuzzer"].split("_")[1]
        except (KeyError, IndexError):
            logger.error("Cannot determine project for issue %s", local_id)
            return False

    # Store local_id for later use
    issue["localId"] = int(local_id)
    return issue


def download_arvo_poc(
    issue: dict[str, Any], output_dir: str | Path
) -> Path | bool:
    """Download the crashing PoC input for an ARVO issue.

    Returns path to the downloaded PoC file, or False on failure.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Downloading PoC for issue %s...", issue.get("localId", "?"))
    poc_path = arvo_reproducer.download_poc(issue, output_dir, "poc_input")
    if not poc_path or not Path(poc_path).exists():
        logger.error("Failed to download PoC")
        return False
    return Path(poc_path)


def build_arvo_vulnerable(local_id: int | str, issue: dict[str, Any]) -> bool:
    """Build the vulnerable version of a fuzz target using ARVO.

    Calls arvo_reproducer to handle the full build pipeline:
    clone OSS-Fuzz at right date, rebase Dockerfile, clone deps at
    right commit, build.

    Built fuzzers end up at /tmp/{localId}_OUT/.

    Returns True on success.
    """
    local_id = int(local_id)
    logger.info("Building vulnerable version for issue %s...", local_id)

    # Download srcmap from regressed URL
    tmpdir = Path(tempfile.mkdtemp())
    try:
        srcmap_url = issue["regressed"]
        srcmap_files = arvo_reproducer.download_build_artifacts(
            issue, srcmap_url, tmpdir
        )
        if not srcmap_files:
            logger.error("Failed to download srcmap for %s", local_id)
            return False

        srcmap = Path(srcmap_files[0])
        result = arvo_reproducer.build_from_srcmap(srcmap, issue, "vul")
        return bool(result)
    finally:
        _force_remove(tmpdir)


def build_arvo_with_source_intercept(
    local_id: int | str, issue: dict[str, Any]
) -> Optional[Path]:
    """Build vulnerable version and return the source directory.

    Similar to build_arvo_vulnerable but intercepts the build process
    to preserve the source tree for fold-deterministic-calls optimization.

    Returns the path to the source directory (caller must clean up with
    sudo rm -rf), or None on failure.

    The built fuzzers still end up at /tmp/{localId}_OUT/.
    """
    local_id = int(local_id)
    logger.info(
        "Building vulnerable version with source intercept for %s...",
        local_id,
    )

    # Track temp dirs for cleanup
    tmpdir = Path(tempfile.mkdtemp())
    oss_tmp_dir = None
    source_dir = None

    try:
        return _build_with_source_intercept_inner(
            local_id, issue, tmpdir,
        )
    except Exception as e:
        logger.error("build_arvo_with_source_intercept failed: %s", e)
        return None


def _build_with_source_intercept_inner(
    local_id: int, issue: dict[str, Any], tmpdir: Path,
) -> Optional[Path]:
    """Inner implementation — returns source_dir on success, None on failure.

    On failure, cleans up all temp dirs. On success, cleans up everything
    except source_dir (caller is responsible for that).
    """
    srcmap_url = issue["regressed"]
    srcmap_files = arvo_reproducer.download_build_artifacts(
        issue, srcmap_url, tmpdir
    )
    if not srcmap_files:
        logger.error("Failed to download srcmap for %s", local_id)
        _force_remove(tmpdir)
        return None

    srcmap = Path(srcmap_files[0])

    fuzzer_info = issue["job_type"].split("_")
    engine = fuzzer_info[0]
    sanitizer = arvo_reproducer.get_sanitizer(fuzzer_info[1])
    arch = "i386" if fuzzer_info[2] == "i386" else "x86_64"

    issue_date = srcmap.name.split(".")[0].split("-")[-1]
    from datetime import datetime
    commit_date = datetime.strptime(issue_date + " +0000", "%Y%m%d%H%M %z")

    if "issue" not in issue:
        issue["issue"] = {"localId": issue["localId"]}

    with open(srcmap, encoding="utf-8") as f:
        srcmap_items = json.loads(f.read())

    if (
        "/src" in srcmap_items
        and srcmap_items["/src"]["url"] == "https://github.com/google/oss-fuzz.git"
    ):
        result = arvo_reproducer.prepare_ossfuzz(
            issue["project"], srcmap_items["/src"]["rev"]
        )
    else:
        result = arvo_reproducer.prepare_ossfuzz(issue["project"], commit_date)

    if not result:
        _force_remove(tmpdir)
        return None

    oss_tmp_dir, project_dir = result
    source_dir = Path(tempfile.mkdtemp())

    def _cleanup(include_source=True):
        _force_remove(oss_tmp_dir)
        _force_remove(tmpdir)
        if include_source:
            _force_remove(source_dir)

    dockerfile = project_dir / "Dockerfile"

    from arvo_reproducer import BuildData, rebase_dockerfile, get_language
    from arvo_data import (
        fix_dockerfile, fix_build_script, extra_scripts,
        skip_component, special_component, update_resource_info,
    )
    from arvo_utils import clone, svn_clone, hg_clone, check_call, docker_run

    build_data = BuildData(
        sanitizer=sanitizer, architecture=arch,
        engine=engine, project_name=issue["project"],
    )

    if not rebase_dockerfile(dockerfile, str(commit_date).replace(" ", "-")):
        logger.error("Failed to rebase dockerfile for %s", local_id)
        _cleanup()
        return None

    if not fix_dockerfile(dockerfile, issue["project"], commit_date):
        logger.error("Failed to fix dockerfile for %s", local_id)
        _cleanup()
        return None

    with open(srcmap, encoding="utf-8") as f:
        data = json.loads(f.read())

    src = source_dir / "src"
    src.mkdir(parents=True, exist_ok=True)
    docker_volume = []
    sorted_keys = sorted(data.keys(), key=len)
    main_component = arvo_reproducer.get_project_name(issue, srcmap)

    if main_component is False:
        _cleanup()
        return None

    for item_key in sorted_keys:
        if skip_component(issue["project"], item_key):
            continue

        approximate = "-"

        new_data = {}
        new_data["rev"] = data[item_key]["rev"]
        new_key, new_data["url"], new_data["type"] = update_resource_info(
            item_key, data[item_key]["url"], data[item_key]["type"]
        )
        del data[item_key]
        data[new_key] = new_data

        item_url = data[new_key]["url"]
        item_type = data[new_key]["type"]
        item_rev = data[new_key]["rev"]
        item_name = "/".join(new_key.split("/")[2:])

        if special_component(issue["project"], new_key, data[new_key], dockerfile):
            continue
        if item_name == "aflplusplus" and "AFLplusplus" in item_url:
            continue
        if item_name == "libfuzzer" and "llvm.org" in item_url:
            continue
        if item_rev in ("", "UNKNOWN"):
            logger.error("Broken meta: no revision for %s", item_name)
            _cleanup()
            return None
        if item_type not in ("git", "svn", "hg"):
            logger.error("Unsupported VCS type: %s", item_type)
            _cleanup()
            return None

        if arvo_reproducer.update_revision_info(
            dockerfile, new_key, data[new_key], commit_date, approximate
        ):
            continue

        if item_type == "git":
            clone_result = clone(
                item_url, item_rev, src, item_name, commit_date=commit_date
            )
            if clone_result is False:
                logger.error("Failed to clone %s", item_name)
                _cleanup()
                return None
            elif clone_result is None:
                cmd = (
                    f'git log --before="{commit_date.isoformat()}" '
                    f'-n 1 --format="%H"'
                )
                r = subprocess.run(
                    cmd, stdout=subprocess.PIPE, text=True,
                    shell=True, cwd=src / item_name,
                )
                commit_hash = r.stdout.strip()
                if not check_call(
                    ["git", "reset", "--hard", commit_hash],
                    cwd=src / item_name,
                ):
                    logger.error("Failed to checkout %s", item_name)
                    _cleanup()
                    return None
            docker_volume.append(new_key)

        elif item_type == "svn":
            if not svn_clone(item_url, item_rev, src, item_name):
                logger.error("Failed to svn clone %s", item_name)
                _cleanup()
                return None
            docker_volume.append(new_key)

        elif item_type == "hg":
            if not hg_clone(item_url, item_rev, src, item_name):
                logger.error("Failed to hg clone %s", item_name)
                _cleanup()
                return None
            docker_volume.append(new_key)

    if not extra_scripts(issue["project"], source_dir):
        logger.error("Extra scripts failed for %s", local_id)
        _cleanup()
        return None

    if not fix_build_script(project_dir / "build.sh", issue["project"]):
        logger.error("Build script fix failed for %s", local_id)
        _cleanup()
        return None

    result = arvo_reproducer.build_fuzzers_impl(
        local_id,
        project_dir=project_dir,
        engine=build_data.engine,
        sanitizer=build_data.sanitizer,
        architecture=build_data.architecture,
        source_path=source_dir / "src",
        mount_path=Path("/src"),
    )

    # Always clean up oss-fuzz temp and srcmap; only clean source on failure
    _cleanup(include_source=not result)

    if not result:
        return None

    return source_dir


def get_arvo_build_output(local_id: int | str) -> Path:
    """Get the path where ARVO puts built fuzzers."""
    return config.ARVO_OUT_DIR / f"{int(local_id)}_OUT"


def get_arvo_fuzz_target(issue: dict[str, Any]) -> str:
    """Extract the fuzz target name from an ARVO issue."""
    return issue.get("fuzz_target", "")


def get_arvo_crash_type(issue: dict[str, Any]) -> str:
    """Extract the crash type from an ARVO issue."""
    return issue.get("crash_type", "")
