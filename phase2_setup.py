#!/usr/bin/env python3
"""Phase 2: Environment Setup.

For each CVE in the manifest:
1. Build baseline fuzzers (via ARVO if local_id present, else OSS-Fuzz)
2. Extract source and apply apply-fuzz-source-folds optimization
3. Build optimized fuzzers
4. Verify both variants reproduce the crash (if PoC available)
5. Download seed corpus

Supports two manifest formats:
- ARVO: entries have "local_id" → uses ARVO reproducer
- OSV:  entries have "vulnerable_commit"/"repo_url" → uses OSS-Fuzz helper.py
"""

import argparse
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
from lib import corpus as corpus_util
from lib import docker_util

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


class MutationAugmentationError(RuntimeError):
    """Mutation-augmented profiling could not be performed for a target.

    Raised when the mutation-capture step cannot run or yields no mutations while
    mutation-augmented profiling is required (config.PHASE2_MUTATION_REQUIRED).
    There is NO seed-only fall-back: the caller records the target as a phase-2
    failure (stage=mutation_augmentation) instead of optimizing on the seeds alone.
    """


_SOURCE_FILE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx",
    ".h", ".hh", ".hpp", ".hxx",
}

_LOW_CONFIDENCE_PATTERNS = [
    "fallback static hotspot scan only",
    "build gate fails before a usable profiling binary can be built",
    "internal smoke-run: blocked",
    "internal smoke-run: `blocked`",
    "internal oss-fuzz build: failed",
    "internal oss-fuzz build: `failed`",
    "reached, heuristically",
    # NOTE: BLOCKED_LOW_CONFIDENCE is intentionally NOT a substring pattern here —
    # an honest "no qualifying fold" result often says "...not a
    # BLOCKED_LOW_CONFIDENCE..." to deny it, which must not be mis-flagged. The
    # genuine status is detected line-anchored in _emits_blocked_low_confidence().
]


def force_remove(path: str | Path):
    """Remove a directory that may contain root-owned files (from Docker).

    Tries regular rm first, falls back to docker-based removal so we
    never need an interactive sudo password prompt.
    """
    path = str(path)
    if not os.path.exists(path):
        return
    # Try normal removal first (works if we own the files)
    try:
        shutil.rmtree(path)
        return
    except PermissionError:
        pass
    # Use a lightweight Docker container to rm as root — no sudo needed
    subprocess.run(
        ["docker", "run", "--rm",
         "-v", f"{path}:/cleanup",
         "alpine:3.19",
         "rm", "-rf", "/cleanup"],
        capture_output=True, timeout=120,
    )
    # The mount point dir itself remains; remove it
    try:
        os.rmdir(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Manifest I/O
# ---------------------------------------------------------------------------

def load_manifest(path: str = config.MANIFEST_PATH) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def save_manifest(manifest: list[dict], path: str = config.MANIFEST_PATH):
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)


def is_arvo_entry(entry: dict) -> bool:
    """Return True if the manifest entry uses the ARVO format."""
    return "local_id" in entry


def is_n132_entry(entry: dict) -> bool:
    """Return True for ARVO entries sourced from an n132/arvo prebuilt image.

    These are keyed by ARVO-Meta Monorail ids and carry an `image` field like
    `n132/arvo:<id>-vul`; they are built/optimized via the image's `arvo` /
    `arvo compile` contract instead of the OSS-Fuzz IssueTracker source-rebuild.
    """
    return "n132/arvo" in str(entry.get("image", ""))


def get_experiment_dir(experiment_id: str, entry: dict) -> str:
    cve_dir_name = f"{entry['project']}-{entry['cve']}"
    return os.path.join(config.RESULTS_DIR, experiment_id, cve_dir_name)


# ---------------------------------------------------------------------------
# OSV-path helpers  (original build pipeline)
# ---------------------------------------------------------------------------

def resolve_vulnerable_commit(entry: dict) -> str:
    """Resolve PARENT_OF: prefix to an actual commit SHA."""
    vc = entry["vulnerable_commit"]
    if not vc.startswith("PARENT_OF:"):
        return vc

    fixed = vc.split(":", 1)[1]
    repo_url = entry["repo_url"]

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = os.path.join(tmpdir, "repo")
        logger.info("Cloning %s to resolve parent of %s...", repo_url, fixed[:12])
        subprocess.run(
            ["git", "clone", "--no-checkout", repo_url, repo_dir],
            capture_output=True, check=True,
        )
        result = subprocess.run(
            ["git", "log", "--format=%H", "-n1", f"{fixed}~1"],
            cwd=repo_dir, capture_output=True, text=True,
        )
        parent = result.stdout.strip()
        if not parent:
            subprocess.run(
                ["git", "fetch", "origin", fixed],
                cwd=repo_dir, capture_output=True,
            )
            result = subprocess.run(
                ["git", "log", "--format=%H", "-n1", f"{fixed}~1"],
                cwd=repo_dir, capture_output=True, text=True,
            )
            parent = result.stdout.strip()

        if not parent:
            raise RuntimeError(f"Cannot resolve parent of {fixed} in {repo_url}")
        logger.info("Resolved vulnerable commit: %s", parent[:12])
        return parent


def resolve_oss_fuzz_project_commit(entry: dict) -> str:
    """Find the oss-fuzz project commit matching the vulnerable commit date."""
    project = entry["project"]
    repo_url = entry["repo_url"]
    vc = entry["vulnerable_commit"]

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = os.path.join(tmpdir, "repo")
        subprocess.run(
            ["git", "clone", "--no-checkout", repo_url, repo_dir],
            capture_output=True,
        )
        result = subprocess.run(
            ["git", "log", "--format=%aI", "-n1", vc],
            cwd=repo_dir, capture_output=True, text=True,
        )
        commit_date = result.stdout.strip()

    if not commit_date:
        logger.warning("Could not get date for commit %s, using HEAD", vc[:12])
        commit_date = datetime.now().isoformat()

    projects_dir = os.path.join("projects", project)
    result = subprocess.run(
        ["git", "log", f"--before={commit_date}", "-n1", "--format=%H",
         "--", projects_dir],
        cwd=config.OSS_FUZZ_DIR, capture_output=True, text=True,
    )
    oss_fuzz_commit = result.stdout.strip()

    if not oss_fuzz_commit:
        result = subprocess.run(
            ["git", "log", "-n1", "--format=%H", "--", projects_dir],
            cwd=config.OSS_FUZZ_DIR, capture_output=True, text=True,
        )
        oss_fuzz_commit = result.stdout.strip()

    return oss_fuzz_commit


def checkout_oss_fuzz_at_commit(project: str, oss_fuzz_commit: str):
    if not oss_fuzz_commit:
        logger.warning("No oss-fuzz commit for %s, using current HEAD", project)
        return
    projects_dir = os.path.join("projects", project)
    logger.info("Checking out oss-fuzz/%s at %s", projects_dir, oss_fuzz_commit[:12])
    subprocess.run(
        ["git", "checkout", oss_fuzz_commit, "--", projects_dir],
        cwd=config.OSS_FUZZ_DIR, capture_output=True, check=True,
    )


def restore_oss_fuzz_project(project: str):
    projects_dir = os.path.join("projects", project)
    subprocess.run(
        ["git", "checkout", "HEAD", "--", projects_dir],
        cwd=config.OSS_FUZZ_DIR, capture_output=True,
    )


def build_baseline_ossfuzz(entry: dict, experiment_dir: str) -> bool:
    """Build baseline fuzzer via OSS-Fuzz helper.py."""
    project = entry["project"]
    bin_dir = os.path.join(experiment_dir, "baseline", "bin")
    os.makedirs(bin_dir, exist_ok=True)

    logger.info("Building baseline for %s...", project)

    if not docker_util.build_image(project):
        logger.error("Failed to build image for %s", project)
        return False

    if not docker_util.build_fuzzers(project):
        logger.error("Failed to build fuzzers for %s", project)
        return False

    build_out = os.path.join(config.OSS_FUZZ_DIR, "build", "out", project)
    if os.path.isdir(build_out):
        _copy_build_output(build_out, bin_dir)
        logger.info("Copied baseline binaries to %s", bin_dir)
    else:
        logger.error("Build output not found at %s", build_out)
        return False

    return True


def extract_source_from_build(project: str, output_dir: str) -> bool:
    """Extract project source from Docker build container."""
    os.makedirs(output_dir, exist_ok=True)
    image_name = f"gcr.io/oss-fuzz/{project}"
    container_name = f"{project}_src_extract"

    result = subprocess.run(
        ["docker", "create", "--name", container_name, image_name],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logger.error("Failed to create container for source extraction: %s",
                      result.stderr)
        return False

    try:
        subprocess.run(
            ["docker", "cp", f"{container_name}:/src/.", output_dir],
            check=True, capture_output=True,
        )
        logger.info("Extracted source to %s", output_dir)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Failed to extract source: %s", e)
        return False
    finally:
        subprocess.run(["docker", "rm", container_name], capture_output=True)


def prepare_optimized_project(project: str) -> str:
    """Copy project dir as <project>_opt. Returns opt project name."""
    opt_project = f"{project}_opt"
    base_dir = os.path.join(config.OSS_FUZZ_DIR, "projects", project)
    opt_dir = os.path.join(config.OSS_FUZZ_DIR, "projects", opt_project)
    if os.path.exists(opt_dir):
        shutil.rmtree(opt_dir)
    shutil.copytree(base_dir, opt_dir)
    logger.info("Created optimized project variant: %s", opt_project)
    return opt_project


def build_optimized_ossfuzz(
    entry: dict, experiment_dir: str, opt_project: str,
    source_dir: str | None = None,
    capture_log: bool = False,
) -> bool | tuple[bool, str]:
    """Build optimized fuzzer via OSS-Fuzz helper.py.

    Args:
        capture_log: If True, return (success, build_log) instead of just bool.
    """
    bin_dir = os.path.join(experiment_dir, "optimized", "bin")
    os.makedirs(bin_dir, exist_ok=True)

    logger.info("Building optimized variant for %s...", opt_project)

    if not docker_util.build_image(opt_project):
        logger.error("Failed to build image for %s", opt_project)
        if capture_log:
            return False, "Docker image build failed"
        return False

    if capture_log:
        success, log = docker_util.build_fuzzers(
            opt_project, source_path=source_dir, capture_log=True,
        )
    else:
        success = docker_util.build_fuzzers(opt_project, source_path=source_dir)
        log = ""

    if not success:
        logger.error("Failed to build optimized fuzzers for %s", opt_project)
        if capture_log:
            return False, log
        return False

    build_out = os.path.join(config.OSS_FUZZ_DIR, "build", "out", opt_project)
    if os.path.isdir(build_out):
        _copy_build_output(build_out, bin_dir)
        logger.info("Copied optimized binaries to %s", bin_dir)
        if capture_log:
            return True, log
        return True

    logger.error("Optimized build output not found at %s", build_out)
    if capture_log:
        return False, log + "\nBuild output directory not found"
    return False


# ---------------------------------------------------------------------------
# ARVO-path helpers
# ---------------------------------------------------------------------------

def _lazy_import_arvo():
    """Import ARVO module lazily (only when local_id entries exist)."""
    from lib import arvo as arvo_util
    return arvo_util


def copy_arvo_output(local_id: int, dest_dir: str) -> bool:
    arvo_util = _lazy_import_arvo()
    arvo_out = arvo_util.get_arvo_build_output(local_id)
    if not arvo_out.exists():
        logger.error("ARVO build output not found at %s", arvo_out)
        return False
    os.makedirs(dest_dir, exist_ok=True)
    _copy_build_output(str(arvo_out), dest_dir)
    logger.info("Copied ARVO build output to %s", dest_dir)
    return True


def extract_source_from_arvo_image(local_id: int, output_dir: str) -> bool:
    """Extract /src from an ARVO Docker image into output_dir.

    Fallback for when build_arvo_with_source_intercept returns an empty
    source tree (happens when the Dockerfile clones the source itself
    rather than it being listed as a srcmap component).
    """
    image_name = f"gcr.io/oss-fuzz/{local_id}"
    container_name = f"arvo_{local_id}_src_extract"

    # Remove stale container if any
    subprocess.run(["docker", "rm", container_name],
                   capture_output=True)

    result = subprocess.run(
        ["docker", "create", "--name", container_name, image_name],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logger.error("Failed to create container from %s: %s",
                     image_name, result.stderr)
        return False

    try:
        subprocess.run(
            ["docker", "cp", f"{container_name}:/src/.", output_dir],
            check=True, capture_output=True,
        )
        logger.info("Extracted ARVO source from %s to %s", image_name, output_dir)
        return True
    except subprocess.CalledProcessError as e:
        logger.error("Failed to extract source from %s: %s", image_name, e)
        return False
    finally:
        subprocess.run(["docker", "rm", container_name], capture_output=True)


def rebuild_with_modified_source_arvo(
    local_id: int, issue: dict, source_dir: Path, dest_bin_dir: str,
    capture_log: bool = False,
) -> bool | tuple[bool, str]:
    """Rebuild using ARVO Docker image with modified source mounted.

    Args:
        capture_log: If True, return (success, build_log) tuple.
    """
    logger.info("Rebuilding with modified source for %s...", local_id)

    import arvo_reproducer
    from arvo_utils import OSS_OUT, OSS_WORK

    project_out = OSS_OUT / f"{local_id}_OUT"
    project_work = OSS_WORK / f"{local_id}_WORK"

    if project_out.exists():
        force_remove(project_out)
    if project_work.exists():
        force_remove(project_work)

    project_out.mkdir(exist_ok=True)
    project_work.mkdir(exist_ok=True)

    clone_prep_cmd = _make_arvo_clone_prep_cmd(
        source_dir=source_dir,
        state_dir=project_work,
    )
    prep_result = subprocess.run(clone_prep_cmd, capture_output=True, text=True)
    if prep_result.returncode != 0:
        build_log = (prep_result.stdout or "") + (prep_result.stderr or "")
        logger.error("Failed to prepare ARVO source clone for %s", local_id)
        if capture_log:
            return False, build_log
        return False

    cmd = _make_arvo_build_container_cmd(
        local_id=local_id,
        issue=issue,
        source_mount=project_work / "src-clone",
        out_dir=project_out,
        work_dir=project_work,
    )

    logger.info("Docker Run:\n%s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    build_log = result.stdout + result.stderr

    if result.returncode != 0:
        logger.error("Rebuild with modified source failed for %s", local_id)
        if capture_log:
            return False, build_log
        return False

    ok = copy_arvo_output(local_id, dest_bin_dir)
    if capture_log:
        return ok, build_log
    return ok


# ---------------------------------------------------------------------------
# n132/arvo prebuilt-image helpers (Monorail-id ARVO targets)
# ---------------------------------------------------------------------------

def _seed_corpus_is_real(experiment_dir: str | Path) -> bool:
    """True if the merged seed corpus has real (non-fallback) files."""
    merged = Path(experiment_dir) / "seed_corpus" / "merged"
    if not merged.is_dir():
        return False
    return any(
        p.is_file() and not p.name.startswith("seed_fallback")
        for p in merged.rglob("*")
    )


def _dir_has_real_corpus(d: str | Path) -> bool:
    d = Path(d)
    return d.is_dir() and any(
        p.is_file() and not p.name.startswith("seed_fallback")
        for p in d.rglob("*")
    )


def _phase2_corpus_source(experiment_dir: str | Path, entry: dict) -> tuple[Path, int]:
    """Resolve the corpus used for phase-2 profile/replay/optimize.

    Policy: use ONLY the seed corpus PROVIDED WITH THE PROJECT (the bundled
    ``<target>_seed_corpus.zip``) -- never the GCS accumulated public corpus. This
    matches what the phase-3 campaign actually starts from. Resolution order:

        seed_corpus/build  ->  bundled <target>_seed_corpus.zip  ->  local cache.

    Returns (corpus_dir, build_duration_secs); build_duration is always 0 -- phase-2
    now augments the seed corpus with captured mutations (see
    _prebuild_phase2_corpus_and_profile) rather than fuzz-generating from scratch.
    """
    ed = Path(experiment_dir)
    ft = entry.get("fuzz_target", "")

    # 1) bundled <target>_seed_corpus.zip: the gcr path pre-extracts it into
    #    seed_corpus/build; the n132 image path ships it in the extracted /out.
    if _dir_has_real_corpus(ed / "seed_corpus" / "build"):
        return ed / "seed_corpus" / "build", 0
    # 2) extract the bundled zip straight from the baseline /out if build/ was empty.
    if ft:
        zip_path = ed / "baseline" / "bin" / f"{ft}_seed_corpus.zip"
        if zip_path.is_file():
            bundled = ed / "seed_corpus" / "bundled"
            bundled.mkdir(parents=True, exist_ok=True)
            import zipfile
            try:
                with zipfile.ZipFile(zip_path) as zf:
                    for info in zf.infolist():
                        if not info.is_dir():
                            (bundled / Path(info.filename).name).write_bytes(
                                zf.read(info))
            except Exception as exc:
                logger.warning("bundled seed_corpus.zip extract failed: %s", exc)
            if _dir_has_real_corpus(bundled):
                return bundled, 0
    # 3) local corpus-cache fallback (also project-provided, not GCS) merged in.
    if _dir_has_real_corpus(ed / "seed_corpus" / "merged"):
        return ed / "seed_corpus" / "merged", 0
    # 4) nothing usable -> the merged dir (with its 1-byte fallback seed); the
    #    mutation-capture step still grows it into a real corpus.
    return ed / "seed_corpus" / "merged", 0


def _phase2_mutation_builder(entry: dict | None) -> tuple[str | None, str]:
    """Resolve (builder_image, compile_cmd) for the mutation-capture shim build.

    ARVO image paths only: n132/arvo images build via ``arvo compile``; the ARVO
    reproducer path uses ``gcr.io/oss-fuzz/<local_id>`` + ``compile``. Returns
    (None, "") when no ARVO builder image is available (e.g. an OSV entry), so the
    caller falls back to seed-only profiling.
    """
    if not entry:
        return None, ""
    image = str(entry.get("image") or "")
    if "n132/arvo" in image:
        return image, "arvo compile"
    local_id = entry.get("local_id")
    if local_id:
        return f"gcr.io/oss-fuzz/{local_id}", "compile"
    return None, ""


def _make_n132_build_container_cmd(
    image: str, source_mount: Path, out_dir: Path, work_dir: Path,
) -> list[str]:
    """`arvo compile` rebuild from a bind-mounted (modified) /src into /out.

    The n132/arvo image bakes SANITIZER/FUZZING_ENGINE, so no build env is
    needed; `arvo compile` runs the project's OSS-Fuzz build against /src.
    """
    return [
        "docker", "run", "--rm", "--privileged",
        "-v", f"{Path(source_mount)}:/src",
        "-v", f"{Path(out_dir)}:/out",
        "-v", f"{Path(work_dir)}:/work",
        image, "arvo", "compile",
    ]


def extract_n132_image(
    image: str, *, source_dir: Path, baseline_bin_dir: str, poc_dir: str,
    pull_timeout: int = 1200, run_timeout: int = 900,
) -> tuple[bool, str]:
    """Pull n132/arvo:<id>-vul; extract /src, /out, and the PoC; verify baseline.

    Source and baseline binaries are pulled out with `docker cp` so the host
    copies are owned by the invoking user (the optimizer must edit the source).
    The PoC is materialized and the baseline reproduce is checked by running the
    image's `arvo` contract. Returns (baseline_crashed, reproduce_log).
    """
    src_out = Path(source_dir) / "src"
    src_out.mkdir(parents=True, exist_ok=True)
    os.makedirs(baseline_bin_dir, exist_ok=True)
    os.makedirs(poc_dir, exist_ok=True)

    pull = subprocess.run(
        ["docker", "pull", image],
        capture_output=True, text=True, errors="replace", timeout=pull_timeout,
    )
    if pull.returncode != 0:
        return False, f"docker pull failed: {(pull.stderr or '')[-400:]}"

    # Reproduce + extract the PoC in one run: `arvo` runs /out/<target> /tmp/poc.
    poc_path = Path(poc_dir)
    subprocess.run(
        ["docker", "run", "--rm", "--privileged",
         "-v", f"{poc_path}:/pocout", "--entrypoint", "/bin/bash", image, "-lc",
         "arvo > /pocout/repro.log 2>&1; echo \"arvo_rc=$?\" >> /pocout/repro.log; "
         "cp /tmp/poc /pocout/poc_input 2>/dev/null || true; "
         "chmod a+rX /pocout/poc_input /pocout/repro.log 2>/dev/null || true"],
        capture_output=True, text=True, errors="replace", timeout=run_timeout,
    )
    repro_log = ""
    log_file = poc_path / "repro.log"
    if log_file.exists():
        repro_log = log_file.read_text(errors="replace")
    crashed = (
        "AddressSanitizer:" in repro_log
        or "ERROR: libFuzzer:" in repro_log
        or "SUMMARY:" in repro_log
        or "arvo_rc=1" in repro_log
    )

    # Extract /src and /out via docker cp (user-owned: editable + runnable).
    container = "n132_" + re.sub(r"[^a-zA-Z0-9_]", "_", image) + "_extract"
    subprocess.run(["docker", "rm", "-f", container], capture_output=True)
    create = subprocess.run(
        ["docker", "create", "--name", container, image],
        capture_output=True, text=True, errors="replace",
    )
    if create.returncode != 0:
        return crashed, repro_log + f"\ndocker create failed: {(create.stderr or '')[-300:]}"
    try:
        cp_src = subprocess.run(
            ["docker", "cp", f"{container}:/src/.", str(src_out)],
            capture_output=True, text=True, errors="replace",
        )
        cp_out = subprocess.run(
            ["docker", "cp", f"{container}:/out/.", baseline_bin_dir],
            capture_output=True, text=True, errors="replace",
        )
        if cp_src.returncode != 0 or cp_out.returncode != 0:
            repro_log += ("\ndocker cp failed: "
                          + (cp_src.stderr or "") + (cp_out.stderr or ""))[-400:]
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True)

    return crashed, repro_log


def rebuild_with_modified_source_n132(
    image: str, source_dir: Path, dest_bin_dir: str, capture_log: bool = False,
) -> bool | tuple[bool, str]:
    """Rebuild via `arvo compile` with the modified source bind-mounted at /src."""
    logger.info("Rebuilding (n132 arvo compile) for %s...", image)
    state = Path(tempfile.mkdtemp(prefix="n132-rebuild-"))
    try:
        prep = subprocess.run(
            _make_arvo_clone_prep_cmd(source_dir=source_dir, state_dir=state),
            capture_output=True, text=True, errors="replace",
        )
        if prep.returncode != 0:
            build_log = (prep.stdout or "") + (prep.stderr or "")
            logger.error("n132 source-clone prep failed for %s", image)
            return (False, build_log) if capture_log else False

        cmd = _make_n132_build_container_cmd(
            image, state / "src-clone", state / "out", state / "work",
        )
        logger.info("Docker Run:\n%s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        build_log = (result.stdout or "") + (result.stderr or "")
        if result.returncode != 0:
            logger.error("n132 arvo compile failed for %s", image)
            return (False, build_log) if capture_log else False

        os.makedirs(dest_bin_dir, exist_ok=True)
        _copy_build_output(str(state / "out"), dest_bin_dir)
        return (True, build_log) if capture_log else True
    finally:
        force_remove(state)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _copy_build_output(src_dir: str, dst_dir: str):
    """Copy all files/dirs from src_dir to dst_dir."""
    os.makedirs(dst_dir, exist_ok=True)
    for item in os.listdir(src_dir):
        src = os.path.join(src_dir, item)
        dst = os.path.join(dst_dir, item)
        if os.path.isfile(src):
            shutil.copy2(src, dst)
        elif os.path.isdir(src):
            if os.path.exists(dst):
                shutil.rmtree(dst)
            shutil.copytree(src, dst)


def verify_poc_crash(
    bin_dir: str, fuzz_target: str, poc_path: str,
    timeout: int = config.QUICK_VERIFY_DURATION,
) -> bool:
    """Run the fuzzer with the PoC input and check for a crash."""
    fuzzer_path = os.path.join(bin_dir, fuzz_target)
    if not os.path.isfile(fuzzer_path):
        logger.warning("Fuzzer binary not found: %s", fuzzer_path)
        return False

    os.chmod(fuzzer_path, 0o755)

    cmd = [
        "docker", "run", "--rm", "--privileged",
        "--memory", config.MEMORY_LIMIT,
        "-v", f"{bin_dir}:/out:ro",
        "-v", f"{poc_path}:/testcase:ro",
        "gcr.io/oss-fuzz-base/base-runner",
        "/bin/bash", "-c",
        f"timeout {timeout} /out/{fuzz_target} /testcase 2>&1; exit 0",
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 30,
        )
        output = result.stdout + result.stderr
        crash_indicators = [
            "SUMMARY:", "AddressSanitizer", "ERROR:", "SEGV",
            "heap-buffer-overflow", "stack-buffer-overflow",
            "use-after-free", "double-free", "buffer-overflow",
        ]
        for indicator in crash_indicators:
            if indicator in output:
                logger.info("PoC verification: crash detected (%s)", indicator)
                return True

        logger.warning("PoC verification: no crash detected")
        return False
    except subprocess.TimeoutExpired:
        logger.warning("PoC verification: timed out after %ds", timeout)
        return False
    except Exception as e:
        logger.error("PoC verification failed: %s", e)
        return False


def verify_crash_reproduction(entry: dict, experiment_dir: str) -> dict[str, bool]:
    """Verify both baseline and optimized fuzzer binaries exist."""
    results = {"baseline": False, "optimized": False}
    fuzz_target = entry.get("fuzz_target", "")

    if not fuzz_target:
        logger.warning("No fuzz target specified, skipping verification")
        return results

    for variant in ["baseline", "optimized"]:
        bin_dir = os.path.join(experiment_dir, variant, "bin")
        fuzzer_path = os.path.join(bin_dir, fuzz_target)
        if os.path.isfile(fuzzer_path):
            logger.info("%s/%s fuzzer binary exists", variant, fuzz_target)
            results[variant] = True
        else:
            logger.warning("%s/%s fuzzer binary not found", variant, fuzz_target)

    return results


def apply_fold_deterministic_calls(
    source_dir: str, fuzz_target: str, diff_output_dir: str,
    project: str = "",
) -> bool:
    """Apply apply-fuzz-source-folds optimization via a single Codex session.

    This is used by the ARVO path where the build function is different.
    For the OSV path, use optimize_and_build() which integrates the
    build-retry loop.
    """
    os.makedirs(diff_output_dir, exist_ok=True)
    _stage_project_fuzz_support(source_dir, project)

    subprocess.run(["git", "init"], cwd=source_dir, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=source_dir, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "baseline"],
        cwd=source_dir, capture_output=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "benchmark",
             "GIT_AUTHOR_EMAIL": "bench@test",
             "GIT_COMMITTER_NAME": "benchmark",
             "GIT_COMMITTER_EMAIL": "bench@test"},
    )

    harness_path = _find_harness_source(source_dir, fuzz_target)
    logger.info("Applying %s to %s (target: %s, harness: %s)...",
                config.PHASE2_OPTIMIZER_SKILL, source_dir, fuzz_target, harness_path)

    backend = _optimizer_backend()
    prompt = _make_apply_fuzz_source_folds_prompt(harness_path, backend=backend)
    os.environ["FUZZ_TARGET"] = fuzz_target
    codex_result = _invoke_agent_capture(
        source_dir, prompt, project=project, backend=backend,
        timeout=getattr(config, "PHASE2_OPTIMIZER_TIMEOUT_SECS", None),
    )
    if codex_result["timed_out"]:
        logger.error(
            "%s optimization for %s/%s timed out", backend, project, fuzz_target,
        )
        return False
    if _codex_output_is_low_confidence(
        codex_result["stdout"], codex_result["stderr"],
    ):
        logger.error(
            "Codex optimization for %s/%s was low-confidence; refusing to "
            "use a static-only result",
            project, fuzz_target,
        )
        return False

    # Save the diff
    diff_result = subprocess.run(
        ["git", "diff", "HEAD"],
        cwd=source_dir, capture_output=True, text=True,
    )
    with open(os.path.join(diff_output_dir, "optimization.diff"), "w") as f:
        f.write(diff_result.stdout)

    stat_result = subprocess.run(
        ["git", "diff", "--stat", "HEAD"],
        cwd=source_dir, capture_output=True, text=True,
    )
    with open(os.path.join(diff_output_dir, "changes_summary.txt"), "w") as f:
        f.write(stat_result.stdout)

    num_changed = len([
        line for line in stat_result.stdout.strip().split("\n")
        if line and "|" in line
    ])
    logger.info("%s made changes to %d files",
                config.PHASE2_OPTIMIZER_SKILL, num_changed)

    if num_changed == 0:
        logger.warning("No changes were made by %s", config.PHASE2_OPTIMIZER_SKILL)
        return False

    _clean_build_artifacts(source_dir)
    return True


def _find_harness_source(source_dir: str, fuzz_target: str) -> str:
    """Find the harness source file in the source tree.

    Searches for files containing LLVMFuzzerTestOneInput in source_dir
    and its parent directory. Returns the path relative to source_dir,
    or the fuzz_target name as-is if not found.
    """
    # Search in source_dir and one level up (harness may be alongside project dir)
    search_dirs = [source_dir]
    parent = os.path.dirname(source_dir)
    if parent and parent != source_dir:
        search_dirs.append(parent)

    candidates = []
    for search_dir in search_dirs:
        try:
            result = subprocess.run(
                ["grep", "-rl", "LLVMFuzzerTestOneInput", "."],
                cwd=search_dir, capture_output=True, text=True, timeout=30,
            )
        except subprocess.TimeoutExpired:
            continue
        if result.returncode != 0 or not result.stdout.strip():
            continue

        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            if any(skip in line for skip in [
                "aflplusplus", "libfuzzer", "honggfuzz", ".git/",
                "compiler-rt", "FuzzerMain", "FuzzerLoop",
                "aflpp_driver", "fuzztest", "centipede", "/puzzles/",
            ]):
                continue
            # Convert to path relative to source_dir
            full = os.path.normpath(os.path.join(search_dir, line))
            rel = os.path.relpath(full, source_dir)
            candidates.append(rel)

    if not candidates:
        logger.warning("Could not find LLVMFuzzerTestOneInput for %s", fuzz_target)
        return fuzz_target

    # Try to match by fuzz_target binary name
    target_lower = fuzz_target.lower()
    core_parts = target_lower.replace("_fuzzer", "").replace("fuzz_", "").split("_")

    # Exact filename match first
    for c in candidates:
        basename = os.path.basename(c).lower()
        bare = basename.replace(".c", "").replace(".cc", "").replace(".cpp", "")
        if fuzz_target.lower() in basename or bare == target_lower:
            logger.info("Found harness source (exact match): %s", c)
            return c

    # Partial match on core name parts
    for c in candidates:
        c_lower = c.lower()
        if any(part in c_lower for part in core_parts if len(part) > 3):
            logger.info("Found harness source (partial match): %s", c)
            return c

    # If only one candidate, use it
    if len(candidates) == 1:
        logger.info("Found single harness source: %s", candidates[0])
        return candidates[0]

    # Multiple candidates — log them and return the first
    logger.info("Multiple harness candidates for %s: %s", fuzz_target, candidates[:5])
    return candidates[0]


def _is_infra_build_error(build_log: str) -> bool:
    """Check if the build error is infrastructure-related (not code)."""
    infra_patterns = [
        "No such file or directory",
        "No rule to make target",
        "command not found",
        "Permission denied",
        "docker",
        "Could not resolve host",
        "fatal: repository",
    ]
    # Look at the last 50 lines for the actual error
    tail = "\n".join(build_log.strip().split("\n")[-50:])
    # Only flag as infra if there are NO compiler errors in the log
    has_compiler_error = any(
        pat in build_log
        for pat in [": error:", ": fatal error:", "undefined reference"]
    )
    if has_compiler_error:
        return False
    return any(pat in tail for pat in infra_patterns)


def _clean_build_artifacts(source_dir: str):
    """Remove build artifacts from source tree to avoid stale .o files."""
    for pattern in ["*.o", "*.a", "*.so", "*.so.*", "*.dylib"]:
        for root, dirs, files in os.walk(source_dir):
            for fname in files:
                if (fname.endswith(pattern.lstrip("*")) and
                        not fname.startswith("llvm-")):
                    try:
                        os.remove(os.path.join(root, fname))
                    except OSError:
                        pass
    for cache_name in ["cachedObjs", "CMakeCache.txt", "CMakeFiles",
                       "build", "_build"]:
        for root, dirs, _files in os.walk(source_dir):
            if cache_name in dirs:
                subprocess.run(["rm", "-rf", os.path.join(root, cache_name)],
                               capture_output=True)


def _project_workdir_from_dockerfile(project: str) -> str:
    """Resolve the effective project workdir used by OSS-Fuzz helper.py."""
    dockerfile = (
        Path(config.OSS_FUZZ_DIR) / "projects" / project / "Dockerfile"
    )
    workdir = "/src"
    if not dockerfile.exists():
        return workdir

    for raw_line in dockerfile.read_text().splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line.upper().startswith("WORKDIR "):
            continue
        value = line.split(None, 1)[1].strip().strip("'\"")
        value = value.replace("${SRC}", "/src").replace("$SRC", "/src")
        if value.startswith("/"):
            workdir = os.path.normpath(value)
        else:
            workdir = os.path.normpath(os.path.join(workdir, value))

    return workdir


def _phase2_fixed_corpus_dir(diff_output_dir: str | Path) -> Path:
    """Path of the fixed corpus snapshot built once and replayed everywhere."""
    return Path(diff_output_dir) / "profiles" / "fixed_corpus"


def _cap_corpus_dir(corpus_dir: Path, experiment_dir: Path, cap: int) -> Path:
    """Return a dir holding at most ``cap`` files from ``corpus_dir`` (deterministic
    first-N by sorted name). Used to bound the optimizer's profiling/validation
    corpus so each docker step (crash-filter, replay) completes within the agent's
    600s tool-timeout — large corpora (e.g. selinux ~14k) otherwise force the agent
    to background docker and yield in headless single-turn mode. The authoritative
    replay comparison is measured separately on the FULL corpus.
    """
    corpus_dir = Path(corpus_dir)
    files = sorted(p for p in corpus_dir.glob("*") if p.is_file())
    if len(files) <= cap:
        return corpus_dir
    capped = Path(experiment_dir) / "seed_corpus" / f"capped_{cap}"
    capped.mkdir(parents=True, exist_ok=True)
    for old in capped.glob("*"):
        if old.is_file():
            old.unlink()
    for p in files[:cap]:
        shutil.copy2(p, capped / p.name)
    logger.info("Capped optimizer corpus: %d -> %d files (%s)",
                len(files), cap, capped)
    return capped


def _make_phase2_profile_env(
    experiment_dir: str | Path,
    diff_output_dir: str | Path,
    out_dir: str | Path,
    *,
    profile_cpu: int | None = None,
    baseline_profile_duration: int | None = None,
    refresh_profile_duration: int | None = None,
    corpus_build_duration: int | None = None,
    corpus_dir: str | Path | None = None,
    entry: dict | None = None,
    baseline_out_dir: str | Path | None = None,
) -> dict[str, str]:
    """Build env vars for profile-once-fuzz-folds phase-2 optimization.

    The skill grows ONE fixed corpus off the baseline binary, profiles the
    baseline once on a replay of it, then iterates hotspots with a replay-timing
    gate (no re-profiling). ``baseline_profile_duration`` /
    ``refresh_profile_duration`` are still accepted because the orchestrator
    passes them by introspection, but they are unused here: there is no baseline
    profile window and no refresh profile in this loop.
    """
    experiment_dir = Path(experiment_dir)
    diff_output_dir = Path(diff_output_dir)
    profiles_dir = diff_output_dir / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)

    if profile_cpu is None:
        reserved_cores = getattr(config, "RESERVED_CORES", 1)
        profile_cpu = max(int(reserved_cores) - 1, 0)
    # Resolve the phase-2 corpus per policy (GCS -> bundled -> 1h-generate) when an
    # entry is supplied; an explicit corpus_dir / corpus_build_duration still wins.
    if entry is not None and (corpus_dir is None or corpus_build_duration is None):
        resolved_dir, resolved_dur = _phase2_corpus_source(experiment_dir, entry)
        if corpus_dir is None:
            corpus_dir = resolved_dir
        if corpus_build_duration is None:
            corpus_build_duration = resolved_dur
    if corpus_dir is None:
        corpus_dir = experiment_dir / "seed_corpus" / "merged"
    if corpus_build_duration is None:
        corpus_build_duration = int(
            getattr(config, "PHASE2_CORPUS_BUILD_DURATION_SECS", 3600)
        )

    # Optional cap on the optimizer's profiling/validation corpus so every docker
    # step stays under the agent's tool-timeout (see _cap_corpus_dir). Reported
    # replay speedups are still measured on the full corpus, separately.
    _max_files = os.environ.get("FUZZ_SOURCE_FOLDS_MAX_CORPUS_FILES")
    if _max_files:
        try:
            _cap = int(_max_files)
        except ValueError:
            _cap = 0
        if _cap > 0:
            corpus_dir = _cap_corpus_dir(Path(corpus_dir), experiment_dir, _cap)

    env = {
        "FUZZ_SOURCE_FOLDS_CORPUS_DIR": str(corpus_dir),
        # Fixed corpus: build_corpus.py grows it once off the baseline binary and
        # freezes a flat snapshot here. The single profile and every replay-timing
        # gate use this exact set, so what is profiled is what is measured.
        "FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR": str(
            _phase2_fixed_corpus_dir(diff_output_dir)
        ),
        "FUZZ_SOURCE_FOLDS_CORPUS_BUILD_DURATION": str(corpus_build_duration),
        "FUZZ_SOURCE_FOLDS_OUT_DIR": str(Path(out_dir)),
        "FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR": str(profiles_dir),
        "FUZZ_SOURCE_FOLDS_PROFILE_CPU": str(profile_cpu),
        "FUZZ_SOURCE_FOLDS_REPLAY_REPEATS": str(
            int(getattr(config, "PHASE2_REPLAY_REPEATS", 3))
        ),
        # Time-budget corpus sizing: the agent-run fallback (when the harness
        # prebuild did not run) should pass this to build_corpus.py
        # --replay-budget-secs so a slow target gets a tractable corpus too.
        "FUZZ_SOURCE_FOLDS_CORPUS_REPLAY_BUDGET": str(
            int(getattr(config, "PHASE2_CORPUS_REPLAY_BUDGET_SECS", 1800))
        ),
    }
    # Baseline binary: used to grow the corpus, take the one profile, anchor the
    # baseline replay time, and as the reference in the replay-timing gate (a fold
    # is kept only if the optimized binary replays the same frozen corpus faster;
    # coverage is allowed to drop).
    if baseline_out_dir is not None:
        env["FUZZ_SOURCE_FOLDS_BASELINE_OUT_DIR"] = str(Path(baseline_out_dir))

    # Mutation-augmented profiling: when enabled and an ARVO builder image is
    # available, the prebuild captures the mutations libFuzzer generates from the
    # seed corpus and profiles + gates on seed+mutations (see
    # _prebuild_phase2_corpus_and_profile). Absent these vars it stays seed-only.
    if getattr(config, "PHASE2_MUTATION_ENABLED", False) and entry is not None:
        mut_image, mut_compile = _phase2_mutation_builder(entry)
        if mut_image:
            env["FUZZ_SOURCE_FOLDS_MUTATION_IMAGE"] = mut_image
            env["FUZZ_SOURCE_FOLDS_MUTATION_COMPILE_CMD"] = mut_compile
            env["FUZZ_SOURCE_FOLDS_MUTATION_SANITIZER"] = "address"
            env["FUZZ_SOURCE_FOLDS_MUTATION_CAP"] = str(
                int(getattr(config, "PHASE2_MUTATION_CAP", 50000)))
            env["FUZZ_SOURCE_FOLDS_MUTATION_DURATION"] = str(
                int(getattr(config, "PHASE2_MUTATION_DURATION_SECS", 120)))
            env["FUZZ_SOURCE_FOLDS_MUTATION_EVERY"] = str(
                int(getattr(config, "PHASE2_MUTATION_EVERY", 1)))
    return env


def _augment_corpus_with_mutations(env: dict[str, str], fuzz_target: str) -> str | None:
    """Capture mutations from the seed corpus and return a combined seed+mutations dir.

    Builds a shim-instrumented target (custom-mutator that saves every mutation),
    fuzzes it from the seed corpus, freezes the captured mutations, and writes a
    combined ``corpus_combined`` dir (seeds + mutations). That combined set becomes
    the fixed corpus that is profiled AND used as the replay-timing gate, so the
    optimizer targets the hotspots of the real fuzzing workload.

    Mutation-augmented profiling is the required, non-optional path. When it cannot
    be performed -- no ARVO builder image, import/capture failure, or 0 mutations
    captured -- and config.PHASE2_MUTATION_REQUIRED is set (the default), this
    raises MutationAugmentationError so the caller HARD-FAILS the target rather than
    silently falling back to seed-only profiling. Returns the combined corpus path
    on success. Only when mutation is explicitly not required (legacy opt-out) does
    it return None to signal a seed-only corpus.
    """
    mutation_enabled = bool(getattr(config, "PHASE2_MUTATION_ENABLED", False))
    mutation_required = mutation_enabled and bool(
        getattr(config, "PHASE2_MUTATION_REQUIRED", True))

    def _fail(msg: str, exc: Exception | None = None):
        """Hard-fail when required, else fall back to seed-only (return None)."""
        if mutation_required:
            raise MutationAugmentationError(msg + "; no seed-only fall-back") from exc
        logger.warning("%s; seed-only profiling", msg)
        return None

    image = env.get("FUZZ_SOURCE_FOLDS_MUTATION_IMAGE")
    seed_dir = env.get("FUZZ_SOURCE_FOLDS_CORPUS_DIR")
    profile_root = env.get("FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR")
    if not (image and seed_dir and profile_root):
        return _fail("mutation-augmented profiling unavailable: no ARVO builder "
                     f"image for this target (image={image!r})")
    try:
        import mutation_capture
    except Exception as exc:  # noqa: BLE001
        return _fail(f"mutation_capture import failed ({exc})", exc)

    profiles = Path(profile_root)
    cap = int(env.get("FUZZ_SOURCE_FOLDS_MUTATION_CAP", "20000"))
    duration = int(env.get("FUZZ_SOURCE_FOLDS_MUTATION_DURATION", "600"))
    every = int(env.get("FUZZ_SOURCE_FOLDS_MUTATION_EVERY", "1"))
    # Reservoir-sample the whole run (uniform) by default; set to 0 for the legacy
    # first-N prefix (biased to the opening of the run, but early-exits faster).
    reservoir = env.get("FUZZ_SOURCE_FOLDS_MUTATION_RESERVOIR", "1") not in ("0", "false", "False", "")
    # Guaranteed one-pass over the seed queue so every input is represented >=1x
    # (queue_depth mutations each, libFuzzer mutate_depth=5).
    guarantee_queue = env.get("FUZZ_SOURCE_FOLDS_MUTATION_QUEUE_PASS", "1") not in ("0", "false", "False", "")
    queue_depth = int(env.get("FUZZ_SOURCE_FOLDS_MUTATION_QUEUE_DEPTH", "5"))
    # Run for max(duration, time_for_one_queue) so slow/large-queue targets get >=1 full pass.
    ensure_one_queue_pass = env.get("FUZZ_SOURCE_FOLDS_MUTATION_ENSURE_QUEUE_PASS", "1") not in ("0", "false", "False", "")
    sanitizer = env.get("FUZZ_SOURCE_FOLDS_MUTATION_SANITIZER", "address")
    compile_cmd = env.get("FUZZ_SOURCE_FOLDS_MUTATION_COMPILE_CMD", "compile")
    cpu = int(env.get("FUZZ_SOURCE_FOLDS_PROFILE_CPU", "0") or 0)
    seed = int(getattr(config, "BASE_SEED", 1337))

    try:
        logger.info("Phase-2 mutation capture: shim-build %s, generate <=%d mutations "
                    "(%ss) for %s", image, cap, duration, fuzz_target)
        frozen_dir, meta = mutation_capture.run_mutation_capture(
            image=image, shim_src=mutation_capture.SHIM_SRC_DEFAULT,
            gen_out_dir=profiles / "mutgen", seed_corpus_dir=seed_dir,
            work_corpus_dir=profiles / "gen_corpus", mut_raw_dir=profiles / "mutations_raw",
            frozen_dir=profiles / "mutations", fuzz_target=fuzz_target,
            duration=duration, seed=seed, cap=cap, every=every, reservoir=reservoir,
            guarantee_queue=guarantee_queue, queue_depth=queue_depth,
            ensure_one_queue_pass=ensure_one_queue_pass,
            cpu=cpu, sanitizer=sanitizer, compile_cmd=compile_cmd,
            build_timeout=int(getattr(config, "PHASE2_CRASH_FILTER_TIMEOUT_SECS", 3600)),
        )
    except MutationAugmentationError:
        raise
    except Exception as exc:  # noqa: BLE001
        return _fail(f"mutation capture failed ({exc})", exc)

    # A capture that ran but produced no mutations is NOT a usable mutation profile
    # (it would degrade to seed-only). Hard-fail when required.
    mut_files = [p for p in sorted(Path(frozen_dir).rglob("*")) if p.is_file()]
    if not mut_files:
        return _fail(f"mutation capture produced 0 mutations for {fuzz_target} "
                     f"(meta={meta})")

    # Combine seed + mutations into one flat corpus (seeds first, then mutations).
    combined = profiles / "corpus_combined"
    if combined.exists():
        shutil.rmtree(combined, ignore_errors=True)
    combined.mkdir(parents=True, exist_ok=True)
    n = 0
    for p in sorted(Path(seed_dir).rglob("*")):
        if p.is_file():
            shutil.copy2(p, combined / f"seed_{n:08d}")
            n += 1
    m = 0
    for p in mut_files:
        shutil.copy2(p, combined / f"mut_{m:08d}")
        m += 1
    logger.info("Phase-2 combined corpus: %d seeds + %d mutations = %d files (%s)",
                n, m, n + m, combined)
    env["FUZZ_SOURCE_FOLDS_CORPUS_DIR"] = str(combined)
    return str(combined)


def _prebuild_phase2_corpus_and_profile(env: dict[str, str], fuzz_target: str) -> bool:
    """Grow+freeze the fixed corpus and profile the baseline IN THE HARNESS, before
    the optimizer agent runs, and hand the agent the ready artifacts.

    Why: the optimizer is a single-turn ``claude -p`` agent with a ~600s per-tool
    timeout. The crash-filter + replay-profile over a large corpus (e.g. selinux
    ~14k, libavc ~17k files) blows that timeout, so the agent backgrounds the
    docker step and the turn ends with no fold ("yield" quirk). These two steps are
    deterministic infrastructure — they need no LLM — so the harness (which is not
    turn-limited) runs them on the FULL corpus and writes the frozen snapshot +
    profile to the dirs the skill already reads. On success it sets
    ``FUZZ_SOURCE_FOLDS_PREBUILT_CORPUS=1`` so the skill skips its own build/profile.

    Best-effort: on any failure it leaves the flag unset and returns False, so the
    agent falls back to building the corpus itself (no worse than before). Returns
    True when the prebuilt artifacts are ready.
    """
    baseline_out = env.get("FUZZ_SOURCE_FOLDS_BASELINE_OUT_DIR")
    corpus_dir = env.get("FUZZ_SOURCE_FOLDS_CORPUS_DIR")
    fixed_dir = env.get("FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR")
    profile_root = env.get("FUZZ_SOURCE_FOLDS_PROFILE_ARTIFACT_DIR")
    if not (baseline_out and corpus_dir and fixed_dir and profile_root):
        return False  # not a corpus-profiling run; let the agent handle it

    scripts = Path(getattr(config, "PHASE2_SKILL_SCRIPTS_DIR", ""))
    build_corpus = scripts / "build_corpus.py"
    replay_profile = scripts / "replay_fuzzer_profile.py"
    if not (build_corpus.exists() and replay_profile.exists()):
        logger.warning("Phase-2 prebuild scripts missing under %s; agent will build "
                       "the corpus itself", scripts)
        return False

    profile_dir = str(Path(profile_root) / "profile_once")
    duration = str(env.get("FUZZ_SOURCE_FOLDS_CORPUS_BUILD_DURATION",
                           getattr(config, "PHASE2_CORPUS_BUILD_DURATION_SECS", 3600)))
    cpu = str(env.get("FUZZ_SOURCE_FOLDS_PROFILE_CPU", "0"))
    min_sample = str(env.get("FUZZ_SOURCE_FOLDS_REPLAY_PROFILE_SECONDS", "120"))

    # Idempotent: if a non-empty snapshot already exists (e.g. a resumed run), just
    # flag it as prebuilt.
    if _dir_has_files(fixed_dir):
        env["FUZZ_SOURCE_FOLDS_PREBUILT_CORPUS"] = "1"
        logger.info("Phase-2 prebuild: fixed corpus already present at %s; skipping",
                    fixed_dir)
        return True

    # Augment the seed corpus with the mutations libFuzzer generates from it, so the
    # single profile + the replay-timing gate reflect the real fuzzing workload (not
    # just the seeds). Mutation-augmented profiling is REQUIRED: on any failure this
    # raises MutationAugmentationError (no seed-only fall-back) and the caller marks
    # the target failed. On success build_corpus.py still crash-filters + freezes the
    # combined set, but its time-budget sizing is skipped (the mutation corpus is
    # already bounded by the ~5min generation cap -- see replay_budget below).
    combined = _augment_corpus_with_mutations(env, fuzz_target)
    if combined:
        corpus_dir = combined

    grow_dir = str(Path(fixed_dir).parent / "grow")
    artifact_dir = str(Path(profile_root) / "corpus_build")
    try:
        dur_int = int(float(duration))
    except (TypeError, ValueError):
        dur_int = 0

    try:
        logger.info("Phase-2 prebuild: grow+freeze fixed corpus (duration=%ss) for %s",
                    dur_int, fuzz_target)
        # The crash-filter runs every seed through the baseline; for large corpora
        # (libavc ~18k, assimp ~11k files) the per-unit pass needs well over an hour,
        # so raise build_corpus.py's own --filter-timeout (default 5400s) too. The
        # harness is not turn-limited, so it can wait; the wrapper timeout below
        # covers filter + grow + overhead.
        filter_timeout = int(config.PHASE2_CRASH_FILTER_TIMEOUT_SECS)
        # Time-budgeted corpus sizing: cap the corpus to the largest N whose full
        # replay-gate measurement fits the budget, so profiling/gate/filter stay
        # tractable on slow targets. --replay-repeats must match the gate's
        # PHASE2_REPLAY_REPEATS or N is mis-sized. Optional absolute ceiling from
        # FUZZ_SOURCE_FOLDS_MAX_CORPUS_FILES is applied on top (min of the two).
        # When mutations were captured, generation was already time-capped
        # (PHASE2_MUTATION_DURATION_SECS, ~5min), so the corpus replays within that
        # bound -- skip the probe-and-size calculation (budget 0 = no sizing).
        # Overridable (PHASE2_MUTATION_SKIP_SIZING=0) for slow-rebuild targets that
        # hit the cap: sizing keeps the per-fold gate tractable so the optimizer can
        # iterate (see config.PHASE2_MUTATION_SKIP_SIZING).
        _skip_sizing = getattr(config, "PHASE2_MUTATION_SKIP_SIZING", True)
        replay_budget = 0 if (combined and _skip_sizing) else int(
            getattr(config, "PHASE2_CORPUS_REPLAY_BUDGET_SECS", 1800))
        filter_ncpu = int(getattr(config, "PHASE2_CRASH_FILTER_NCPU", 8))
        max_files = os.environ.get("FUZZ_SOURCE_FOLDS_MAX_CORPUS_FILES", "0")
        bc = subprocess.run(
            ["python3", str(build_corpus),
             "--out-dir", baseline_out, "--corpus-dir", corpus_dir,
             "--evolving-corpus-dir", grow_dir, "--snapshot-dir", fixed_dir,
             "--artifact-dir", artifact_dir, "--fuzz-target", fuzz_target,
             "--duration", str(dur_int), "--cpu", cpu,
             "--filter-timeout", str(filter_timeout),
             "--filter-ncpu", str(filter_ncpu),
             "--replay-budget-secs", str(replay_budget),
             "--replay-repeats", str(int(getattr(config, "PHASE2_REPLAY_REPEATS", 3))),
             "--probe-sample", str(int(getattr(config, "PHASE2_CORPUS_PROBE_SAMPLE", 100))),
             "--sizing-margin", str(getattr(config, "PHASE2_CORPUS_SIZING_MARGIN", 0.7)),
             "--n-min", str(int(getattr(config, "PHASE2_CORPUS_N_MIN", 200))),
             "--probe-timeout", "900",
             "--max-corpus-files", str(max_files if max_files else "0")],
            # wrapper covers sizing probe (2 containers <=900s) + filter + grow + overhead
            capture_output=True, text=True, timeout=dur_int + filter_timeout + 1800 + 3600,
        )
        if bc.returncode != 0 or not _dir_has_files(fixed_dir):
            logger.warning("Phase-2 prebuild corpus failed (rc=%s); agent will build it. "
                           "tail: %s", bc.returncode, (bc.stderr or "")[-400:])
            return False

        logger.info("Phase-2 prebuild: profiling baseline over the fixed corpus")
        rp = subprocess.run(
            ["python3", str(replay_profile),
             "--out-dir", baseline_out, "--corpus-dir", fixed_dir,
             "--artifact-dir", profile_dir, "--fuzz-target", fuzz_target,
             "--min-sample-seconds", min_sample, "--cpu", cpu],
            capture_output=True, text=True, timeout=int(min_sample) + 1800,
        )
        if rp.returncode != 0:
            logger.warning("Phase-2 prebuild profile failed (rc=%s); agent will profile. "
                           "tail: %s", rp.returncode, (rp.stderr or "")[-400:])
            return False
    except subprocess.TimeoutExpired as e:
        logger.warning("Phase-2 prebuild timed out (%s); agent will build the corpus itself", e)
        return False
    except Exception as e:  # noqa: BLE001 - best-effort, never block optimization
        logger.warning("Phase-2 prebuild error (%s); agent will build the corpus itself", e)
        return False

    env["FUZZ_SOURCE_FOLDS_PREBUILT_CORPUS"] = "1"
    logger.info("Phase-2 prebuild complete: fixed corpus + profile ready; the optimizer "
                "agent will skip its build/profile steps.")
    return True


def _load_replay_timing_module():
    """Load the skill's replay_timing helper module by path."""
    import importlib.util

    script = Path(
        getattr(config, "PHASE2_SKILL_SCRIPTS_DIR",
                "/home/sefcom/.codex/skills/apply-profile-guided-folds/scripts")
    ) / "replay_timing.py"
    spec = importlib.util.spec_from_file_location("replay_timing", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load replay_timing from {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_replay_speedup(
    *,
    diff_output_dir: str | Path,
    baseline_bin_dir: str | Path,
    optimized_bin_dir: str | Path,
    fuzz_target: str,
    experiment_dir: str | Path,
    profile_cpu: int | None = None,
    repeats: int | None = None,
    measure_fn=None,
) -> dict | None:
    """Headline throughput metric: deterministic corpus-replay speedup.

    Freezes the fixed corpus snapshot (falling back to the merged seed corpus)
    into an immutable snapshot, then replays that identical input set on the
    baseline and optimized binaries and returns
    ``replay_speedup = baseline_time / optimized_time``. This replaces live
    exec/s, which is confounded because the two binaries explore different
    corpora. Returns None on any failure so setup is never broken by the metric.
    """
    if not fuzz_target:
        return None
    try:
        replay = _load_replay_timing_module() if measure_fn is None else None
        measure = measure_fn or replay.measure_binary

        fixed = _phase2_fixed_corpus_dir(diff_output_dir)
        merged = Path(experiment_dir) / "seed_corpus" / "merged"
        source_corpus = fixed if _dir_has_files(fixed) else merged
        if not _dir_has_files(source_corpus):
            logger.warning("Replay speedup skipped: no corpus available")
            return None

        snapshot_dir = Path(diff_output_dir) / "profiles" / "replay_snapshot"
        snapshot_count = _freeze_corpus_snapshot(source_corpus, snapshot_dir)

        if profile_cpu is None:
            profile_cpu = max(int(getattr(config, "RESERVED_CORES", 1)) - 1, 0)
        if repeats is None:
            repeats = int(getattr(config, "PHASE2_REPLAY_REPEATS", 3))

        common = dict(
            corpus_dir=str(snapshot_dir),
            fuzz_target=fuzz_target,
            cpu=profile_cpu,
            repeats=repeats,
            seed=int(getattr(config, "BASE_SEED", 1337)),
            memory=getattr(config, "MEMORY_LIMIT", "4g"),
            shm_size=getattr(config, "DOCKER_SHM_SIZE", "2g"),
            run_timeout=int(getattr(config, "TRIAL_DURATION_SECS", 3600)),
            min_partial_units=int(
                getattr(config, "PHASE2_REPLAY_MIN_PARTIAL_UNITS", 500)
            ),
        )
        baseline = measure(out_dir=str(baseline_bin_dir), **common)
        optimized = measure(out_dir=str(optimized_bin_dir), **common)

        b = baseline.get("median_time_s")
        o = optimized.get("median_time_s")
        # A deterministic corpus crasher truncates both binaries at the SAME unit
        # count, so rate-normalize (executed_units/time) to stay apples-to-apples
        # over that common prefix; reduces to base_time/opt_time when units match.
        partial = bool(baseline.get("partial") or optimized.get("partial"))
        if partial:
            bu = baseline.get("executed_units")
            ou = optimized.get("executed_units")
            speedup = round((ou / o) / (bu / b), 4) if (b and o and bu and ou) else None
        else:
            speedup = round(b / o, 4) if (b and o) else None
        return {
            "replay_speedup": speedup,
            "partial": partial,
            "baseline": baseline,
            "optimized": optimized,
            "corpus_file_count": snapshot_count,
            "corpus_source": "fixed" if source_corpus == fixed else "merged",
        }
    except Exception as exc:  # never let the metric break setup
        logger.warning("Replay speedup measurement failed: %s", exc)
        return None


def _dir_has_files(directory: str | Path) -> bool:
    directory = Path(directory)
    return directory.is_dir() and any(p.is_file() for p in directory.rglob("*"))


def _freeze_corpus_snapshot(source_dir: str | Path, dest_dir: str | Path) -> int:
    """Copy a flat, immutable snapshot of a corpus for replay timing."""
    source_dir = Path(source_dir)
    dest_dir = Path(dest_dir)
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for src_path in sorted(source_dir.rglob("*")):
        if not src_path.is_file():
            continue
        shutil.copy2(src_path, dest_dir / f"unit_{count:08d}")
        count += 1
    return count


def _is_source_or_header_file(path: Path) -> bool:
    return path.suffix.lower() in _SOURCE_FILE_SUFFIXES


def _merge_missing_support_tree(
    support_root: str | Path, target_root: str | Path,
) -> list[str]:
    """Copy only missing non-source support files into a fuzz support tree."""
    support_root = Path(support_root)
    target_root = Path(target_root)
    copied: list[str] = []

    if not support_root.exists():
        return copied

    for src_path in sorted(support_root.rglob("*")):
        if not src_path.is_file() or _is_source_or_header_file(src_path):
            continue
        rel_path = src_path.relative_to(support_root)
        dst_path = target_root / rel_path
        if dst_path.exists():
            continue
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_path, dst_path)
        copied.append(str(rel_path))

    return copied


def _project_build_requires_fuzz_support(project: str) -> bool:
    build_sh = Path(config.OSS_FUZZ_DIR) / "projects" / project / "build.sh"
    return build_sh.exists() and "./fuzz/oss_fuzz_build.sh" in build_sh.read_text()


def _extract_project_fuzz_support_tree(
    project: str, destination_root: str | Path,
) -> Path | None:
    """Extract the current project's fuzz support dir from its OSS-Fuzz image."""
    image = f"gcr.io/oss-fuzz/{project}"
    inspect = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        text=True,
    )
    if inspect.returncode != 0 and not docker_util.build_image(project):
        logger.warning("Could not build project image for %s fuzz support staging", project)
        return None

    workdir = _project_workdir_from_dockerfile(project)
    container_id = ""
    try:
        created = subprocess.run(
            ["docker", "create", image],
            capture_output=True,
            text=True,
            check=False,
        )
        if created.returncode != 0:
            logger.warning("docker create failed for %s: %s", image, created.stderr)
            return None
        container_id = created.stdout.strip()
        copy_result = subprocess.run(
            ["docker", "cp", f"{container_id}:{workdir}/fuzz", str(destination_root)],
            capture_output=True,
            text=True,
            check=False,
        )
        if copy_result.returncode != 0:
            logger.warning(
                "docker cp for %s fuzz support failed: %s",
                project, copy_result.stderr,
            )
            return None
        return Path(destination_root) / "fuzz"
    finally:
        if container_id:
            subprocess.run(
                ["docker", "rm", "-f", container_id],
                capture_output=True,
            )


def _stage_project_fuzz_support(source_dir: str, project: str) -> list[str]:
    """Stage missing non-source fuzz support files into extracted source trees."""
    if not project or not _project_build_requires_fuzz_support(project):
        return []

    build_script = Path(source_dir) / "fuzz" / "oss_fuzz_build.sh"
    if build_script.exists():
        return []

    with tempfile.TemporaryDirectory(prefix="phase2-fuzz-support-") as tmpdir:
        support_root = _extract_project_fuzz_support_tree(project, tmpdir)
        if support_root is None:
            return []
        copied = _merge_missing_support_tree(support_root, Path(source_dir) / "fuzz")

    if copied:
        logger.info(
            "Staged %d missing non-source fuzz support files for %s",
            len(copied), project,
        )
    return copied


def _codex_output_is_low_confidence(stdout: str, stderr: str) -> bool:
    # `codex exec` writes the assistant's final answer to stdout and a
    # verbose transcript (including the original prompt) to stderr. Inspect
    # stdout first so prompt text like `BLOCKED_LOW_CONFIDENCE` does not
    # create false positives on otherwise successful runs.
    primary = stdout if (stdout or "").strip() else stderr
    combined = (primary or "").lower()
    if any(pattern in combined for pattern in _LOW_CONFIDENCE_PATTERNS):
        return True
    return _emits_blocked_low_confidence(primary or "")


def _emits_blocked_low_confidence(text: str) -> bool:
    """True only when the agent emits BLOCKED_LOW_CONFIDENCE as a genuine status,
    not when it merely mentions the token to deny it.

    The skill's contract is to *output* ``BLOCKED_LOW_CONFIDENCE`` when it truly
    blocks. An honest "no qualifying fold, 1.00x" result frequently writes
    "...not a BLOCKED_LOW_CONFIDENCE (corpus/profile were valid)..." to say the
    opposite — a substring match treats that as a block and wrongly discards a
    perfectly valid run. Detect the token only on a line that does not negate it.
    """
    for raw in (text or "").splitlines():
        low = raw.lower()
        if "blocked_low_confidence" in low and "not" not in low:
            return True
    return False


_RATE_LIMIT_PATTERNS = [
    "rate limit", "rate_limit", "Rate limit",
    "usage limit", "Usage limit",
    "Too many requests", "too many requests",
    "429", "quota exceeded", "Quota exceeded",
    "over your limit", "Over capacity",
    "overloaded", "Overloaded",
    "ResourceExhausted",
]

# Session/usage-limit notices that reset after a while (e.g. Claude's
# "You've hit your session limit · resets 2:50pm"). Unlike the patterns above
# these can come back with exit code 0 — the CLI prints the notice and exits
# cleanly without doing work — so they are matched regardless of return code so
# the wait-and-retry loop rides out the reset instead of failing the project.
_SESSION_LIMIT_PATTERNS = [
    "hit your session limit",
    "session limit",
    "Session limit",
    "5-hour limit",
    "weekly limit",
]

RATE_LIMIT_WAIT_SECS = int(os.environ.get("RATE_LIMIT_WAIT_SECS", "300"))
RATE_LIMIT_MAX_WAITS = int(os.environ.get("RATE_LIMIT_MAX_WAITS", "48"))


def _is_rate_limited(result) -> bool:
    """Check if a CLI result indicates a rate / usage / session limit."""
    combined = (result.stdout or "") + (result.stderr or "")
    # Session-limit notices can exit 0 — check them irrespective of return code.
    if any(pat in combined for pat in _SESSION_LIMIT_PATTERNS):
        return True
    if result.returncode == 0:
        return False
    return any(pat in combined for pat in _RATE_LIMIT_PATTERNS)


def _skill_mention(backend: str = "codex") -> str:
    """How to reference the skill in a prompt for the given agent backend."""
    skill = getattr(config, "PHASE2_OPTIMIZER_SKILL", "profile-once-fuzz-folds")
    if backend.lower() == "claude":
        return f"the {skill} skill"
    return f"${skill}"


_HEADLESS_SYNC_DIRECTIVE = (
    "HEADLESS SINGLE-TURN MODE: this session is non-interactive and ends the "
    "moment you stop — you will NOT be resumed and any deferred or backgrounded "
    "work is discarded. Run every step (corpus build, profiling, replay, "
    "rebuilds) synchronously in the FOREGROUND and block until each finishes; "
    "long steps (e.g. crash-filtering a large seed corpus) are expected — just "
    "wait for them. Never start background or detached processes (no "
    "run_in_background, no trailing '&', no nohup, no setsid) and never call "
    "ScheduleWakeup or otherwise defer work to a later turn. Complete all source "
    "edits and the replay-timing validation before your final message, then "
    "report the cumulative speedup."
)


def _make_apply_fuzz_source_folds_prompt(
    harness_path: str, use_wrapper_validation: bool = False,
    backend: str = "codex",
) -> str:
    """Build the initial agent prompt for phase 2 source-fold optimization."""
    return _make_apply_fuzz_source_folds_prompt_with_mode(
        harness_path=harness_path,
        use_wrapper_validation=use_wrapper_validation,
        backend=backend,
    )


def _make_apply_fuzz_source_folds_prompt_with_mode(
    harness_path: str, use_wrapper_validation: bool = False,
    backend: str = "codex",
) -> str:
    """Build the initial agent prompt for phase 2 source-fold optimization."""
    validation_lines = [
        "The outer phase 2 wrapper performs the authoritative rebuild and "
        "smoke-run after you finish.",
        "Build the fixed corpus once: fuzz the baseline binary "
        "(FUZZ_SOURCE_FOLDS_BASELINE_OUT_DIR, else FUZZ_SOURCE_FOLDS_OUT_DIR) "
        "on FUZZ_SOURCE_FOLDS_CORPUS_DIR for "
        "FUZZ_SOURCE_FOLDS_CORPUS_BUILD_DURATION seconds, then freeze it to "
        "FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR. Do not rebuild the baseline.",
        "Profile the baseline once by replaying that fixed corpus to produce "
        "one ranked hotspot list. Do not re-profile or run any refresh "
        "profile.",
        "Iterate the ranked hotspots from that single profile; for each, apply "
        "source folds and keep the change only if deterministic replay timing "
        "on the fixed corpus is measurably faster than the previous best, else "
        "revert it. Report the cumulative speedup at the end.",
        "Do not edit the harness, shared fuzz-only support code, build "
        "scripts, Dockerfiles, or project metadata.",
    ]
    if use_wrapper_validation:
        validation_lines.insert(
            0,
            "The wrapper has provided external validation commands in "
            "FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND, "
            "FUZZ_SOURCE_FOLDS_BUILD_COMMAND, and "
            "FUZZ_SOURCE_FOLDS_SMOKE_COMMAND. Use those wrapper-provided "
            "external validation commands, with "
            "FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND as the authoritative "
            "sequential validation gate, instead of assuming "
            "phase2_build_check.py or the current OSS-Fuzz helper path.",
        )
        validation_lines.append(
            "Never run the wrapper build and smoke commands in parallel. The "
            "smoke command depends on build artifacts from the build command.",
        )
        validation_lines.append(
            "Treat those commands as the real historical-image build/smoke "
            "loop for this extracted tree. If they remain unusable for a "
            "pre-existing reason, output exactly BLOCKED_LOW_CONFIDENCE and "
            "stop instead of silently falling back to static-only heuristics.",
        )
    else:
        validation_lines.insert(
            0,
            "The wrapper has already staged any missing non-source OSS-Fuzz "
            "support files it could find.",
        )
        validation_lines.append(
            "do not stop just because this is an extracted tree. First try "
            "to use the staged support files and recover a real OSS-Fuzz "
            "build/profile/smoke loop. If that still remains blocked, do not "
            "silently fall back to static-only heuristics. Output exactly "
            "BLOCKED_LOW_CONFIDENCE and stop.",
        )
        validation_lines.append(
            "Use internal validation only if it is genuinely available.",
        )

    return (
        f"Use {_skill_mention(backend)}.\n\n"
        "Use the current directory as source_dir and "
        f"'{harness_path}' as harness_path.\n"
        "Default to aggressive mode.\n"
        + _HEADLESS_SYNC_DIRECTIVE + "\n"
        + "\n".join(validation_lines)
    )


def _make_retry_prompt(
    fuzz_target: str, build_log: str, use_wrapper_validation: bool = False,
    backend: str = "codex",
) -> str:
    """Build the follow-up agent prompt after an outer phase-2 build failure."""
    error_excerpt = "\n".join(build_log.strip().split("\n")[-200:])
    if use_wrapper_validation:
        validation_text = (
            "The wrapper-provided historical validation commands remain "
            "available in FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND, "
            "FUZZ_SOURCE_FOLDS_BUILD_COMMAND, and "
            "FUZZ_SOURCE_FOLDS_SMOKE_COMMAND. Use "
            "FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND as the authoritative "
            "sequential validation gate instead of "
            "phase2_build_check.py or the current OSS-Fuzz helper path. If "
            "they remain unusable for a pre-existing blocker, output exactly "
            "BLOCKED_LOW_CONFIDENCE and stop instead of relying on "
            "static-only heuristics. Never run the wrapper build and smoke "
            "commands in parallel. Reuse the single fixed corpus "
            "(FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR) and the one "
            "profile-on-replay hotspot list you already built; do not "
            "re-profile. Keep each fold only if deterministic replay timing on "
            "the fixed corpus beats the previous best, else revert it."
        )
    else:
        validation_text = (
            "The outer phase 2 wrapper performs the authoritative rebuild and "
            "smoke-run. If you cannot recover a real build/profile/smoke loop, "
            "output exactly BLOCKED_LOW_CONFIDENCE and stop instead of "
            "relying on static-only heuristics. Reuse the single fixed corpus "
            "(FUZZ_SOURCE_FOLDS_FIXED_CORPUS_DIR) and the one "
            "profile-on-replay hotspot list you already built; do not "
            "re-profile. Keep each fold only if deterministic replay timing on "
            "the fixed corpus beats the previous best, else revert it."
        )
    return (
        f"You are optimizing the fuzz target '{fuzz_target}' in the current "
        f"source tree using {_skill_mention(backend)}. The previous "
        "session ended before phase 2 completed successfully.\n\n"
        f"Build errors:\n```\n{error_excerpt}\n```\n\n"
        "Fix all remaining compilation or smoke-test issues. If a specific "
        "optimization cannot be made to work, revert only that change. Then "
        "continue applying any remaining source-only candidates from that "
        "skill. "
        f"{validation_text} Keep harness code, fuzz-only support files, "
        "build scripts, Dockerfiles, and project metadata unchanged.\n"
        + _HEADLESS_SYNC_DIRECTIVE
    )


def _optimizer_backend() -> str:
    """Which agent CLI drives optimization: 'claude' or 'codex'."""
    return os.environ.get(
        "BENCHMARK_OPTIMIZER", getattr(config, "OPTIMIZER_BACKEND", "claude")
    ).lower()


def _agent_child_env(
    project: str, extra_env: dict[str, str] | None, *, pop_claude: bool,
) -> dict:
    """Build the child-process environment shared by all optimizer backends."""
    child_env = dict(os.environ)
    child_env["OSS_FUZZ_DIR"] = config.OSS_FUZZ_DIR
    child_env["OSS_FUZZ_PROJECT"] = project
    if "FUZZ_TARGET" not in child_env:
        child_env["FUZZ_TARGET"] = ""
    # Codex must not inherit the parent Claude Code session env, which would
    # confuse its auth/session plumbing. Claude keeps these.
    if pop_claude:
        for var in ("CLAUDECODE", "CLAUDE_CODE"):
            child_env.pop(var, None)
    if extra_env:
        child_env.update({k: str(v) for k, v in extra_env.items()})
    return child_env


def _run_agent_cli(
    cmd: list[str], *, cwd: str, child_env: dict, timeout: int | None, label: str,
    resume_cmd: list[str] | None = None,
) -> dict:
    """Run an agent CLI with rate-limit retry. Returns a result dict.

    When a usage/session limit is hit, sleep and retry. If ``resume_cmd`` is
    provided (Claude backend passes a ``--resume <session-id>`` variant), the
    retries CONTINUE the interrupted session instead of restarting a fresh one,
    so the optimizer keeps its accumulated context and partial progress rather
    than re-planning from scratch after the reset.
    """
    import time as _time

    current_cmd = cmd
    for wait_attempt in range(RATE_LIMIT_MAX_WAITS + 1):
        try:
            result = subprocess.run(
                current_cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=child_env,
            )
        except subprocess.TimeoutExpired:
            logger.warning("%s session timed out after %ds", label, timeout)
            return {"ok": False, "stdout": "", "stderr": "", "timed_out": True}

        # Check for rate/usage limit
        if _is_rate_limited(result):
            if wait_attempt >= RATE_LIMIT_MAX_WAITS:
                logger.error(
                    "Rate limit still active after %d waits, giving up",
                    RATE_LIMIT_MAX_WAITS,
                )
                return {
                    "ok": False,
                    "stdout": result.stdout or "",
                    "stderr": result.stderr or "",
                    "timed_out": False,
                }
            logger.warning(
                "Rate/usage limit detected (wait %d/%d). "
                "Sleeping %ds before %s...",
                wait_attempt + 1, RATE_LIMIT_MAX_WAITS,
                RATE_LIMIT_WAIT_SECS,
                "resuming the interrupted session" if resume_cmd else "retry",
            )
            stderr_tail = (result.stderr or "")[-300:]
            if stderr_tail:
                logger.warning("%s stderr: %s", label, stderr_tail)
            _time.sleep(RATE_LIMIT_WAIT_SECS)
            # After an interruption the session is saved; continue it instead of
            # restarting from scratch when the backend supports resume.
            if resume_cmd is not None:
                current_cmd = resume_cmd
            continue

        # Not rate-limited — process normally
        if result.returncode != 0:
            logger.warning("%s exited with code %d", label, result.returncode)
            stderr_tail = (result.stderr or "")[-500:]
            if stderr_tail:
                logger.warning("%s stderr (last 500 chars): %s",
                               label, stderr_tail)
        stdout_tail = (result.stdout or "")[-200:]
        if stdout_tail:
            logger.info("%s stdout (last 200 chars): %s", label, stdout_tail)
        return {
            "ok": result.returncode == 0,
            "stdout": result.stdout or "",
            "stderr": result.stderr or "",
            "timed_out": False,
        }

    return {"ok": False, "stdout": "", "stderr": "", "timed_out": False}


def _invoke_codex_capture(
    source_dir: str, prompt: str, timeout: int | None = None,
    project: str = "", extra_env: dict[str, str] | None = None,
) -> dict:
    """Invoke the Codex CLI with a prompt.

    If a usage/rate limit is detected, waits and retries automatically.
    """
    child_env = _agent_child_env(project, extra_env, pop_claude=True)

    codex_cmd = [
        "codex",
        "exec",
        "--dangerously-bypass-approvals-and-sandbox",
    ]
    model = os.environ.get("BENCHMARK_CODEX_MODEL")
    if model:
        codex_cmd += ["--model", model]
    # Per-invocation reasoning-effort override (config.toml default may be invalid
    # for the chosen --model, e.g. gpt-5.5 rejects "max"; it supports up to "xhigh").
    reasoning = os.environ.get("BENCHMARK_CODEX_REASONING")
    if reasoning:
        codex_cmd += ["-c", f"model_reasoning_effort={reasoning}"]
    codex_cmd.append(prompt)

    logger.info("Codex cmd: %s", " ".join(codex_cmd[:3]))
    logger.info("Codex cwd: %s", source_dir)
    return _run_agent_cli(
        codex_cmd, cwd=source_dir, child_env=child_env,
        timeout=timeout, label="Codex",
    )


def _invoke_claude_capture(
    source_dir: str, prompt: str, timeout: int | None = None,
    project: str = "", extra_env: dict[str, str] | None = None,
) -> dict:
    """Invoke the Claude Code CLI headlessly with a prompt.

    Mirrors _invoke_codex_capture: same env, rate-limit retry, and result dict.
    `claude -p` runs non-interactively; `--dangerously-skip-permissions` lets the
    skill edit source and run its Docker build/profile/replay steps unattended.
    """
    child_env = _agent_child_env(project, extra_env, pop_claude=False)
    # Lift the Bash-tool timeout. Claude Code caps a single Bash call at
    # BASH_MAX_TIMEOUT_MS (default 600000ms = 10min); a replay-timing / profile /
    # crash-filter step over a large corpus exceeds that, the tool kills it, and
    # the agent reacts by backgrounding the docker step and yielding (turn ends,
    # no fold). Raising the cap lets those long steps run inline to completion.
    # The overall optimizer wall-clock is still bounded by PHASE2_OPTIMIZER_TIMEOUT_SECS.
    _agent_bash_ms = str(getattr(config, "PHASE2_AGENT_BASH_TIMEOUT_MS", 5400000))
    child_env.setdefault("BASH_DEFAULT_TIMEOUT_MS", _agent_bash_ms)
    child_env.setdefault("BASH_MAX_TIMEOUT_MS", _agent_bash_ms)

    # Pin a session id so a usage/session-limit interruption can be CONTINUED
    # (--resume) on retry instead of restarting a fresh session that loses the
    # optimizer's accumulated context. Edits the agent already made persist on
    # disk; resuming lets it pick up exactly where it left off after the reset.
    session_id = str(uuid.uuid4())
    common = [
        "--dangerously-skip-permissions",
        # Headless single-turn mode: forbid the yield/resume tool so the
        # optimizer cannot defer work to a future turn that never runs.
        "--disallowedTools", "ScheduleWakeup",
    ]
    model = os.environ.get("BENCHMARK_CLAUDE_MODEL")
    if model:
        common += ["--model", model]

    claude_cmd = ["claude", "-p", prompt, "--session-id", session_id, *common]

    resume_nudge = (
        "Your previous turn was interrupted by a usage/session limit, which has "
        "now reset. Continue the optimization from exactly where you left off: "
        "your earlier source edits persist on disk, so re-read the current tree "
        "state and proceed under the same Behavior-Preservation Contract. Do not "
        "restart from scratch."
    )
    resume_cmd = ["claude", "-p", resume_nudge, "--resume", session_id, *common]

    logger.info("Claude cmd: %s (session %s)", " ".join(claude_cmd[:2]), session_id)
    logger.info("Claude cwd: %s", source_dir)
    return _run_agent_cli(
        claude_cmd, cwd=source_dir, child_env=child_env,
        timeout=timeout, label="Claude", resume_cmd=resume_cmd,
    )


def _invoke_agent_capture(
    source_dir: str, prompt: str, timeout: int | None = None,
    project: str = "", extra_env: dict[str, str] | None = None,
    backend: str | None = None,
) -> dict:
    """Dispatch to the configured optimizer backend (Claude or Codex)."""
    backend = (backend or _optimizer_backend()).lower()
    if backend == "claude":
        return _invoke_claude_capture(source_dir, prompt, timeout, project, extra_env)
    return _invoke_codex_capture(source_dir, prompt, timeout, project, extra_env)


def _invoke_codex(
    source_dir: str, prompt: str, timeout: int | None = None,
    project: str = "", extra_env: dict[str, str] | None = None,
) -> bool:
    result = _invoke_codex_capture(
        source_dir, prompt, timeout=timeout, project=project,
        extra_env=extra_env,
    )
    return bool(result["ok"])


def optimize_and_build(
    source_dir: str, fuzz_target: str, diff_output_dir: str,
    project: str, build_fn, max_attempts: int = 10,
    codex_extra_env: dict[str, str] | None = None,
    use_wrapper_validation: bool = False,
) -> bool:
    """Run the full optimize→build→fix loop until the build succeeds.

    Invokes Codex with apply-fuzz-source-folds, then builds.
    If the build fails, re-invokes Codex with the error log. Each
    invocation is a fresh session, so context limits are not a problem.

    Args:
        source_dir: Path to the project source tree.
        fuzz_target: Name of the fuzz target binary.
        diff_output_dir: Where to save diffs and build logs.
        project: OSS-Fuzz project name.
        build_fn: Callable that builds and returns (success, log).
        max_attempts: Max total Codex invocations.

    Returns True if build eventually succeeds.
    """
    os.makedirs(diff_output_dir, exist_ok=True)
    _stage_project_fuzz_support(source_dir, project)

    # Initialize git repo for tracking changes
    subprocess.run(["git", "init"], cwd=source_dir, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=source_dir, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "baseline"],
        cwd=source_dir, capture_output=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "benchmark",
             "GIT_AUTHOR_EMAIL": "bench@test",
             "GIT_COMMITTER_NAME": "benchmark",
             "GIT_COMMITTER_EMAIL": "bench@test"},
    )

    harness_path = _find_harness_source(source_dir, fuzz_target)
    logger.info("Harness source for %s: %s", fuzz_target, harness_path)

    backend = _optimizer_backend()
    build_log = None

    # Do the deterministic heavy steps (corpus grow/freeze + baseline profile) in
    # the harness so the single-turn agent never has to background a long docker
    # step and yield. Best-effort: if it fails, the agent builds the corpus itself.
    if codex_extra_env:
        _prebuild_phase2_corpus_and_profile(codex_extra_env, fuzz_target)

    for attempt in range(max_attempts):
        # Choose prompt based on whether we have a previous build failure
        if build_log is None:
            prompt = _make_apply_fuzz_source_folds_prompt_with_mode(
                harness_path,
                use_wrapper_validation=use_wrapper_validation,
                backend=backend,
            )
            logger.info(
                "Invoking %s via %s (attempt %d/%d)...",
                config.PHASE2_OPTIMIZER_SKILL, backend, attempt + 1, max_attempts,
            )
        else:
            # Subsequent: give build errors + tell it to continue optimizing
            if _is_infra_build_error(build_log):
                logger.warning(
                    "Build failure is infrastructure-related, not a code "
                    "error. Stopping retries."
                )
                return False

            prompt = _make_retry_prompt(
                fuzz_target,
                build_log,
                use_wrapper_validation=use_wrapper_validation,
                backend=backend,
            )
            logger.info(
                "Re-invoking %s to fix + continue (attempt %d/%d)...",
                backend, attempt + 1, max_attempts,
            )

        # Set FUZZ_TARGET for the skill's Docker commands
        os.environ["FUZZ_TARGET"] = fuzz_target

        codex_result = _invoke_agent_capture(
            source_dir, prompt, project=project, extra_env=codex_extra_env,
            backend=backend,
            timeout=getattr(config, "PHASE2_OPTIMIZER_TIMEOUT_SECS", None),
        )
        if codex_result["timed_out"]:
            logger.error(
                "%s optimization for %s/%s timed out", backend, project, fuzz_target,
            )
            return False
        if _codex_output_is_low_confidence(
            codex_result["stdout"], codex_result["stderr"],
        ):
            logger.error(
                "Codex optimization for %s/%s was low-confidence; refusing "
                "to accept a static-only result",
                project, fuzz_target,
            )
            report_path = os.path.join(
                diff_output_dir, f"codex_attempt_{attempt}.txt",
            )
            with open(report_path, "w") as f:
                f.write(codex_result["stdout"])
                if codex_result["stderr"]:
                    f.write("\n\n[stderr]\n")
                    f.write(codex_result["stderr"])
            return False

        # Save current diff
        diff_result = subprocess.run(
            ["git", "diff", "HEAD"],
            cwd=source_dir, capture_output=True, text=True,
        )
        diff_path = os.path.join(
            diff_output_dir,
            "optimization.diff" if attempt == 0 else f"attempt_{attempt}.diff",
        )
        with open(diff_path, "w") as f:
            f.write(diff_result.stdout)

        if not diff_result.stdout.strip():
            if attempt == 0:
                logger.warning("No changes made by %s", config.PHASE2_OPTIMIZER_SKILL)
                return False
            logger.warning(
                "Codex made no changes on attempt %d", attempt + 1
            )
            # Re-invoke with the skill prompt next time (fresh start)
            build_log = None
            continue

        # Save change summary
        stat_result = subprocess.run(
            ["git", "diff", "--stat", "HEAD"],
            cwd=source_dir, capture_output=True, text=True,
        )
        with open(os.path.join(diff_output_dir, "changes_summary.txt"), "w") as f:
            f.write(stat_result.stdout)

        _clean_build_artifacts(source_dir)

        # Try building
        success, build_log = build_fn()

        log_path = os.path.join(diff_output_dir, f"build_log_{attempt}.txt")
        with open(log_path, "w") as lf:
            lf.write(build_log)

        if success:
            if attempt > 0:
                logger.info(
                    "Build succeeded after %d attempt(s)", attempt + 1
                )
            return True

        logger.warning(
            "Build failed (attempt %d/%d)",
            attempt + 1, max_attempts,
        )

    logger.error("Build failed after %d attempts for %s", max_attempts, project)
    return False


def _make_arvo_build_container_cmd(
    local_id: int, issue: dict, source_mount: Path, out_dir: Path, work_dir: Path,
) -> list[str]:
    job_type = issue.get("job_type", "libfuzzer_asan_x86_64")
    fuzzer_info = job_type.split("_")
    engine = fuzzer_info[0]
    sanitizer_name = fuzzer_info[1]
    arch = "i386" if fuzzer_info[2] == "i386" else "x86_64"
    src_path = Path(source_mount)
    try:
        import arvo_reproducer
    except ModuleNotFoundError:
        arvo_reproducer = None

    sanitizer_map = {
        "asan": "address",
        "msan": "memory",
        "ubsan": "undefined",
        "coverage": "coverage",
        "dataflow": "dataflow",
        "none": "none",
    }
    sanitizer = (
        arvo_reproducer.get_sanitizer(sanitizer_name)
        if arvo_reproducer is not None
        else sanitizer_map.get(sanitizer_name, sanitizer_name)
    )
    fuzzing_language = (
        arvo_reproducer.get_language(None)
        if arvo_reproducer is not None
        else "c++"
    )

    env = [
        f"FUZZING_ENGINE={engine}",
        f"SANITIZER={sanitizer}",
        f"ARCHITECTURE={arch}",
        f"FUZZING_LANGUAGE={fuzzing_language}",
    ]

    cmd = ["docker", "run", "--rm", "--privileged"]
    for item in env:
        cmd += ["-e", item]
    cmd += [
        "-v", f"{src_path}:/src",
        "-v", f"{out_dir}:/out",
        "-v", f"{work_dir}:/work",
        "-t", f"gcr.io/oss-fuzz/{local_id}",
    ]
    return cmd


def _make_arvo_clone_prep_cmd(source_dir: Path, state_dir: Path) -> list[str]:
    source_src = Path(source_dir) / "src"
    state_dir = Path(state_dir)
    return [
        "docker", "run", "--rm",
        "-v", f"{source_src}:/live-src:ro",
        "-v", f"{state_dir}:/state",
        "alpine:3.19",
        "sh", "-lc",
        (
            "rm -rf /state/out /state/work /state/src-clone && "
            "mkdir -p /state/out /state/work /state/src-clone && "
            "cp -a /live-src/. /state/src-clone"
        ),
    ]


def _make_arvo_wrapper_validation_env(
    local_id: int, issue: dict, source_dir: Path, fuzz_target: str,
    state_dir: Path,
) -> dict[str, str]:
    state_dir = Path(state_dir)
    out_dir = state_dir / "out"
    work_dir = state_dir / "work"
    src_clone_dir = state_dir / "src-clone"
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)
    src_clone_dir.mkdir(parents=True, exist_ok=True)

    cleanup_cmd = _make_arvo_clone_prep_cmd(
        source_dir=source_dir,
        state_dir=state_dir,
    )
    build_cmd = _make_arvo_build_container_cmd(
        local_id=local_id,
        issue=issue,
        source_mount=src_clone_dir,
        out_dir=out_dir,
        work_dir=work_dir,
    )
    smoke_cmd = [
        "docker", "run", "--rm", "--privileged",
        "--memory", config.MEMORY_LIMIT,
        "-v", f"{out_dir}:/out:ro",
        "gcr.io/oss-fuzz-base/base-runner",
        "/bin/bash", "-lc",
        (
            "printf '\\n' | timeout "
            "${FUZZ_SOURCE_FOLDS_RUN_TIMEOUT:-"
            "${APPLY_PROFILE_GUIDED_FOLDS_RUN_TIMEOUT:-"
            "${APPLY_FOLD_STEPS_RUN_TIMEOUT:-300}}} "
            f"/out/{fuzz_target} "
            "-runs=${FUZZ_SOURCE_FOLDS_SMOKE_RUNS:-"
            "${APPLY_PROFILE_GUIDED_FOLDS_SMOKE_RUNS:-"
            "${APPLY_FOLD_STEPS_SMOKE_RUNS:-256}}} "
            "-seed=${FUZZ_SOURCE_FOLDS_SMOKE_SEED:-"
            "${APPLY_PROFILE_GUIDED_FOLDS_SMOKE_SEED:-"
            "${APPLY_FOLD_STEPS_SMOKE_SEED:-1337}}} "
            "-print_final_stats=1"
        ),
    ]

    return {
        "FUZZ_SOURCE_FOLDS_VALIDATION_MODE": "wrapper",
        "FUZZ_SOURCE_FOLDS_BUILD_COMMAND": (
            f"{shlex.join(cleanup_cmd)} && {shlex.join(build_cmd)}"
        ),
        "FUZZ_SOURCE_FOLDS_SMOKE_COMMAND": shlex.join(smoke_cmd),
        "FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND": (
            f"{shlex.join(cleanup_cmd)} && {shlex.join(build_cmd)} && "
            f"{shlex.join(smoke_cmd)}"
        ),
        "FUZZ_SOURCE_FOLDS_OUT_DIR": str(out_dir),
        "FUZZ_SOURCE_FOLDS_WORK_DIR": str(work_dir),
    }


def _make_n132_wrapper_validation_env(
    image: str, source_dir: Path, fuzz_target: str, state_dir: Path,
) -> dict[str, str]:
    """Wrapper build/smoke commands for an n132/arvo image (uses `arvo compile`)."""
    state_dir = Path(state_dir)
    out_dir = state_dir / "out"
    work_dir = state_dir / "work"
    src_clone_dir = state_dir / "src-clone"
    for d in (out_dir, work_dir, src_clone_dir):
        d.mkdir(parents=True, exist_ok=True)

    cleanup_cmd = _make_arvo_clone_prep_cmd(source_dir=source_dir, state_dir=state_dir)
    build_cmd = _make_n132_build_container_cmd(image, src_clone_dir, out_dir, work_dir)
    smoke_cmd = [
        "docker", "run", "--rm", "--privileged",
        "--memory", config.MEMORY_LIMIT,
        "-v", f"{out_dir}:/out:ro",
        "gcr.io/oss-fuzz-base/base-runner",
        "/bin/bash", "-lc",
        (
            "printf '\\n' | timeout "
            "${FUZZ_SOURCE_FOLDS_RUN_TIMEOUT:-"
            "${APPLY_PROFILE_GUIDED_FOLDS_RUN_TIMEOUT:-"
            "${APPLY_FOLD_STEPS_RUN_TIMEOUT:-300}}} "
            f"/out/{fuzz_target} "
            "-runs=${FUZZ_SOURCE_FOLDS_SMOKE_RUNS:-"
            "${APPLY_PROFILE_GUIDED_FOLDS_SMOKE_RUNS:-"
            "${APPLY_FOLD_STEPS_SMOKE_RUNS:-256}}} "
            "-seed=${FUZZ_SOURCE_FOLDS_SMOKE_SEED:-"
            "${APPLY_PROFILE_GUIDED_FOLDS_SMOKE_SEED:-"
            "${APPLY_FOLD_STEPS_SMOKE_SEED:-1337}}} "
            "-print_final_stats=1"
        ),
    ]
    return {
        "FUZZ_SOURCE_FOLDS_VALIDATION_MODE": "wrapper",
        "FUZZ_SOURCE_FOLDS_BUILD_COMMAND": (
            f"{shlex.join(cleanup_cmd)} && {shlex.join(build_cmd)}"
        ),
        "FUZZ_SOURCE_FOLDS_SMOKE_COMMAND": shlex.join(smoke_cmd),
        "FUZZ_SOURCE_FOLDS_VALIDATE_COMMAND": (
            f"{shlex.join(cleanup_cmd)} && {shlex.join(build_cmd)} && "
            f"{shlex.join(smoke_cmd)}"
        ),
        "FUZZ_SOURCE_FOLDS_OUT_DIR": str(out_dir),
        "FUZZ_SOURCE_FOLDS_WORK_DIR": str(work_dir),
    }


def download_seed_corpus(entry: dict, experiment_dir: str) -> bool:
    """Download and prepare seed corpus for both variants."""
    corpus_dir = os.path.join(experiment_dir, "seed_corpus")
    project = entry["project"]
    fuzz_target = entry.get("fuzz_target", "")

    if not fuzz_target:
        logger.warning("No fuzz target, cannot download corpus")
        merged_dir = os.path.join(corpus_dir, "merged")
        os.makedirs(merged_dir, exist_ok=True)
        corpus_util.ensure_fallback_seed(merged_dir)
        return True

    # Policy: NEVER download a corpus. Phase-2/3 use ONLY the project's bundled
    # <target>_seed_corpus.zip -- never the GCS/ClusterFuzz accumulated public
    # corpus. The GCS download path is disabled unconditionally (the
    # PHASE2_USE_GCS_CORPUS flag is ignored).
    gcs_dir = os.path.join(corpus_dir, "gcs")
    gcs_ok = False

    # Collect from build artifacts (ARVO or standard)
    build_dir = os.path.join(corpus_dir, "build")
    build_count = 0

    local_id = entry.get("local_id")
    if local_id:
        arvo_util = _lazy_import_arvo()
        arvo_out = arvo_util.get_arvo_build_output(local_id)
        seed_zip = arvo_out / f"{fuzz_target}_seed_corpus.zip"
        if seed_zip.exists():
            import zipfile
            os.makedirs(build_dir, exist_ok=True)
            try:
                with zipfile.ZipFile(seed_zip) as zf:
                    zf.extractall(build_dir)
                build_count = len(os.listdir(build_dir))
            except Exception as e:
                logger.warning("Failed to extract ARVO build corpus: %s", e)

    if build_count == 0:
        build_count = corpus_util.collect_build_corpus(project, fuzz_target, build_dir)

    # Merge all sources
    source_dirs = []
    if gcs_ok and os.path.isdir(gcs_dir):
        source_dirs.append(gcs_dir)
    if build_count > 0 and os.path.isdir(build_dir):
        source_dirs.append(build_dir)

    # Local corpus-cache fallback: used when the public GCS corpus is
    # unavailable (e.g. HTTP 403) and the build ships no seed corpus.
    # Layout: <LOCAL_CORPUS_CACHE_DIR>/<project>/<fuzz_target>/<seed files>
    cache_root = getattr(config, "LOCAL_CORPUS_CACHE_DIR", "")
    cache_dir = os.path.join(cache_root, project, fuzz_target) if cache_root else ""
    if cache_dir and os.path.isdir(cache_dir) and any(
        os.path.isfile(os.path.join(cache_dir, f)) for f in os.listdir(cache_dir)
    ):
        source_dirs.append(cache_dir)
        logger.info("Including local corpus cache: %s", cache_dir)

    merged_dir = os.path.join(corpus_dir, "merged")
    if source_dirs:
        total = corpus_util.merge_corpus_dirs(source_dirs, merged_dir)
        logger.info("Total seed corpus: %d files", total)
    else:
        os.makedirs(merged_dir, exist_ok=True)

    corpus_util.ensure_fallback_seed(merged_dir)
    return True


# ---------------------------------------------------------------------------
# Setup dispatch: ARVO vs OSV
# ---------------------------------------------------------------------------

def setup_cve_arvo(
    entry: dict,
    experiment_id: str,
    *,
    profile_cpu: int | None = None,
    baseline_profile_duration: int | None = None,
    refresh_profile_duration: int | None = None,
) -> bool:
    """Setup pipeline for an ARVO-format manifest entry."""
    arvo_util = _lazy_import_arvo()
    project = entry["project"]
    local_id = entry["local_id"]
    logger.info("=== Setting up %s / %s (ARVO local_id=%d) ===",
                project, entry["cve"], local_id)

    experiment_dir = get_experiment_dir(experiment_id, entry)
    os.makedirs(experiment_dir, exist_ok=True)
    poc_path_str: str | None = None

    # Fetch issue metadata
    issue = arvo_util.fetch_arvo_issue(local_id)
    if not issue:
        logger.error("Failed to fetch ARVO issue for %s", entry["cve"])
        _record_setup_failure(
            entry=entry,
            experiment_dir=experiment_dir,
            experiment_id=experiment_id,
            stage="issue_fetch",
            reason=f"Failed to fetch ARVO issue for {entry['cve']}",
        )
        return False

    if not entry.get("fuzz_target"):
        entry["fuzz_target"] = arvo_util.get_arvo_fuzz_target(issue)
    if not entry.get("crash_type"):
        entry["crash_type"] = arvo_util.get_arvo_crash_type(issue) or ""

    fuzz_target = entry["fuzz_target"]
    if not fuzz_target:
        logger.error("No fuzz target for %s", entry["cve"])
        _record_setup_failure(
            entry=entry,
            experiment_dir=experiment_dir,
            experiment_id=experiment_id,
            stage="fuzz_target",
            reason=f"No fuzz target for {entry['cve']}",
        )
        return False

    # Download PoC
    poc_dir = os.path.join(experiment_dir, "poc")
    poc_path = arvo_util.download_arvo_poc(issue, poc_dir)
    if not poc_path:
        logger.error("Failed to download PoC for %s", entry["cve"])
        _record_setup_failure(
            entry=entry,
            experiment_dir=experiment_dir,
            experiment_id=experiment_id,
            stage="poc_download",
            reason=f"Failed to download PoC for {entry['cve']}",
        )
        return False
    poc_path_str = str(poc_path)

    # Build baseline with source intercept
    source_dir = arvo_util.build_arvo_with_source_intercept(local_id, issue)
    if source_dir is None:
        logger.error("ARVO build failed for %s", entry["cve"])
        _record_setup_failure(
            entry=entry,
            experiment_dir=experiment_dir,
            experiment_id=experiment_id,
            stage="baseline_build",
            reason=f"ARVO build failed for {entry['cve']}",
            poc_path=poc_path_str,
        )
        return False

    # Check if source intercept actually captured source files.
    # Some projects have the Dockerfile clone source directly, so the
    # intercepted tree is empty. Fall back to extracting from the image.
    src_subdir = source_dir / "src"
    src_has_files = (
        src_subdir.exists()
        and any(
            d.is_dir() and d.name not in ("afl", "aflplusplus", "libfuzzer", "honggfuzz")
            for d in src_subdir.iterdir()
        )
    )
    if not src_has_files:
        logger.warning(
            "Source intercept returned empty tree for %s, "
            "extracting from Docker image instead", project,
        )
        src_subdir.mkdir(parents=True, exist_ok=True)
        if not extract_source_from_arvo_image(local_id, str(src_subdir)):
            logger.error("Failed to extract source from ARVO image for %s", entry["cve"])
            force_remove(source_dir)
            _record_setup_failure(
                entry=entry,
                experiment_dir=experiment_dir,
                experiment_id=experiment_id,
                stage="source_extract",
                reason=f"Failed to extract source from ARVO image for {entry['cve']}",
                poc_path=poc_path_str,
            )
            return False

    baseline_bin_dir = os.path.join(experiment_dir, "baseline", "bin")
    if not copy_arvo_output(local_id, baseline_bin_dir):
        force_remove(source_dir)
        _record_setup_failure(
            entry=entry,
            experiment_dir=experiment_dir,
            experiment_id=experiment_id,
            stage="baseline_output_copy",
            reason=f"Failed to copy ARVO build output for local_id {local_id}",
            poc_path=poc_path_str,
        )
        return False

    # Verify baseline crashes
    if not verify_poc_crash(baseline_bin_dir, fuzz_target, str(poc_path)):
        logger.warning("Baseline does NOT crash with PoC for %s — skipping",
                       entry["cve"])
        force_remove(source_dir)
        _record_setup_failure(
            entry=entry,
            experiment_dir=experiment_dir,
            experiment_id=experiment_id,
            stage="baseline_poc_verify",
            reason=f"Baseline did not reproduce PoC for {entry['cve']}",
            poc_path=poc_path_str,
        )
        return False
    logger.info("Baseline PoC verification: PASSED")

    download_seed_corpus(entry, experiment_dir)

    # Apply optimization and build (integrated loop with retries)
    project_src_dir = _find_project_source(source_dir, project)
    diff_dir = os.path.join(experiment_dir, "optimized", "source_diff")
    optimized_bin_dir = os.path.join(experiment_dir, "optimized", "bin")
    validation_env = _make_phase2_profile_env(
        experiment_dir=experiment_dir,
        diff_output_dir=diff_dir,
        out_dir=Path(experiment_dir) / "optimized" / "validation" / "out",
        profile_cpu=profile_cpu,
        baseline_profile_duration=baseline_profile_duration,
        refresh_profile_duration=refresh_profile_duration,
        entry=entry,
        baseline_out_dir=baseline_bin_dir,
    )
    validation_env.update(_make_arvo_wrapper_validation_env(
        local_id=local_id,
        issue=issue,
        source_dir=source_dir,
        fuzz_target=fuzz_target,
        state_dir=Path(experiment_dir) / "optimized" / "validation",
    ))

    def build_fn():
        return rebuild_with_modified_source_arvo(
            local_id, issue, source_dir, optimized_bin_dir,
            capture_log=True,
        )

    try:
        build_ok = optimize_and_build(
            project_src_dir, fuzz_target, diff_dir,
            project=project, build_fn=build_fn,
            codex_extra_env=validation_env,
            use_wrapper_validation=True,
        )
    except MutationAugmentationError as exc:
        _record_mutation_augmentation_failure(
            exc, entry=entry, experiment_dir=experiment_dir,
            experiment_id=experiment_id, project=project)
        return False

    # Check if optimization was applied
    opt_diff = os.path.join(diff_dir, "optimization.diff")
    opt_applied = False
    if os.path.exists(opt_diff):
        with open(opt_diff) as df:
            opt_applied = bool(df.read().strip())

    optimization_ready = build_ok and opt_applied
    if not optimization_ready:
        if opt_applied:
            logger.warning("Optimized rebuild failed, copying baseline as fallback")
        else:
            logger.warning("Optimization not applied for %s, optimized = baseline", project)
        os.makedirs(optimized_bin_dir, exist_ok=True)
        shutil.copytree(baseline_bin_dir, optimized_bin_dir, dirs_exist_ok=True)

    force_remove(source_dir)

    opt_crashes = verify_poc_crash(optimized_bin_dir, fuzz_target, str(poc_path))
    logger.info("Optimized PoC verification: %s",
                "PASSED" if opt_crashes else "FAILED")

    optimization_ready, opt_rejection = _reject_if_optimization_removed_bug(
        project=project, cve=entry["cve"],
        optimization_ready=optimization_ready,
        baseline_reproduced=bool(poc_path_str),
        opt_crashes=opt_crashes,
        baseline_bin_dir=baseline_bin_dir,
        optimized_bin_dir=optimized_bin_dir,
    )

    replay = None
    if optimization_ready:
        replay = run_replay_speedup(
            diff_output_dir=diff_dir,
            baseline_bin_dir=baseline_bin_dir,
            optimized_bin_dir=optimized_bin_dir,
            fuzz_target=fuzz_target,
            experiment_dir=experiment_dir,
            profile_cpu=profile_cpu,
        )
        optimization_ready, replay_rejection = _reject_if_no_replay_speedup(
            project=project, cve=entry["cve"],
            optimization_ready=optimization_ready, replay=replay,
            baseline_bin_dir=baseline_bin_dir, optimized_bin_dir=optimized_bin_dir,
        )
        opt_rejection = opt_rejection or replay_rejection

    _save_setup_metadata(entry, experiment_dir, experiment_id,
                         opt_applied, poc_path=poc_path_str,
                         baseline_ok=True,
                         optimized_ok=bool(optimization_ready and opt_crashes),
                         failure=opt_rejection,
                         replay=replay)
    return optimization_ready


def setup_cve_arvo_image(
    entry: dict,
    experiment_id: str,
    *,
    profile_cpu: int | None = None,
    baseline_profile_duration: int | None = None,
    refresh_profile_duration: int | None = None,
) -> bool:
    """Setup pipeline for an n132/arvo prebuilt-image ARVO entry.

    Mirrors `setup_cve_arvo` but sources baseline/source/PoC from the
    `n132/arvo:<id>-vul` image and rebuilds via `arvo compile` (no IssueTracker
    metadata or srcmap). Corpus-grow duration is adaptive: 20 min if a real seed
    corpus downloads, else 1 h (a from-scratch target needs the longer grow).
    """
    project = entry["project"]
    local_id = entry["local_id"]
    image = entry["image"]
    fuzz_target = entry.get("fuzz_target", "")
    logger.info("=== Setting up %s / %s (n132 image %s) ===",
                project, entry["cve"], image)

    experiment_dir = get_experiment_dir(experiment_id, entry)
    os.makedirs(experiment_dir, exist_ok=True)

    if not fuzz_target:
        _record_setup_failure(
            entry=entry, experiment_dir=experiment_dir, experiment_id=experiment_id,
            stage="fuzz_target", reason=f"No fuzz_target for {entry['cve']}",
        )
        return False

    source_dir = Path(tempfile.mkdtemp(prefix=f"n132-src-{local_id}-"))
    baseline_bin_dir = os.path.join(experiment_dir, "baseline", "bin")
    poc_dir = os.path.join(experiment_dir, "poc")

    crashed, repro_log = extract_n132_image(
        image, source_dir=source_dir, baseline_bin_dir=baseline_bin_dir,
        poc_dir=poc_dir,
    )
    poc_path = os.path.join(poc_dir, "poc_input")
    poc_path_str = poc_path if os.path.exists(poc_path) else None

    if not os.path.isfile(os.path.join(baseline_bin_dir, fuzz_target)):
        logger.error("n132 extract did not yield /out/%s for %s", fuzz_target, image)
        force_remove(source_dir)
        _record_setup_failure(
            entry=entry, experiment_dir=experiment_dir, experiment_id=experiment_id,
            stage="n132_extract",
            reason=f"n132 image extract failed for {entry['cve']}: {repro_log[-200:]}",
            poc_path=poc_path_str,
        )
        return False

    if not crashed:
        logger.warning("Baseline did NOT reproduce via `arvo` for %s — skipping", entry["cve"])
        force_remove(source_dir)
        _record_setup_failure(
            entry=entry, experiment_dir=experiment_dir, experiment_id=experiment_id,
            stage="baseline_poc_verify",
            reason=f"Baseline did not reproduce for {entry['cve']}",
            poc_path=poc_path_str,
        )
        return False
    logger.info("Baseline PoC verification: PASSED (arvo reproduce)")

    download_seed_corpus(entry, experiment_dir)
    # Corpus policy (resolved in _phase2_corpus_source): profile/replay on the GCS
    # corpus -> else the bundled <target>_seed_corpus.zip -> else fuzz the baseline
    # 1h to generate one. (Phase-3 seeds use the bundled corpus only.)
    _csrc, _cdur = _phase2_corpus_source(experiment_dir, entry)
    logger.info("Phase-2 corpus for %s: %s (%s)", project, _csrc.name,
                "use as-is" if _cdur == 0 else f"{_cdur}s baseline-generate")

    project_src_dir = _find_project_source(source_dir, project)
    diff_dir = os.path.join(experiment_dir, "optimized", "source_diff")
    optimized_bin_dir = os.path.join(experiment_dir, "optimized", "bin")
    validation_env = _make_phase2_profile_env(
        experiment_dir=experiment_dir,
        diff_output_dir=diff_dir,
        out_dir=Path(experiment_dir) / "optimized" / "validation" / "out",
        profile_cpu=profile_cpu,
        entry=entry,
        baseline_out_dir=baseline_bin_dir,
    )
    validation_env.update(_make_n132_wrapper_validation_env(
        image=image,
        source_dir=source_dir,
        fuzz_target=fuzz_target,
        state_dir=Path(experiment_dir) / "optimized" / "validation",
    ))

    def build_fn():
        return rebuild_with_modified_source_n132(
            image, source_dir, optimized_bin_dir, capture_log=True,
        )

    try:
        build_ok = optimize_and_build(
            project_src_dir, fuzz_target, diff_dir,
            project=project, build_fn=build_fn,
            codex_extra_env=validation_env,
            use_wrapper_validation=True,
        )
    except MutationAugmentationError as exc:
        _record_mutation_augmentation_failure(
            exc, entry=entry, experiment_dir=experiment_dir,
            experiment_id=experiment_id, project=project)
        return False

    opt_diff = os.path.join(diff_dir, "optimization.diff")
    opt_applied = False
    if os.path.exists(opt_diff):
        with open(opt_diff) as df:
            opt_applied = bool(df.read().strip())

    optimization_ready = build_ok and opt_applied
    if not optimization_ready:
        logger.warning("Optimization not applied/built for %s, optimized = baseline", project)
        os.makedirs(optimized_bin_dir, exist_ok=True)
        shutil.copytree(baseline_bin_dir, optimized_bin_dir, dirs_exist_ok=True)

    force_remove(source_dir)

    opt_crashes = False
    if poc_path_str:
        opt_crashes = verify_poc_crash(optimized_bin_dir, fuzz_target, poc_path)
        logger.info("Optimized PoC verification: %s",
                    "PASSED" if opt_crashes else "FAILED")

    optimization_ready, opt_rejection = _reject_if_optimization_removed_bug(
        project=project, cve=entry["cve"],
        optimization_ready=optimization_ready,
        baseline_reproduced=bool(poc_path_str),
        opt_crashes=opt_crashes,
        baseline_bin_dir=baseline_bin_dir,
        optimized_bin_dir=optimized_bin_dir,
    )

    replay = None
    if optimization_ready:
        replay = run_replay_speedup(
            diff_output_dir=diff_dir,
            baseline_bin_dir=baseline_bin_dir,
            optimized_bin_dir=optimized_bin_dir,
            fuzz_target=fuzz_target,
            experiment_dir=experiment_dir,
            profile_cpu=profile_cpu,
        )
        optimization_ready, replay_rejection = _reject_if_no_replay_speedup(
            project=project, cve=entry["cve"],
            optimization_ready=optimization_ready, replay=replay,
            baseline_bin_dir=baseline_bin_dir, optimized_bin_dir=optimized_bin_dir,
        )
        opt_rejection = opt_rejection or replay_rejection

    _save_setup_metadata(entry, experiment_dir, experiment_id,
                         opt_applied, poc_path=poc_path_str,
                         baseline_ok=True,
                         optimized_ok=bool(optimization_ready and opt_crashes),
                         failure=opt_rejection,
                         replay=replay)
    return optimization_ready


def setup_cve_osv(
    entry: dict,
    experiment_id: str,
    *,
    profile_cpu: int | None = None,
    baseline_profile_duration: int | None = None,
    refresh_profile_duration: int | None = None,
) -> bool:
    """Setup pipeline for an OSV-format manifest entry."""
    project = entry["project"]
    logger.info("=== Setting up %s / %s (OSV) ===", project, entry["cve"])

    experiment_dir = get_experiment_dir(experiment_id, entry)
    os.makedirs(experiment_dir, exist_ok=True)
    poc_path_str: str | None = None

    # Step 1: Resolve vulnerable commit
    try:
        entry["vulnerable_commit"] = resolve_vulnerable_commit(entry)
    except Exception as e:
        logger.error("Failed to resolve vulnerable commit: %s", e)
        _record_setup_failure(
            entry=entry,
            experiment_dir=experiment_dir,
            experiment_id=experiment_id,
            stage="vulnerable_commit",
            reason=f"Failed to resolve vulnerable commit: {e}",
        )
        return False

    # Step 2: Resolve oss-fuzz project commit
    if not entry.get("oss_fuzz_project_commit"):
        entry["oss_fuzz_project_commit"] = resolve_oss_fuzz_project_commit(entry)

    try:
        # Step 3: Build baseline
        if not build_baseline_ossfuzz(entry, experiment_dir):
            logger.warning("Baseline build failed with current config, "
                           "trying historical oss-fuzz config...")
            try:
                checkout_oss_fuzz_at_commit(
                    project, entry["oss_fuzz_project_commit"]
                )
            except Exception as e:
                logger.error("Failed to checkout oss-fuzz project: %s", e)
                return False
            if not build_baseline_ossfuzz(entry, experiment_dir):
                logger.error("Baseline build failed for %s", project)
                _record_setup_failure(
                    entry=entry,
                    experiment_dir=experiment_dir,
                    experiment_id=experiment_id,
                    stage="baseline_build",
                    reason=f"Baseline build failed for {project}",
                )
                return False

        # Step 4: Extract source and apply optimization
        src_tmp = tempfile.mkdtemp()
        try:
            src_dir = os.path.join(src_tmp, "src")
            if not extract_source_from_build(project, src_dir):
                logger.error("Source extraction failed for %s", project)
                _record_setup_failure(
                    entry=entry,
                    experiment_dir=experiment_dir,
                    experiment_id=experiment_id,
                    stage="source_extract",
                    reason=f"Source extraction failed for {project}",
                )
                return False

            project_src_dir = os.path.join(src_dir, project)
            if not os.path.isdir(project_src_dir):
                logger.warning("Project subdir %s not found, using %s",
                               project_src_dir, src_dir)
                project_src_dir = src_dir

            diff_dir = os.path.join(experiment_dir, "optimized", "source_diff")
            fuzz_target = entry.get("fuzz_target", "")
            download_seed_corpus(entry, experiment_dir)

            # Step 5: Optimize and build (integrated loop with retries)
            opt_project = prepare_optimized_project(project)
            profile_env = _make_phase2_profile_env(
                experiment_dir=experiment_dir,
                diff_output_dir=diff_dir,
                out_dir=Path(config.OSS_FUZZ_DIR) / "build" / "out" / opt_project,
                profile_cpu=profile_cpu,
                baseline_profile_duration=baseline_profile_duration,
                refresh_profile_duration=refresh_profile_duration,
                entry=entry,
                baseline_out_dir=os.path.join(experiment_dir, "baseline", "bin"),
            )

            if fuzz_target:
                def build_fn():
                    return build_optimized_ossfuzz(
                        entry, experiment_dir, opt_project,
                        source_dir=project_src_dir,
                        capture_log=True,
                    )

                try:
                    build_ok = optimize_and_build(
                        project_src_dir, fuzz_target, diff_dir,
                        project=project, build_fn=build_fn,
                        codex_extra_env=profile_env,
                    )
                except MutationAugmentationError as exc:
                    _record_mutation_augmentation_failure(
                        exc, entry=entry, experiment_dir=experiment_dir,
                        experiment_id=experiment_id, project=project)
                    return False
            else:
                build_ok = build_optimized_ossfuzz(
                    entry, experiment_dir, opt_project,
                )

            # Check if optimization was applied (diff file exists and non-empty)
            opt_diff = os.path.join(diff_dir, "optimization.diff")
            opt_applied = False
            if os.path.exists(opt_diff):
                with open(opt_diff) as df:
                    opt_applied = bool(df.read().strip())

            if not build_ok:
                logger.error("Optimized build failed for %s", project)
                _record_setup_failure(
                    entry=entry,
                    experiment_dir=experiment_dir,
                    experiment_id=experiment_id,
                    stage="optimized_build",
                    reason=f"Optimized build failed for {project}",
                )
                return False
        finally:
            force_remove(src_tmp)

        # Step 6: Verify
        verification = verify_crash_reproduction(entry, experiment_dir)
        logger.info("Verification results: %s", verification)

        optimization_ready, opt_rejection = _reject_if_optimization_removed_bug(
            project=project, cve=entry["cve"],
            optimization_ready=bool(opt_applied and build_ok),
            baseline_reproduced=bool(verification.get("baseline")),
            opt_crashes=bool(verification.get("optimized")),
            baseline_bin_dir=os.path.join(experiment_dir, "baseline", "bin"),
            optimized_bin_dir=os.path.join(experiment_dir, "optimized", "bin"),
        )

        replay = None
        if optimization_ready:
            replay = run_replay_speedup(
                diff_output_dir=diff_dir,
                baseline_bin_dir=os.path.join(experiment_dir, "baseline", "bin"),
                optimized_bin_dir=os.path.join(experiment_dir, "optimized", "bin"),
                fuzz_target=fuzz_target,
                experiment_dir=experiment_dir,
                profile_cpu=profile_cpu,
            )
            optimization_ready, replay_rejection = _reject_if_no_replay_speedup(
                project=project, cve=entry["cve"],
                optimization_ready=optimization_ready, replay=replay,
                baseline_bin_dir=os.path.join(experiment_dir, "baseline", "bin"),
                optimized_bin_dir=os.path.join(experiment_dir, "optimized", "bin"),
            )
            opt_rejection = opt_rejection or replay_rejection

        _save_setup_metadata(
            entry, experiment_dir, experiment_id,
            opt_applied,
            poc_path=poc_path_str,
            baseline_ok=verification["baseline"],
            optimized_ok=bool(optimization_ready and verification["optimized"]),
            failure=opt_rejection,
            replay=replay,
        )
        return False if opt_rejection else True

    finally:
        restore_oss_fuzz_project(project)
        opt_dir = os.path.join(config.OSS_FUZZ_DIR, "projects", f"{project}_opt")
        if os.path.exists(opt_dir):
            shutil.rmtree(opt_dir)


def setup_cve(
    entry: dict,
    experiment_id: str,
    *,
    profile_cpu: int | None = None,
    baseline_profile_duration: int | None = None,
    refresh_profile_duration: int | None = None,
) -> bool:
    """Dispatch to ARVO-image / ARVO / OSV setup based on manifest entry format."""
    if is_n132_entry(entry):
        return setup_cve_arvo_image(
            entry,
            experiment_id,
            profile_cpu=profile_cpu,
            baseline_profile_duration=baseline_profile_duration,
            refresh_profile_duration=refresh_profile_duration,
        )
    if is_arvo_entry(entry):
        return setup_cve_arvo(
            entry,
            experiment_id,
            profile_cpu=profile_cpu,
            baseline_profile_duration=baseline_profile_duration,
            refresh_profile_duration=refresh_profile_duration,
        )
    else:
        return setup_cve_osv(
            entry,
            experiment_id,
            profile_cpu=profile_cpu,
            baseline_profile_duration=baseline_profile_duration,
            refresh_profile_duration=refresh_profile_duration,
        )


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

def _find_project_source(source_dir: Path, project: str) -> str:
    """Find the project source subdirectory under an ARVO source tree."""
    src_subdir = source_dir / "src"
    if src_subdir.exists():
        for d in src_subdir.iterdir():
            if d.is_dir() and d.name.lower() == project.lower():
                return str(d)
        skip_names = {"afl", "aflplusplus", "honggfuzz", "libfuzzer", "oss-fuzz"}
        for d in sorted(src_subdir.iterdir()):
            if d.is_dir() and d.name.lower() not in skip_names:
                return str(d)
    return str(src_subdir) if src_subdir.exists() else str(source_dir)


def _save_setup_metadata(
    entry, experiment_dir, experiment_id, opt_applied,
    poc_path=None, baseline_ok=False, optimized_ok=False,
    failure: dict | None = None, replay: dict | None = None,
):
    metadata = {
        "entry": entry,
        "verification": {
            "baseline": baseline_ok,
            "optimized": optimized_ok,
            "optimization_applied": opt_applied,
        },
        "experiment_id": experiment_id,
        "setup_timestamp": datetime.now().isoformat(),
    }
    if poc_path:
        metadata["poc_path"] = poc_path
    if failure:
        metadata["failure"] = failure
    if replay:
        metadata["replay"] = replay
    with open(os.path.join(experiment_dir, "setup_metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)


def _record_setup_failure(
    *,
    entry: dict,
    experiment_dir: str,
    experiment_id: str,
    stage: str,
    reason: str,
    poc_path: str | None = None,
):
    _save_setup_metadata(
        entry,
        experiment_dir,
        experiment_id,
        opt_applied=False,
        poc_path=poc_path,
        baseline_ok=False,
        optimized_ok=False,
        failure={
            "stage": stage,
            "reason": reason,
        },
    )


def _record_mutation_augmentation_failure(
    exc: Exception, *, entry: dict, experiment_dir: str, experiment_id: str,
    project: str,
) -> None:
    """Mark a target failed because mutation-augmented profiling was unavailable.

    Mutation-augmented profiling is the required path (config.PHASE2_MUTATION_REQUIRED);
    there is no seed-only fall-back. This records the target as a phase-2 failure
    (stage=mutation_augmentation) so it is reported FAILED rather than silently
    optimized on the seeds alone.
    """
    logger.error("[FAIL] %s: mutation-augmented profiling required but unavailable "
                 "(%s); no seed-only fall-back", project, exc)
    _record_setup_failure(
        entry=entry, experiment_dir=experiment_dir, experiment_id=experiment_id,
        stage="mutation_augmentation", reason=str(exc),
    )


def _reject_if_optimization_removed_bug(
    *,
    project: str,
    cve: str,
    optimization_ready: bool,
    baseline_reproduced: bool,
    opt_crashes: bool,
    baseline_bin_dir: str,
    optimized_bin_dir: str,
) -> tuple[bool, dict | None]:
    """Reject an optimization that removed the bug.

    If the baseline reproduces a crash but the built optimized binary no longer
    does, the optimization has hidden a real bug — the single outcome the whole
    benchmark exists to prevent. Such a fold is invalid no matter how large its
    speedup: discard the bug-removing binary, fall back to the baseline build
    (so no bug-removing variant and no illusory speedup ever reach phase 3), and
    return a failure record for the metadata.

    Returns ``(optimization_ready, failure_or_None)``. When the fold is rejected,
    ``optimization_ready`` comes back ``False`` and the caller should treat setup
    as unsuccessful, exactly as it already does when an optimization fails to
    build. The ``optimized_poc_verify`` stage is intentionally NOT a denylist
    stage: the baseline is fine, so a later run may still produce a valid fold.
    """
    if not (optimization_ready and baseline_reproduced and not opt_crashes):
        return optimization_ready, None

    logger.error(
        "Optimization REMOVED the bug for %s (%s): the optimized binary no longer "
        "reproduces the PoC. Rejecting the fold and falling back to baseline.",
        project, cve,
    )
    force_remove(optimized_bin_dir)
    os.makedirs(optimized_bin_dir, exist_ok=True)
    shutil.copytree(baseline_bin_dir, optimized_bin_dir, dirs_exist_ok=True)
    return False, {
        "stage": "optimized_poc_verify",
        "reason": (
            f"Optimization removed the bug (optimized did not reproduce PoC for "
            f"{cve}); fold rejected and reverted to baseline"
        ),
    }


def _reject_if_no_replay_speedup(
    *,
    project: str,
    cve: str,
    optimization_ready: bool,
    replay: dict | None,
    baseline_bin_dir: str,
    optimized_bin_dir: str,
) -> tuple[bool, dict | None]:
    """Reject an optimization that does not measurably speed up replay.

    Strict throughput gate: an accepted fold MUST beat the baseline on the
    deterministic replay of the fixed corpus by at least
    ``config.PHASE2_MIN_REPLAY_SPEEDUP`` (default 1.0 = any real speedup). A fold
    whose replay speedup does not exceed that — INCLUDING one whose replay could
    not be measured at all (``replay`` is None / has no ``replay_speedup``) — is
    "not worth keeping": discard the optimized binary, fall back to baseline, and
    return a failure record. This runs after the bug-preservation gate, so a fold
    only reaches here if it built and still reproduces the PoC.

    Returns ``(optimization_ready, failure_or_None)``. Like the bug-removal gate,
    the ``replay_no_speedup`` stage is NOT a denylist stage — the baseline is
    fine and a later run may still produce a worthwhile fold.
    """
    if not optimization_ready:
        return optimization_ready, None

    min_speedup = float(getattr(config, "PHASE2_MIN_REPLAY_SPEEDUP", 1.0))
    speedup = None
    partial = False
    if isinstance(replay, dict):
        speedup = replay.get("replay_speedup")
        partial = bool(replay.get("partial"))

    # A partial measurement (a deterministic corpus crasher truncated the pass, so
    # the speedup is a rate over the reached prefix rather than the full corpus)
    # is weaker evidence, so demand a wider margin before keeping the fold on it.
    if partial:
        min_speedup = max(
            min_speedup,
            float(getattr(config, "PHASE2_MIN_REPLAY_SPEEDUP_PARTIAL", 1.05)),
        )

    if speedup is not None and speedup > min_speedup:
        return optimization_ready, None  # verified speedup — keep

    measured = "unmeasurable" if speedup is None else f"{speedup:.4f}x"
    if partial:
        measured += " (partial)"
    logger.warning(
        "Optimization for %s (%s) is NOT worth keeping: replay speedup %s does not "
        "exceed required %.4fx. Reverting the fold to baseline.",
        project, cve, measured, min_speedup,
    )
    force_remove(optimized_bin_dir)
    os.makedirs(optimized_bin_dir, exist_ok=True)
    shutil.copytree(baseline_bin_dir, optimized_bin_dir, dirs_exist_ok=True)
    return False, {
        "stage": "replay_no_speedup",
        "reason": (
            f"Optimization not worth keeping: replay speedup {measured} did not "
            f"exceed required {min_speedup:.4f}x; fold reverted to baseline"
        ),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Phase 2: Environment Setup")
    parser.add_argument(
        "--manifest", default=config.MANIFEST_PATH,
        help="Path to manifest.json",
    )
    parser.add_argument(
        "--experiment-id", default=None,
        help="Experiment ID (default: timestamp-based)",
    )
    parser.add_argument(
        "--project", default=None,
        help="Only setup a specific project (for testing)",
    )
    parser.add_argument(
        "--retry-unoptimized", action="store_true",
        help="Re-run setup for projects where optimization was not applied "
             "(e.g. after a usage-limit reset)",
    )
    parser.add_argument(
        "--model", default=None,
        help="Model to use for Codex CLI",
    )
    args = parser.parse_args()

    # Store model choice so phase 2 Codex invocations can use it
    if args.model:
        os.environ["BENCHMARK_CODEX_MODEL"] = args.model

    experiment_id = args.experiment_id or datetime.now().strftime("%Y%m%d_%H%M%S")
    logger.info("Experiment ID: %s", experiment_id)

    manifest = load_manifest(args.manifest)
    logger.info("Loaded manifest with %d entries", len(manifest))

    results = []
    for entry in manifest:
        if args.project and entry["project"] != args.project:
            continue

        # Skip already-completed projects (unless retrying unoptimized)
        experiment_dir = get_experiment_dir(experiment_id, entry)
        metadata_path = os.path.join(experiment_dir, "setup_metadata.json")
        if os.path.exists(metadata_path):
            if args.retry_unoptimized:
                try:
                    with open(metadata_path) as f:
                        meta = json.load(f)
                    if not meta.get("verification", {}).get("optimization_applied", False):
                        logger.info("Retrying %s (optimization was not applied)",
                                    entry["project"])
                        # Remove old metadata so setup_cve re-runs
                        os.remove(metadata_path)
                    else:
                        logger.info("Skipping %s (already optimized)", entry["project"])
                        results.append({"project": entry["project"], "success": True})
                        continue
                except (json.JSONDecodeError, OSError):
                    pass  # fall through to re-run
            else:
                logger.info("Skipping %s (already complete)", entry["project"])
            results.append({"project": entry["project"], "success": True})
            continue

        success = setup_cve(entry, experiment_id)
        results.append({"project": entry["project"], "success": success})

        if success:
            logger.info("[OK] %s setup complete", entry["project"])
        else:
            logger.error("[FAIL] %s setup failed", entry["project"])

    # Update manifest with resolved commits
    save_manifest(manifest, args.manifest)

    # Summary
    passed = sum(1 for r in results if r["success"])
    print(f"\n=== Setup Summary ===")
    print(f"  Passed: {passed}/{len(results)}")
    for r in results:
        status = "OK" if r["success"] else "FAIL"
        print(f"  [{status}] {r['project']}")
    print()

    if passed < config.MIN_CVE_COUNT:
        logger.error("Insufficient projects built successfully")
        sys.exit(1)


if __name__ == "__main__":
    main()
