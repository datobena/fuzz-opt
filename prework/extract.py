"""Extract the vulnerable source, harness, and PoC from an ARVO image.

The ARVO image is used ONLY as a source of artifacts -- never as a build
environment. Its toolchain is historical (clang 9-15 depending on the bug's era)
and cannot build AFL++ v5.02c, which needs LLVM >= 14. See
docs/superpowers/specs/2026-07-30-aflpp-migration-sandboxed-optimizer-design.md.

The PoC extracted here is BROKER-ONLY. It must never reach an image or a path an
agent container mounts (leak vectors 1-3 in the spec's leak inventory).
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# ARVO images bake the reproducer input here; `arvo` with no argument runs it.
BAKED_POC_PATH = "/tmp/poc"


@dataclass
class ExtractResult:
    source_dir: Path
    build_sh: Path
    poc_path: Path | None
    repro_log: str
    baseline_crashed: bool


def strip_identity(source_dir: str | Path) -> list[str]:
    """Remove every .git from an extracted tree.

    The ARVO image ships the project's real checkout, so .git carries the
    upstream remote and the exact vulnerable commit -- enough to locate the fix
    (leak vector 7). Submodules carry their own .git, which is a FILE containing
    a `gitdir:` pointer rather than a directory, hence handling both.

    Returns the paths removed, for the extraction manifest.
    """
    source_dir = Path(source_dir)
    removed: list[str] = []
    for git_path in sorted(source_dir.rglob(".git")):
        removed.append(str(git_path))
        if git_path.is_dir():
            shutil.rmtree(git_path, ignore_errors=True)
        else:
            git_path.unlink(missing_ok=True)
    return removed


def build_cp_command(container: str, src: str, dest: str) -> list[str]:
    """`docker cp` out of a CREATED (not running) container.

    Copying via `docker cp` -- rather than a bind-mounted `cp` -- leaves the host
    copies owned by the invoking user, which the optimizer needs in order to edit
    them. Mirrors extract_n132_image in phase2_setup.py.
    """
    return ["docker", "cp", f"{container}:{src}", dest]


def build_poc_command(image: str, poc_host_dir: str) -> list[str]:
    """Reproduce the bug inside the ARVO image and copy the PoC + log out.

    The exit code and log are the only evidence that this image's bug is live,
    which prework/verify.py then re-checks against the NEW build.
    """
    script = (
        "arvo > /pocout/repro.log 2>&1; "
        'echo "arvo_rc=$?" >> /pocout/repro.log; '
        f"cp {BAKED_POC_PATH} /pocout/poc_input 2>/dev/null || true; "
        "chmod a+rX /pocout/poc_input /pocout/repro.log 2>/dev/null || true"
    )
    return [
        "docker", "run", "--rm", "--privileged",
        "-v", f"{poc_host_dir}:/pocout",
        "--entrypoint", "/bin/bash", image, "-lc", script,
    ]


def _run(cmd: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, capture_output=True, text=True, errors="replace",
        timeout=timeout, check=False,
    )


def extract_arvo(
    image: str, project: str, dest: str | Path, *, pull_timeout: int = 1200,
    run_timeout: int = 900,
) -> ExtractResult:
    """Pull an ARVO image and extract source, build.sh, harness, and PoC.

    `dest` gets two subdirectories:
      src/    the vulnerable tree, .git stripped -- safe to hand to a build
      poc/    poc_input + repro.log -- BROKER-ONLY, never mounted into an agent
    """
    dest = Path(dest)
    src_out = dest / "src"
    poc_out = dest / "poc"
    for d in (src_out, poc_out):
        d.mkdir(parents=True, exist_ok=True)

    pull = _run(["docker", "pull", image], timeout=pull_timeout)
    if pull.returncode != 0:
        raise RuntimeError(f"docker pull {image} failed: {(pull.stderr or '')[-400:]}")

    _run(build_poc_command(image, str(poc_out)), timeout=run_timeout)
    log_file = poc_out / "repro.log"
    repro_log = log_file.read_text(errors="replace") if log_file.exists() else ""
    baseline_crashed = (
        "AddressSanitizer:" in repro_log
        or "SUMMARY:" in repro_log
        or "arvo_rc=1" in repro_log
    )

    container = f"arvo_extract_{project}"
    _run(["docker", "rm", "-f", container])
    create = _run(["docker", "create", "--name", container, image])
    if create.returncode != 0:
        raise RuntimeError(f"docker create failed: {(create.stderr or '')[-300:]}")
    try:
        cp = _run(build_cp_command(container, "/src/.", str(src_out)))
        if cp.returncode != 0:
            raise RuntimeError(f"docker cp /src failed: {(cp.stderr or '')[-300:]}")
    finally:
        _run(["docker", "rm", "-f", container])

    removed = strip_identity(src_out)
    logger.info("Stripped %d .git path(s) from %s", len(removed), src_out)

    build_sh = src_out / "build.sh"
    if not build_sh.is_file():
        raise RuntimeError(f"no /src/build.sh in {image}")

    poc_path = poc_out / "poc_input"
    return ExtractResult(
        source_dir=src_out,
        build_sh=build_sh,
        poc_path=poc_path if poc_path.exists() else None,
        repro_log=repro_log,
        baseline_crashed=baseline_crashed,
    )
