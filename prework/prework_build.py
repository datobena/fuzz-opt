"""Build a modified source tree inside the pinned prework image.

Phase 2 previously rebuilt through `arvo compile` in the ARVO image
(phase2_setup.rebuild_with_modified_source_n132). That path is retired for three
reasons:

  * `arvo` exports FUZZING_ENGINE=libfuzzer unconditionally, which is exactly the
    engine the benchmark is migrating away from;
  * the ARVO toolchain is historical (clang 9-15) and cannot build AFL++ v5.02c,
    so the engine version would differ per target;
  * the ARVO image bakes /tmp/poc and the `arvo` reproducer, both of which are
    direct answers to "where is the bug" for any agent that can reach docker.

The prework image has none of those problems: one pinned AFL++ v5.02c on LLVM 18
across every target, and no reproducer baked in.
"""
from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from prework.build_image import image_tag

logger = logging.getLogger(__name__)

BUILD_TIMEOUT_SECS = 5400


def prework_image_for(entry: dict) -> str:
    """Resolve a manifest entry to its pinned prework image."""
    local_id = entry.get("local_id")
    if not local_id:
        raise ValueError(
            f"entry for {entry.get('project')!r} has no local_id; the prework "
            "image tag is derived from it"
        )
    return image_tag(entry["project"], int(local_id))


def build_prework_rebuild_command(
    *, image: str, source_dir: str, out_dir: str, project: str,
    cpu: int | None = None,
) -> list[str]:
    """`docker run <prework image> compile` with the modified source mounted.

    The source is bind-mounted over $SRC/<project> so the image's own build.sh
    (curated per target during prework) compiles the optimizer's edits rather
    than the copy baked into the image.
    """
    cmd = ["docker", "run", "--rm", "--privileged"]
    if cpu is not None:
        cmd += ["--cpuset-cpus", str(cpu)]
    cmd += [
        "-e", "FUZZING_ENGINE=afl",
        "-e", "SANITIZER=address",
        "-e", "ARCHITECTURE=x86_64",
        "-e", "FUZZING_LANGUAGE=c++",
        "-v", f"{Path(source_dir).absolute()}:/src/{project}",
        "-v", f"{Path(out_dir).absolute()}:/out",
        image, "compile",
    ]
    return cmd


def rebuild_with_prework_image(
    *, entry: dict, source_dir: str, out_dir: str, cpu: int | None = None,
    capture_log: bool = False, timeout: int = BUILD_TIMEOUT_SECS,
) -> bool | tuple[bool, str]:
    """Rebuild the target from a modified tree. Mirrors the old n132 signature."""
    image = prework_image_for(entry)
    project = entry["project"]
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    cmd = build_prework_rebuild_command(
        image=image, source_dir=source_dir, out_dir=out_dir,
        project=project, cpu=cpu,
    )
    logger.info("Rebuilding %s in %s", project, image)
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        log = f"build timed out after {timeout}s"
        logger.error("%s for %s", log, project)
        return (False, log) if capture_log else False
    log = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0:
        logger.error("prework rebuild failed for %s (exit %d)", project, r.returncode)
    ok = r.returncode == 0
    return (ok, log) if capture_log else ok
