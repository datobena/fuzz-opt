"""Build one modernized, pinned image per ARVO target.

Every target is built from a hand-written Dockerfile (a curated, reviewed
artifact) on a digest-pinned base-builder, with AFL++ built from a pinned release
over $SRC/aflplusplus. Pinning both is what makes the engine identical across
targets -- the property ARVO's baked-in AFL++ could never provide: of 16 ARVO
images screened, 10 ship only classic AFL 2.5x and the rest are a mix of
3.13a/4.01a/4.09a.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

PREWORK_DIR = Path(__file__).parent


def image_tag(project: str, arvo_id: int) -> str:
    """Neutral image name. Deliberately carries no '-vul' marker.

    Lowercased because Docker repository names must be: a project whose upstream
    name has capitals (PcapPlusPlus) otherwise fails the build with
    "repository name must be lowercase". Only the TAG is lowered -- the project
    name itself still has to match the real directory under $SRC, which is what
    build.sh and the source bind-mounts use.
    """
    return f"bench-aflpp/{project.lower()}-arvo-{arvo_id}"


def load_meta(target_dir: str | Path) -> dict:
    return json.loads((Path(target_dir) / "meta.json").read_text())


def read_pin(name: str) -> str:
    return (PREWORK_DIR / name).read_text().strip()


def build_docker_command(
    *, target_dir: str | Path, tag: str, base: str, aflpp_ref: str,
) -> list[str]:
    """`docker build` for one target. Refuses a base that is not digest-pinned."""
    if "@sha256:" not in base:
        raise ValueError(
            f"base image must be digest-pinned, got {base!r}; a tag re-pulls "
            "to a different toolchain and silently changes the experiment"
        )
    return [
        "docker", "build",
        "--build-arg", f"BASE={base}",
        "--build-arg", f"AFLPP_REF={aflpp_ref}",
        "-t", tag,
        "-f", str(Path(target_dir) / "Dockerfile"),
        str(target_dir),
    ]


# Fuzzing-engine source trees that ARVO ships under /src. The base image supplies
# its own, and prework replaces $SRC/aflplusplus with the pinned release -- so
# copying ARVO's would both bloat the build context and risk shadowing the pin
# with the image's historical AFL++ (3.13a/4.01a/4.09a, or classic AFL 2.5x).
ENGINE_TREES = ("aflplusplus", "afl", "honggfuzz", "libfuzzer", "fuzztest", "centipede")


def stage_source(source_dir: str | Path, staged: str | Path) -> list[str]:
    """Copy the extracted $SRC into the build context, minus the engine trees.

    ARVO's /src IS the OSS-Fuzz $SRC layout (project dir + harness sources +
    .options/dict + build.sh), so it is copied wholesale and the Dockerfile lands
    it back at $SRC. Returns the names pruned, for the build record.
    """
    source_dir, staged = Path(source_dir), Path(staged)
    if staged.exists():
        shutil.rmtree(staged, ignore_errors=True)
    pruned: list[str] = []

    def _ignore(directory, names):
        if Path(directory) != source_dir:
            return []
        skip = [n for n in names if n in ENGINE_TREES]
        pruned.extend(skip)
        return skip

    shutil.copytree(source_dir, staged, symlinks=True, ignore=_ignore)
    return pruned


def build_image(
    target_dir: str | Path, source_dir: str | Path, tag: str, *, timeout: int = 5400,
) -> tuple[bool, str]:
    """Stage the extracted source into the build context, then build.

    Staged source is a build artifact, not source of record -- see .gitignore.
    """
    target_dir = Path(target_dir)
    staged = target_dir / "src"
    pruned = stage_source(source_dir, staged)
    if pruned:
        logger.info("Pruned engine trees from build context: %s", ", ".join(pruned))

    cmd = build_docker_command(
        target_dir=target_dir, tag=tag,
        base=read_pin("base.pin"), aflpp_ref=read_pin("aflpp.pin"),
    )
    logger.info("Building %s", tag)
    r = subprocess.run(
        cmd, capture_output=True, text=True, errors="replace",
        timeout=timeout, check=False,
    )
    return r.returncode == 0, (r.stdout or "") + (r.stderr or "")
