"""Image definition for the upstream kind: a current OSS-Fuzz project built as
OSS-Fuzz builds it.

Each onboarded project lives in prework/upstream/<project>/: the project's own
projects/<p>/ tree vendored from a pinned OSS-Fuzz commit, its Dockerfile with
only the FROM lines rewritten to digests (pinned_dockerfile, from bases.json),
meta.json and pins.json. Nothing else of OSS-Fuzz's build is changed: the image
is the project's Dockerfile, and the build inside it is OSS-Fuzz's `compile`
with FUZZING_ENGINE=afl (prework_build.upstream_compile_args).
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import subprocess
from pathlib import Path

from lib.target_kind import UPSTREAM_IMAGE_PREFIX
from prework.build_image import PREWORK_DIR

logger = logging.getLogger(__name__)

UPSTREAM_DIR = PREWORK_DIR / "upstream"
# {"<image ref as written in an OSS-Fuzz FROM>": "<ref>@sha256:<digest>", ...}
BASES_FILE = UPSTREAM_DIR / "bases.json"
# Image label carrying definition_hash(), as bench-aflpp images carry theirs.
DEFINITION_LABEL = "bench-upstream.definition-sha256"
# Written by onboarding next to the definition; an outcome, not an input.
RESULT_FILE = "onboard_result.json"


def upstream_image_tag(project: str) -> str:
    """Lowercased: Docker repository names must be (see build_image.image_tag)."""
    return UPSTREAM_IMAGE_PREFIX + project.lower()


def load_meta(project_dir: str | Path) -> dict:
    return json.loads((Path(project_dir) / "meta.json").read_text())


def load_pins(project_dir: str | Path) -> dict:
    return json.loads((Path(project_dir) / "pins.json").read_text())


def definition_hash(project_dir: str | Path) -> str:
    """sha256 over every regular file under ``project_dir`` (the whole build
    context), sorted by relative POSIX path, each fed as
    ``relpath \\0 sha256(bytes) \\n``. onboard_result.json is excluded wherever it
    sits: it records what a build did, not what it was built from."""
    root = Path(project_dir)
    files = sorted(
        (p.relative_to(root).as_posix(), p) for p in root.rglob("*")
        if p.is_file() and not p.is_symlink() and p.name != RESULT_FILE
    )
    h = hashlib.sha256()
    for rel, path in files:
        h.update(rel.encode() + b"\0"
                 + hashlib.sha256(path.read_bytes()).hexdigest().encode() + b"\n")
    return h.hexdigest()


# FROM [--flag=...]... <ref> [AS name]; keyword case-insensitive, one line.
_FROM_RE = re.compile(r"^([ \t]*FROM[ \t]+(?:--\S+[ \t]+)*)(\S+)([^\n]*)$",
                      re.IGNORECASE | re.MULTILINE)
_AS_RE = re.compile(r"[ \t]+AS[ \t]+(\S+)", re.IGNORECASE)


def pinned_dockerfile(text: str, bases: dict) -> str:
    """``text`` with every FROM ref replaced by its digest-pinned form from
    ``bases``. A ref already carrying @sha256: is kept, as is a reference to an
    earlier build stage (``FROM <stage>``) or ``scratch``, neither of which is an
    image to pull. An unknown ref raises KeyError(ref). Every other byte --
    flags, ``AS`` clause, comments, line endings, the trailing newline or its
    absence -- is unchanged."""
    stages: set[str] = set()

    def _pin(m: re.Match) -> str:
        head, ref, rest = m.group(1), m.group(2), m.group(3)
        alias = _AS_RE.match(rest)
        keep = "@sha256:" in ref or ref.lower() in stages or ref.lower() == "scratch"
        if alias:
            stages.add(alias.group(1).lower())
        if keep:
            return m.group(0)
        if ref not in bases:
            raise KeyError(ref)
        return head + bases[ref] + rest

    return _FROM_RE.sub(_pin, text)


def build_command(project_dir: str | Path, tag: str) -> list[str]:
    """The context is the vendored ossfuzz/ tree when there is one: OSS-Fuzz
    Dockerfiles ``COPY build.sh $SRC/`` relative to their own directory, and the
    pinned Dockerfile next to that tree is passed with -f. The label still
    hashes all of ``project_dir``, Dockerfile and meta included."""
    project_dir = Path(project_dir)
    context = project_dir / "ossfuzz"
    if not context.is_dir():
        context = project_dir
    return [
        "docker", "build",
        "--label", f"{DEFINITION_LABEL}={definition_hash(project_dir)}",
        "-t", tag,
        "-f", f"{project_dir}/Dockerfile",
        str(context),
    ]


def build_upstream_image(
    project_dir: str | Path, *, cpuset: str | int | None = None, timeout: int = 7200,
) -> tuple[bool, str]:
    """Build bench-upstream/<project> from ``project_dir``.

    Refuses a Dockerfile with any FROM not digest-pinned (a tag re-pulls to a
    different toolchain and silently changes the experiment). ``cpuset`` pins
    the docker CLIENT with taskset; `docker build` has no --cpuset-cpus, and the
    daemon's build containers are not confined by it.
    """
    project_dir = Path(project_dir)
    try:
        pinned_dockerfile((project_dir / "Dockerfile").read_text(), {})
    except KeyError as e:
        return False, f"Dockerfile FROM is not digest-pinned: {e.args[0]}"
    tag = upstream_image_tag(load_meta(project_dir)["project"]
                             if (project_dir / "meta.json").is_file() else project_dir.name)
    cmd = build_command(project_dir, tag)
    if cpuset is not None:
        cmd = ["taskset", "-c", str(cpuset), *cmd]
    logger.info("Building %s", tag)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return False, f"docker build timed out after {timeout}s"
    return r.returncode == 0, (r.stdout or "") + (r.stderr or "")
