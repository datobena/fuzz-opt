# AFL++ Prework Images Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a reusable, pinned Docker image per ARVO target that builds the vulnerable source with AFL++ v5.02c on a modern toolchain, and prove the target bug still reproduces in it.

**Architecture:** Pull the ARVO image only to *extract* the vulnerable source, harness, and PoC — never to build. Build instead from a hand-written per-target Dockerfile based on a digest-pinned OSS-Fuzz `base-builder`, with AFL++ v5.02c compiled over `/src/aflplusplus` so the stock `compile_afl` path picks it up unmodified. Verify the PoC still crashes the resulting ASAN binary; drop the target if not.

**Tech Stack:** Python 3.11, Docker, OSS-Fuzz `base-builder`, AFL++ v5.02c, pytest.

## Context

This is **Plan 1 of 3** for the migration described in
`docs/superpowers/specs/2026-07-30-aflpp-migration-sandboxed-optimizer-design.md`
(branch `feat/aflpp-sandboxed-optimizer`).

- **Plan 1 (this document) — Prework images.** Self-contained deliverable: a built,
  verified `bench-aflpp/<project>-<arvoid>` image plus the broker-only artifacts
  (pristine source, PoC) that later plans consume.
- **Plan 2 — Sandbox.** Broker, agent container, scrubber, leak-audit test. Depends on
  Plan 1's image existing.
- **Plan 3 — Engine migration.** Phases 2–4 on AFL++.

**Write Plans 2 and 3 only after Plan 1 lands.** Toolchain attrition is unmeasured — if
most targets lose their bug under a modern clang, the target-pool question reopens and
that changes what Plans 2 and 3 are built against.

## Global Constraints

- **AFL++ pinned to release `v5.02c`**, identical across every target. Never use the
  AFL++ that ships in a base image.
- **`base-builder` pinned by digest**, not by tag. Record the digest in `prework/base.pin`.
- **Sanitizer: `address`.** Engine: `afl`. Architecture: `x86_64`.
- **The PoC is broker-only.** It must never be copied into any image, and never written
  under a path that a later agent container mounts.
- **`.git` is stripped** from every extracted source tree.
- **Per-target Dockerfiles are hand-written and committed**, treated as curated artifacts.
- Run top-level test files explicitly (`python -m pytest test_foo.py`). Bare `pytest`
  breaks on the cloned trees under `results/`.
- Python style follows the existing repo: module docstring explaining *why*, `logging`
  not `print`, `subprocess.run(..., capture_output=True, text=True, errors="replace")`.

---

### Task 1: ARVO source extraction

Extracts the vulnerable source, build script, harness, and PoC from an ARVO image. This
is the only step that touches the ARVO image at all.

**Files:**
- Create: `prework/__init__.py` (empty)
- Create: `prework/extract.py`
- Test: `test_prework_extract.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `extract_arvo(image: str, project: str, dest: Path) -> ExtractResult`
  - `ExtractResult` dataclass with fields `source_dir: Path`, `build_sh: Path`,
    `poc_path: Path | None`, `repro_log: str`, `baseline_crashed: bool`
  - `strip_identity(source_dir: Path) -> list[str]` — removes `.git`, returns removed paths.

- [ ] **Step 1: Write the failing test for `strip_identity`**

```python
# test_prework_extract.py
import subprocess
from pathlib import Path

from prework.extract import strip_identity


def test_strip_identity_removes_git_dir(tmp_path):
    """The upstream .git exposes the vulnerable commit and remote (leak vector 7)."""
    src = tmp_path / "libxml2"
    (src / ".git").mkdir(parents=True)
    (src / ".git" / "config").write_text("[remote \"origin\"]\n")
    (src / "parser.c").write_text("int main(void){return 0;}\n")

    removed = strip_identity(src)

    assert not (src / ".git").exists()
    assert (src / "parser.c").exists(), "source files must survive"
    assert str(src / ".git") in removed


def test_strip_identity_removes_nested_git(tmp_path):
    """Submodules carry their own .git; those leak upstream identity too."""
    src = tmp_path / "assimp"
    (src / "contrib" / "zlib" / ".git").mkdir(parents=True)
    (src / "contrib" / "zlib" / "zlib.c").write_text("\n")

    strip_identity(src)

    assert not (src / "contrib" / "zlib" / ".git").exists()
    assert (src / "contrib" / "zlib" / "zlib.c").exists()


def test_strip_identity_is_idempotent(tmp_path):
    """Re-running on an already-clean tree must not raise."""
    src = tmp_path / "lua"
    src.mkdir()
    (src / "lua.c").write_text("\n")

    assert strip_identity(src) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest test_prework_extract.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'prework'`

- [ ] **Step 3: Implement `strip_identity`**

```python
# prework/extract.py
"""Extract the vulnerable source, harness, and PoC from an ARVO image.

The ARVO image is used ONLY as a source of artifacts -- never as a build
environment. Its toolchain is historical (clang 9-15 depending on the bug's era)
and cannot build AFL++ v5.02c, which needs LLVM >= 14. See
docs/superpowers/specs/2026-07-30-aflpp-migration-sandboxed-optimizer-design.md.

The PoC extracted here is BROKER-ONLY. It must never reach an image or a path an
agent container mounts (leak vectors 1-3).
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


def strip_identity(source_dir: Path) -> list[str]:
    """Remove every .git directory from an extracted tree.

    The ARVO image ships the project's real checkout, so .git carries the
    upstream remote and the exact vulnerable commit -- enough to locate the fix
    (leak vector 7). Submodules carry their own .git, hence the recursive walk.

    Returns the paths removed, for the extraction manifest.
    """
    source_dir = Path(source_dir)
    removed: list[str] = []
    for git_path in sorted(source_dir.rglob(".git")):
        removed.append(str(git_path))
        if git_path.is_dir():
            shutil.rmtree(git_path, ignore_errors=True)
        else:
            git_path.unlink(missing_ok=True)  # submodule .git files
    return removed
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest test_prework_extract.py -v`
Expected: 3 passed

- [ ] **Step 5: Write the failing test for the docker command builders**

Command construction is tested without invoking docker; the integration path is
exercised in Task 3.

```python
# append to test_prework_extract.py
from prework.extract import build_cp_command, build_poc_command


def test_build_cp_command_targets_the_container_not_the_image():
    cmd = build_cp_command("arvo_extract_1972", "/src/.", "/tmp/out")
    assert cmd[:2] == ["docker", "cp"]
    assert cmd[2] == "arvo_extract_1972:/src/."
    assert cmd[3] == "/tmp/out"


def test_build_poc_command_writes_poc_and_log_to_the_mounted_dir():
    cmd = build_poc_command("n132/arvo:1972-vul", "/host/poc")
    joined = " ".join(cmd)
    assert "-v" in cmd and "/host/poc:/pocout" in cmd
    assert "--entrypoint" in cmd
    assert "arvo" in joined and "/pocout/repro.log" in joined
    assert "/tmp/poc" in joined, "the PoC is baked at /tmp/poc in ARVO images"
```

- [ ] **Step 6: Run test to verify it fails**

Run: `python -m pytest test_prework_extract.py -v`
Expected: FAIL with `ImportError: cannot import name 'build_cp_command'`

- [ ] **Step 7: Implement the command builders and `extract_arvo`**

```python
# append to prework/extract.py

BAKED_POC_PATH = "/tmp/poc"


@dataclass
class ExtractResult:
    source_dir: Path
    build_sh: Path
    poc_path: Path | None
    repro_log: str
    baseline_crashed: bool


def build_cp_command(container: str, src: str, dest: str) -> list[str]:
    """`docker cp` out of a CREATED (not running) container.

    Copying via `docker cp` -- rather than a bind-mounted `cp` -- leaves the host
    copies owned by the invoking user, which the optimizer needs in order to edit
    them. Mirrors extract_n132_image in phase2_setup.py.
    """
    return ["docker", "cp", f"{container}:{src}", dest]


def build_poc_command(image: str, poc_host_dir: str) -> list[str]:
    """Reproduce the bug inside the ARVO image and copy the PoC + log out.

    `arvo` with no argument runs the baked reproducer. Its exit code and log are
    the only evidence that this image's bug is live, which Task 3 re-checks
    against the NEW build.
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
    image: str, project: str, dest: Path, *, pull_timeout: int = 1200,
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
        _run(build_cp_command(container, "/src/.", str(src_out)))
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
```

- [ ] **Step 8: Run test to verify it passes**

Run: `python -m pytest test_prework_extract.py -v`
Expected: 5 passed

- [ ] **Step 9: Commit**

```bash
git add prework/__init__.py prework/extract.py test_prework_extract.py
git commit -m "feat(prework): extract ARVO source, harness, and PoC

The ARVO image is used only as an artifact source, never as a build
environment -- its historical clang cannot build AFL++ v5.02c. .git is
stripped on the way out (leak vector 7) and the PoC lands in a
broker-only directory that no agent container will mount."
```

---

### Task 2: Pinned per-target image build

Builds the modernized image. The Dockerfile is hand-written per target and committed.

**Files:**
- Create: `prework/base.pin`
- Create: `prework/aflpp.pin`
- Create: `prework/targets/libxml2-arvo-1972/Dockerfile`
- Create: `prework/targets/libxml2-arvo-1972/meta.json`
- Create: `prework/build_image.py`
- Test: `test_prework_build.py`

**Interfaces:**
- Consumes: `prework.extract.ExtractResult` from Task 1.
- Produces:
  - `image_tag(project: str, arvo_id: int) -> str` → `"bench-aflpp/<project>-arvo-<id>"`
  - `build_image(target_dir: Path, source_dir: Path, tag: str) -> tuple[bool, str]`
  - `load_meta(target_dir: Path) -> dict` with keys `project`, `arvo_id`, `fuzz_target`,
    `crash_type`, `arvo_image`.

- [ ] **Step 1: Write the pin files**

```bash
# prework/aflpp.pin — AFL++ v5.02c, released 2026-06-29
v5.02c
```

Resolve the base-builder digest and write it to `prework/base.pin`:

```bash
docker pull gcr.io/oss-fuzz-base/base-builder
docker inspect --format '{{index .RepoDigests 0}}' gcr.io/oss-fuzz-base/base-builder \
  > prework/base.pin
cat prework/base.pin   # expect gcr.io/oss-fuzz-base/base-builder@sha256:...
```

- [ ] **Step 2: Write the libxml2 target metadata**

```json
{
  "project": "libxml2",
  "arvo_id": 1972,
  "arvo_image": "n132/arvo:1972-vul",
  "fuzz_target": "libxml2_xml_read_memory_fuzzer",
  "crash_type": "Stack-buffer-overflow WRITE {*}"
}
```

`crash_type` is orchestrator-only — it is the triage signature for Plan 3 and must
never reach an agent container.

- [ ] **Step 3: Write the libxml2 Dockerfile**

Dependencies come from `oss-fuzz/projects/libxml2/Dockerfile` (autotools + a newer
automake), with its `git clone` and `COPY` lines dropped because Task 1 supplies the
source.

```dockerfile
# syntax=docker/dockerfile:1
# Modernized build environment for libxml2 / ARVO 1972.
#
# Deps mirror oss-fuzz/projects/libxml2/Dockerfile, minus its git clone (ARVO
# supplies the vulnerable source) and minus its automake pin (the modern base
# already ships a newer automake than the historical image did).
ARG BASE
FROM ${BASE}

RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf automake libtool pkg-config zlib1g-dev liblzma-dev python3 \
    && rm -rf /var/lib/apt/lists/*

# Replace the base image's bundled AFL++ with the pinned release. compile_afl
# copies libAFLDriver.a and the afl-* binaries out of $SRC/aflplusplus, so
# building v5.02c in place makes the stock OSS-Fuzz build path use it with no
# further patching.
ARG AFLPP_REF
RUN rm -rf $SRC/aflplusplus && \
    git clone --depth 1 --branch "${AFLPP_REF}" \
        https://github.com/AFLplusplus/AFLplusplus $SRC/aflplusplus && \
    cd $SRC/aflplusplus && \
    unset CFLAGS CXXFLAGS && \
    make clean && \
    make -j"$(nproc)" source-only && \
    test -f libAFLDriver.a && test -x afl-fuzz && test -x afl-showmap

COPY src/ $SRC/libxml2/
COPY src/build.sh $SRC/build.sh
WORKDIR $SRC
```

- [ ] **Step 4: Write the failing test**

```python
# test_prework_build.py
import json
from pathlib import Path

import pytest

from prework.build_image import build_docker_command, image_tag, load_meta

TARGET = Path("prework/targets/libxml2-arvo-1972")


def test_image_tag_is_neutral():
    """The tag must not carry '-vul' or anything that names the bug."""
    tag = image_tag("libxml2", 1972)
    assert tag == "bench-aflpp/libxml2-arvo-1972"
    assert "vul" not in tag


def test_load_meta_reads_the_committed_target():
    meta = load_meta(TARGET)
    assert meta["project"] == "libxml2"
    assert meta["arvo_id"] == 1972
    assert meta["fuzz_target"] == "libxml2_xml_read_memory_fuzzer"
    assert meta["crash_type"]


def test_build_docker_command_pins_base_and_aflpp(tmp_path):
    base = "gcr.io/oss-fuzz-base/base-builder@sha256:deadbeef"
    cmd = build_docker_command(
        target_dir=tmp_path, tag="bench-aflpp/x-arvo-1", base=base, aflpp_ref="v5.02c",
    )
    joined = " ".join(cmd)
    assert "BASE=" + base in joined, "base must be digest-pinned, not tag-pinned"
    assert "AFLPP_REF=v5.02c" in joined
    assert "@sha256:" in joined


def test_build_docker_command_rejects_unpinned_base(tmp_path):
    """A tag-pinned base silently drifts when re-pulled; refuse it."""
    with pytest.raises(ValueError, match="digest"):
        build_docker_command(
            target_dir=tmp_path, tag="bench-aflpp/x-arvo-1",
            base="gcr.io/oss-fuzz-base/base-builder:latest", aflpp_ref="v5.02c",
        )
```

- [ ] **Step 5: Run test to verify it fails**

Run: `python -m pytest test_prework_build.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'prework.build_image'`

- [ ] **Step 6: Implement `prework/build_image.py`**

```python
# prework/build_image.py
"""Build one modernized, pinned image per ARVO target.

Every target is built from a hand-written Dockerfile (a curated, reviewed
artifact) on a digest-pinned base-builder, with AFL++ v5.02c compiled over
$SRC/aflplusplus. Pinning both is what makes the engine identical across
targets -- the property ARVO's baked-in AFL++ (a mix of 3.13a/4.01a/4.09a, and
classic AFL 2.5x on most images) could never provide.
"""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

PREWORK_DIR = Path(__file__).parent


def image_tag(project: str, arvo_id: int) -> str:
    """Neutral image name. Deliberately carries no '-vul' marker."""
    return f"bench-aflpp/{project}-arvo-{arvo_id}"


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


def build_image(
    target_dir: str | Path, source_dir: Path, tag: str, *, timeout: int = 5400,
) -> tuple[bool, str]:
    """Stage the extracted source into the build context, then build.

    The Dockerfile COPYs `src/`, so the extracted tree is placed there first.
    """
    target_dir = Path(target_dir)
    staged = target_dir / "src"
    if staged.exists():
        subprocess.run(["rm", "-rf", str(staged)], check=False)
    subprocess.run(["cp", "-a", str(source_dir), str(staged)], check=True)

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
```

- [ ] **Step 7: Run test to verify it passes**

Run: `python -m pytest test_prework_build.py -v`
Expected: 4 passed

- [ ] **Step 8: Build the real image and verify AFL++ landed**

```bash
python3 -c "
import logging; logging.basicConfig(level=logging.INFO)
from pathlib import Path
from prework.extract import extract_arvo
from prework.build_image import build_image, image_tag, load_meta
m = load_meta('prework/targets/libxml2-arvo-1972')
r = extract_arvo(m['arvo_image'], m['project'], Path('/tmp/prework-libxml2'))
print('baseline crashed in ARVO image:', r.baseline_crashed)
ok, log = build_image('prework/targets/libxml2-arvo-1972', r.source_dir,
                      image_tag(m['project'], m['arvo_id']))
print('build ok:', ok)
print(log[-3000:] if not ok else '')
"
docker run --rm --entrypoint /bin/bash bench-aflpp/libxml2-arvo-1972 -lc \
  '/src/aflplusplus/afl-fuzz 2>&1 | head -1; clang --version | head -1'
```

Expected: `afl-fuzz++5.02c`, and a clang of 14 or newer.

**If the AFL++ build fails**, the likely cause is an LLVM floor. Check
`clang --version` in the base; if it is below 14, the base pin is too old — re-pull
`base-builder` and re-pin. Record the outcome either way; it is a Plan-2 input.

- [ ] **Step 9: Commit**

```bash
git add prework/base.pin prework/aflpp.pin prework/build_image.py \
        prework/targets/libxml2-arvo-1972/Dockerfile \
        prework/targets/libxml2-arvo-1972/meta.json test_prework_build.py
git commit -m "feat(prework): pinned per-target image with AFL++ v5.02c

Digest-pinned base-builder plus AFL++ v5.02c built over \$SRC/aflplusplus,
so stock compile_afl picks it up. build_docker_command refuses a
tag-pinned base, which would silently re-pull a different toolchain and
change the experiment underneath us."
```

Add `prework/targets/*/src/` to `.gitignore` in this commit — the staged source is a
build artifact, not source of record.

---

### Task 3: Build the target and verify the bug survives

The decision gate for the whole migration: does a 2017 bug still reproduce under a 2026
toolchain?

**Files:**
- Create: `prework/verify.py`
- Create: `prework/run_prework.py`
- Test: `test_prework_verify.py`

**Interfaces:**
- Consumes: `image_tag`, `load_meta` (Task 2); `extract_arvo` (Task 1).
- Produces:
  - `compile_command(tag: str, out_dir: Path) -> list[str]`
  - `verify_poc(tag: str, out_dir: Path, fuzz_target: str, poc: Path, expected: str) -> VerifyResult`
  - `VerifyResult` dataclass: `reproduced: bool`, `detected_signature: str`, `log: str`
  - CLI: `python -m prework.run_prework --target prework/targets/libxml2-arvo-1972`

- [ ] **Step 1: Write the failing test**

Signature matching reuses `lib.crash_classify.normalize_signature`, which already
handles the `"Heap-use-after-free READ 8"` → `"heap-use-after-free"` reduction.

```python
# test_prework_verify.py
from prework.verify import compile_command, signature_matches


def test_compile_command_selects_afl_and_asan():
    cmd = compile_command("bench-aflpp/libxml2-arvo-1972", "/tmp/out")
    joined = " ".join(cmd)
    assert "FUZZING_ENGINE=afl" in joined
    assert "SANITIZER=address" in joined
    assert "ARCHITECTURE=x86_64" in joined
    assert joined.rstrip().endswith("compile"), "must invoke OSS-Fuzz compile"
    assert "arvo" not in joined, "the arvo wrapper hardcodes FUZZING_ENGINE=libfuzzer"


def test_signature_matches_ignores_access_and_size_suffixes():
    assert signature_matches("stack-buffer-overflow", "Stack-buffer-overflow WRITE {*}")
    assert signature_matches("heap-buffer-overflow READ 8", "Heap-buffer-overflow READ 1")


def test_signature_mismatch_is_not_the_target_bug():
    """A fold can introduce a DIFFERENT crash; that is not the bug reproducing."""
    assert not signature_matches("heap-use-after-free", "Stack-buffer-overflow WRITE {*}")


def test_signature_matches_requires_a_detection():
    assert not signature_matches("", "Stack-buffer-overflow WRITE {*}")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest test_prework_verify.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'prework.verify'`

- [ ] **Step 3: Implement `prework/verify.py`**

```python
# prework/verify.py
"""Build a prework image's target and check the ARVO bug still reproduces.

This is the migration's decision gate. The bugs are from 2016-2021 and are being
rebuilt on a 2026 toolchain: different inlining and stack layout can stop ASAN
catching a stack overflow, and a newer clang can optimize away UB the bug relied
on. Per the spec, a target whose PoC no longer reproduces is DROPPED rather than
patched around, so the benchmark only ever measures bugs that demonstrably exist
in the binary under test.
"""
from __future__ import annotations

import logging
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lib.crash_classify import normalize_signature

logger = logging.getLogger(__name__)

RUNNER_IMAGE = "gcr.io/oss-fuzz-base/base-runner"
_SUMMARY_RE = re.compile(r"SUMMARY:\s*\w*Sanitizer:\s*([a-zA-Z0-9_\- ]+)")


@dataclass
class VerifyResult:
    reproduced: bool
    detected_signature: str
    log: str


def compile_command(tag: str, out_dir: str | Path) -> list[str]:
    """Run OSS-Fuzz `compile` with the AFL engine.

    Deliberately calls `compile` and not `arvo compile`: the arvo wrapper exports
    FUZZING_ENGINE=libfuzzer unconditionally, which is exactly what we are
    migrating away from.
    """
    return [
        "docker", "run", "--rm", "--privileged",
        "-e", "FUZZING_ENGINE=afl",
        "-e", "SANITIZER=address",
        "-e", "ARCHITECTURE=x86_64",
        "-e", "FUZZING_LANGUAGE=c++",
        "-v", f"{Path(out_dir).absolute()}:/out",
        tag, "compile",
    ]


def signature_matches(detected: str, expected: str) -> bool:
    """True iff a detected ASAN signature is the manifest's expected bug class."""
    if not detected:
        return False
    return normalize_signature(detected) == normalize_signature(expected)


def verify_poc(
    tag: str, out_dir: str | Path, fuzz_target: str, poc: str | Path,
    expected_signature: str, *, timeout: int = 300,
) -> VerifyResult:
    """Replay the PoC on the freshly built AFL++/ASAN binary.

    aflpp_driver's ExecuteFilesOnyByOne runs file arguments once each, so the
    libFuzzer-style `<target> <file>` invocation still works on an AFL build.
    """
    cmd = [
        "docker", "run", "--rm", "--privileged",
        "-v", f"{Path(out_dir).absolute()}:/out:ro",
        "-v", f"{Path(poc).absolute()}:/testcase:ro",
        RUNNER_IMAGE, "/bin/bash", "-lc",
        f"export ASAN_OPTIONS=detect_leaks=0; /out/{fuzz_target} /testcase",
    ]
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return VerifyResult(False, "", "timeout")

    blob = (r.stdout or "") + (r.stderr or "")
    m = _SUMMARY_RE.search(blob)
    detected = m.group(1).strip() if m else ""
    return VerifyResult(
        reproduced=signature_matches(detected, expected_signature),
        detected_signature=detected,
        log=blob,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest test_prework_verify.py -v`
Expected: 4 passed

- [ ] **Step 5: Implement the driver `prework/run_prework.py`**

```python
# prework/run_prework.py
"""Drive the full prework for one target: extract -> build -> compile -> verify.

Writes prework_result.json next to the extracted artifacts. A target whose PoC
does not reproduce is reported as dropped; nothing downstream should use it.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from prework.build_image import build_image, image_tag, load_meta
from prework.extract import extract_arvo
from prework.verify import compile_command, verify_poc

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def main() -> int:
    ap = argparse.ArgumentParser(description="Prework for one ARVO target")
    ap.add_argument("--target", required=True, help="prework/targets/<name>")
    ap.add_argument("--work", default="/tmp/prework", help="artifact root")
    args = ap.parse_args()

    target_dir = Path(args.target)
    meta = load_meta(target_dir)
    work = Path(args.work) / f"{meta['project']}-arvo-{meta['arvo_id']}"
    tag = image_tag(meta["project"], meta["arvo_id"])

    logger.info("[1/4] extracting from %s", meta["arvo_image"])
    extracted = extract_arvo(meta["arvo_image"], meta["project"], work)
    if not extracted.baseline_crashed:
        logger.error("ARVO image itself does not reproduce; target is unusable")
        return 2
    if extracted.poc_path is None:
        logger.error("no PoC extracted; cannot verify")
        return 2

    logger.info("[2/4] building %s", tag)
    ok, build_log = build_image(target_dir, extracted.source_dir, tag)
    if not ok:
        (work / "build.log").write_text(build_log)
        logger.error("image build failed; see %s", work / "build.log")
        return 3

    logger.info("[3/4] compiling target with FUZZING_ENGINE=afl")
    out_dir = work / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    import subprocess
    c = subprocess.run(
        compile_command(tag, out_dir), capture_output=True, text=True,
        errors="replace", check=False,
    )
    if c.returncode != 0:
        (work / "compile.log").write_text((c.stdout or "") + (c.stderr or ""))
        logger.error("compile failed; see %s", work / "compile.log")
        return 4

    logger.info("[4/4] verifying the PoC still reproduces")
    v = verify_poc(
        tag, out_dir, meta["fuzz_target"], extracted.poc_path, meta["crash_type"],
    )
    result = {
        "target": target_dir.name,
        "image": tag,
        "fuzz_target": meta["fuzz_target"],
        "expected_signature": meta["crash_type"],
        "detected_signature": v.detected_signature,
        "reproduced": v.reproduced,
        "status": "ready" if v.reproduced else "dropped",
    }
    (work / "prework_result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0 if v.reproduced else 5


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 6: Run the real prework end-to-end**

```bash
python3 -m prework.run_prework --target prework/targets/libxml2-arvo-1972
```

Expected: `"reproduced": true`, `"status": "ready"`, and a detected signature
normalizing to `stack-buffer-overflow`.

Also confirm the AFL binary is usable as a fuzzer, not just as a replayer:

```bash
ls /tmp/prework/libxml2-arvo-1972/out/ | grep -E '^afl-(fuzz|showmap)$'
```

Expected: both present — `compile_afl` copies them into `$OUT`, which is what Plan 3's
phase-3 runner will invoke.

**If `reproduced` is false**, do not patch around it. Record the detected signature in
`prework_result.json`, mark the target dropped, and report the outcome — it is the
attrition signal that governs whether Plans 2 and 3 proceed against ARVO at all.

- [ ] **Step 7: Commit**

```bash
git add prework/verify.py prework/run_prework.py test_prework_verify.py
git commit -m "feat(prework): verify the bug survives the modern toolchain

Replays the ARVO PoC on the freshly built AFL++/ASAN binary and matches
the signature against the manifest crash_type, reusing
crash_classify.normalize_signature. A target that no longer reproduces is
dropped, not patched around, so the benchmark only measures bugs that
demonstrably exist in the binary under test."
```

---

## Self-Review

**Spec coverage.** Plan 1 covers the spec's Component 1 in full: extraction (Task 1),
hand-written pinned Dockerfile and AFL++ v5.02c (Task 2), PoC verification and the
drop-on-failure rule (Task 3). Components 2 and 3 are deliberately deferred to Plans 2
and 3, gated on Task 3's attrition result.

**Placeholders.** None. Every step carries runnable code or a concrete command. The one
value resolved at runtime — the base-builder digest — has an explicit command to
produce it and a test that rejects an unpinned substitute.

**Type consistency.** `image_tag`, `load_meta`, `build_docker_command`, `build_image`,
`extract_arvo`, `ExtractResult`, `compile_command`, `signature_matches`, `verify_poc`,
and `VerifyResult` are each defined once and referenced with matching signatures.
`run_prework.py` consumes exactly the names Tasks 1–2 produce.

**Known uncertainty, deliberately left to measurement.** Whether `make source-only`
yields `libAFLDriver.a` on this AFL++ release, and whether the base-builder's clang
clears AFL++'s LLVM-14 floor, are both checked by explicit assertions in Task 2 Step 8
rather than assumed. Same for the `time:` field semantics that Plan 3 will depend on.

## Verification

```bash
python -m pytest test_prework_extract.py test_prework_build.py test_prework_verify.py -v
python3 -m prework.run_prework --target prework/targets/libxml2-arvo-1972
```

Green tests plus `"status": "ready"` means Plan 1 is done and Plan 2 can be written.

---

## Execution Record (2026-07-31)

**Outcome: Plan 1 complete.** libxml2/arvo-1972 verdict `reproduced` / status `ready`.
23 tests passing. Commits `4cefa73`, `8f6e64b`, `30ba6aa` on
`feat/aflpp-sandboxed-optimizer`.

The plan above is preserved as written. Five things execution changed, and they are
what a second target should start from:

**1. LLVM must be pinned, not inherited.** `base-builder` currently ships a clang 22
trunk build, and AFL++ v5.02c does not compile against LLVM 22 headers
(`afl-llvm-common.o` fails on changed `StringLiteral` signatures). AFL++'s makefile
treats LLVM-mode failure as **non-fatal**, so the result was an `afl-cc` with no
compiler mode: it builds clean and silently emits an **uninstrumented** target. The
Dockerfile now installs `clang-18`/`llvm-18-dev` and builds AFL++ with
`LLVM_CONFIG=llvm-config-18`. This also removes the base image's drifting clang from
the experiment, which is strictly better than the plan's original design.

**2. Assert on instrumentation, not on artifacts.** `test -x afl-clang-fast` is
insufficient. The image now compiles a trivial program **with `-fsanitize=address`**
and greps for `__afl_area_ptr`. The ASAN part matters: a plain build passes even when
compiler-rt is missing, which surfaces later only as configure's opaque "C compiler
cannot create executables".

**3. Three per-target build facts** (all belong in the hand-written Dockerfile/build.sh,
which is exactly the curated-artifact model chosen):
- `WORKDIR $SRC/<project>` — OSS-Fuzz runs `build.sh` from the project dir, not `$SRC`.
- `libclang-rt-<v>-dev` — Ubuntu's `clang-N` omits the sanitizer runtimes.
- Do **not** add dev packages the ARVO image lacked. Adding `zlib1g-dev`/`liblzma-dev`
  made configure enable compression that the historical link line cannot satisfy.
  Check with `nm -u` on the ARVO binary before adding any dependency.

**4. Run the target in the prework image, not `base-runner`.** The target links the
pinned LLVM's shared `libc++.so.1`, which `base-runner` does not carry. Using the
pinned image end-to-end also keeps a second, unpinned environment out of the study.

**5. Verification is four-state, not boolean** (`prework/verify.py:classify_run`):
`reproduced` / `wrong_crash` / `no_crash` / `did_not_run`. This is measurement-critical
rather than cosmetic — the study's headline result is a bug-**survival** rate, so an
infrastructure failure recorded as "did not reproduce" becomes fabricated evidence that
optimization removed a bug. This exact false negative occurred during execution (missing
`libc++.so.1` → `status: dropped`). Only a proven clean execution — aflpp_driver's
`Execution successful.` marker — counts as attrition.

### Carry into Plan 3

- `lib/crash_classify.py`'s `_SUMMARY_RE` permits spaces in the bug class, so a relative
  path in an ASAN SUMMARY is absorbed into the signature. Fixed in `prework/verify.py`;
  the shared copy still needs reconciling.
- The same four-state discipline must apply to the post-hoc PoC check, for the same
  reason.
- `$OUT` contains `afl-fuzz`, `afl-showmap`, `afl-cmin`; the target carries AFL
  instrumentation and aflpp_driver symbols. Phase 3 can invoke them directly.

### Still unmeasured

Attrition across the **other** targets. libxml2 was the most favourable case (its ARVO
image was already Ubuntu 20.04 / clang 15). The 16.04-based targets — libavc, assimp,
wolfssl — are untested and are what determine whether the ARVO pool is viable.

---

## Execution Record — Plans 2 & 3 (2026-07-31)

**9 of 10 tasks complete.** 185 tests passing. Commits `898c928` … `95272de` on
`feat/aflpp-sandboxed-optimizer`.

Complete: log scrubber, build broker, agent container + launcher, leak audit,
AFL parsing (live-validated), phase-3 AFL runner, crash triage, phase-4 bug
survival, signature-regex reconciliation.

**Task 8 (phase-2 rewiring) is PARTIAL.** Done: the bug-preservation gate is
removed and replaced with a recorder, `poc_verdict` is threaded into
`setup_metadata.json`, and the retry prompt is scrubbed. Still to do:

1. Point the build path at `bench-aflpp/<project>-arvo-<id>`; delete the
   `arvo compile` path.
2. Replace `_invoke_agent_capture` with a broker-mediated sandbox launch.
   **The sandbox is inert until this lands** — every component exists and is
   tested, but phase 2 still invokes the agent unconfined.
3. Move corpus grow / crash filter / mutation capture broker-side; replace the
   link-time libFuzzer shim with an `AFL_CUSTOM_MUTATOR_LIBRARY` `.so` and delete
   `mutation_dump_mutator.c`.

### Findings that changed the design

- **AFL++ v5.02c does not build against clang 22** (what `base-builder` ships).
  Its makefile treats LLVM-mode failure as non-fatal, producing an `afl-cc` with
  no compiler mode: builds clean, emits an **uninstrumented** target. Fixed by
  pinning LLVM 18, which also removes the base image's drifting clang from the
  experiment.
- **`time:` is milliseconds** — confirmed live: `time:119719` over `run_time: 120`.
- **`plot_data` has 15 columns in v5.02c**, not the 13 assumed. The parser was
  header-driven, so it absorbed this unchanged.
- **`/proc/1/cmdline` is readable inside the container.** Anything on the agent's
  argv — above all the phase-2 prompt — is visible regardless of filesystem
  confinement. Now asserted.
- **The scrubber's whitelist was too strict**, dropping real build failures that
  match no `file:line:` shape. Broadened, safe because the fail-closed check runs
  first on the raw log.
- **`ubuntu:24.04` already has a uid-1000 user**, so `useradd -u 1000 agent || true`
  silently failed and every agent container died at startup. The `|| true` hid it.

### Still unmeasured

Attrition on targets other than libxml2. libavc, assimp, and wolfssl are Ubuntu
16.04-based and have no prework image yet.
