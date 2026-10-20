"""Build FuzzBench-parity images (`fb-aflpp/<fuzzbench_dir>`) and their build command.

For manifest entries with ``"kind": "fuzzbench"`` the target must be built exactly as
FuzzBench builds it with its ``aflplusplus`` fuzzer. FuzzBench's image chain
(docker/image_types.yaml) is replicated with the vendored, verbatim upstream files in
prework/fuzzbench_upstream/ (FuzzBench 3234e151):

  1. ``fb-aflpp-stage/<dir>:benchmark``     benchmarks/<dir>/Dockerfile (digest-pinned
                                            base-builder@87ca1e9e), context = that dir
  2. ``fb-aflpp-stage/<dir>:intermediate``  fuzzers/aflplusplus/builder.Dockerfile
                                            (AFL++ 56d5aa31 at /afl), parent = 1
  3. ``fb-aflpp/<dir>``                     docker/benchmark-builder/Dockerfile, parent = 2

Deviations from upstream, applied as checked text substitutions below (each raises if
the upstream text it edits ever moves, so a re-vendor cannot silently drop one):

  * stage 2: ``git checkout <commit> || true`` -> checkout must succeed and HEAD is
    asserted (upstream silently builds AFL++ dev HEAD if the checkout fails);
  * stage 3: the ``gcr.io/fuzzbench/base-image`` stage (source of python3.10 + PyYAML)
    is pinned by digest;
  * stage 3: the final ``RUN fuzzer_build`` is NOT run at image-build time. The same
    build runs at ``docker run`` time through /fold/fb_build.sh (prework/fb_build.sh),
    so every rebuild can supply modified source. The image records the benchmark
    WORKDIR (``ENV FB_WORKDIR`` + label) so that script can cd there after replacing
    the source tree, and snapshots its build-time ``$OUT`` into /fb_image_out (some
    benchmark Dockerfiles write seeds into $OUT; FuzzBench's runner copies them).
  * stage 3, last step: ccache unpacked to /opt/fb_ccache/ccache, never on PATH (see
    CCACHE_STEP). Inert unless a rebuild mounts /ccache for a verified target (optimized
    arm only); then both builds use it.

Everything else -- checkout_commit.py (unshallow + checkout -f <benchmark.yaml commit>),
``apt-get upgrade``, ENV FUZZER/BENCHMARK, build-time ASAN_OPTIONS, the python swap --
is upstream's own text. ``apt-get upgrade`` and the benchmark Dockerfiles' ``git clone``
of HEAD (then checked out to the pinned commit) are upstream behaviour too.

CLI:  python3 -m prework.fuzzbench_image --dir mruby_mruby_fuzzer_8c8bbd
      python3 -m prework.fuzzbench_image --all
      python3 -m prework.fuzzbench_image --dir X --dockerfile-dir /path/to/benchmark/dir
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

logger = logging.getLogger(__name__)

PREWORK_DIR = Path(__file__).resolve().parent
REPO_DIR = PREWORK_DIR.parent
UPSTREAM_DIR = PREWORK_DIR / "fuzzbench_upstream"
BENCHMARKS_DIR = PREWORK_DIR / "fuzzbench"
FB_BUILD_SH = PREWORK_DIR / "fb_build.sh"

FB_IMAGE_PREFIX = "fb-aflpp/"
FB_STAGE_PREFIX = "fb-aflpp-stage/"
FUZZER = "aflplusplus"
FUZZBENCH_COMMIT = "3234e151d70f6093272a9b4155e68ee57faf986c"
AFLPP_COMMIT = "56d5aa3101945e81519a3fac8783d0d8fad82779"
BASE_BUILDER = ("gcr.io/oss-fuzz-base/base-builder@sha256:"
                "87ca1e9e19235e731fac8de8d1892ebe8d55caf18e7aa131346fc582a2034fdd")
# gcr.io/fuzzbench/base-image:latest as of 2026-10-10 (ubuntu:focal + python 3.10.8).
FB_BASE_IMAGE = ("gcr.io/fuzzbench/base-image@sha256:"
                 "cc9bb2a509c2c75da3cd27a14b530b91becc599e19f5e60a7b5d0f6bf20c33dc")
DEFAULT_CPUSET = "40-79"
IMAGE_BUILD_TIMEOUT_SECS = 4 * 3600
MANIFESTS = (REPO_DIR / "data" / "manifests" / "manifest_fuzzbench.json",
             REPO_DIR / "data" / "manifests" / "manifest_fuzzbench_bugs.json")


# --------------------------------------------------------------------------- naming

def fuzzbench_image_tag(fuzzbench_dir: str) -> str:
    return f"{FB_IMAGE_PREFIX}{fuzzbench_dir.lower()}"


def is_fuzzbench_image(image: str) -> bool:
    """Build-flavour switch for callers that only know the image (the broker)."""
    return str(image).startswith(FB_IMAGE_PREFIX)


def _stage_tag(fuzzbench_dir: str, stage: str) -> str:
    return f"{FB_STAGE_PREFIX}{fuzzbench_dir.lower()}:{stage}"


# ------------------------------------------------------------------ build command

def fuzzbench_build_command(
    *, image: str, source_dir: str | None, out_dir: str, cpu: int | str | None = None,
    extra_docker_args: list[str] | tuple[str, ...] = (),
    ccache_dir: str | None = None,
) -> list[str]:
    """`docker run` that builds /out exactly as FuzzBench's fuzzer_build would.

    The modified tree is mounted read-only at /fold/src and COPIED over
    $SRC/<basename(source_dir)> inside the container: nothing is mounted under /src,
    because FuzzBench's restore_directory($SRC) rmtree's /src (it would delete a
    host mount's contents, then fail EBUSY). The host tree is never written.
    No -O override and no OSS-Fuzz `compile` env: FuzzBench sets CFLAGS itself
    (-O1 + ASan/UBSan for bug, -O3 for coverage).

    ``ccache_dir`` (optimized-arm rebuilds of a verified target only) is mounted
    read-write at /ccache together with the verified list; fb_build.sh then caches
    both builds (main and cmplog). None -> the command is exactly as before.
    """
    cmd = ["docker", "run", "--rm"]
    if cpu is not None:
        cmd += ["--cpuset-cpus", str(cpu)]
    cmd += list(extra_docker_args)
    if source_dir:
        src = Path(source_dir).absolute()
        cmd += ["-e", f"FB_SRC_NAME={src.name}", "-v", f"{src}:/fold/src:ro"]
    if ccache_dir:
        from prework import fb_ccache
        cmd += ["-v", f"{Path(ccache_dir).absolute()}:{fb_ccache.CONTAINER_CACHE_DIR}",
                "-v", f"{fb_ccache.VERIFIED_LIST}:{fb_ccache.CONTAINER_VERIFIED_LIST}:ro"]
    cmd += [
        "-v", f"{FB_BUILD_SH}:/fold/fb_build.sh:ro",
        "-v", f"{Path(out_dir).absolute()}:/out",
        "--entrypoint", "/bin/bash",
        image, "/fold/fb_build.sh",
    ]
    return cmd


# ------------------------------------------------------- Dockerfile substitutions

def _replace_once(text: str, old: str, new: str, what: str) -> str:
    if text.count(old) != 1:
        raise RuntimeError(
            f"vendored FuzzBench text for '{what}' not found exactly once; "
            "the upstream file changed -- re-check the deviation")
    return text.replace(old, new)


def patched_builder_dockerfile() -> str:
    """fuzzers/aflplusplus/builder.Dockerfile with the AFL++ checkout made fatal."""
    text = (UPSTREAM_DIR / "fuzzers" / FUZZER / "builder.Dockerfile").read_text()
    return _replace_once(
        text,
        f"    git checkout {AFLPP_COMMIT} || \\\n    true\n",
        f"    git checkout {AFLPP_COMMIT} && \\\n"
        f"    test \"$(git rev-parse HEAD)\" = {AFLPP_COMMIT}\n",
        "aflplusplus builder checkout")


# fuzz-opt deviation: ccache, used ONLY for optimized-arm rebuilds (both halves), ONLY for a
# target on prework/fuzzbench_ccache_verified.txt, and ONLY when the caller mounts a
# cache at /ccache (see prework/fb_build.sh). It is the LAST step, so every upstream
# layer above it is unchanged.
# The binary is UNPACKED from the image's own Ubuntu 20.04 archive (ccache 3.7.7-1),
# not installed: it lives only at CCACHE_BIN, off PATH, with no /usr/lib/ccache
# masquerade dir, no man page and no dpkg record. Build systems auto-detect ccache
# (jsoncpp's CMakeLists does find_program(ccache) + CMAKE_<LANG>_COMPILER_LAUNCHER):
# with ccache on PATH every jsoncpp build, baseline included, went through an
# un-namespaced ~/.ccache that does not key on AFL_LLVM_CMPLOG, so its cmplog binary
# reused main-build objects (603 -> 2 cmplog hook sites). The step fails if any
# `ccache` is still findable. Tries the lists the upstream `apt-get update` layer
# left first, so the index is refreshed only if needed.
CCACHE_BIN = "/opt/fb_ccache/ccache"
CCACHE_DEB_VERSION = "3.7.7-1"
CCACHE_STEP = (
    "# fuzz-opt deviation: ccache for cmplog rebuilds of verified targets only,\n"
    f"# unpacked to {CCACHE_BIN} (never on PATH; see prework/fuzzbench_image.py).\n"
    "RUN set -e; d=$(mktemp -d); cd \"$d\"; \\\n"
    f"    apt-get download ccache={CCACHE_DEB_VERSION} || \\\n"
    f"      (apt-get update && apt-get download ccache={CCACHE_DEB_VERSION}); \\\n"
    "    dpkg-deb -x ccache_*.deb x; \\\n"
    f"    install -D -m 0755 x/usr/bin/ccache {CCACHE_BIN}; \\\n"
    "    cd /; rm -rf \"$d\"; \\\n"
    "    if command -v ccache || [ -e /usr/lib/ccache ] || \\\n"
    "       [ -e /usr/local/bin/ccache ] || [ -e /usr/bin/ccache ]; then \\\n"
    "      echo 'fb-aflpp: a ccache is findable by build systems' >&2; exit 1; \\\n"
    "    fi; \\\n"
    f"    {CCACHE_BIN} --version | head -1 | tee /fb_ccache_version\n"
)


def patched_benchmark_builder_dockerfile(*, fuzzbench_dir: str, workdir: str) -> str:
    """docker/benchmark-builder/Dockerfile minus the build RUN, plus the records."""
    if not workdir.startswith("/"):
        raise ValueError(f"benchmark WORKDIR must be absolute, got {workdir!r}")
    text = (UPSTREAM_DIR / "docker" / "benchmark-builder" / "Dockerfile").read_text()
    text = _replace_once(
        text, "FROM gcr.io/fuzzbench/base-image AS base-image\n",
        f"FROM {FB_BASE_IMAGE} AS base-image\n", "base-image stage")
    labels = {
        "fb-aflpp.benchmark": fuzzbench_dir,
        "fb-aflpp.workdir": workdir,
        "fb-aflpp.fuzzbench-commit": FUZZBENCH_COMMIT,
        "fb-aflpp.aflpp-commit": AFLPP_COMMIT,
        "fb-aflpp.base-builder": BASE_BUILDER,
    }
    tail = (
        # checkout_commit.py exits 0 even when no checkout succeeded (main()'s return
        # value is never passed to sys.exit), which silently builds today's HEAD.
        # Same commit extraction as upstream; an empty commit (sqlite3) is skipped,
        # as upstream does. At least one top-level repo under $SRC must now be AT
        # the commit (libjpeg-turbo has two, by design).
        "# fb-aflpp: fail the build unless a repo under $SRC is at the yaml commit.\n"
        "RUN export CHECKOUT_COMMIT=$(cat /benchmark.yaml | tr -d ' ' | grep 'commit:' "
        "| cut -d ':' -f2) && \\\n"
        "    if [ -n \"$CHECKOUT_COMMIT\" ]; then \\\n"
        "      want=$(echo \"$CHECKOUT_COMMIT\" | tr 'A-F' 'a-f'); ok=; \\\n"
        "      for d in \"$SRC\"/*/; do \\\n"
        "        h=$(git -C \"$d\" rev-parse HEAD 2>/dev/null) || continue; \\\n"
        "        case \"$h\" in \"$want\"*) ok=1; echo \"fb-aflpp: $d is at $h\";; esac; \\\n"
        "      done; \\\n"
        "      if [ -z \"$ok\" ]; then \\\n"
        "        echo \"fb-aflpp: no repo under $SRC is at $CHECKOUT_COMMIT\" >&2; exit 1; \\\n"
        "      fi; \\\n"
        "    fi\n"
        "# fb-aflpp: fuzzer_build is NOT run here; /fold/fb_build.sh runs the same\n"
        "# build at `docker run` time (see prework/fuzzbench_image.py).\n"
        "RUN if [ -d \"$OUT\" ]; then cp -a \"$OUT\" /fb_image_out; "
        "else mkdir /fb_image_out; fi\n"
        f"ENV FB_WORKDIR={workdir}\n"
        + "".join(f'LABEL {k}="{v}"\n' for k, v in labels.items())
        + CCACHE_STEP
    )
    return _replace_once(
        text,
        'RUN echo "Run fuzzer_build to build the target" && '
        'if [ -z "$debug_builder" ] ; then fuzzer_build; fi',
        tail.rstrip("\n"), "fuzzer_build RUN")


_FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?",
                      re.IGNORECASE | re.MULTILINE)


def check_benchmark_dockerfile(text: str) -> None:
    """Refuse a benchmark Dockerfile whose base is not digest-pinned."""
    froms = _FROM_RE.findall(text)
    if not froms:
        raise ValueError("benchmark Dockerfile has no FROM")
    stages = set()
    for ref, alias in froms:
        if ref not in stages and "@sha256:" not in ref:
            raise ValueError(
                f"benchmark Dockerfile FROM {ref!r} is not digest-pinned (upstream "
                f"FuzzBench form is FROM {BASE_BUILDER}); refusing a moving base")
        if alias:
            stages.add(alias)


# ------------------------------------------------------------------ image builds

def _docker_build(args: list[str], log, timeout: int) -> None:
    cmd = ["docker", "build", "--progress=plain", *args]
    log.write(f"\n$ {' '.join(cmd)}\n")
    log.flush()
    r = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, timeout=timeout,
                       env={**os.environ, "DOCKER_BUILDKIT": "1"})
    if r.returncode != 0:
        raise RuntimeError(f"docker build failed (exit {r.returncode}): {' '.join(cmd)}")


def _image_workdir(tag: str) -> str:
    r = subprocess.run(["docker", "image", "inspect", "-f", "{{.Config.WorkingDir}}", tag],
                       capture_output=True, text=True, check=True)
    return r.stdout.strip()


def build_fuzzbench_image(
    fuzzbench_dir: str, *, dockerfile_dir: str | Path | None = None,
    cpuset: str | None = DEFAULT_CPUSET, no_cache: bool = False,
    log_path: str | Path | None = None, timeout: int = IMAGE_BUILD_TIMEOUT_SECS,
) -> dict:
    """Build fb-aflpp/<fuzzbench_dir> through the 3-stage chain. Returns a record."""
    bdir = Path(dockerfile_dir) if dockerfile_dir else BENCHMARKS_DIR / fuzzbench_dir
    dockerfile = bdir / "Dockerfile"
    yaml_path = bdir / "benchmark.yaml"
    if not dockerfile.is_file() or not yaml_path.is_file():
        raise FileNotFoundError(f"{bdir} needs Dockerfile and benchmark.yaml")
    check_benchmark_dockerfile(dockerfile.read_text())

    log_path = Path(log_path) if log_path else (
        Path(tempfile.gettempdir()) / "fb-aflpp-logs" / f"{fuzzbench_dir}.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    common = []
    if cpuset:
        common += ["--cpuset-cpus", str(cpuset)]
    if no_cache:
        common += ["--no-cache"]
    tag1 = _stage_tag(fuzzbench_dir, "benchmark")
    tag2 = _stage_tag(fuzzbench_dir, "intermediate")
    final = fuzzbench_image_tag(fuzzbench_dir)
    times: dict[str, float] = {}
    with open(log_path, "w") as log, tempfile.TemporaryDirectory(prefix="fb-aflpp-") as tmp:
        tmp = Path(tmp)
        # 1. benchmark project builder
        t0 = time.time()
        _docker_build([*common, "--tag", tag1, "--file", str(dockerfile), str(bdir)],
                      log, timeout)
        times["benchmark"] = time.time() - t0
        workdir = _image_workdir(tag1)
        # 2. aflplusplus builder intermediate
        df2 = tmp / "builder.Dockerfile"
        df2.write_text(patched_builder_dockerfile())
        t0 = time.time()
        _docker_build([*common, "--tag", tag2, "--build-arg", f"parent_image={tag1}",
                       "--file", str(df2), str(UPSTREAM_DIR / "fuzzers" / FUZZER)],
                      log, timeout)
        times["intermediate"] = time.time() - t0
        # 3. benchmark-builder (context mirrors FuzzBench's repo-root context)
        ctx = tmp / "ctx"
        shutil.copytree(UPSTREAM_DIR / "fuzzers", ctx / "fuzzers")
        (ctx / "benchmarks" / fuzzbench_dir).mkdir(parents=True)
        shutil.copy2(yaml_path, ctx / "benchmarks" / fuzzbench_dir / "benchmark.yaml")
        shutil.copytree(UPSTREAM_DIR / "docker" / "benchmark-builder",
                        ctx / "docker" / "benchmark-builder")
        df3 = tmp / "benchmark-builder.Dockerfile"
        df3.write_text(patched_benchmark_builder_dockerfile(
            fuzzbench_dir=fuzzbench_dir, workdir=workdir))
        t0 = time.time()
        _docker_build([*common, "--tag", final,
                       "--build-arg", f"parent_image={tag2}",
                       "--build-arg", f"fuzzer={FUZZER}",
                       "--build-arg", f"benchmark={fuzzbench_dir}",
                       "--file", str(df3), str(ctx)], log, timeout)
        times["builder"] = time.time() - t0
    rec = {"image": final, "workdir": workdir, "dockerfile_dir": str(bdir),
           "log": str(log_path), "stage_secs": {k: round(v, 1) for k, v in times.items()}}
    logger.info("built %s: %s", final, rec)
    return rec


def manifest_fuzzbench_dirs() -> list[str]:
    dirs: list[str] = []
    for m in MANIFESTS:
        if not m.is_file():
            continue
        for e in json.loads(m.read_text()):
            d = e.get("fuzzbench_dir")
            if e.get("kind") == "fuzzbench" and d and d not in dirs:
                dirs.append(d)
    return dirs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--dir", help="FuzzBench benchmark dir name")
    g.add_argument("--all", action="store_true", help="every kind=fuzzbench manifest entry")
    ap.add_argument("--dockerfile-dir", help="benchmark dir override (Dockerfile + "
                    "benchmark.yaml + COPY'd files); --dir only")
    ap.add_argument("--cpuset", default=DEFAULT_CPUSET)
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--log-dir")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    if a.dockerfile_dir and a.all:
        ap.error("--dockerfile-dir needs --dir")
    dirs = [a.dir] if a.dir else manifest_fuzzbench_dirs()
    failed = []
    for d in dirs:
        log = Path(a.log_dir) / f"{d}.log" if a.log_dir else None
        try:
            rec = build_fuzzbench_image(d, dockerfile_dir=a.dockerfile_dir,
                                        cpuset=a.cpuset, no_cache=a.no_cache, log_path=log)
            print(json.dumps(rec))
        except Exception as e:  # noqa: BLE001 -- report and continue with --all
            logger.error("%s: %s", d, e)
            failed.append(d)
    if failed:
        print("FAILED: " + " ".join(failed), file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
