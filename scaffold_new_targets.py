#!/usr/bin/env python3
"""Extract candidate ARVO targets and scaffold prework target directories.

Phase A of adding new benchmark targets: pull each n132/arvo:<id>-vul image,
extract its vulnerable source + baked PoC, then read the ACTUAL /src layout to
write meta.json and a Dockerfile. The project's directory under $SRC is read from
the extraction rather than assumed equal to the project name -- they differ often
enough (PcapPlusPlus, c-blosc2) that guessing produces a Dockerfile whose WORKDIR
does not exist, and the failure surfaces much later as an opaque build error.

Build tools are installed as a superset; project-specific -dev libraries are NOT,
because linking against a library the ARVO build did not use would silently
change the target. Missing ones surface as compile failures and get added per
target, deliberately.

    python3 scaffold_new_targets.py --projects assimp,lcms --work /tmp/prework-new
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from prework.extract import extract_arvo

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Build tools only. Mirrors the union of what the existing four targets install,
# plus the common OSS-Fuzz build-system deps. No -dev libraries here on purpose.
COMMON_DEPS = (
    "make cmake autoconf automake libtool pkg-config python3 python3-setuptools "
    "wget zip unzip bison flex gawk gettext texinfo nasm yasm ninja-build "
    "bsdmainutils file subversion"
)

DOCKERFILE = '''# syntax=docker/dockerfile:1
# Modernized build environment for {project} / ARVO {arvo_id}.
#
# The ARVO image predates AFL++ v5.02c's LLVM floor, so only the vulnerable
# SOURCE is carried over; the toolchain comes from the pinned base + AFL++ pin.
ARG BASE
FROM ${{BASE}}

# Build tools. Deliberately no -dev libraries: linking against a library the
# ARVO build did not use would silently change the target under test.
RUN apt-get update && apt-get install -y --no-install-recommends \\
        {deps} \\
    && rm -rf /var/lib/apt/lists/*
{extra_deps}
# Pin the LLVM that AFL++ is built against rather than inheriting base-builder's
# clang. base-builder carries a clang trunk build that AFL++ v5.02c does not
# compile against; its makefile treats that as NON-FATAL, so the result would be
# an afl-cc with no compiler mode -- it "builds" and then silently produces an
# UNINSTRUMENTED target.
ARG LLVM_VERSION=18
RUN apt-get update && apt-get install -y --no-install-recommends \\
        "clang-${{LLVM_VERSION}}" "llvm-${{LLVM_VERSION}}-dev" \\
        "libclang-${{LLVM_VERSION}}-dev" "lld-${{LLVM_VERSION}}" \\
        "libc++-${{LLVM_VERSION}}-dev" "libc++abi-${{LLVM_VERSION}}-dev" \\
        "libclang-rt-${{LLVM_VERSION}}-dev" \\
    && rm -rf /var/lib/apt/lists/*

# Replace the base image's bundled AFL++ with the pinned release. compile_afl
# copies libAFLDriver.a and the afl-* binaries out of $SRC/aflplusplus, so
# building the pin in place makes the stock OSS-Fuzz build path use it.
# `source-only` also builds the GCC plugin and Rust bindings, whose failures the
# makefile ignores -- hence asserting on artifacts, not on make's exit code.
ARG AFLPP_REF
RUN rm -rf "$SRC/aflplusplus" && \\
    git clone --depth 1 --branch "${{AFLPP_REF}}" \\
        https://github.com/AFLplusplus/AFLplusplus "$SRC/aflplusplus" && \\
    cd "$SRC/aflplusplus" && \\
    unset CFLAGS CXXFLAGS && \\
    LLVM_CONFIG="llvm-config-${{LLVM_VERSION}}" make -j"$(nproc)" source-only; \\
    test -f libAFLDriver.a && \\
    test -x afl-fuzz && \\
    test -x afl-showmap && \\
    test -x afl-clang-fast

# Prove instrumentation is live, built WITH -fsanitize=address (the configuration
# `compile` actually uses). `test -x afl-clang-fast` is not enough: afl-cc exists
# even when every compiler mode failed, and a plain build passes even when the
# compiler-rt sanitizer runtimes are missing.
RUN printf 'int main(void){{return 0;}}\\n' > /tmp/instrtest.c && \\
    "$SRC/aflplusplus/afl-clang-fast" -fsanitize=address \\
        -o /tmp/instrtest /tmp/instrtest.c && \\
    nm /tmp/instrtest | grep -q __afl_area_ptr && \\
    echo "AFL++ instrumentation verified (with ASAN)" && \\
    rm -f /tmp/instrtest /tmp/instrtest.c

# ARVO's /src IS the OSS-Fuzz $SRC layout; stage_source has already pruned the
# bundled engine trees so they cannot shadow the AFL++ pin.
COPY src/ $SRC/

# OSS-Fuzz runs build.sh from the PROJECT directory, not $SRC.
WORKDIR $SRC/{workdir}
'''


def pick_workdir(src_dir: Path, project: str) -> str:
    """The project's own directory under $SRC, read from the extraction."""
    names = sorted(p.name for p in src_dir.iterdir() if p.is_dir())
    engines = {"aflplusplus", "libfuzzer", "honggfuzz", "fuzztest", "afl", "libfuzzer-src"}
    cands = [n for n in names if n not in engines]
    exact = [n for n in cands if n.lower() == project.lower()]
    if exact:
        return exact[0]
    partial = [n for n in cands if project.lower() in n.lower() or n.lower() in project.lower()]
    if partial:
        return sorted(partial, key=len)[0]
    return cands[0] if cands else project


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--projects", required=True, help="comma-separated project names")
    ap.add_argument("--candidates", default="new_arvo_projects.json")
    ap.add_argument("--work", default="/tmp/prework-new")
    args = ap.parse_args()

    pool = {e["project"]: e for e in json.loads(Path(args.candidates).read_text())}
    wanted = [p.strip() for p in args.projects.split(",") if p.strip()]
    out = {}
    for name in wanted:
        e = pool.get(name)
        if e is None:
            logger.error("%s not in %s", name, args.candidates)
            out[name] = {"status": "not_a_candidate"}
            continue
        work = Path(args.work) / f"{name}-arvo-{e['local_id']}"
        logger.info("=== %s (arvo %s) -> %s", name, e["local_id"], work)
        try:
            r = extract_arvo(e["image"], name, work)
        except Exception as exc:                              # noqa: BLE001
            logger.error("  extract raised: %s", exc)
            out[name] = {"status": "extract_error", "error": str(exc)}
            continue
        if r.poc_path is None or not r.baseline_crashed:
            logger.error("  unusable: poc=%s baseline_crashed=%s",
                         r.poc_path, r.baseline_crashed)
            out[name] = {"status": "arvo_unusable",
                         "baseline_crashed": r.baseline_crashed}
            continue

        workdir = pick_workdir(Path(r.source_dir), name)
        tdir = Path("prework/targets") / f"{name}-arvo-{e['local_id']}"
        tdir.mkdir(parents=True, exist_ok=True)
        (tdir / "meta.json").write_text(json.dumps({
            "project": name,
            "arvo_id": e["local_id"],
            "arvo_image": e["image"],
            "fuzz_target": e["fuzz_target"],
            "crash_type": e["crash_type"],
            "workdir": workdir,
            "deviations": [],
        }, indent=2) + "\n")
        (tdir / "Dockerfile").write_text(DOCKERFILE.format(
            project=name, arvo_id=e["local_id"], deps=COMMON_DEPS,
            extra_deps="", workdir=workdir,
        ))
        logger.info("  scaffolded %s (workdir=%s)", tdir, workdir)
        out[name] = {"status": "scaffolded", "target_dir": str(tdir),
                     "workdir": workdir, "work": str(work),
                     "source_dir": str(r.source_dir), "poc": str(r.poc_path)}

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
