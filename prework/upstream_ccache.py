"""ccache for the pipeline's upstream build path: host-side helpers.

Inside the container the AFL++ compiler driver (afl-clang-fast) runs the
BACKEND clang through AFL_CC/AFL_CXX. The wrappers in upstream_ccache_wrap/
are those backends: `exec ccache /usr/local/bin/clang[++] "$@"`. Wrapping
afl-clang-fast itself would recurse, and AFL_CC=ccache would make
afl-clang-fast exec `ccache <flags>`, which ccache rejects.

The image bakes CCACHE_DIR=/ccache/cache, so a cached build always sets
CCACHE_DIR explicitly. Pure Python (no docker, no import-time side effects).
"""
from __future__ import annotations

from pathlib import Path

PREWORK_DIR = Path(__file__).resolve().parent
WRAPPER_DIR = PREWORK_DIR / "upstream_ccache_wrap"
CONTAINER_WRAPPER_DIR = "/opt/upstream_ccache_wrap"
# Deliberately not the image's baked /ccache/cache.
CONTAINER_CACHE_DIR = "/upstream_ccache"
CONTAINER_DENYLIST = "/src/aflpp_fold_denylist.txt"


def ccache_docker_args(*, cache_dir: str | None,
                       denylist_path: str = CONTAINER_DENYLIST,
                       statslog: str | None) -> list[str]:
    """`-e`/`-v` docker args for an upstream build.

    cache_dir=None is the uncached form: CCACHE_DISABLE=1, no mounts.
    Otherwise `statslog` is the container path of the stats log (should be
    under CONTAINER_CACHE_DIR to land on the host cache mount)."""
    if cache_dir is None:
        return ["-e", "CCACHE_DISABLE=1"]
    args = [
        "-v", f"{WRAPPER_DIR}:{CONTAINER_WRAPPER_DIR}:ro",
        "-v", f"{cache_dir}:{CONTAINER_CACHE_DIR}",
        "-e", f"CCACHE_DIR={CONTAINER_CACHE_DIR}",
        "-e", "CCACHE_COMPILERCHECK=content",
        "-e", f"CCACHE_EXTRAFILES={denylist_path}",
        "-e", f"AFL_CC={CONTAINER_WRAPPER_DIR}/cc",
        "-e", f"AFL_CXX={CONTAINER_WRAPPER_DIR}/cxx",
    ]
    if statslog:
        args += ["-e", f"CCACHE_STATSLOG={statslog}"]
    return args
