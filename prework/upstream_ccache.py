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

import logging
import os
from pathlib import Path

from prework.fb_ccache import (  # general single-file ELF noise helpers, reused as-is
    MODE_NOISE, MODE_PASS, MODES, masked_compare, noise_model)

logger = logging.getLogger(__name__)

PREWORK_DIR = Path(__file__).resolve().parent
WRAPPER_DIR = PREWORK_DIR / "upstream_ccache_wrap"
CONTAINER_WRAPPER_DIR = "/opt/upstream_ccache_wrap"
# Deliberately not the image's baked /ccache/cache.
CONTAINER_CACHE_DIR = "/upstream_ccache"
CONTAINER_DENYLIST = "/src/aflpp_fold_denylist.txt"
VERIFIED_LIST = PREWORK_DIR / "upstream_ccache_verified.txt"
_HIT_RESULTS = frozenset({"direct_cache_hit", "preprocessed_cache_hit"})
_MISS_RESULTS = frozenset({"cache_miss"})


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


def read_verified_modes(path: str | os.PathLike | None = None) -> dict[str, str]:
    """{project: "pass" | "pass_noise_masked"}; same format as
    fb_ccache.read_verified_modes (`#` comments, blanks ignored, malformed
    lines warned and skipped). Default path: upstream_ccache_verified.txt."""
    p = Path(path) if path else VERIFIED_LIST
    try:
        text = p.read_text()
    except FileNotFoundError:
        return {}
    out: dict[str, str] = {}
    for line in text.splitlines():
        f = line.split("#", 1)[0].split()
        if len(f) == 1:
            out[f[0]] = MODE_PASS
        elif len(f) == 2 and f[1] in MODES:
            out[f[0]] = f[1]
        elif f:
            logger.warning("upstream ccache verified list: ignoring malformed line %r", line)
    return out


def parse_stats(statslog: str | os.PathLike | None) -> dict:
    """Parse a CCACHE_STATSLOG (text, or a path to the file).

    Lines are `<timestamp> <result>` tokens as ccache logs them
    (`direct_cache_hit`, `preprocessed_cache_hit`, `cache_miss`, ...).
    Returns {"hits", "misses", "other", "used", "results"}; `used` is True
    iff any hit or miss was recorded (empty/absent input -> False)."""
    text = ""
    if statslog is not None:
        s = str(statslog)
        if "\n" not in s and s.strip() and not s.strip().isspace():
            try:
                if Path(s).is_file():
                    s = Path(s).read_text(errors="replace")
            except (OSError, ValueError):
                pass
        elif isinstance(statslog, os.PathLike):
            s = Path(statslog).read_text(errors="replace")
        text = s
    results: dict[str, int] = {}
    for line in text.splitlines():
        f = line.split()
        if not f:
            continue
        tok = f[-1] if len(f) > 1 else f[0]
        if tok.startswith("#"):
            continue
        results[tok] = results.get(tok, 0) + 1
    hits = sum(n for k, n in results.items() if k in _HIT_RESULTS)
    misses = sum(n for k, n in results.items() if k in _MISS_RESULTS)
    other = sum(results.values()) - hits - misses
    return {"hits": hits, "misses": misses, "other": other,
            "used": bool(hits or misses), "results": results}


def slim_stats(d: dict | None) -> dict | None:
    """parse_stats() result without the per-result table (for provenance)."""
    if not d:
        return d
    return {k: v for k, v in d.items() if k != "results"}


def upstream_noise_model(p0_path, p1_path) -> dict:
    """Noise regions of one /out/<target> from two plain builds (fb_ccache.noise_model).
    Differences in loaded non-string code make the model not ok (never maskable)."""
    return noise_model(p0_path, p1_path)


def upstream_masked_compare(x_path, y_path, model: dict | None) -> dict:
    """Plain vs cached /out/<target>: identical | masked | differs
    (fb_ccache.masked_compare)."""
    return masked_compare(x_path, y_path, model)
