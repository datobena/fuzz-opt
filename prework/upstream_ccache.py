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
import shutil
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
# Upstream-specific broker env key (distinct from fb_ccache.BROKER_ENV_KEY): the
# per-trial cache dir the broker mounts into that optimizer's agent builds.
BROKER_ENV_KEY = "PHASE2_UPSTREAM_CCACHE_DIR"
TEMPLATE_DIRNAME = "upstream_ccache_template"
TRIAL_DIRNAME = "upstream_ccache"
STATSLOG_NAME = "statslog"   # basename of prework_build.UPSTREAM_CCACHE_STATSLOG
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


# ------------------------------------------------------- campaign (phase3) side

def template_dir(online_dir) -> str:
    return str(Path(online_dir) / TEMPLATE_DIRNAME)


def trial_cache_dir(trial_online_dir) -> str:
    return str(Path(trial_online_dir) / TRIAL_DIRNAME)


def seed_cache(template, dest) -> str:
    """Fresh copy of the template at ``dest`` (each optimized trial owns one)."""
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(template, dest, symlinks=False,
                    ignore=shutil.ignore_patterns("tmp", "*.lock", "*.tmp.*"))
    return str(dest)


def read_trial_stats(cache_dir) -> dict:
    """parse_stats of the statslog under ``cache_dir`` (host side). A build that
    produced no statslog (or an unreadable one) yields used=False, never raises."""
    try:
        p = Path(cache_dir) / STATSLOG_NAME
        text = p.read_text(errors="replace") if p.is_file() else ""
    except (OSError, ValueError, TypeError):
        text = ""
    return parse_stats(text if text.strip() else None)


def prepare_upstream_ccache_template(*, entry: dict, online_dir, baseline_bin_dir,
                                     fuzz_target: str, build_fn,
                                     verified: dict | None = None,
                                     work_dir=None) -> dict:
    """Fill the target-level template with ONE extra pristine CACHED build.

    ``build_fn(out_dir, cache_dir_or_None, stage) -> (ok, log)`` runs one upstream
    build (cache_dir=None means uncached). Only an upstream target on the verified
    list is attempted. The cached /out/<fuzz_target> must equal the uncached
    baseline's (byte-identical; for pass_noise_masked, equal outside the noise one
    extra UNCACHED build reveals). Any failure, including an exception, returns
    OFF: {"enabled": False, "template": None, "reason": ...}. Never raises.
    """
    rec: dict = {"enabled": False, "template": None}
    template = None
    outs: list[str] = []
    try:
        from lib import target_kind
        if not target_kind.is_upstream(entry):
            return rec
        if verified is None:
            verified = read_verified_modes()
        mode = verified.get(entry.get("project"))
        if mode is None:
            rec["reason"] = "not-verified"
            return rec
        rec["verified_mode"] = mode
        import tempfile
        template = template_dir(online_dir)
        shutil.rmtree(template, ignore_errors=True)
        os.makedirs(template, exist_ok=True)
        wd = str(work_dir or online_dir)
        out = tempfile.mkdtemp(prefix="upstream-ccache-template-out-", dir=wd)
        outs.append(out)
        ok, log = build_fn(out, template, "upstream_ccache_template_build")
        st = read_trial_stats(template)
        rec["stats"] = slim_stats(st)
        if not ok:
            rec["reason"] = "template-build-failed"
            logger.error("upstream ccache template build failed for %s; trials run uncached: %s",
                         entry.get("project"), (log or "")[-400:])
            return rec
        if not st["used"]:
            rec["reason"] = "cache-not-used"
            return rec
        base = Path(baseline_bin_dir) / fuzz_target
        cached = Path(out) / fuzz_target
        if mode == MODE_NOISE:
            noise_out = tempfile.mkdtemp(prefix="upstream-ccache-noise-", dir=wd)
            outs.append(noise_out)
            ok2, _l2 = build_fn(noise_out, None, "upstream_ccache_template_noise_build")
            if not ok2:
                rec["reason"] = "noise-build-failed"
                return rec
            model = upstream_noise_model(base, Path(noise_out) / fuzz_target)
        else:
            model = None
        cmp = upstream_masked_compare(base, cached, model)
        rec["matches_uncached_baseline"] = cmp
        if cmp.get("status") not in ("identical", "masked") or (
                cmp["status"] == "masked" and mode != MODE_NOISE):
            rec["reason"] = "cold-cache-build-differs-from-uncached-baseline"
            logger.error("upstream ccache template build differs from the uncached "
                         "baseline for %s; trials run uncached", entry.get("project"))
            return rec
        rec.update(enabled=True, template=template)
        return rec
    except Exception as e:  # noqa: BLE001 - ccache is an optimization; never block a campaign
        logger.error("upstream ccache template failed (%s); trials run uncached", e)
        rec.update(enabled=False, template=None, reason=f"error:{type(e).__name__}")
        return rec
    finally:
        for o in outs:
            shutil.rmtree(o, ignore_errors=True)
        if template and not rec.get("enabled"):
            shutil.rmtree(template, ignore_errors=True)
        if not rec.get("enabled"):
            rec["template"] = None
