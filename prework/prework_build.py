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
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from lib.core_lock import cpuset_lock
from prework.build_image import image_tag
from prework.fuzzbench_image import (
    fuzzbench_build_command, fuzzbench_image_tag, is_fuzzbench_image,
)

logger = logging.getLogger(__name__)

BUILD_TIMEOUT_SECS = 5400


def restore_ownership(image: str, paths: list[str]) -> None:
    """Give bind-mounted build output back to the user running the benchmark.

    OSS-Fuzz `compile` runs as root, so everything it writes through a bind mount
    -- both $OUT and the in-tree artifacts of an autotools/CMake build -- comes
    back root-owned. For a non-root orchestrator that breaks the steps either side
    of the build, all of them silently:

      * `git clean -fd` in _revert_source_tree cannot remove root-owned artifacts,
        so a REJECTED round leaves its objects behind and the next round links
        against them;
      * `os.chmod` on the fuzzer binary raises EPERM before a trial can start;
      * rmtree of a previous experiment's source tree half-fails.

    A no-op when the benchmark IS run as root, which is why none of this shows up
    on a machine that runs it that way.
    """
    if os.geteuid() == 0:
        return
    mounts: list[str] = []
    for i, p in enumerate(paths):
        mounts += ["-v", f"{Path(p).absolute()}:/fix{i}"]
    r = subprocess.run(
        ["docker", "run", "--rm", *mounts, "--entrypoint", "chown", image,
         "-R", f"{os.getuid()}:{os.getgid()}",
         *[f"/fix{i}" for i in range(len(paths))]],
        capture_output=True, text=True, errors="replace",
    )
    if r.returncode != 0:
        logger.warning("could not restore ownership of %s: %s",
                       paths, (r.stderr or "")[-200:])


def prework_image_for(entry: dict) -> str:
    """Resolve a manifest entry to its pinned prework image.

    kind == "fuzzbench" entries build in the FuzzBench-parity image
    fb-aflpp/<fuzzbench_dir> (prework/fuzzbench_image.py); everything else (ARVO)
    keeps bench-aflpp/<project>-arvo-<local_id>.
    """
    if entry.get("kind") == "fuzzbench":
        fb_dir = entry.get("fuzzbench_dir")
        if not fb_dir:
            raise ValueError(
                f"fuzzbench entry for {entry.get('project')!r} has no fuzzbench_dir; "
                "the fb-aflpp image tag is derived from it"
            )
        return fuzzbench_image_tag(fb_dir)
    local_id = entry.get("local_id")
    if not local_id:
        raise ValueError(
            f"entry for {entry.get('project')!r} has no local_id; the prework "
            "image tag is derived from it"
        )
    return image_tag(entry["project"], int(local_id))


_OPT_ENV_CACHE: dict[str, dict[str, str]] = {}
_OPT_RE = re.compile(r"(?<![\w-])-O[0-3sz]\b")


def arvo_opt_level(level: str | None = None) -> str:
    """The -O override for ARVO builds, normalised ("O3" -> "-O3"); "" for none.

    THE single place the override is resolved. Every ARVO build -- the campaign's
    reference/baseline build, the per-round harness rebuild, the noise-floor and
    setup rebuilds (all through build_prework_rebuild_command), and the agent's own
    builds through the broker (sandbox/broker._build_command) -- reaches it via
    arvo_compile_args, so the binary the agent TIMES while editing and the binary
    the gate measures and deploys can never be compiled at different levels. They
    did diverge once: the launcher defaulted to O3, the harness applied it, the
    broker never did, so the agent optimised -O1 builds while -O3 builds were gated
    and hot-swapped.

    "" (the default) is the benchmark's own build: the image's CFLAGS and build.sh
    exactly as ARVO / OSS-Fuzz compiled the target. FuzzBench images never consult
    this (their level is fixed per benchmark type by fuzzers/utils.py).
    """
    level = (level if level is not None
             else str(getattr(config, "BUILD_OPT_LEVEL", "") or "")).strip()
    if level and not level.startswith("-"):
        level = "-" + level
    return level


_IMAGE_ENV_CACHE: dict[str, dict[str, str]] = {}


def _image_env(image: str) -> dict[str, str]:
    """The image's ENV as a dict (`docker image inspect`), cached per image."""
    if image in _IMAGE_ENV_CACHE:
        return dict(_IMAGE_ENV_CACHE[image])
    r = subprocess.run(
        ["docker", "image", "inspect", "-f",
         "{{range .Config.Env}}{{println .}}{{end}}", image],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"cannot read env from image {image}: {(r.stderr or '')[-200:]}")
    env = {}
    for line in (r.stdout or "").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            env[k] = v
    _IMAGE_ENV_CACHE[image] = dict(env)
    return env


def opt_level_env(image: str, level: str | None = None) -> dict[str, str]:
    """CFLAGS/CXXFLAGS overrides that rebuild the target at a different -O level.

    Returns {} when no level is configured (arvo_opt_level), which leaves the
    image's own OSS-Fuzz defaults (-O1 for a sanitizer build) untouched.

    The flags are read back OUT of the image rather than written here. Hardcoding
    them would silently drift the moment base-builder changes its defaults, and
    the failure mode is invisible: the build still succeeds, it just no longer
    carries the warning suppressions and -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    the rest of the pipeline assumes. Substituting inside the real string keeps
    everything else byte-identical, so -O level is the only variable that moved.
    """
    level = arvo_opt_level(level)
    if not level:
        return {}
    key = f"{image}|{level}"
    if key in _OPT_ENV_CACHE:
        return dict(_OPT_ENV_CACHE[key])

    env = _image_env(image)
    out: dict[str, str] = {}
    for var in ("CFLAGS", "CXXFLAGS"):
        base = env.get(var, "")
        if not base:
            raise RuntimeError(f"image {image} exposes no {var}; cannot retarget -O level")
        new, n = _OPT_RE.subn(level, base)
        if n == 0:
            # No -O in the defaults: append rather than silently doing nothing.
            new = f"{base} {level}"
        out[var] = new
    _OPT_ENV_CACHE[key] = dict(out)
    logger.info("build opt level %s -> CFLAGS=%s", level, out["CFLAGS"][:90])
    return out


def arvo_build_opt_record(image: str) -> dict:
    """The -O level an ARVO build of ``image`` actually compiles at, for provenance.

    Recording the raw BUILD_OPT_LEVEL string is not enough now that its default is
    "": "" says "no override", not which level ran. With no override the level is
    the one in the image's own CFLAGS (the last -O wins, as in clang); with one, it
    is the override, and ``cflags`` is the exact string every build was given.
    ``source`` says which. A build.sh that hardcodes its own -O on top of CFLAGS
    is the benchmark's own build too, and is not visible here.
    """
    override = arvo_opt_level()
    if override:
        cflags = opt_level_env(image).get("CFLAGS", "")
        return {"level": override, "source": "BUILD_OPT_LEVEL",
                "override": override, "cflags": cflags}
    cflags = _image_env(image).get("CFLAGS", "")
    found = _OPT_RE.findall(cflags)
    return {"level": found[-1] if found else "", "source": "arvo-image-cflags",
            "override": "", "cflags": cflags}


def build_opt_provenance(entry: dict) -> dict:
    """campaign_provenance.json's -O fields for ``entry``: the level that RAN.

    FuzzBench: the per-type level fuzzers/utils.py sets (-O1 bug, -O3 coverage);
    BUILD_OPT_LEVEL never applies (unchanged from before). ARVO: arvo_build_opt_record
    -- the image's own CFLAGS level, or the override -- with the full record under
    "build_opt". Provenance must not kill a campaign, so an unreadable image is
    recorded as an error rather than raised.
    """
    from lib import afl_launch
    if afl_launch.is_fuzzbench(entry):
        return {"build_opt_level": afl_launch.fuzzbench_opt_level(entry),
                "build_opt_level_source": "fuzzbench:" + str(entry.get("type")
                                                             or "coverage")}
    try:
        rec = arvo_build_opt_record(prework_image_for(entry))
    except Exception as e:  # noqa: BLE001 -- provenance must not kill a campaign
        rec = {"level": None, "source": "unknown", "override": arvo_opt_level(),
               "error": f"{type(e).__name__}: {e}"}
    return {"build_opt_level": rec.get("level"),
            "build_opt_level_source": rec.get("source"),
            "build_opt": rec}


def arvo_compile_args(*, image: str, source_dir: str, out_dir: str,
                      project: str) -> list[str]:
    """Everything of an ARVO `docker run ... compile` after the resource flags.

    Shared VERBATIM by the harness rebuild (build_prework_rebuild_command) and the
    agent's broker build (sandbox/broker._build_command): the -O override, the
    OSS-Fuzz compile env, the fold denylist and the mounts. The callers add only
    `docker run`, the cpuset and (broker) the core-dump ulimit, none of which
    changes what is compiled. With no override this is byte-identical to the argv
    both paths built by hand before.
    """
    args: list[str] = []
    # -O level override, when configured (arvo_opt_level). Applied identically to
    # BOTH arms and to the agent's builds, because they all come through here.
    for _k, _v in opt_level_env(image).items():
        args += ["-e", f"{_k}={_v}"]
    args += [
        "-e", "FUZZING_ENGINE=afl",
        # FuzzBench benchmark build.sh scripts reference $FUZZER_LIB (the engine
        # driver lib), which OSS-Fuzz's compile exposes as $LIB_FUZZING_ENGINE
        # (=/usr/lib/libFuzzingEngine.a for afl). Providing it lets those targets
        # link; ARVO build.sh scripts don't read it, so it's a harmless no-op there.
        "-e", "FUZZER_LIB=/usr/lib/libFuzzingEngine.a",
        "-e", "FUZZER=afl",
        # Exclude the optimizer's INSERTED helpers from coverage instrumentation.
        # A coverage-guided fuzzer biases mutation toward inputs that reach new
        # edges, so helpers the skill adds shift the gradient away from the code
        # under test -- the skill records a ~5x time-to-bug swing from exactly
        # this. Its prescribed `no_sanitize("coverage")` is libFuzzer's mechanism
        # and does NOT work here: AFL++ 5.02c runs LLVM-PCGUARD, its own fork of
        # the sancov pass, and instruments a marked helper identically to an
        # unmarked one (verified by counting __afl_area_ptr relocations). The
        # denylist is the mechanism that does work, which is why the skill
        # requires every inserted function to be named fold_*.
        "-e", "AFL_LLVM_DENYLIST=/src/aflpp_fold_denylist.txt",
        "-e", "SANITIZER=address",
        "-e", "ARCHITECTURE=x86_64",
        "-e", "FUZZING_LANGUAGE=c++",
        "-v", f"{Path(__file__).resolve().parent / 'aflpp_fold_denylist.txt'}"
              f":/src/aflpp_fold_denylist.txt:ro",
        "-v", f"{Path(source_dir).absolute()}:/src/{project}",
        "-v", f"{Path(out_dir).absolute()}:/out",
        image, "compile",
    ]
    return args


def build_prework_rebuild_command(
    *, image: str, source_dir: str, out_dir: str, project: str,
    cpu: int | str | None = None, ccache_dir: str | None = None,
) -> list[str]:
    """`docker run <prework image> compile` with the modified source mounted.

    The source is bind-mounted over $SRC/<project> so the image's own build.sh
    (curated per target during prework) compiles the optimizer's edits rather
    than the copy baked into the image.

    FuzzBench-parity images (fb-aflpp/...) take a different command entirely:
    copy-in of the tree and FuzzBench's own fuzzer.build() via /fold/fb_build.sh,
    and no -O override (FuzzBench fixes -O1 for bug, -O3 for coverage).
    ``ccache_dir`` applies to those images only (main + cmplog build cache, see
    prework/fb_ccache.py); ARVO commands never take one.
    """
    if is_fuzzbench_image(image):
        return fuzzbench_build_command(
            image=image, source_dir=source_dir, out_dir=out_dir, cpu=cpu,
            ccache_dir=ccache_dir)
    if ccache_dir:
        raise ValueError("ccache_dir is only supported for FuzzBench-parity images")
    cmd = ["docker", "run", "--rm", "--privileged"]
    if cpu is not None:
        cmd += ["--cpuset-cpus", str(cpu)]
    # Env (incl. the -O override), denylist and mounts are arvo_compile_args, the
    # SAME list the broker builds the agent's candidates with.
    cmd += arvo_compile_args(image=image, source_dir=source_dir, out_dir=out_dir,
                             project=project)
    return cmd


def rebuild_with_prework_image(
    *, entry: dict, source_dir: str, out_dir: str, cpu: int | str | None = None,
    capture_log: bool = False, timeout: int = BUILD_TIMEOUT_SECS,
    ccache_dir: str | None = None,
) -> bool | tuple[bool, str]:
    """Rebuild the target from a modified tree. Mirrors the old n132 signature.

    ``ccache_dir``: FuzzBench targets only -- a per-trial cache for the main and cmplog
    builds (prework/fb_ccache.py). Never pass one for a baseline/reference build.
    """
    image = prework_image_for(entry)
    project = entry["project"]
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    if is_fuzzbench_image(image):
        return _rebuild_fuzzbench(image=image, project=project, source_dir=source_dir,
                                  out_dir=out_dir, cpu=cpu, capture_log=capture_log,
                                  timeout=timeout, ccache_dir=ccache_dir)
    if ccache_dir:
        raise ValueError("ccache_dir is only supported for FuzzBench targets")
    # Clear stale build output from the source tree before compiling. The online
    # flow runs the SAME build.sh on the SAME tree repeatedly (extract -> baseline
    # -> noise-floor x2 -> every optimizer round); a script that does an
    # out-of-source `mkdir build` (mbedtls's cmake step) aborts on the 2nd run
    # with "mkdir: cannot create directory 'build': File exists" unless the prior
    # output is gone. Builds here are from-scratch regardless, so this only
    # removes debris. Lazy import: phase2_setup imports THIS module, so a
    # top-level import would be circular.
    try:
        from phase2_setup import _clean_build_artifacts
        _clean_build_artifacts(source_dir)
    except Exception:  # noqa: BLE001 -- cleaning must never block a build
        pass
    cmd = build_prework_rebuild_command(
        image=image, source_dir=source_dir, out_dir=out_dir,
        project=project, cpu=cpu,
    )
    logger.info("Rebuilding %s in %s", project, image)
    try:
        # Serialize against any replay/smoke timing on the same optimizer core (the
        # agent's broker runs those in another process); a build overlapping a
        # measurement inflates the measured wall clock and skews the gate.
        with cpuset_lock(cpu):
            r = subprocess.run(
                cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
            )
    except subprocess.TimeoutExpired:
        log = f"build timed out after {timeout}s"
        logger.error("%s for %s", log, project)
        # A build killed mid-flight leaves the MOST root-owned debris, so this
        # path needs the restore more than the success path does.
        restore_ownership(image, [source_dir, out_dir])
        return (False, log) if capture_log else False
    log = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0:
        logger.error("prework rebuild failed for %s (exit %d)", project, r.returncode)
    ok = r.returncode == 0
    restore_ownership(image, [source_dir, out_dir])
    return (ok, log) if capture_log else ok


def _rebuild_fuzzbench(
    *, image: str, project: str, source_dir: str, out_dir: str, cpu: int | str | None,
    capture_log: bool, timeout: int, ccache_dir: str | None = None,
) -> bool | tuple[bool, str]:
    """FuzzBench-parity rebuild. The source is mounted read-only and copied inside
    the container, so the host tree is never written: no artifact cleaning before,
    no ownership repair of the tree after. /out is wiped by fb_build.sh itself.
    A cache dir, when given, is created up front (docker would create it root-owned)
    and handed back to the user afterwards like /out."""
    if ccache_dir:
        Path(ccache_dir).mkdir(parents=True, exist_ok=True)
    cmd = build_prework_rebuild_command(
        image=image, source_dir=source_dir, out_dir=out_dir, project=project, cpu=cpu,
        ccache_dir=ccache_dir,
    )
    owned = [out_dir] + ([ccache_dir] if ccache_dir else [])
    logger.info("Rebuilding %s in %s (FuzzBench aflplusplus build%s)", project, image,
                ", ccache " + str(ccache_dir) if ccache_dir else "")
    try:
        with cpuset_lock(cpu):
            r = subprocess.run(
                cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
            )
    except subprocess.TimeoutExpired:
        log = f"build timed out after {timeout}s"
        logger.error("%s for %s", log, project)
        restore_ownership(image, owned)
        return (False, log) if capture_log else False
    log = (r.stdout or "") + (r.stderr or "")
    ok = r.returncode == 0
    if not ok:
        logger.error("fuzzbench rebuild failed for %s (exit %d)", project, r.returncode)
    if ccache_dir:
        from prework import fb_ccache
        logger.info("ccache for %s: %s", project,
                    fb_ccache.slim_stats(fb_ccache.parse_stats(log)))
    restore_ownership(image, owned)
    return (ok, log) if capture_log else ok
