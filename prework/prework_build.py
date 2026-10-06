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
from lib.core_lock import core_lock
from prework.build_image import image_tag

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
    """Resolve a manifest entry to its pinned prework image."""
    local_id = entry.get("local_id")
    if not local_id:
        raise ValueError(
            f"entry for {entry.get('project')!r} has no local_id; the prework "
            "image tag is derived from it"
        )
    return image_tag(entry["project"], int(local_id))


_OPT_ENV_CACHE: dict[str, dict[str, str]] = {}
_OPT_RE = re.compile(r"(?<![\w-])-O[0-3sz]\b")


def opt_level_env(image: str, level: str | None = None) -> dict[str, str]:
    """CFLAGS/CXXFLAGS overrides that rebuild the target at a different -O level.

    Returns {} when no level is configured, which leaves the image's own
    OSS-Fuzz defaults (-O1 for a sanitizer build) untouched.

    The flags are read back OUT of the image rather than written here. Hardcoding
    them would silently drift the moment base-builder changes its defaults, and
    the failure mode is invisible: the build still succeeds, it just no longer
    carries the warning suppressions and -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    the rest of the pipeline assumes. Substituting inside the real string keeps
    everything else byte-identical, so -O level is the only variable that moved.
    """
    level = (level if level is not None
             else str(getattr(config, "BUILD_OPT_LEVEL", "") or "")).strip()
    if not level:
        return {}
    if not level.startswith("-"):
        level = "-" + level
    key = f"{image}|{level}"
    if key in _OPT_ENV_CACHE:
        return dict(_OPT_ENV_CACHE[key])

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
    # -O level override, when configured. Applied to BOTH arms (the baseline
    # build goes through this same function), so the arms stay comparable.
    for _k, _v in opt_level_env(image).items():
        cmd += ["-e", f"{_k}={_v}"]
    cmd += [
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
    return cmd


def rebuild_with_prework_image(
    *, entry: dict, source_dir: str, out_dir: str, cpu: int | None = None,
    capture_log: bool = False, timeout: int = BUILD_TIMEOUT_SECS,
) -> bool | tuple[bool, str]:
    """Rebuild the target from a modified tree. Mirrors the old n132 signature."""
    image = prework_image_for(entry)
    project = entry["project"]
    Path(out_dir).mkdir(parents=True, exist_ok=True)
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
        with core_lock(cpu):
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
