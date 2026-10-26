#!/usr/bin/env python3
"""Shared libraries the target needs that the PROFILER image cannot supply.

The profile runs the target inside the kernel-matched profiler image
(``replay_fuzzer_profile.PROFILER_IMAGE``, Ubuntu 24.04), not in the image it was
built in. A build can link a system library of its OWN image: a FuzzBench
build whose meson auto-detects glib needs libglib-2.0.so.0 and, through it,
libpcre.so.3 -- both in the 20.04 build image, neither in the profiler image.
There the loader refuses the binary before main, afl-showmap swallows the error,
perf still exits 0, and the profile is 0% target (it stopped a campaign in
setup). Trials and the replay gate run in the target's own image and never see
this; the build is not changed.

:func:`prepare` bridges the gap:

  1. target image: ``ldd`` the binary, afl-showmap and every /out shared library
     (with /out on the library path, as FuzzBench's runner has it), and stage a
     copy of every resolved library outside /out -- symlinks dereferenced, the
     real file stored under the name the loader asks for.
  2. profiler image: ``ldd`` the same files, and the staged copies, on the
     profiler's own library path. The names it cannot resolve, or resolves to a
     copy too old for the version the target asks for, are followed through the
     staged copies until nothing new appears (glib's own libpcre need is only
     visible once glib is found). The libc/loader family is never supplied: it
     must come from the profiler image.
  3. those libraries are copied into the per-profile ``target_libs`` dir, which
     the profile mounts read-only at TARGET_LIBS_MOUNT and puts on
     LD_LIBRARY_PATH for the target process only (perf keeps its own), and a
     profiler re-check must then resolve everything.

The target and afl-showmap are also checked symbol by symbol (``ldd -r``) on the
final path, so a profiler library older than the one the build linked (a newer
libc++, a missing symbol version) fails here too; /out modules are not, since
they legitimately leave symbols to the main binary.

Anything still unresolved raises TargetLibsError (message starts with
UNRESOLVED_MARK); a probe container that fails twice raises TargetLibsProbeError
(PROBE_FAILED_MARK). The result is cached in ``target_libs.json``, keyed on the
content of every probed file and both image IDs, so a retry or a re-profile of
the same build runs no container.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import time
import uuid
from pathlib import Path

DIRNAME = "target_libs"
RECORD = "target_libs.json"
STAGE_SUFFIX = ".stage"
# Not under /out: hotspot_table treats every /out DSO as part of the build, and
# these are system libraries of the build image (classified "libc", like every
# other shared library outside /out).
TARGET_LIBS_MOUNT = "/opt/target-libs"
CONTAINER_OUT = "/out"
VERSION = 2
PROBE_MEMORY = "1g"
PROBE_TIMEOUT_SECS = 300
RM_TIMEOUT_SECS = 60
UNRESOLVED_MARK = "TARGET LIBS UNRESOLVED"
PROBE_FAILED_MARK = "TARGET LIBS PROBE FAILED"

# glibc and the loader. Never copied from the build image: their GLIBC_PRIVATE
# interfaces only work with the loader they shipped with. libnsl.so.1 is glibc's
# in 20.04. linux-vdso is the kernel's.
_LIBC_FAMILY_RE = re.compile(
    r"^(linux-vdso|linux-gate|ld-linux[\w-]*|ld64|libc|libm|libmvec|libpthread|libdl|"
    r"librt|libutil|libresolv|libanl|libnsl|libnss_\w+|libthread_db|libBrokenLocale|"
    r"libcidn|libc_malloc_debug|libmemusage|libpcprofile|libSegFault)\.so(\.\d+)*$")
# Same filters as lib/afl_launch (fuzzbench_runtime_libs): /out shared libraries,
# minus AFL++'s compiler plugins and preload helpers, which the target never loads
# (an afl-llvm-pass.so needs libLLVM, which no runtime image has).
_SHARED_LIB_RE = re.compile(r"\.so(\.\d+)*$")
_AFL_TOOL_SO_RE = re.compile(
    r"(-pass\.so$|^SanitizerCoverage|^afl-|^lib(dislocator|tokencap|compcov|qasan|"
    r"AFLDriver|AFLQemuDriver)\b|^(argv|socket)fuzz)")

_NEEDED_RE = re.compile(r"^\s*(\S+)\s+=>\s+(.*?)\s*(\(0x[0-9a-fA-F]+\))?\s*$")
_VERSION_RE = re.compile(r"(\S+): version `[^']*' not found")
# ldd -r: "undefined symbol: tanf, version GLIBC_2.2.5\t(/out/t)"
_UNDEFINED_RE = re.compile(r"^\s*undefined symbol: ([^\s,]+)(?:, version (\S+))?\s*\((.*)\)")


class TargetLibsError(RuntimeError):
    """A library the target needs cannot be supplied (deterministic)."""


class TargetLibsProbeError(RuntimeError):
    """A probe container failed twice (docker trouble; possibly transient)."""


def _run(cmd, *, timeout=None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                          timeout=timeout, check=False)


def is_libc_family(name: str) -> bool:
    return bool(_LIBC_FAMILY_RE.match(os.path.basename(name)))


def probe_files(out_dir, fuzz_target: str) -> tuple[list[str], list[str]]:
    """Container paths of what the profile runs, and of what it may load from
    /out: (the target and afl-showmap, the AFL replay's parent), (every /out
    shared library but AFL++'s plugins -- dlopen'd extension modules are not
    in the target's own ldd)."""
    out = Path(out_dir)
    if not (out / fuzz_target).is_file():
        raise TargetLibsError(f"{UNRESOLVED_MARK}: {out / fuzz_target} does not exist; "
                              "nothing to resolve shared libraries for")
    main = [f"{CONTAINER_OUT}/{fuzz_target}"]
    if (out / "afl-showmap").is_file():
        main.append(f"{CONTAINER_OUT}/afl-showmap")
    sos = []
    for root, _dirs, names in os.walk(out):
        for n in names:
            p = Path(root) / n
            if not _SHARED_LIB_RE.search(n) or _AFL_TOOL_SO_RE.search(n):
                continue
            try:
                with open(p, "rb") as fh:
                    if fh.read(4) != b"\x7fELF":
                        continue        # a linker script or other non-ELF
            except OSError:
                continue
            sos.append(f"{CONTAINER_OUT}/{p.relative_to(out).as_posix()}")
    return main, sorted(sos)


def parse_ldd(text: str) -> dict[str, dict]:
    """Output of :func:`_ldd_script` -> {file: {"needed": {name: path or None},
    "version_failed": {library basenames}, "undefined": [symbol[@version] (in
    object)], "exists": bool}}. ``None`` = not found. The vdso and the absolute
    loader line carry no ``=>`` and are skipped; a static file has no entries."""
    res: dict[str, dict] = {}
    cur = None
    for line in text.splitlines():
        if line.startswith("@@ldd "):
            cur = res.setdefault(line[6:].strip(),
                                 {"needed": {}, "version_failed": set(), "undefined": [],
                                  "exists": True})
            continue
        if cur is None:
            continue
        if line.strip() == "@@missing":
            cur["exists"] = False
            continue
        if line.startswith("@@"):
            cur = None                  # @@copyfail / @@end: past the listings
            continue
        m = _UNDEFINED_RE.match(line)
        if m:
            cur["undefined"].append(f"{m.group(1)}{'@' + m.group(2) if m.group(2) else ''}"
                                    f" (in {m.group(3).strip()})")
            continue
        m = _VERSION_RE.search(line)
        if m:
            cur["version_failed"].add(os.path.basename(m.group(1)))
            continue
        m = _NEEDED_RE.match(line)
        if m:
            path = m.group(2).strip()
            cur["needed"].setdefault(m.group(1),
                                     None if path == "not found" else path)
    return res


def _missing(entry: dict | None) -> set[str]:
    if not entry:
        return set()
    return ({n for n, p in entry["needed"].items() if p is None}
            | set(entry["version_failed"]))


def _ldd_script(files, ld_expr: str, *, stage: str | None = None, relocate=()) -> str:
    """bash: ``ldd`` each file with ``LD_LIBRARY_PATH=<ld_expr>`` (shell text),
    each listing headed by an ``@@ldd <file>`` line, then ``@@end``; the files in
    ``relocate`` get ``ldd -r`` (undefined symbols too). With ``stage``, every
    resolved library outside /out is also copied there, symlinks dereferenced,
    under the name the loader looked it up by."""
    q = " ".join(shlex.quote(f) for f in files)
    pick = (f'r=; case "$f" in {"|".join(shlex.quote(f) for f in relocate)}) r=-r;; esac; '
            if relocate else "r=; ")
    s = (f'for f in {q}; do echo "@@ldd $f"; {pick}if [ -e "$f" ]; then '
         f'LD_LIBRARY_PATH={ld_expr} ldd $r "$f" 2>&1; else echo "@@missing"; fi; done; ')
    if stage:
        s += (f'for f in {q}; do [ -e "$f" ] && LD_LIBRARY_PATH={ld_expr} ldd "$f" '
              "2>/dev/null; done | awk '$2 == \"=>\" && $3 ~ /^\\// && "
              "$3 !~ /^\\/out\\// && $1 !~ /\\// {print $1, $3}' | sort -u | "
              f'while read -r n p; do cp -L "$p" {shlex.quote(stage)}/"$n" 2>/dev/null '
              '|| echo "@@copyfail $n $p"; done; ')
    return s + "echo @@end"


def _probe(image: str, out_dir, script: str, *, cpu, mounts=(), what: str) -> str:
    """Run ``script`` in ``image`` with /out mounted read-only; stdout. One
    retry: a failed docker run is more likely the daemon than the probe."""
    last = ""
    for attempt in (1, 2):
        name = f"poff-libs-{attempt}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        cmd = ["docker", "run", "--rm", "--name", name,
               "--network", "none", "--memory", PROBE_MEMORY,
               "--memory-swap", PROBE_MEMORY,
               # As the caller: staged copies come back owned by it.
               "--user", f"{os.getuid()}:{os.getgid()}"]
        if cpu is not None:
            cmd += ["--cpuset-cpus", str(cpu)]
        cmd += ["-v", f"{Path(out_dir).resolve()}:{CONTAINER_OUT}:ro"]
        for host, ctr, mode in mounts:
            cmd += ["-v", f"{Path(host).resolve()}:{ctr}:{mode}"]
        cmd += ["--entrypoint", "/bin/bash", image, "-c", script]
        try:
            r = _run(cmd, timeout=PROBE_TIMEOUT_SECS)
        except subprocess.TimeoutExpired:
            # The timeout kills only the docker client; the container would keep
            # running (and a retry start a second one) without this.
            _remove_container(name)
            last = f"timed out after {PROBE_TIMEOUT_SECS}s"
            continue
        if r.returncode == 0 and "@@end" in (r.stdout or ""):
            return r.stdout
        last = f"docker rc={r.returncode}: {((r.stdout or '') + (r.stderr or ''))[-300:]}"
    # The image is not named (see the record in prepare); the caller knows it.
    raise TargetLibsProbeError(f"{PROBE_FAILED_MARK}: {what} failed twice "
                               f"({last.replace(image, '<image>').strip()})")


def _remove_container(name: str) -> None:
    try:
        _run(["docker", "rm", "-f", name], timeout=RM_TIMEOUT_SECS)
    except subprocess.TimeoutExpired:
        pass                    # the probe error that follows says it timed out


def _image_id(image: str, what: str) -> str:
    try:
        r = _run(["docker", "image", "inspect", "-f", "{{.Id}}", image], timeout=60)
    except subprocess.TimeoutExpired:
        # Not re-raised as is: its message is the command, image name included.
        raise TargetLibsProbeError(f"{PROBE_FAILED_MARK}: inspecting {what} timed "
                                   "out") from None
    if r.returncode != 0 or not (r.stdout or "").strip():
        raise TargetLibsProbeError(
            f"{PROBE_FAILED_MARK}: cannot inspect {what}: "
            f"{(r.stderr or '').replace(image, '<image>').strip()[-200:]}")
    return r.stdout.strip()


def cache_key(out_dir, files, *, target_image_id: str, profiler_image_id: str,
              base_ld_path: str) -> str:
    h = hashlib.sha256(json.dumps(
        [VERSION, target_image_id, profiler_image_id, base_ld_path]).encode())
    out = Path(out_dir)
    for f in files:
        h.update(f.encode() + b"\0")
        with open(out / os.path.relpath(f, CONTAINER_OUT), "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    return h.hexdigest()


def ld_library_path(base_ld_path: str, *, libs: bool, append_out: bool) -> str:
    """The target process's LD_LIBRARY_PATH: the supplied libraries first (they
    are only names the profiler lacks or has too old), then the profiler's own
    path, then /out if a build library is found only through it (FuzzBench's
    runner has ``LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/out``)."""
    parts = ([TARGET_LIBS_MOUNT] if libs else []) + ([base_ld_path] if base_ld_path else [])
    return ":".join(parts + ([CONTAINER_OUT] if append_out else []))


def _cached(libs_dir: Path, key: str) -> dict | None:
    try:
        rec = json.loads((libs_dir / RECORD).read_text())
    except (OSError, ValueError):
        return None
    if rec.get("key") != key or not all((libs_dir / n).is_file() for n in rec.get("libs", {})):
        return None
    return rec


def prepare(*, out_dir, fuzz_target: str, libs_dir, target_image: str,
            profiler_image: str, base_ld_path: str, cpu=None) -> dict:
    """Supply what the profiler image cannot resolve (see the module doc).

    Returns the record written to ``<libs_dir>/target_libs.json``, plus
    ``host_dir`` (mount it at TARGET_LIBS_MOUNT; None when nothing is supplied)
    and ``cached``. ``ld_library_path`` is the target process's library path.
    """
    t0 = time.monotonic()
    libs_dir = Path(libs_dir)
    main, sos = probe_files(out_dir, fuzz_target)
    files = main + sos
    key = cache_key(out_dir, files,
                    target_image_id=_image_id(target_image, "the target's image"),
                    profiler_image_id=_image_id(profiler_image, "the profiler image"),
                    base_ld_path=base_ld_path)
    rec = _cached(libs_dir, key)
    if rec is not None:
        return dict(rec, host_dir=str(libs_dir) if rec["libs"] else None, cached=True)

    shutil.rmtree(libs_dir, ignore_errors=True)
    stage = libs_dir.with_name(libs_dir.name + STAGE_SUFFIX)
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    try:
        # 1. The target's own image: what each file loads and from where, with
        # /out appended to the image's path as the FuzzBench runner does.
        t_out = _probe(target_image, out_dir,
                       _ldd_script(files, f'"${{LD_LIBRARY_PATH:+$LD_LIBRARY_PATH:}}'
                                          f'{CONTAINER_OUT}"', stage="/stage"),
                       cpu=cpu, mounts=[(stage, "/stage", "rw")],
                       what="ldd in the target's image")
        tgt = parse_ldd(t_out)
        resolved: dict[str, str] = {}
        for f in files:
            for n, p in tgt.get(f, {}).get("needed", {}).items():
                if p is not None:
                    resolved.setdefault(n, p)
        copyfail = {ln.split()[1]: ln.split()[2] for ln in t_out.splitlines()
                    if ln.startswith("@@copyfail ") and len(ln.split()) >= 3}
        # An /out library that its own image cannot load is loaded by nothing
        # (trials run in that image): recorded, not required.
        skipped = {f: sorted(_missing(tgt.get(f))) for f in sos if _missing(tgt.get(f))}
        required = main + [f for f in sos if f not in skipped]
        staged = sorted(p.name for p in stage.iterdir()
                        if p.is_file() and not is_libc_family(p.name))

        # 2. The profiler image, on its own path: what it cannot resolve, then
        # what the staged copies of THOSE need, until nothing new appears.
        p_out = _probe(profiler_image, out_dir,
                       _ldd_script(required + [f"/stage/{n}" for n in staged],
                                   shlex.quote(base_ld_path), relocate=main),
                       cpu=cpu, mounts=[(stage, "/stage", "ro")],
                       what="ldd in the profiler image")
        prof = parse_ldd(p_out)
        needed_by: dict[str, str] = {}
        frontier = [(n, f) for f in required for n in sorted(_missing(prof.get(f)))]
        while frontier:
            n, by = frontier.pop()
            if n in needed_by:
                continue
            needed_by[n] = by
            if n in staged:
                frontier += [(m, n) for m in sorted(_missing(prof.get(f"/stage/{n}")))]
        libc = sorted(n for n in needed_by if is_libc_family(n))
        from_out = sorted(n for n in needed_by if n not in libc
                          and (resolved.get(n) or "").startswith(CONTAINER_OUT + "/"))
        copy = sorted(n for n in needed_by
                      if n in staged and n not in libc and n not in from_out)
        nowhere = sorted(set(needed_by) - set(libc) - set(from_out) - set(copy))
        if libc or nowhere:
            why = {n: "libc/loader family, must come from the profiler image"
                   for n in libc}
            why.update({n: (f"found at {copyfail[n]} in the target's image but not "
                            "copyable" if n in copyfail else "not in the target's image either")
                        for n in nowhere})
            raise TargetLibsError(
                f"{UNRESOLVED_MARK}: the profiler image cannot load {fuzz_target}: "
                + "; ".join(f"{n} (needed by {needed_by[n]}; {why[n]})"
                            for n in libc + nowhere))

        libs_dir.mkdir(parents=True, exist_ok=True)
        for n in copy:
            shutil.copyfile(stage / n, libs_dir / n)
            os.chmod(libs_dir / n, 0o644)
        ld = ld_library_path(base_ld_path, libs=bool(copy), append_out=bool(from_out))

        # 3. Re-check on the target's final path, supplied libraries mounted.
        # With nothing supplied, that path is step 2's and so is its listing.
        ver = prof
        if copy or from_out:
            v_out = _probe(profiler_image, out_dir,
                           _ldd_script(required, shlex.quote(ld), relocate=main), cpu=cpu,
                           mounts=[(libs_dir, TARGET_LIBS_MOUNT, "ro")] if copy else [],
                           what="ldd re-check in the profiler image")
            ver = parse_ldd(v_out)
            still = {f: sorted(_missing(ver.get(f))) or ["(not listed)"]
                     for f in required
                     if not ver.get(f, {}).get("exists") or _missing(ver.get(f))}
            if still:
                raise TargetLibsError(f"{UNRESOLVED_MARK}: still unresolved in the "
                                      f"profiler image with LD_LIBRARY_PATH={ld}: {still}")
        undefined = {f: ver[f]["undefined"] for f in main
                     if ver.get(f, {}).get("undefined")}
        if undefined:
            raise TargetLibsError(
                f"{UNRESOLVED_MARK}: undefined symbols in the profiler image with "
                f"LD_LIBRARY_PATH={ld} (a library there is older than the one the "
                "build linked, e.g. libc++, or lacks a symbol version): "
                + "; ".join(f"{f}: {len(u)}, e.g. {', '.join(u[:3])}"
                            for f, u in undefined.items()))
        # No image names: this dir sits in the profile the optimizer agent reads,
        # and an ARVO image tag names the bug.
        rec = {"version": VERSION, "key": key, "files": files,
               "libs": {n: resolved.get(n) for n in copy}, "needed_by":
               {n: needed_by[n] for n in copy + from_out},
               "append_out": bool(from_out), "out_libs": from_out,
               "skipped_out_libs": skipped, "ld_library_path": ld,
               "seconds": round(time.monotonic() - t0, 2)}
        libs_dir.mkdir(parents=True, exist_ok=True)
        (libs_dir / RECORD).write_text(json.dumps(rec, indent=2, sort_keys=True))
        return dict(rec, host_dir=str(libs_dir) if copy else None, cached=False)
    except BaseException:
        shutil.rmtree(libs_dir, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(stage, ignore_errors=True)
