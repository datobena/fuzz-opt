#!/usr/bin/env python3
"""Record what a run actually ran with, while it is running.

Every function here exists because something in this benchmark was concluded
wrongly, or reconstructed expensively, for want of a few hundred bytes written at
the time:

  * assimp's time-to-bug read 0.19-4.8s when the truth was 10.7s (baseline) vs
    103.9s (optimized) -- inverting the result -- because crash_type came from
    the FILENAME and 67% of "crashes" were a libc++ linkage artifact and 31%
    were assertion aborts.  -> classify_artifact()
  * Finding that our binaries dynamically link an uninstrumented libc++ while
    ARVO links it statically took three parallel investigations.  -> binary_fingerprint()
  * ARVO disables alloc_dealloc_mismatch and we did not; that one flag accounts
    for 5845 artifacts.  -> the sanitizer options recorded beside the results.
  * An apport storm (36 processes at ~8000% CPU against fuzzers at 188%) was
    invisible until seen live.  -> host_environment()
  * A 239 GiB OOM killed a campaign leaving no trace of the approach.  -> PeakRSS

Everything written here is small and bounded: a few KB per trial, one row per
restart. Nothing samples continuously and nothing stores payloads.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from lib.crash_classify import replay_sanitizer_env, sanitizer_identity  # noqa: E402

_FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in ([A-Za-z_][A-Za-z0-9_:]*)")
_ASSERT = re.compile(r"assert(?:ion)?[^\n]*?failure[^\n]*?in\s+(\S+?)\((\d+)\)", re.I)
_ASSERT_LIBC = re.compile(r"Assertion\s+`[^']*'\s+failed", re.I)
_RUNTIME = ("__asan", "__sanitizer", "__interceptor", "__lsan", "operator new",
            "malloc", "free", "realloc", "calloc", "__cxa_", "_Unwind_",
            "std::", "__gnu_cxx::", "abort", "raise", "__libc_")
_OPTIMIZER_INSERTED = ("fold_",)


def _run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return (r.stdout or "") + (r.stderr or ""), r.returncode
    except Exception as e:  # noqa: BLE001 - provenance must never kill a run
        return f"<{type(e).__name__}: {e}>", -1


# --------------------------------------------------------------------------- #
# 1. crash classification at save time
# --------------------------------------------------------------------------- #
def classify_artifact(image: str, bin_dir, fuzz_target: str, artifact,
                      cpu: int | None = None, asan_options: str = "detect_leaks=0",
                      timeout: int = 90, ubsan_options: str | None = None) -> dict:
    """Replay ONE artifact and say what it actually is.

    Returns {class, kind, frame, exit_code}. `class` is one of:
      sanitizer  - a real sanitizer report (kind/frame carry the identity):
                   an ASan-family "ERROR: <San>: <kind>" (deadly signals such as
                   SEGV included), or a UBSan finding from a FuzzBench bug build,
                   kind "ubsan:<check>" and frame "<file>:<line>" (UBSan prints
                   no stack under print_stacktrace=0; see
                   crash_classify.ubsan_identity)
      assert     - a reachable assertion abort; real, but not memory safety, and
                   only present while asserts are compiled in
      abort      - SIGABRT reported by the sanitizer's deadly-signal handler
                   with no assertion message (abort(), std::terminate). Real, not
                   memory safety. FuzzBench's UBSAN_OPTIONS sets handle_abort=2,
                   which is what makes these visible at all.
      nocrash    - ran clean; with alloc_dealloc_mismatch=0 this is where the
                   libc++ linkage artifacts land
      infra      - the replay itself failed (docker/loader); NOT evidence

    UBSAN_OPTIONS defaults to config.REPLAY_UBSAN_OPTIONS + symbolize=1
    (crash_classify.replay_sanitizer_env explains the symbolize override).

    The artifact is staged under a neutral name: AFL writes `id:000000,sig:06,...`
    and archives dirs as `crashes.<ts>`, and docker parses colons in a -v spec as
    field separators, so mounting either fails with "too many colons" -- exit 125,
    before the container exists. That failure mode previously scored as "crash".
    """
    artifact = Path(artifact)
    if not artifact.is_file():
        return {"class": "infra", "kind": None, "frame": None, "exit_code": None}
    with tempfile.TemporaryDirectory(prefix="classify-") as tmp:
        staged = Path(tmp) / "tc"
        try:
            shutil.copyfile(artifact, staged)
        except OSError:
            return {"class": "infra", "kind": None, "frame": None, "exit_code": None}
        cmd = ["docker", "run", "--rm", "--privileged"]
        if cpu is not None:
            cmd += ["--cpuset-cpus", str(cpu)]
        env = replay_sanitizer_env(asan_options, ubsan_options=ubsan_options)
        cmd += ["-e", f"ASAN_OPTIONS={env['ASAN_OPTIONS']}",
                "-e", f"UBSAN_OPTIONS={env['UBSAN_OPTIONS']}",
                "-v", f"{Path(bin_dir).absolute()}:/out:ro",
                "-v", f"{tmp}:/tc:ro",
                "--entrypoint", "/bin/bash", image, "-lc",
                f"timeout {max(timeout - 25, 10)} /out/{fuzz_target} /tc/tc 2>&1; echo __RC=$?"]
        out, rc = _run(cmd, timeout=timeout)
    if rc in (125, 126, 127):
        return {"class": "infra", "kind": None, "frame": None, "exit_code": rc}
    # stdout then stderr: when the target aborts (abort_on_error=1, which
    # FuzzBench's UBSAN_OPTIONS sets for every report), bash's "Aborted" notice
    # lands on stderr AFTER the __RC line, so the marker is not at the very end.
    rcs = re.findall(r"^__RC=(\d+)\s*$", out, re.M)
    inner = int(rcs[-1]) if rcs else None
    return classify_replay_output(out, inner)


def classify_replay_output(out: str, inner: int | None = None) -> dict:
    """classify_artifact's verdict for one replay's combined output.

    Split out so the parsing is testable against captured real reports
    (tests/fixtures/sanitizer/). ``inner`` is the target's own exit status.
    """
    ident = sanitizer_identity(out)
    if ident and ident.get("sanitizer") != "UndefinedBehaviorSanitizer" \
            and ident["kind"] != "ABRT":
        frames = [f for f in _FRAME.findall(out)
                  if not f.startswith(_RUNTIME) and not f.startswith(_OPTIMIZER_INSERTED)]
        return {"class": "sanitizer", "kind": ident["kind"],
                "frame": frames[0] if frames else None, "exit_code": inner}
    if ident and ident.get("sanitizer") == "UndefinedBehaviorSanitizer":
        # -fno-sanitize-recover makes every enabled check fatal. A report from a
        # target that still exited 0 came from a recoverable check: logged, not
        # a crash, and AFL would not have saved it as one.
        if inner == 0:
            return {"class": "nocrash", "kind": ident["kind"],
                    "frame": ident["location"], "exit_code": inner}
        return {"class": "sanitizer", "kind": ident["kind"],
                "frame": ident["location"], "exit_code": inner}
    a = _ASSERT.search(out)
    if a:
        return {"class": "assert", "kind": "assert",
                "frame": f"{Path(a.group(1)).name}:{a.group(2)}", "exit_code": inner}
    if _ASSERT_LIBC.search(out):
        return {"class": "assert", "kind": "assert", "frame": "<libc-assert>",
                "exit_code": inner}
    if ident and ident["kind"] == "ABRT":
        frames = [f for f in _FRAME.findall(out)
                  if not f.startswith(_RUNTIME) and not f.startswith(_OPTIMIZER_INSERTED)]
        return {"class": "abort", "kind": "ABRT",
                "frame": frames[0] if frames else None, "exit_code": inner}
    return {"class": "nocrash", "kind": None, "frame": None, "exit_code": inner}


# --------------------------------------------------------------------------- #
# 2. build / toolchain fingerprint
# --------------------------------------------------------------------------- #
def binary_fingerprint(image: str, bin_dir, fuzz_target: str,
                       entry: dict | None = None) -> dict:
    """Compiler, C++ runtime LINKAGE, and hashes for one built target.

    Linkage is the field that matters: dynamically linking libc++/libc++abi (ours)
    vs statically (upstream ARVO) is the whole reason 67% of assimp's crash corpus
    was an artifact -- libc++.so.1 allocates an exception message with `operator
    new` while libc++abi.so.1's separate copy frees it with `free`.

    FuzzBench builds (an ``fb-aflpp/`` image, an image whose ENV carries
    FuzzBench's FUZZER=aflplusplus + BENCHMARK, or ``entry["kind"] ==
    "fuzzbench"`` with an fb-aflpp image) set CFLAGS inside fuzzer.build(), so
    the image ENV is NOT what compiled the binary. For those, cflags/cxxflags
    are the per-type FuzzBench flags (fuzzbench_build_flags) and a ``fuzzbench``
    block records instrumentation mode, cmplog/dict presence, AFL++ commit and
    base-builder digest. ARVO output is unchanged.
    """
    t = fuzz_target
    script = (
        f'echo "__COMMENT__"; readelf -p .comment /out/{t} 2>/dev/null | head -20; '
        f'echo "__LDD__"; ldd /out/{t} 2>&1 | head -30; '
        f'echo "__SHA__"; sha256sum /out/{t} 2>/dev/null; '
        f'echo "__ASANSYM__"; nm -C /out/{t} 2>/dev/null | grep -c "__asan_" || echo 0; '
        f'echo "__CXXFLAGS__"; echo "$CXXFLAGS"; echo "__CFLAGS__"; echo "$CFLAGS"; '
        # Probes for FuzzBench builds; harmless (and ignored) for ARVO images.
        f'echo "__FBENV__"; echo "FUZZER=$FUZZER"; echo "BENCHMARK=$BENCHMARK"; '
        f'echo "__NEEDED__"; readelf -d /out/{t} 2>/dev/null | grep NEEDED; '
        f'echo "__OUTFILES__"; '
        f'test -f /out/cmplog/{t} && echo "cmplog=yes" || echo "cmplog=no"; '
        f'test -f /out/afl++.dict && echo "dict=yes" || echo "dict=no"; '
        f'echo "__AFLHEAD__"; git -C /afl rev-parse HEAD 2>/dev/null; '
        f'echo "__BENCHYAML__"; cat /benchmark.yaml 2>/dev/null | head -40'
    )
    out, _ = _run(["docker", "run", "--rm",
                   "-v", f"{Path(bin_dir).absolute()}:/out:ro",
                   "--entrypoint", "/bin/bash", image, "-lc", script], timeout=120)

    def _sec(name):
        # Markers are whole lines. Anchoring them matters for a probe that
        # printed nothing (git/cat/grep on an ARVO image): the old unanchored
        # pattern then swallowed the NEXT section, marker included.
        m = re.search(rf"^__{name}__$\n?(.*?)(?=^__[A-Z]+__$|\Z)", out, re.S | re.M)
        return (m.group(1).strip() if m else "")

    ldd = _sec("LDD")
    cxx_dyn = sorted({m for m in re.findall(r"(libc\+\+\.so[.\d]*|libc\+\+abi\.so[.\d]*|libstdc\+\+\.so[.\d]*)", ldd)})
    comment = _sec("COMMENT")
    compilers = sorted({c.strip() for c in re.findall(r"((?:Ubuntu |Debian )?clang version [\d.]+|GCC: \([^)]*\) [\d.]+)", comment)})
    image_id, _ = _run(["docker", "image", "inspect", "--format", "{{.Id}}", image], timeout=30)
    rec = {
        "image": image,
        "image_id": image_id.strip()[:71] or None,
        "compilers": compilers,
        "cxx_runtime_dynamic": cxx_dyn,
        # True == ours (the hazardous form). False == upstream ARVO's form.
        "cxx_runtime_dynamically_linked": bool(cxx_dyn),
        "binary_sha256": (_sec("SHA").split() or [None])[0],
        "asan_symbols_in_binary": _sec("ASANSYM").strip().splitlines()[-1:] or None,
        "cflags": _sec("CFLAGS"),
        "cxxflags": _sec("CXXFLAGS"),
    }
    fbenv = dict(re.findall(r"^(FUZZER|BENCHMARK)=(.*)$", _sec("FBENV"), re.M))
    if not _is_fuzzbench_build(image, fbenv):
        return rec

    labels = _image_labels(image)
    needed = _sec("NEEDED")
    needed_cxx = sorted(set(re.findall(
        r"\[(libc\+\+\.so[.\d]*|libc\+\+abi\.so[.\d]*|libstdc\+\+\.so[.\d]*)\]", needed)))
    outfiles = dict(re.findall(r"^(cmplog|dict)=(yes|no)$", _sec("OUTFILES"), re.M))
    bench_type = _benchmark_type(_sec("BENCHYAML"), entry)
    flags = fuzzbench_build_flags(bench_type)
    aflhead = (_sec("AFLHEAD").split() or [None])[0]
    expected_afl = _fb_const("AFLPP_COMMIT", FB_AFLPP_COMMIT)
    rec.update({
        # What actually compiled the binary. The image-ENV values are kept under
        # image_env_* so nobody mistakes them for build flags again.
        "cflags": flags["cflags"],
        "cxxflags": flags["cxxflags"],
        "image_env_cflags": rec["cflags"],
        "image_env_cxxflags": rec["cxxflags"],
        # Linkage from the binary itself: ldd (what resolves at run time) OR the
        # DT_NEEDED entries (what the linker recorded). Measured, never assumed.
        "cxx_runtime_needed": needed_cxx,
        "cxx_runtime_dynamically_linked": bool(cxx_dyn or needed_cxx),
        "fuzzbench": {
            "benchmark": (labels.get("fb-aflpp.benchmark") or fbenv.get("BENCHMARK")
                          or (entry or {}).get("fuzzbench_dir")),
            "benchmark_type": bench_type,
            "flags_source": flags["source"],
            "optimization_level": flags["optimization_level"],
            "sanitizers": flags["sanitizers"],
            "instrumentation_mode": flags["instrumentation_mode"],
            # Decided deviation (DESIGN.md): optimizer-inserted fold_* helpers
            # are excluded from coverage instrumentation.
            "fold_exclusion": ("-fsanitize-coverage-ignorelist (generated per build)"
                               if bench_type == "bug" else "AFL_LLVM_DENYLIST"),
            "cmplog_binary_present": outfiles.get("cmplog") == "yes",
            "aflpp_dict_present": outfiles.get("dict") == "yes",
            "aflpp_commit": aflhead,
            "aflpp_commit_expected": expected_afl,
            "aflpp_commit_matches": (bool(aflhead) and aflhead.startswith(expected_afl[:8])
                                     if aflhead else None),
            "fuzzbench_commit": (labels.get("fb-aflpp.fuzzbench-commit")
                                 or _fb_const("FUZZBENCH_COMMIT", None)),
            **_base_builder_record(image, labels),
        },
    })
    return rec


# FuzzBench constants, used only when prework/fuzzbench_upstream/fuzzers/utils.py
# (the vendored copy, FuzzBench 3234e151) cannot be read. Values are that file's.
FB_SANITIZER_FLAGS = [
    "-fsanitize=address",
    "-fsanitize=array-bounds,bool,builtin,enum,float-divide-by-zero,function,"
    "integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,"
    "shift,signed-integer-overflow,unreachable,vla-bound,vptr",
    "-fno-sanitize-recover=array-bounds,bool,builtin,enum,float-divide-by-zero,"
    "function,integer-divide-by-zero,null,object-size,return,"
    "returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,"
    "vla-bound,vptr",
]
FB_NO_SANITIZER_COMPAT_CFLAGS = ["-pthread", "-Wl,--no-as-needed", "-Wl,-ldl",
                                 "-Wl,-lm", "-Wno-unused-command-line-argument"]
FB_FUZZING_CFLAGS = ["-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"]
FB_LIBCPLUSPLUS_FLAG = "-stdlib=libc++"
FB_BUGS_OPTIMIZATION_LEVEL = "-O1"
FB_DEFAULT_OPTIMIZATION_LEVEL = "-O3"
FB_AFLPP_COMMIT = "56d5aa3101945e81519a3fac8783d0d8fad82779"
FB_BASE_BUILDER = ("gcr.io/oss-fuzz-base/base-builder@sha256:"
                   "87ca1e9e19235e731fac8de8d1892ebe8d55caf18e7aa131346fc582a2034fdd")
FB_IMAGE_PREFIX = "fb-aflpp/"
_FB_UTILS = Path(__file__).resolve().parent.parent / "prework" / "fuzzbench_upstream" \
    / "fuzzers" / "utils.py"
_FB_UTIL_NAMES = ("SANITIZER_FLAGS", "NO_SANITIZER_COMPAT_CFLAGS", "FUZZING_CFLAGS",
                  "LIBCPLUSPLUS_FLAG", "BUGS_OPTIMIZATION_LEVEL",
                  "DEFAULT_OPTIMIZATION_LEVEL")


def _vendored_fb_constants(path: Path = _FB_UTILS) -> dict | None:
    """The flag constants from the vendored FuzzBench utils.py, read with ast
    (importing it needs yaml and FuzzBench's environment). None if unreadable."""
    import ast
    try:
        tree = ast.parse(Path(path).read_text())
    except (OSError, SyntaxError, ValueError):
        return None
    found = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in _FB_UTIL_NAMES:
            try:
                found[node.targets[0].id] = ast.literal_eval(node.value)
            except ValueError:
                return None
    return found if set(found) == set(_FB_UTIL_NAMES) else None


def fuzzbench_build_flags(bench_type: str | None, utils_path: Path = _FB_UTILS) -> dict:
    """CFLAGS/CXXFLAGS FuzzBench's utils.set_compilation_flags() sets for a type.

    bug:      FUZZING_CFLAGS + SANITIZER_FLAGS + -O1  (C++: + -stdlib=libc++)
    coverage: FUZZING_CFLAGS + NO_SANITIZER_COMPAT_CFLAGS + -O3, no sanitizer
    The aflplusplus fuzzer then compiles with /afl/afl-clang-fast in LLVMNATIVE
    mode when CFLAGS contain 'array-bounds' (bug), else PCGUARD (tracepc).
    """
    c = _vendored_fb_constants(utils_path)
    try:
        shown = Path(utils_path).resolve().relative_to(_FB_UTILS.parents[3])
    except ValueError:
        shown = utils_path
    source = (f"reconstructed from vendored {shown}"
              if c else "constant mapping (FuzzBench 3234e151 fuzzers/utils.py)")
    if not c:
        c = {"SANITIZER_FLAGS": FB_SANITIZER_FLAGS,
             "NO_SANITIZER_COMPAT_CFLAGS": FB_NO_SANITIZER_COMPAT_CFLAGS,
             "FUZZING_CFLAGS": FB_FUZZING_CFLAGS,
             "LIBCPLUSPLUS_FLAG": FB_LIBCPLUSPLUS_FLAG,
             "BUGS_OPTIMIZATION_LEVEL": FB_BUGS_OPTIMIZATION_LEVEL,
             "DEFAULT_OPTIMIZATION_LEVEL": FB_DEFAULT_OPTIMIZATION_LEVEL}
    if bench_type == "bug":
        opt = c["BUGS_OPTIMIZATION_LEVEL"]
        cflags = c["FUZZING_CFLAGS"] + c["SANITIZER_FLAGS"] + [opt]
        cxxflags = c["FUZZING_CFLAGS"] + c["SANITIZER_FLAGS"] + [c["LIBCPLUSPLUS_FLAG"], opt]
        sanitizers = ["address", "undefined(no-recover)"]
        mode = "LLVMNATIVE"
    else:
        opt = c["DEFAULT_OPTIMIZATION_LEVEL"]
        cflags = c["FUZZING_CFLAGS"] + c["NO_SANITIZER_COMPAT_CFLAGS"] + [opt]
        cxxflags = (c["FUZZING_CFLAGS"] + c["NO_SANITIZER_COMPAT_CFLAGS"]
                    + [c["LIBCPLUSPLUS_FLAG"], opt])
        sanitizers = []
        mode = "PCGUARD"
    return {"cflags": " ".join(cflags), "cxxflags": " ".join(cxxflags),
            "optimization_level": opt, "sanitizers": sanitizers,
            "instrumentation_mode": mode, "source": source}


def _fb_const(name: str, default):
    """A constant from prework.fuzzbench_image when importable, else default."""
    try:
        from prework import fuzzbench_image  # noqa: PLC0415
        return getattr(fuzzbench_image, name, default) or default
    except Exception:  # noqa: BLE001
        return default


def _is_fuzzbench_build(image: str, fbenv: dict | None = None) -> bool:
    """Is this binary's image a FuzzBench-faithful build? Decided by the IMAGE
    (the build method), not the manifest kind: older fuzzbench-kind experiments
    were built by OSS-Fuzz `compile` in bench-aflpp images and keep ARVO output."""
    if str(image).startswith(FB_IMAGE_PREFIX):
        return True
    fbenv = fbenv or {}
    return fbenv.get("FUZZER") == "aflplusplus" and bool(fbenv.get("BENCHMARK"))


def _benchmark_type(benchmark_yaml: str, entry: dict | None) -> str:
    """FuzzBench semantics: type 'bug' only when benchmark.yaml says so; an
    absent type is a coverage benchmark. Falls back to the manifest entry."""
    m = re.search(r"^type:\s*['\"]?(\w+)", benchmark_yaml or "", re.M)
    if m:
        return m.group(1)
    if benchmark_yaml and re.search(r"^fuzz_target:", benchmark_yaml, re.M):
        return "coverage"
    return str((entry or {}).get("type") or "coverage")


def _image_labels(image: str) -> dict:
    out, rc = _run(["docker", "image", "inspect", "--format",
                    "{{json .Config.Labels}}", image], timeout=30)
    try:
        return json.loads(out) or {} if rc == 0 else {}
    except ValueError:
        return {}


def _image_layers(image: str) -> list[str]:
    out, rc = _run(["docker", "image", "inspect", "--format",
                    "{{json .RootFS.Layers}}", image], timeout=30)
    try:
        return json.loads(out) or [] if rc == 0 else []
    except ValueError:
        return []


def _base_builder_record(image: str, labels: dict) -> dict:
    """The base-builder digest, VERIFIED when the base image is present locally:
    an image built FROM it starts with exactly its filesystem layers."""
    expected = labels.get("fb-aflpp.base-builder") or _fb_const("BASE_BUILDER", FB_BASE_BUILDER)
    base_layers = _image_layers(expected)
    img_layers = _image_layers(image)
    if base_layers and img_layers:
        verified = img_layers[:len(base_layers)] == base_layers
    else:
        verified = None    # base or image not present locally: unverifiable
    return {"base_builder": expected, "base_builder_layers_verified": verified}


# --------------------------------------------------------------------------- #
# 2b. which image an experiment ran with
# --------------------------------------------------------------------------- #
def recorded_image(cve_dir) -> str | None:
    """The image an experiment's binaries were built and fuzzed with, as
    recorded at run time, or None.

    Sources, most authoritative first: campaign_provenance.json's
    baseline_toolchain.image (online design), then any trial metadata.json's
    toolchain.image. Analysis replays of a finished experiment must use THIS
    image: its binaries link that image's runtime (bench-aflpp builds need the
    pinned LLVM's libc++.so.1), and line coverage must come from the source
    the campaign compiled.
    """
    if not cve_dir:
        return None
    d = Path(cve_dir)
    cands = [d / "optimized" / "online" / "campaign_provenance.json"]
    for arm in ("baseline", "optimized"):
        cands += sorted((d / arm).glob("trial_*/metadata.json"))[:3]
    for p in cands:
        try:
            obj = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        tc = obj.get("baseline_toolchain") or obj.get("toolchain") or {}
        img = tc.get("image") if isinstance(tc, dict) else None
        if img:
            return str(img)
    return None


def _legacy_image_tag(entry: dict) -> str | None:
    """The pre-FuzzBench-parity tag: bench-aflpp/<project>-arvo-<local_id>."""
    try:
        return f"bench-aflpp/{entry['project'].lower()}-arvo-{int(entry['local_id'])}"
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def _image_present(image: str) -> bool:
    _, rc = _run(["docker", "image", "inspect", "--format", "{{.Id}}", image], timeout=30)
    return rc == 0


def experiment_image(cve_dir=None, entry: dict | None = None, *,
                     check_local: bool = True) -> str | None:
    """Image for replaying/rebuilding an experiment's binaries.

    1. the image recorded in the experiment dir (recorded_image)
    2. prework.prework_build.prework_image_for(entry) -- fb-aflpp/<dir> for
       FuzzBench-parity entries, bench-aflpp/... for ARVO (imported lazily)
    3. the manifest entry's own "image" field, then the legacy
       bench-aflpp/<project>-arvo-<local_id> tag, so old experiments resolve

    With check_local, the first candidate present in the local docker store
    wins; if none is present the first candidate is returned unverified.
    """
    cands: list[str] = []
    rec = recorded_image(cve_dir)
    if rec:
        cands.append(rec)
    if entry:
        try:
            from prework.prework_build import prework_image_for  # noqa: PLC0415
            cands.append(prework_image_for(entry))
        except Exception:  # noqa: BLE001 - fall back to the old tag
            pass
        if entry.get("image"):
            cands.append(str(entry["image"]))
        legacy = _legacy_image_tag(entry)
        if legacy:
            cands.append(legacy)
    seen: list[str] = []
    for c in cands:
        if c and c not in seen:
            seen.append(c)
    if not seen:
        return None
    if check_local:
        for c in seen:
            if _image_present(c):
                return c
    return seen[0]


# --------------------------------------------------------------------------- #
# 3. host environment
# --------------------------------------------------------------------------- #
def host_environment() -> dict:
    """Host state that has silently changed results before."""
    def _read(p, default=""):
        try:
            return Path(p).read_text().strip()
        except OSError:
            return default
    lscpu, _ = _run(["lscpu"], timeout=30)
    numa = dict(re.findall(r"NUMA (node\d+) CPU\(s\):\s+(\S+)", lscpu))
    gov = sorted({_read(p) for p in
                  Path("/sys/devices/system/cpu").glob("cpu*/cpufreq/scaling_governor")} - {""})
    docker_v, _ = _run(["docker", "--version"], timeout=30)
    return {
        # apport piping cost 36 processes ~8000% CPU against fuzzers at 188%.
        "kernel_core_pattern": _read("/proc/sys/kernel/core_pattern"),
        "kernel": os.uname().release,
        "loadavg": _read("/proc/loadavg"),
        "cpu_count": os.cpu_count(),
        "numa_nodes": numa,
        "scaling_governor": gov,
        "docker_version": docker_v.strip(),
        "recorded_at": time.time(),
    }


# --------------------------------------------------------------------------- #
# 4. orchestrator peak RSS
# --------------------------------------------------------------------------- #
class PeakRSS:
    """Sample this process's RSS so an approach to OOM leaves a trace."""

    def __init__(self, interval: float = 30.0):
        self.interval = interval
        self.peak_kb = 0
        self._stop = threading.Event()
        self._t: threading.Thread | None = None

    def _rss_kb(self) -> int:
        try:
            for line in Path("/proc/self/status").read_text().splitlines():
                if line.startswith("VmHWM:"):
                    return int(line.split()[1])
        except (OSError, ValueError, IndexError):
            pass
        return 0

    def _loop(self):
        while not self._stop.wait(self.interval):
            self.peak_kb = max(self.peak_kb, self._rss_kb())

    def start(self):
        self.peak_kb = self._rss_kb()
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()
        return self

    def snapshot(self) -> dict:
        self.peak_kb = max(self.peak_kb, self._rss_kb())
        return {"peak_rss_mb": round(self.peak_kb / 1024.0, 1)}

    def stop(self) -> dict:
        self._stop.set()
        return self.snapshot()


def write_json(path, obj) -> None:
    """Best-effort provenance write. Never raises into a running campaign."""
    try:
        os.makedirs(os.path.dirname(str(path)) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(obj, f, indent=2, default=str)
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------- #
# 5. per-fold attribution (cheap form)
# --------------------------------------------------------------------------- #
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@\s*(.*)$", re.M)
_DIFF_FILE = re.compile(r"^\+\+\+ b/(\S+)", re.M)
_FN = re.compile(r"([A-Za-z_][A-Za-z0-9_:]*)\s*\(")


def diff_attribution(diff_path) -> dict:
    """Which files/functions a round changed, and which are optimizer-inserted.

    Full per-fold attribution (build each fold alone and measure it) is far too
    expensive to run per round. This is the cheap form: it answers "what did this
    round touch?" from the diff alone. It would have made two findings immediate
    that each took an investigation -- that PcapPlusPlus's iter_03 rewrote
    tbp_my_own_strnlen and silently removed a real 1-byte overread, and that
    yara's extra "bug" was the wide-char loop hoisted into fold_skip_wide_chars.
    """
    try:
        text = Path(diff_path).read_text(errors="replace")
    except OSError:
        return {}
    files = sorted(set(_DIFF_FILE.findall(text)))
    ctx_fns, inserted = set(), set()
    for ctx in _HUNK.findall(text):
        for name in _FN.findall(ctx):
            (inserted if name.startswith("fold_") else ctx_fns).add(name)
    for line in text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            for name in _FN.findall(line):
                if name.startswith("fold_"):
                    inserted.add(name)
    return {
        "files_changed": files,
        "functions_touched": sorted(ctx_fns)[:60],
        # The fold contract requires inserted helpers to be named fold_*; the
        # AFL_LLVM_DENYLIST depends on it. Recording them makes a crash landing
        # inside optimizer-inserted code attributable at analysis time.
        "optimizer_inserted_functions": sorted(inserted),
        "added_lines": sum(1 for l in text.splitlines()
                           if l.startswith("+") and not l.startswith("+++")),
        "removed_lines": sum(1 for l in text.splitlines()
                             if l.startswith("-") and not l.startswith("---")),
    }


# --------------------------------------------------------------------------- #
# 6. build-to-build noise floor
# --------------------------------------------------------------------------- #
def noise_floor(rebuild_fn, measure_fn, rounds: int = 2) -> dict:
    """Measure the target's OWN variance across rebuilds of IDENTICAL source.

    The replay gate accepts a fold when it beats the previous best. That is only
    meaningful relative to how much the measurement moves when NOTHING changes.
    PcapPlusPlus's optimizer discovered this by hand -- 32.36 / 33.32 / 32.59 /
    34.50 s across rebuilds of byte-identical source, a 6.6% spread -- and
    correctly rejected every fold it found, because all of them were worth 1-2%.
    Two campaigns of "no improvement" only became interpretable once that number
    existed. Measured ONCE per campaign, not per round: the cost is one extra
    pristine rebuild plus `rounds` replay passes.

    rebuild_fn() -> out_dir for a fresh build of unmodified source
    measure_fn(out_dir) -> {"median_time_s": float, ...}
    """
    times, errors = [], []
    for i in range(max(rounds, 2)):
        try:
            out_dir = rebuild_fn()
            if not out_dir:
                errors.append(f"rebuild {i}: no output"); continue
            m = measure_fn(out_dir) or {}
            t = m.get("median_time_s")
            if t:
                times.append(float(t))
            else:
                errors.append(f"measure {i}: no median_time_s")
        except Exception as e:  # noqa: BLE001 - never kill a campaign for this
            errors.append(f"{i}: {type(e).__name__}: {e}")
    if len(times) < 2:
        return {"measured": False, "errors": errors, "times_s": times}
    import statistics
    med = statistics.median(times)
    spread = 100.0 * (max(times) - min(times)) / med if med else None
    return {
        "measured": True,
        "rebuilds": len(times),
        "times_s": [round(t, 4) for t in times],
        "median_s": round(med, 4),
        "spread_pct": round(spread, 3) if spread is not None else None,
        # A fold whose measured gain is inside this band is not evidence.
        "min_meaningful_speedup": (round(1.0 + spread / 100.0, 4)
                                   if spread is not None else None),
        "errors": errors,
    }
