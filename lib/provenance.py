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

_ASAN_KIND = re.compile(r"ERROR: \w*Sanitizer: ([a-z-]+)")
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
                      timeout: int = 90) -> dict:
    """Replay ONE artifact and say what it actually is.

    Returns {class, kind, frame, exit_code}. `class` is one of:
      sanitizer  - a real sanitizer report (kind/frame carry the identity)
      assert     - a reachable assertion abort; real, but not memory safety, and
                   only present while asserts are compiled in
      nocrash    - ran clean; with alloc_dealloc_mismatch=0 this is where the
                   libc++ linkage artifacts land
      infra      - the replay itself failed (docker/loader); NOT evidence

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
        cmd += ["-e", f"ASAN_OPTIONS={asan_options}",
                "-v", f"{Path(bin_dir).absolute()}:/out:ro",
                "-v", f"{tmp}:/tc:ro",
                "--entrypoint", "/bin/bash", image, "-lc",
                f"timeout {max(timeout - 25, 10)} /out/{fuzz_target} /tc/tc 2>&1; echo __RC=$?"]
        out, rc = _run(cmd, timeout=timeout)
    if rc in (125, 126, 127):
        return {"class": "infra", "kind": None, "frame": None, "exit_code": rc}
    m = re.search(r"__RC=(\d+)\s*$", out)
    inner = int(m.group(1)) if m else None
    k = _ASAN_KIND.search(out)
    if k:
        frames = [f for f in _FRAME.findall(out)
                  if not f.startswith(_RUNTIME) and not f.startswith(_OPTIMIZER_INSERTED)]
        return {"class": "sanitizer", "kind": k.group(1),
                "frame": frames[0] if frames else None, "exit_code": inner}
    a = _ASSERT.search(out)
    if a:
        return {"class": "assert", "kind": "assert",
                "frame": f"{Path(a.group(1)).name}:{a.group(2)}", "exit_code": inner}
    if _ASSERT_LIBC.search(out):
        return {"class": "assert", "kind": "assert", "frame": "<libc-assert>",
                "exit_code": inner}
    return {"class": "nocrash", "kind": None, "frame": None, "exit_code": inner}


# --------------------------------------------------------------------------- #
# 2. build / toolchain fingerprint
# --------------------------------------------------------------------------- #
def binary_fingerprint(image: str, bin_dir, fuzz_target: str) -> dict:
    """Compiler, C++ runtime LINKAGE, and hashes for one built target.

    Linkage is the field that matters: dynamically linking libc++/libc++abi (ours)
    vs statically (upstream ARVO) is the whole reason 67% of assimp's crash corpus
    was an artifact -- libc++.so.1 allocates an exception message with `operator
    new` while libc++abi.so.1's separate copy frees it with `free`.
    """
    script = (
        f'echo "__COMMENT__"; readelf -p .comment /out/{fuzz_target} 2>/dev/null | head -20; '
        f'echo "__LDD__"; ldd /out/{fuzz_target} 2>&1 | head -30; '
        f'echo "__SHA__"; sha256sum /out/{fuzz_target} 2>/dev/null; '
        f'echo "__ASANSYM__"; nm -C /out/{fuzz_target} 2>/dev/null | grep -c "__asan_" || echo 0; '
        f'echo "__CXXFLAGS__"; echo "$CXXFLAGS"; echo "__CFLAGS__"; echo "$CFLAGS"'
    )
    out, _ = _run(["docker", "run", "--rm",
                   "-v", f"{Path(bin_dir).absolute()}:/out:ro",
                   "--entrypoint", "/bin/bash", image, "-lc", script], timeout=120)

    def _sec(name):
        m = re.search(rf"__{name}__\n(.*?)(?=\n__[A-Z]+__|\Z)", out, re.S)
        return (m.group(1).strip() if m else "")

    ldd = _sec("LDD")
    cxx_dyn = sorted({m for m in re.findall(r"(libc\+\+\.so[.\d]*|libc\+\+abi\.so[.\d]*|libstdc\+\+\.so[.\d]*)", ldd)})
    comment = _sec("COMMENT")
    compilers = sorted({c.strip() for c in re.findall(r"((?:Ubuntu |Debian )?clang version [\d.]+|GCC: \([^)]*\) [\d.]+)", comment)})
    image_id, _ = _run(["docker", "image", "inspect", "--format", "{{.Id}}", image], timeout=30)
    return {
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
