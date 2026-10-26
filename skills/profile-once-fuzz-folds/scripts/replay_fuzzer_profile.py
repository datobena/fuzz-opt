#!/usr/bin/env python3
"""Profile a fuzz target under Docker with perf while it REPLAYS a fixed corpus.

Unlike ``real_fuzzer_profile.py`` (which perf-records an *active* fuzzing window
with ``-max_total_time``), this profiles a binary *replaying* an immutable,
already-frozen corpus in libFuzzer's non-mutating ``-runs=0`` mode. The replay is
repeated in a loop until at least ``--min-sample-seconds`` of wall-clock has
elapsed, so even a tiny or very fast corpus yields enough perf samples for a
stable hotspot ranking. The corpus is mounted read-only so a profile pass can
never mutate the fixed evaluation set.

This is the single, authoritative profile for the ``profile-once-fuzz-folds``
loop: the hotspots it reports correspond exactly to the deterministic replay
workload that ``replay_timing.py`` later uses as the acceptance gate, so what is
profiled is what is measured.

Shared helpers (``_count_files``, ``RUNNER_IMAGE``) are imported from the sibling
``real_fuzzer_profile.py`` rather than duplicated, so that file stays
byte-identical to the copy the other skills ship and test (``_run`` is defined
locally with ``errors='replace'`` because the sibling's lacks it). The perf reports
(``flat.txt``, ``callgraph.txt``) are generated *inside* the container, where the
recorded binary lives at ``/out`` and a matching perf is installed, so symbols
resolve to function names -- host-side reporting against a container-recorded
``perf.data`` only yields raw addresses (the ``/out`` path does not exist on the
host).

The same container run also dumps every sample's call chain (``perf script``,
symbol-resolved there) to ``perf_script.txt.gz``, each sample's own IP
(``perf script -G``) to ``perf_script_ip.txt.gz``, and perf report's exact
sample count. The host then builds the ranked target-source hotspot table from
them (``hotspot_table.py`` -> ``hotspots.txt`` / ``hotspots.json``), the
optimizer's primary ranking input. A failure to build that table -- including a
failed or truncated dump, or a perf without ``-F dsoff`` -- fails the profile
loudly.

Before recording, ``target_libs.py`` works out which shared libraries the binary
loads in its OWN image (RUNNER_IMAGE) that the profiler image cannot resolve
(a build that let meson auto-detect the build image's glib), copies them into the
profile's ``target_libs`` dir and puts them on the target's LD_LIBRARY_PATH;
one it cannot supply fails the profile loudly.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import os
import sys
import time
import uuid
from pathlib import Path


def _load_real_fuzzer_profile():
    """Load the sibling real_fuzzer_profile module to reuse its shared helpers."""
    path = Path(__file__).with_name("real_fuzzer_profile.py")
    spec = importlib.util.spec_from_file_location("real_fuzzer_profile", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load real_fuzzer_profile from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rfp = _load_real_fuzzer_profile()
RUNNER_IMAGE = rfp.RUNNER_IMAGE

# Image used for the PERF pass. It must carry a perf that MATCHES THE HOST KERNEL:
# a perf older than the kernel (e.g. the 20.04 base-runner's perf 5.4 under a 6.8
# kernel) records the afl-showmap parent but NOT its exec'd forkserver children,
# so every AFL profile comes back ~75% afl-showmap and 0% target -- a silent,
# total failure that hands the optimizer a hotspot list of pure harness noise.
# libFuzzer targets are replayed as one direct long-lived process and are NOT
# affected, but the AFL path is, so this matters the moment a target is built with
# FUZZING_ENGINE=afl. The default image (bench-sandbox/profiler) is 24.04 (perf
# 6.8) and supplies the target's own libc++/unwind/python at /opt/oss-libs, since
# OSS-Fuzz targets are built against the 20.04 base-runner runtime. Override with
# the env var to pin a different kernel-matched perf; set it to the RUNNER_IMAGE
# value to restore the old (kernel-fragile) behaviour.
PROFILER_IMAGE = os.environ.get("FUZZ_SOURCE_FOLDS_PROFILER_IMAGE", "bench-sandbox/profiler")
# The profiler image's own library path (its copies of the 20.04 base-runner's
# libc++/unwind/python). perf runs with it; the target gets target_libs in front.
PROFILER_LD_LIBRARY_PATH = "/opt/oss-libs"

# The perf/kernel-mismatch failure above (perf never samples the target) is
# caught by the harness, from hotspots.json: it refuses a profile whose
# target-source functions received almost no samples (an absolute sample floor,
# phase2_setup.PHASE2_MIN_TARGET_SOURCE_SAMPLES). The DSO shares below are kept
# in metadata.json as information only; there is no percentage gate.


def _load_hotspot_table():
    """Load the sibling hotspot_table module (it has no other dependencies)."""
    path = Path(__file__).with_name("hotspot_table.py")
    spec = importlib.util.spec_from_file_location("hotspot_table", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load hotspot_table from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hotspot_table = _load_hotspot_table()


def _load_target_libs():
    """Load the sibling target_libs module (it has no other dependencies)."""
    path = Path(__file__).with_name("target_libs.py")
    spec = importlib.util.spec_from_file_location("target_libs", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load target_libs from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tlibs = _load_target_libs()

PERF_SCRIPT_NAME = "perf_script.txt.gz"
PERF_SCRIPT_IP_NAME = "perf_script_ip.txt.gz"
PERF_SCRIPT_STATUS = "perf_script.status"
# Everything a profile attempt writes. Removed before an attempt and after a
# failed one, so a retry or a resumed run can never pick up a stale report.
PROFILE_OUTPUTS = ("perf.data", "flat.txt", "callgraph.txt", "children.txt",
                   "dso.txt", PERF_SCRIPT_NAME, PERF_SCRIPT_IP_NAME,
                   PERF_SCRIPT_STATUS, "hotspots.json", "hotspots.txt")


def flat_target_share(flat_path, fuzz_target: str) -> float:
    """Sum of self-time %% in flat.txt attributed to the target's own DSO.

    Robust companion to target_dso_share (which reads dso.txt and can be None):
    parses the ranked report directly, summing rows whose Shared-Object column is
    the fuzz target. ~0 means perf never sampled the target -- the profile is
    harness noise, not a hotspot list.
    """
    try:
        text = Path(flat_path).read_text(errors="replace")
    except OSError:
        return 0.0
    total = 0.0
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        # "<pct>%  <command>  <dso>  [.] <symbol...>"
        if len(parts) < 4 or not parts[0].endswith("%"):
            continue
        try:
            pct = float(parts[0].rstrip("%"))
        except ValueError:
            continue
        if parts[2] == fuzz_target:
            total += pct
    return total


def _run(cmd, *, timeout=None) -> subprocess.CompletedProcess:
    """subprocess.run with errors='replace'. Docker/libFuzzer output can contain
    non-UTF-8 bytes, which would crash the default text decoding that
    ``real_fuzzer_profile._run`` uses."""
    return subprocess.run(
        cmd, capture_output=True, text=True, errors="replace",
        timeout=timeout, check=False,
    )


def build_replay_profile_docker_command(
    *,
    out_dir: str | Path,
    corpus_dir: str | Path,
    artifact_dir: str | Path,
    fuzz_target: str,
    min_sample_seconds: int,
    seed: int,
    cpu: int,
    memory: str,
    shm_size: str,
    rss_limit_mb: int = 3072,
    malloc_limit_mb: int = 1536,
    container_name: str | None = None,
    target_libs: dict | None = None,
) -> list[str]:
    """Build a ``docker run`` that perf-records the binary replaying the corpus.

    The corpus is mounted read-only and replayed with ``-runs=0`` (each unit once,
    no mutation). The replay is wrapped in a ``while`` loop that keeps relaunching
    until ``min_sample_seconds`` of wall-clock has passed, all under a single
    ``perf record`` session, so the sample count does not depend on corpus size or
    target speed. Pinning to one CPU and fixing the seed keep the profile stable.

    ``target_libs`` (from :func:`prepare_target_libs`): its ``host_dir`` is
    mounted read-only at target_libs.TARGET_LIBS_MOUNT and its
    ``ld_library_path`` exported inside the replay loop, so only the target (and
    afl-showmap) sees it -- never perf.
    """
    # Inner replay loop. Single-quoted in the final script so the OUTER bash
    # passes it verbatim to the perf-launched bash; the $(date +%s) clock and the
    # arithmetic are evaluated at runtime by that inner shell, once per iteration.
    # Two replay forms. The libFuzzer one takes a corpus DIRECTORY plus -runs=0;
    # aflpp_driver implements none of those flags and expects file arguments, so
    # on an AFL build the target exits immediately and the `while` loop just
    # respawns it. The resulting profile is pure process startup/teardown --
    # measured on a real campaign it was 0.00% project code, topped by
    # __lsan::ScanRangeForPointers (17%) and the dynamic loader, with `date`
    # from this very loop outranking the target.
    #
    # afl-showmap -C replays the whole corpus once through the forkserver, which
    # is also what the replay-timing gate measures -- so the profile the agent
    # optimizes against and the metric it is scored on come from the same
    # execution shape. Selected by probing for the binary rather than by a flag,
    # so a libFuzzer target keeps its original path.
    afl_loop = (
        # Same AFL_MAP_SIZE export as the broker gate (large-map FuzzBench
        # targets abort afl-showmap without it); no-op if the dump is empty.
        "m=$(AFL_DUMP_MAP_SIZE=1 /out/{target} 2>/dev/null); "
        'case "$m" in ""|*[!0-9]*) ;; *) export AFL_MAP_SIZE=$m;; esac; '
        "end=$(( $(date +%s) + {min_sec} )); "
        'while [ "$(date +%s)" -lt "$end" ]; do '
        "/out/afl-showmap -C -i /corpus -o /dev/null -t 5000+ -m none "
        "-- /out/{target} >/dev/null 2>&1 || true; "
        "done"
    ).format(min_sec=int(min_sample_seconds), target=fuzz_target)
    libfuzzer_loop = (
        "end=$(( $(date +%s) + {min_sec} )); "
        'while [ "$(date +%s)" -lt "$end" ]; do '
        "/out/{target} /corpus -runs=0 -seed={seed} "
        "-rss_limit_mb={rss} -malloc_limit_mb={malloc} -print_final_stats=1 "
        "|| true; "
        "done"
    ).format(
        min_sec=int(min_sample_seconds),
        target=fuzz_target,
        seed=int(seed),
        rss=int(rss_limit_mb),
        malloc=int(malloc_limit_mb),
    )
    replay_loop = (
        f'if [ -x /out/afl-showmap ]; then {afl_loop}; else {libfuzzer_loop}; fi'
    )
    lib_mounts = []
    if target_libs and target_libs.get("ld_library_path") not in (
            None, "", PROFILER_LD_LIBRARY_PATH):
        # Before the map-size dump too: a target that cannot load prints no size.
        replay_loop = (f"export LD_LIBRARY_PATH={target_libs['ld_library_path']}; "
                       + replay_loop)
        if target_libs.get("host_dir"):
            lib_mounts = ["-v", f"{Path(target_libs['host_dir']).resolve()}:"
                                f"{tlibs.TARGET_LIBS_MOUNT}:ro"]
    cmd = ["docker", "run", "--rm"]
    if container_name:
        cmd += ["--name", container_name]
    cmd += [
        "--cpuset-cpus", str(cpu),
        "--memory", memory,
        "--shm-size", shm_size,
        "--privileged",
        # Keep the profile on the TARGET, not on its sanitizer tooling.
        # Sanitizer reports are symbolized by a separate llvm-symbolizer
        # process, and its DWARF parsing lands in the SAME perf session: on one
        # assimp campaign libLLVM was 46.2% of samples against 6.4% for the
        # target binary itself, so the ranked hotspot list was mostly symbolizer
        # internals. Everything else is the fuzzer's own sanitizer set
        # (FuzzBench's fuzz-run options, but detect_leaks=0), so the profile
        # executes what the fuzzer executes -- e.g. alloc_dealloc_mismatch=0 lets
        # an input that throws a C++ exception run on instead of aborting. MUST equal
        # fuzz-opt's config.REPLAY_ASAN_OPTIONS / REPLAY_UBSAN_OPTIONS, which the
        # replay-timing gate uses, so profile and gate execute the same work.
        "-e", "ASAN_OPTIONS=abort_on_error=1:alloc_dealloc_mismatch=0:"
              "allocator_may_return_null=1:allocator_release_to_os_interval_ms=500:"
              "allow_user_segv_handler=0:check_malloc_usable_size=0:detect_leaks=0:"
              "detect_odr_violation=0:detect_stack_use_after_return=1:"
              "fast_unwind_on_fatal=0:handle_abort=2:handle_segv=2:handle_sigbus=2:"
              "handle_sigfpe=2:handle_sigill=2:max_uar_stack_size_log=16:"
              "quarantine_size_mb=64:strict_memcmp=1:symbolize=0:"
              "symbolize_inline_frames=0",
        "-e", "UBSAN_OPTIONS=abort_on_error=1:allocator_release_to_os_interval_ms=500:"
              "handle_abort=2:handle_segv=2:handle_sigbus=2:handle_sigfpe=2:"
              "handle_sigill=2:print_stacktrace=0:symbolize=0:"
              "symbolize_inline_frames=0",
        "-e", "MSAN_OPTIONS=symbolize=0",
        # The target was built against the 20.04 base-runner runtime; when the
        # profiler image differs (the kernel-matched 24.04 one), its own
        # libc++/unwind/python live here. Harmless with RUNNER_IMAGE (dir absent).
        # Libraries of the target's own build image come on top of this, for the
        # target process only (target_libs, exported in the replay loop).
        "-e", f"LD_LIBRARY_PATH={PROFILER_LD_LIBRARY_PATH}",
        # Absolute paths are required: docker treats a relative `-v src:/dst` as
        # a named volume, not a bind mount (fails with "invalid characters for a
        # local volume name"). The agent may invoke this with paths relative to
        # its cwd, so resolve them here.
        "-v", f"{Path(out_dir).resolve()}:/out:ro",
        "-v", f"{Path(corpus_dir).resolve()}:/corpus:ro",
        "-v", f"{Path(artifact_dir).resolve()}:/artifacts",
        *lib_mounts,
        PROFILER_IMAGE,
        "/bin/bash", "-lc",
        (
            "set -uo pipefail; "
            # The kernel-matched profiler image ships perf already. Only fall back
            # to installing it (the old RUNNER_IMAGE path) when none is present --
            # and prefer a perf whose version matches `uname -r` if several exist.
            "PERF_BIN=$(find /usr/lib -path '*/linux-tools*' -name perf 2>/dev/null "
            "| grep -F \"$(uname -r)\" | head -n 1); "
            'if [ -z "$PERF_BIN" ]; then '
            "PERF_BIN=$(find /usr/lib -path '*/linux-tools*' -name perf 2>/dev/null | sort | head -n 1); "
            "fi; "
            'if [ -z "$PERF_BIN" ]; then '
            "apt-get update >/dev/null 2>&1; "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y linux-tools-generic >/dev/null 2>&1 || true; "
            "PERF_BIN=$(find /usr/lib -path '*/linux-tools*' -name perf | sort | head -n 1); "
            "fi; "
            'test -n "$PERF_BIN"; '
            "mkdir -p /tmp/profile-artifacts; "
            "rc=0; "
            # Call-graph unwinding mode. The OSS-Fuzz build ships -gline-tables-only
            # (no DWARF CFI), so `--call-graph dwarf` yields an EMPTY call graph and
            # every caller/inclusive report comes back blank -- which silently hid
            # all allocator/libc cost from the target functions that drive it. Use
            # LBR (hardware branch stack: needs no frame info, immune to fuzz input
            # sitting on the stack) where the CPU supports it, else fall back to FP
            # (-fno-omit-frame-pointer is also in the global OSS-Fuzz CFLAGS). Never
            # dwarf here. The probe records `true` once: perf_event_open rejects the
            # branch-stack attr at setup on hardware without LBR, so rc is decisive.
            'CG=fp; "$PERF_BIN" record --call-graph lbr -o /tmp/.cgprobe -- true '
            ">/dev/null 2>&1 && CG=lbr; rm -f /tmp/.cgprobe; "
            '"$PERF_BIN" record -g --call-graph "$CG" -F 997 '
            "-o /artifacts/perf.data -- "
            f"/bin/bash -c '{replay_loop}' "
            "> /artifacts/fuzzer.log 2>&1 || rc=$?; "
            # Generate the reports here, in-container, so symbols resolve to
            # function names (the recorded /out binary is present and perf
            # matches the data).
            'if [ "$rc" -eq 0 ]; then '
            '"$PERF_BIN" report --stdio --no-children -g none --percent-limit 0.5 '
            "-i /artifacts/perf.data > /artifacts/flat.txt 2>>/artifacts/fuzzer.log || rc=$?; "
            # callgraph/dso are SUPPLEMENTARY. Their perf symbolization spawns
            # addr2line, which can SIGPIPE (exit 141) on some perf builds -- and
            # letting that override rc would discard a perfectly good flat.txt.
            # Only record + the flat report gate success; these are best-effort.
            '"$PERF_BIN" report --stdio -g callee,0.5 --percent-limit 0.5 '
            "-i /artifacts/perf.data > /artifacts/callgraph.txt 2>>/artifacts/fuzzer.log || true; "
            # Inclusive (self + descendants) ranking: credits each TARGET function
            # with the allocator/libc/kernel cost it drives, so hotspot selection is
            # no longer limited to self-time (where allocation cost hides under the
            # uneditable __asan/libc rows). Best-effort, same as callgraph.
            '"$PERF_BIN" report --stdio -g caller --children --percent-limit 0.5 '
            "-i /artifacts/perf.data > /artifacts/children.txt 2>>/artifacts/fuzzer.log || true; "
            # Whole-file DSO breakdown with NO percent floor. flat.txt is cut at
            # 0.5% and its listed rows can sum to as little as 39% of samples,
            # so it cannot answer "how much of this profile is even the target".
            # This can, and metadata.json records the share.
            '"$PERF_BIN" report --stdio --no-children -g none --sort dso --percent-limit 0 '
            "-i /artifacts/perf.data > /artifacts/dso.txt 2>>/artifacts/fuzzer.log || true; "
            # Every sample's full call chain, leaf first, symbols resolved HERE
            # (the /out binary and a matching perf exist only in this container),
            # and in a second pass (-G) each sample's own IP: under LBR the first
            # chain entry can be a callee that has not run yet. The host turns
            # both into hotspots.txt/json (hotspot_table.py). No percent floor.
            # --no-inline: there is no addr2line in this image, and inlined frames
            # are reported under their container anyway. Both pipelines' exit
            # codes, the dsoff support and perf report's exact sample count go to
            # perf_script.status so the host can refuse a failed or truncated
            # dump, loudly; none of it can mask a good flat.txt.
            "t0=$(date +%s%N); cg_rc=na; ip_rc=na; "
            # `perf script -h` exits 129, so under pipefail a `| grep -q` test
            # would always fail; match the captured usage text instead.
            'ph=$("$PERF_BIN" script -h 2>&1 || true); '
            'case "$ph" in *dsoff*) dsoff=yes; '
            '"$PERF_BIN" script -i /artifacts/perf.data --no-inline '
            "-F comm,pid,period,ip,sym,symoff,dso,dsoff 2>>/artifacts/fuzzer.log "
            "| gzip -1 > /artifacts/perf_script.txt.gz; "
            'cg_rc="${PIPESTATUS[0]} ${PIPESTATUS[1]}"; '
            '"$PERF_BIN" script -i /artifacts/perf.data --no-inline -G '
            "-F comm,pid,period,ip,sym,symoff,dso,dsoff 2>>/artifacts/fuzzer.log "
            "| gzip -1 > /artifacts/perf_script_ip.txt.gz; "
            'ip_rc="${PIPESTATUS[0]} ${PIPESTATUS[1]}"; '
            ";; *) dsoff=no;; esac; "
            'ns=$("$PERF_BIN" report -i /artifacts/perf.data --stats 2>/dev/null '
            "| awk '/SAMPLE events:/{print $3; exit}'); "
            '{ echo "dsoff=$dsoff"; echo "cg_rc=$cg_rc"; echo "ip_rc=$ip_rc"; '
            'echo "report_samples=${ns:-}"; '
            'echo "perf=$("$PERF_BIN" version 2>/dev/null)"; '
            'echo "ms=$(( ($(date +%s%N) - t0) / 1000000 ))"; } '
            "> /artifacts/perf_script.status; "
            "fi; "
            "chmod a+r /artifacts/perf.data /artifacts/fuzzer.log /artifacts/flat.txt /artifacts/callgraph.txt /artifacts/children.txt /artifacts/dso.txt /artifacts/perf_script.txt.gz /artifacts/perf_script_ip.txt.gz /artifacts/perf_script.status 2>/dev/null || true; "
            "exit $rc"
        ),
    ]
    return cmd


def prepare_target_libs(*, out_dir, fuzz_target: str, artifact_dir, cpu) -> dict | None:
    """The libraries of the target's own image (RUNNER_IMAGE) the profiler image
    lacks, copied into ``<artifact_dir>/target_libs`` (target_libs.prepare;
    cached there per binary and image pair). None when the target's image IS the
    profiler image: then nothing needs bridging. Raises target_libs.TargetLibsError
    or TargetLibsProbeError, both loud and marked for the harness."""
    if RUNNER_IMAGE == PROFILER_IMAGE:
        return None
    return tlibs.prepare(out_dir=out_dir, fuzz_target=fuzz_target,
                         libs_dir=Path(artifact_dir) / tlibs.DIRNAME,
                         target_image=RUNNER_IMAGE, profiler_image=PROFILER_IMAGE,
                         base_ld_path=PROFILER_LD_LIBRARY_PATH, cpu=cpu)


def run_replay_profile(args: argparse.Namespace) -> int:
    artifact_dir = Path(args.artifact_dir)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    corpus_dir = Path(args.corpus_dir)
    corpus_count = rfp._count_files(corpus_dir)
    if corpus_count == 0:
        raise RuntimeError(f"replay-profile corpus is empty: {corpus_dir}")

    # Once, before both attempts: what the binary loads in its own image that the
    # profiler image lacks. Without it a target linking a build-image library
    # (e.g. glib) dies in the loader, afl-showmap hides the error, and the
    # profile is 0% target. Failures raise with a marker the harness stages on.
    libs = prepare_target_libs(out_dir=args.out_dir, fuzz_target=args.fuzz_target,
                               artifact_dir=artifact_dir, cpu=args.cpu)
    if libs and (libs["libs"] or libs["append_out"]):
        how = "cached" if libs["cached"] else f"resolved in {libs['seconds']}s"
        # No image name: this stderr's tail can land in prebuild_status.json, in
        # the profile dir the agent reads, and an ARVO image tag names the bug.
        print(f"target libs: supplying {sorted(libs['libs'])} from the target's "
              f"image, target LD_LIBRARY_PATH={libs['ld_library_path']} ({how})",
              file=sys.stderr)

    perf_data = artifact_dir / "perf.data"
    flat = artifact_dir / "flat.txt"
    callgraph = artifact_dir / "callgraph.txt"
    dso = artifact_dir / "dso.txt"
    timeout = max(int(args.loop_timeout), int(args.min_sample_seconds) + 600)

    # Nothing from an earlier attempt or run may survive into this one.
    _remove_profile_outputs(artifact_dir)

    # perf inside a container is occasionally flaky (apt/network/transient), so
    # retry once and surface the docker + fuzzer.log output on failure instead of
    # a bare "perf failed" that hides the cause.
    success = False
    last_err = ""
    docker_rc = None
    for attempt in (1, 2):
        docker_cmd = build_replay_profile_docker_command(
            out_dir=args.out_dir,
            corpus_dir=corpus_dir,
            artifact_dir=artifact_dir,
            fuzz_target=args.fuzz_target,
            min_sample_seconds=args.min_sample_seconds,
            seed=args.seed,
            cpu=args.cpu,
            memory=args.memory,
            shm_size=args.shm_size,
            container_name=f"poff-replay-{attempt}-{os.getpid()}-{uuid.uuid4().hex[:8]}",
            target_libs=libs,
        )
        docker_result = _run(docker_cmd, timeout=timeout)
        docker_rc = docker_result.returncode
        if (docker_rc == 0
                and perf_data.exists() and perf_data.stat().st_size > 0
                and flat.exists() and flat.stat().st_size > 0):
            success = True
            break
        last_err = ((docker_result.stdout or "") + "\n" + (docker_result.stderr or ""))[-1500:]
        log_path = artifact_dir / "fuzzer.log"
        if log_path.exists():
            last_err += "\n--- fuzzer.log tail ---\n" + log_path.read_text(
                errors="replace"
            )[-1000:]
        _remove_profile_outputs(artifact_dir)

    if not success:
        raise RuntimeError(
            f"perf replay-profile failed after 2 attempts "
            f"(last docker rc={docker_rc}); output:\n{last_err}"
        )

    # Shares of samples in the target's own DSO, recorded as INFORMATION only
    # (dso.txt has no percent floor but can be missing; the flat.txt sum is
    # floored at 0.5%). Whether perf sampled the target at all is decided by the
    # harness from hotspots.json's absolute target-source sample count.
    dso_share = target_dso_share(dso, args.fuzz_target)
    flat_share = flat_target_share(flat, args.fuzz_target)

    metadata = {
        "mode": "replay",
        "min_sample_seconds": args.min_sample_seconds,
        "seed": args.seed,
        "cpu": args.cpu,
        "corpus_dir": str(corpus_dir),
        "corpus_file_count": corpus_count,
        "docker_exit_code": docker_rc,
        "target_dso_share_pct": dso_share,
        "flat_target_share_pct": round(flat_share, 2),
        "profiler_image": PROFILER_IMAGE,
        "target_libs": (None if libs is None else
                        {k: libs[k] for k in ("libs", "append_out", "ld_library_path",
                                              "skipped_out_libs", "cached")}),
    }

    # The ranked target-source hotspot table: the optimizer's primary input, so
    # a failure here fails the profile (loudly) instead of handing the agent a
    # profile without it.
    hot_err = None
    try:
        hot = build_hotspots(
            artifact_dir=artifact_dir, out_dir=args.out_dir,
            fuzz_target=args.fuzz_target,
            source_root=getattr(args, "source_root", None),
            harness=getattr(args, "harness", None) or [],
            source_tree=getattr(args, "source_tree", None),
        )
        metadata["hotspots"] = hot
    except Exception as e:  # noqa: BLE001 - any failure is a failed profile, loudly
        hot_err = (str(e) if isinstance(e, hotspot_table.HotspotError)
                   else f"{type(e).__name__}: {e}")
        metadata["hotspots_error"] = hot_err
        for stale in (artifact_dir / hotspot_table.HOTSPOTS_JSON,
                      artifact_dir / hotspot_table.HOTSPOTS_TXT):
            try:
                stale.unlink()
            except FileNotFoundError:
                pass
    (artifact_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True)
    )
    if hot_err is not None:
        print(f"HOTSPOT TABLE FAILED: {hot_err}", file=sys.stderr)
        raise RuntimeError(f"hotspot table (hotspots.json) could not be built: "
                           f"{hot_err}")
    h = metadata["hotspots"]
    print(f"hotspots: {h['target_source_samples']} of {h['total_samples']} samples "
          f"attributed to {h['target_source_functions']} target-source functions; "
          f"added {h['seconds_total']:.1f}s (perf script {h['perf_script_seconds']}s "
          f"in-container, host {h['host_seconds']:.1f}s)", file=sys.stderr)
    return 0


def _remove_profile_outputs(artifact_dir: Path) -> None:
    for name in PROFILE_OUTPUTS:
        try:
            (Path(artifact_dir) / name).unlink()
        except FileNotFoundError:
            pass


def read_perf_script_status(path: Path) -> dict:
    """perf_script.status -> dict. Raises HotspotError on any sign that the
    container's dumps are missing, failed, or cannot be trusted."""
    HE = hotspot_table.HotspotError
    try:
        text = Path(path).read_text(errors="replace")
    except OSError as e:
        raise HE(f"{path} missing: the perf script step never ran ({e})") from e
    st = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    if st.get("dsoff") != "yes":
        raise HE(f"the profiler image's perf ({st.get('perf', '?')}) does not "
                 "support `perf script -F dsoff`, which the hotspot table needs; "
                 "use a kernel-matched perf >= 6.x (FUZZ_SOURCE_FOLDS_PROFILER_IMAGE)")
    for key in ("cg_rc", "ip_rc"):
        if st.get(key, "").split() != ["0", "0"]:
            raise HE(f"perf script | gzip failed ({key}={st.get(key)!r}: exit codes "
                     "of perf script and gzip); see fuzzer.log")
    try:
        st["report_samples"] = int(st.get("report_samples", ""))
    except ValueError:
        raise HE("perf report --stats gave no sample count to cross-check the "
                 "perf script dump against") from None
    try:
        st["ms"] = int(st.get("ms", ""))
    except ValueError:
        st["ms"] = None
    return st


def build_hotspots(*, artifact_dir: Path, out_dir, fuzz_target: str,
                   source_root: str | None, harness, source_tree=None) -> dict:
    """hotspots.txt/json from the container's perf script dumps.

    Returns a summary for metadata.json; raises hotspot_table.HotspotError. The
    dumps are deleted on success (perf.data stays, so they can be regenerated)
    and kept on failure for debugging.
    """
    artifact_dir = Path(artifact_dir)
    script = artifact_dir / PERF_SCRIPT_NAME
    ip_script = artifact_dir / PERF_SCRIPT_IP_NAME
    st = read_perf_script_status(artifact_dir / PERF_SCRIPT_STATUS)
    perf_script_s = round(st["ms"] / 1000.0, 2) if st.get("ms") is not None else None
    timings: dict = {}
    t0 = time.monotonic()
    res = hotspot_table.build_hotspot_table(
        perf_script=script, ip_script=ip_script,
        binary=Path(out_dir) / fuzz_target, host_out_dir=out_dir,
        fuzz_target=fuzz_target, out_dir=artifact_dir,
        source_root=source_root, harness_paths=harness, source_tree=source_tree,
        expected_samples=st["report_samples"], timings=timings)
    host_s = time.monotonic() - t0
    for stale in (script, ip_script, artifact_dir / PERF_SCRIPT_STATUS):
        try:
            stale.unlink()
        except FileNotFoundError:
            pass
    tot = res["totals"]
    return {
        "total_samples": tot["samples"],
        "target_source_samples": tot["target_attributed"]["samples"],
        "target_source_pct": tot["target_attributed"]["pct"],
        "outside_target_samples": tot["outside_target"]["samples"],
        "target_source_functions": res["target_source_functions"],
        "source_root": res["source_root"],
        "editable_tree_known": res["editable_tree_known"],
        "build_dsos": res["build_dsos"],
        "harness_files": res["harness_files"],
        "perf_script_seconds": perf_script_s,
        "host_seconds": round(host_s, 2),
        "seconds_total": round(host_s + (perf_script_s or 0.0), 2),
        "host_timings": timings,
    }


def target_dso_share(dso_path, fuzz_target: str) -> float | None:
    """Percent of perf samples attributed to the target binary's own DSO.

    Reads the ``--sort dso --percent-limit 0`` report, whose rows are
    ``<pct>%  <dso>``. Returns None when the report is missing or unparseable.
    A low share means the hotspot list describes something other than the
    target -- a symbolizer subprocess, the loader, or the kernel.
    """
    try:
        text = Path(dso_path).read_text(errors="replace")
    except OSError:
        return None
    total = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("%", 1)
        if len(parts) != 2:
            continue
        try:
            pct = float(parts[0].strip())
        except ValueError:
            continue
        if fuzz_target in parts[1]:
            total = (total or 0.0) + pct
    return total


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Profile a fuzz target with perf while it replays a fixed corpus."
    )
    parser.add_argument("--out-dir", required=True,
                        help="/out dir of the binary to profile (the baseline)")
    parser.add_argument("--corpus-dir", required=True,
                        help="the FIXED corpus snapshot to replay and profile; "
                             "mounted read-only")
    parser.add_argument("--artifact-dir", required=True,
                        help="where perf.data/flat.txt/callgraph.txt/metadata.json go")
    parser.add_argument("--fuzz-target", required=True)
    parser.add_argument("--min-sample-seconds", type=int, default=60,
                        help="keep replaying the corpus in a loop until at least "
                             "this many wall-clock seconds of perf samples are "
                             "collected (guards against tiny/fast corpora)")
    parser.add_argument("--loop-timeout", type=int, default=1800,
                        help="hard cap on the perf session wall-clock")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--cpu", type=int, default=3)
    parser.add_argument("--memory", default="4g")
    parser.add_argument("--shm-size", default="2g")
    parser.add_argument("--source-root", default=None,
                        help="in-image project source root (e.g. /src/<project>) "
                             "for hotspots.txt; inferred from the harness's debug "
                             "info when omitted")
    parser.add_argument("--source-tree", default=None,
                        help="host path of the editable project tree; maps debug "
                             "paths of copies built elsewhere and sets each "
                             "row's editable flag")
    parser.add_argument("--harness", action="append", default=[],
                        help="in-image harness source path(s), excluded from "
                             "hotspots.txt (the LLVMFuzzerTestOneInput file is "
                             "always excluded)")
    return parser.parse_args()


def main() -> int:
    return run_replay_profile(parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
