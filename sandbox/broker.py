"""Host-side broker: the ONLY channel from the sandboxed optimizer to docker.

The agent container has no docker socket and no host filesystem. When it needs a
build, a smoke run, or a replay timing, it writes one JSON object to a unix
socket and gets one JSON object back. The broker performs the docker work against
the pinned prework image and returns the result.

Two invariants make this a boundary rather than a suggestion:

  1. The request surface is a CLOSED ENUM. There is no field anywhere that
     reaches a shell, a path, or an image name. The agent chooses WHICH of three
     operations runs, never HOW it runs -- everything else comes from
     BrokerContext, which the orchestrator sets.

  2. Build and smoke logs reach the agent as they are, sanitizer reports
     included, cut only to their tail (LOG_TAIL_CHARS) so a multi-megabyte
     compile log cannot flood its context. Showing the agent a bug is fine: a
     smoke crash comes from inputs that did NOT crash the round-start binary
     (the orchestrator removes those first), so it is the agent's own edit. The
     full output is kept host-side in an audit log.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import socket
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config
from lib import cpu_ledger
from lib.core_lock import core_lock
from prework.prework_build import restore_ownership

logger = logging.getLogger(__name__)

# An agent asking for a huge repeat count must not be able to wedge the host.
MAX_REPLAY_REPEATS = 5
DEFAULT_REPLAY_REPEATS = 3
BUILD_TIMEOUT_SECS = 5400
REPLAY_TIMEOUT_SECS = 3600
# Tail of a build/smoke log returned to the agent. Errors sit at the end of a
# build log; the head is configure noise.
LOG_TAIL_CHARS = 40000
# Crashing inputs re-run for a full sanitizer report, per smoke or gate check.
MAX_CRASH_REPORTS = 3


@dataclass
class BrokerContext:
    """Everything the agent is NOT allowed to choose."""
    image: str
    source_dir: str
    out_dir: str
    corpus_dir: str
    fuzz_target: str
    project: str
    cpu: int
    audit_log: str = ""
    # Drift-corrected ("bracketed") replay timing. When ``baseline_ref_dir`` is set
    # the broker snapshots the FIRST successfully built /out there -- the round's
    # pristine "beat-this" binary -- and every later replay interleaves that
    # reference with the candidate, reporting the candidate's time normalised to the
    # reference's time at the first measurement. That cancels machine drift (turbo /
    # memory-bandwidth / thermal from neighbour cores) that a stale once-per-round
    # anchor cannot. Empty -> disabled, falls back to a plain single-binary replay.
    baseline_ref_dir: str = ""
    # Online rounds: the sample of the round's crash-filtered mutations that
    # `smoke` runs the candidate on. Empty -> the legacy empty-input smoke.
    smoke_corpus_dir: str = ""
    # Runtime state (not agent-chosen): set true once the reference is captured, and
    # the reference's own replay time at that first measurement (the normalisation
    # anchor). One BrokerContext per session, so these persist across requests.
    ref_ready: bool = field(default=False, repr=False)
    ref_anchor_s: float = field(default=0.0, repr=False)


def _audit(ctx: BrokerContext, op: str, blob: str) -> None:
    """Record the full output host-side; the agent gets only its tail."""
    if not ctx.audit_log:
        return
    try:
        with open(ctx.audit_log, "a") as f:
            f.write(f"\n===== {op} @ {time.time():.0f} =====\n{blob}\n")
    except OSError as e:
        logger.warning("audit log write failed: %s", e)


def _run(cmd: list[str], timeout: int) -> tuple[int, str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def _build_command(ctx: BrokerContext) -> list[str]:
    """OSS-Fuzz `compile` with the agent's current source bind-mounted over $SRC."""
    return [
        "docker", "run", "--rm", "--privileged",
        "--cpuset-cpus", str(ctx.cpu),
        # No core dumps: these containers run the target too, and a
        # smoke/replay that crashes would otherwise dump its image
        # synchronously. See phase3_runner for the full reasoning.
        "--ulimit", "core=0",
        "-e", "FUZZING_ENGINE=afl",
        # FuzzBench build.sh scripts read $FUZZER_LIB (OSS-Fuzz exposes it as
        # $LIB_FUZZING_ENGINE = /usr/lib/libFuzzingEngine.a for afl). Harmless for
        # ARVO targets, which don't reference it.
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
        "-v", f"{Path(__file__).resolve().parent.parent / 'prework' / 'aflpp_fold_denylist.txt'}"
              f":/src/aflpp_fold_denylist.txt:ro",
        "-v", f"{Path(ctx.source_dir).absolute()}:/src/{ctx.project}",
        "-v", f"{Path(ctx.out_dir).absolute()}:/out",
        ctx.image, "compile",
    ]


def _replay_command(ctx: BrokerContext, out_dir: str | None = None) -> list[str]:
    """Deterministic corpus replay via afl-showmap.

    afl-showmap -i replays every file in a directory exactly once through the
    forkserver -- the AFL analogue of libFuzzer's -runs=0, and the measurement
    the replay-speedup gate is built on. Pinned to one CPU so timings are stable.
    ``out_dir`` selects which built /out to replay (default: the candidate); the
    bracketed path passes the reference binary's dir here too.
    """
    out_dir = out_dir or ctx.out_dir
    return [
        "docker", "run", "--rm", "--privileged",
        "--cpuset-cpus", str(ctx.cpu),
        # No core dumps: these containers run the target too, and a
        # smoke/replay that crashes would otherwise dump its image
        # synchronously. See phase3_runner for the full reasoning.
        "--ulimit", "core=0",
        "-v", f"{Path(out_dir).absolute()}:/out:ro",
        "-v", f"{Path(ctx.corpus_dir).absolute()}:/corpus:ro",
        "--entrypoint", "/bin/bash", ctx.image, "-lc",
        "export AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 "
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 "
        # symbolize=0: a sanitizer finding otherwise spawns llvm-symbolizer to
        # turn addresses into file:line by parsing the binary's DWARF. Measured
        # at 42-52% of a replay pass on assimp and PcapPlusPlus -- work no source
        # fold can reduce, which dilutes every speedup ratio and adds variance
        # (its cost scales with how many reports fire). Execution is unchanged:
        # same code runs, same bugs detected, reports just carry raw addresses.
        # Must stay identical to the profiler's env (replay_fuzzer_profile.py) or
        # the hotspot ranking and this gate describe different workloads.
        "ASAN_OPTIONS=detect_leaks=0:symbolize=0 "
        "UBSAN_OPTIONS=symbolize=0 MSAN_OPTIONS=symbolize=0; "
        # -C (collect-coverage) is REQUIRED with -i <dir>. Without it afl-showmap
        # treats -o as a DIRECTORY to write one bitmap per input into, so
        # `-o /dev/null` aborts instantly with
        #   SYSTEM ERROR : cannot create output directory /dev/null (File exists)
        # and the call still returns a plausible-looking wall-clock. Every fold
        # was then accepted or rejected on ~0.5s of start-up failure rather than
        # on execution time. With -C the whole corpus is replayed and -o is a
        # single file, so /dev/null is valid and no per-input I/O pollutes the
        # timing.
        f"/out/afl-showmap -C -i /corpus -o /dev/null -t 5000+ -m none -- "
        f"/out/{ctx.fuzz_target}",
    ]


def _run_build(ctx: BrokerContext) -> tuple[bool, str]:
    # Serialize against any replay/smoke on this optimizer's core (incl. the
    # harness-side rebuild in another process): never measure a core mid-build.
    with core_lock(ctx.cpu):
        rc, blob = _run(_build_command(ctx), BUILD_TIMEOUT_SECS)
    _audit(ctx, "build", blob)
    # `compile` runs as root through a bind mount, so it leaves root-owned objects
    # in the tree the AGENT (uid 1000) is editing and the orchestrator later has to
    # `git clean` when a round is rejected. Restored on failure too: a build that
    # died halfway leaves exactly the artifacts that have to be cleanable.
    restore_ownership(ctx.image, [ctx.source_dir, ctx.out_dir])
    if rc == 0:
        _capture_reference(ctx)
    return rc == 0, blob


def _capture_reference(ctx: BrokerContext) -> None:
    """Snapshot the FIRST successfully built /out as the bracketing reference.

    The skill builds the pristine round-start tree before applying any fold (to
    anchor the baseline), so the first successful build is that "beat-this" binary.
    Copied aside once because the next build overwrites /out with a candidate.
    Best-effort: on any failure bracketing simply stays off and the replay falls
    back to a plain single-binary measurement.
    """
    if not ctx.baseline_ref_dir or ctx.ref_ready:
        return
    try:
        if os.path.exists(ctx.baseline_ref_dir):
            shutil.rmtree(ctx.baseline_ref_dir, ignore_errors=True)
        shutil.copytree(ctx.out_dir, ctx.baseline_ref_dir, symlinks=True)
        ctx.ref_ready = True
        logger.info("captured bracketing reference binary into %s", ctx.baseline_ref_dir)
    except OSError as e:
        logger.warning("could not capture bracketing reference (%s); replay timing "
                       "will be un-bracketed", e)


def _crash_scan_command(ctx: BrokerContext, out_dir: str, corpus_dir: str) -> list[str]:
    """Run every input in ``corpus_dir`` once through the forkserver and name the
    ones that crash.

    afl-showmap's cmin mode (-Z) writes one map file per input; with
    AFL_CMIN_CRASHES_ONLY=1 the file is EMPTY unless that input crashed, so the
    non-empty files name the crashers (same behaviour in AFL++ 4.03a and 5.02c).
    Timeouts also get an empty file, so a hang is not reported as a crash. The
    file count proves the scan really ran over the whole set -- the old
    libFuzzer-style crash filter exited 0 without executing anything and nobody
    could tell. Same per-input timeout and sanitizer env as the replay gate.
    """
    return [
        "docker", "run", "--rm", "--privileged",
        "--cpuset-cpus", str(ctx.cpu),
        "--memory", str(config.MEMORY_LIMIT), "--memory-swap", str(config.MEMORY_LIMIT),
        "--ulimit", "core=0",
        "--tmpfs", "/maps",
        "-v", f"{Path(out_dir).absolute()}:/out:ro",
        "-v", f"{Path(corpus_dir).absolute()}:/corpus:ro",
        "--entrypoint", "/bin/bash", ctx.image, "-lc",
        "export AFL_NO_AFFINITY=1 AFL_SKIP_CPUFREQ=1 "
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_CMIN_CRASHES_ONLY=1 "
        f"ASAN_OPTIONS={config.REPLAY_ASAN_OPTIONS} "
        f"UBSAN_OPTIONS={config.REPLAY_UBSAN_OPTIONS} MSAN_OPTIONS=symbolize=0; "
        f"/out/afl-showmap -q -Z -i /corpus -o /maps -t 5000+ -m none -- "
        f"/out/{ctx.fuzz_target} >/dev/null 2>/tmp/showmap.err; rc=$?; "
        "tail -c 2000 /tmp/showmap.err; "
        "find /maps -type f -size +0c -printf 'CRASHER %f\\n'; "
        "echo \"SCANNED $(find /maps -type f | wc -l)\"; echo \"SCAN_RC=$rc\"",
    ]


def _crash_report_command(ctx: BrokerContext, out_dir: str, corpus_dir: str,
                          names: list[str]) -> list[str]:
    """Re-run each crashing input directly for a SYMBOLIZED sanitizer report,
    plus a hexdump of its first 256 bytes, so the agent can see what broke."""
    asan = config.REPLAY_ASAN_OPTIONS.replace("symbolize=0", "symbolize=1")
    ubsan = (config.REPLAY_UBSAN_OPTIONS.replace("symbolize=0", "symbolize=1")
             .replace("print_stacktrace=0", "print_stacktrace=1"))
    steps = []
    for n in names:
        q = shlex.quote(f"/corpus/{n}")
        steps.append(
            f"echo '===== crashing input {n}' \"($(stat -c %s {q}) bytes)\"; "
            f"od -A x -t x1z -v -N 256 {q}; "
            f"timeout 60 /out/{ctx.fuzz_target} {q} 2>&1 | tail -n 120; "
            "echo \"exit=${PIPESTATUS[0]}\"")
    return [
        "docker", "run", "--rm", "--privileged",
        "--cpuset-cpus", str(ctx.cpu),
        "--memory", str(config.MEMORY_LIMIT), "--memory-swap", str(config.MEMORY_LIMIT),
        "--ulimit", "core=0",
        "-v", f"{Path(out_dir).absolute()}:/out:ro",
        "-v", f"{Path(corpus_dir).absolute()}:/corpus:ro",
        "--entrypoint", "/bin/bash", ctx.image, "-lc",
        f"export ASAN_OPTIONS={asan} UBSAN_OPTIONS={ubsan}; "
        "[ -x /out/llvm-symbolizer ] && export ASAN_SYMBOLIZER_PATH=/out/llvm-symbolizer; "
        + "; ".join(steps),
    ]


def scan_for_crashers(ctx: BrokerContext, out_dir: str, corpus_dir: str) -> dict:
    """Run ``corpus_dir`` through the binary in ``out_dir``; name what crashes.

    Returns ``ok`` (the scan provably covered every input), ``crashers`` (sorted
    input names), ``scanned``, ``expected``, ``seconds`` and the raw ``log``.
    afl-showmap skips zero-byte files, so they are not expected.
    """
    expected = sum(1 for p in Path(corpus_dir).iterdir()
                   if p.is_file() and p.stat().st_size > 0)
    t0 = time.monotonic()
    rc, blob = _run(_crash_scan_command(ctx, out_dir, corpus_dir), REPLAY_TIMEOUT_SECS)
    seconds = time.monotonic() - t0
    crashers, scanned = [], -1
    for line in blob.splitlines():
        if line.startswith("CRASHER "):
            crashers.append(line[len("CRASHER "):].strip())
        elif line.startswith("SCANNED "):
            try:
                scanned = int(line.split()[1])
            except (IndexError, ValueError):
                pass
    return {"ok": rc == 0 and scanned == expected, "crashers": sorted(crashers),
            "scanned": scanned, "expected": expected, "seconds": seconds,
            "log": blob}


def crash_report(ctx: BrokerContext, out_dir: str, corpus_dir: str,
                 names: list[str]) -> str:
    """Symbolized sanitizer reports for up to MAX_CRASH_REPORTS ``names``."""
    names = [n for n in names if _SAFE_NAME_RE.match(n)][:MAX_CRASH_REPORTS]
    if not names:
        return ""
    _, blob = _run(_crash_report_command(ctx, out_dir, corpus_dir, names),
                   60 * len(names) + 120)
    return blob


_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.,:+=-]+$")


def _smoke_on_sample(ctx: BrokerContext) -> tuple[bool, str]:
    """Run the candidate on the round's smoke sample; fail with the sanitizer
    report of the first crashers. The sample was filtered against the
    round-start binary, so any crash here comes from this round's edits."""
    with core_lock(ctx.cpu):
        scan = scan_for_crashers(ctx, ctx.out_dir, ctx.smoke_corpus_dir)
        report = (crash_report(ctx, ctx.out_dir, ctx.smoke_corpus_dir, scan["crashers"])
                  if scan["crashers"] else "")
    _audit(ctx, "smoke", scan["log"] + ("\n" + report if report else ""))
    if scan["crashers"]:
        n = len(scan["crashers"])
        head = (f"SMOKE FAILED: {n} of {scan['expected']} fuzzer inputs crash this "
                f"build. None of them crash the round-start binary, so this round's "
                f"edits caused it. Crashing inputs: {', '.join(scan['crashers'][:20])}"
                f"{' ...' if n > 20 else ''}\n"
                f"Sanitizer reports for the first {min(n, MAX_CRASH_REPORTS)}:\n")
        return False, head + report
    if not scan["ok"]:
        return False, (f"SMOKE FAILED: the target did not run the whole sample "
                       f"({scan['scanned']} of {scan['expected']} inputs; exit "
                       f"status in the log below).\n" + scan["log"])
    return True, (f"smoke ok: {scan['expected']} fuzzer inputs ran on this build, "
                  f"none crashed ({scan['seconds']:.1f}s)")


def _run_smoke(ctx: BrokerContext) -> tuple[bool, str]:
    """Run the built target briefly to confirm it is not dead on arrival.

    Online rounds run it on a sample of real fuzzer inputs (_smoke_on_sample).
    Without one, this legacy smoke runs a single EMPTY input -- which the AFL
    driver skips before calling LLVMFuzzerTestOneInput, so it only proves the
    binary loads.
    """
    if ctx.smoke_corpus_dir and any(
            p.is_file() for p in Path(ctx.smoke_corpus_dir).iterdir()):
        return _smoke_on_sample(ctx)
    cmd = [
        "docker", "run", "--rm", "--privileged",
        "--cpuset-cpus", str(ctx.cpu),
        # No core dumps: these containers run the target too, and a
        # smoke/replay that crashes would otherwise dump its image
        # synchronously. See phase3_runner for the full reasoning.
        "--ulimit", "core=0",
        "-v", f"{Path(ctx.out_dir).absolute()}:/out:ro",
        "--entrypoint", "/bin/bash", ctx.image, "-lc",
        f"export ASAN_OPTIONS=detect_leaks=0; printf '' > /tmp/e; "
        f"timeout 120 /out/{ctx.fuzz_target} /tmp/e",
    ]
    with core_lock(ctx.cpu):
        rc, blob = _run(cmd, 300)
    _audit(ctx, "smoke", blob)
    return rc == 0, blob


def _timed_replay(ctx: BrokerContext, out_dir: str) -> float | None:
    """One replay pass over the fixed corpus; wall seconds, or None if it did not
    actually execute the corpus (afl-showmap prints no coverage line -- the run
    failed before the forkserver and the elapsed time is pure start-up cost,
    indistinguishable from a very fast binary, so it must never be timed)."""
    t0 = time.monotonic()
    rc, blob = _run(_replay_command(ctx, out_dir), REPLAY_TIMEOUT_SECS)
    elapsed = time.monotonic() - t0
    _audit(ctx, "replay", f"dir={out_dir} rc={rc} elapsed={elapsed:.3f}\n{blob[-2000:]}")
    if rc == 124:
        return None
    if "coverage of" not in blob and "Captured" not in blob:
        logger.error("replay produced no coverage report; refusing to time it: %s",
                     blob[-300:])
        return None
    return elapsed


def _run_replay(ctx: BrokerContext, repeats: int) -> dict | None:
    """Median replay time of the candidate /out, in seconds (or None on failure).

    Plain mode (no reference captured): median of ``repeats`` passes over the
    candidate, compared later against a separately-anchored baseline.

    Bracketed mode (reference captured on the first build): each of ``repeats``
    pairs times the reference binary and the candidate back-to-back, so machine
    drift (turbo / memory-bandwidth / thermal from neighbour cores) hits both
    equally. The reported ``seconds`` is the candidate normalised to the
    reference's time at the first measurement (``ref_anchor_s``) -- i.e. the
    candidate expressed in the anchor's conditions -- which is directly comparable
    across cycles without a stale once-per-round baseline.

    The whole measurement holds the core lock so no build (this process or the
    harness rebuild) can slip between passes and skew it.
    """
    bracketed = bool(ctx.baseline_ref_dir) and ctx.ref_ready
    ref_times: list[float] = []
    cand_times: list[float] = []
    with core_lock(ctx.cpu):
        if not bracketed:
            for _ in range(repeats):
                e = _timed_replay(ctx, ctx.out_dir)
                if e is None:
                    return None
                cand_times.append(e)
        else:
            for _ in range(repeats):
                e_ref = _timed_replay(ctx, ctx.baseline_ref_dir)
                if e_ref is None:
                    return None
                e_cand = _timed_replay(ctx, ctx.out_dir)
                if e_cand is None:
                    return None
                ref_times.append(e_ref)
                cand_times.append(e_cand)
    if not cand_times:
        return None
    if not bracketed:
        return {"seconds": statistics.median(cand_times), "bracketed": False}
    ref_now = statistics.median(ref_times)
    # Anchor on the first bracketed call -- a real measured pass, not a guess.
    if ctx.ref_anchor_s <= 0.0:
        ctx.ref_anchor_s = ref_now
    anchor = ctx.ref_anchor_s
    # Per-pair normalisation cancels within-pair drift, then median across pairs.
    corrected = [c * (anchor / r) if r > 0 else c
                 for r, c in zip(ref_times, cand_times)]
    out = {
        "seconds": statistics.median(corrected),
        "raw_seconds": statistics.median(cand_times),
        "reference_seconds": ref_now,
        "reference_anchor_seconds": anchor,
        "bracketed": True,
    }
    _audit(ctx, "replay-bracket",
           f"corrected={out['seconds']:.3f} raw={out['raw_seconds']:.3f} "
           f"ref_now={ref_now:.3f} ref_anchor={anchor:.3f} "
           f"drift={anchor / ref_now if ref_now else 1.0:.3f}x")
    return out


def _tail(blob: str) -> str:
    """The last LOG_TAIL_CHARS of a log, marked when anything was cut."""
    if len(blob) <= LOG_TAIL_CHARS:
        return blob
    return (f"[... {len(blob) - LOG_TAIL_CHARS} earlier characters omitted ...]\n"
            + blob[-LOG_TAIL_CHARS:])


def handle_request(req, ctx: BrokerContext) -> dict:
    """Dispatch one request. Never raises -- a broker crash would kill the round.

    Every op here is real CPU work the optimizer causes, so each is timed into
    the CPU ledger. This is the ONLY place agent-requested compute can happen --
    the request surface is a closed enum -- which is what makes "everything
    except the model wait" measurable at a single point. All three ops are
    pinned to ctx.cpu, so core-seconds equal wall-seconds.
    """
    if not isinstance(req, dict):
        return {"ok": False, "error": "malformed request"}
    op = req.get("op")
    if not isinstance(op, str) or not op:
        return {"ok": False, "error": "missing or malformed op"}

    if op == "build":
        with cpu_ledger.timed("broker_build", cores=1) as info:
            ok, blob = _run_build(ctx)
            info["ok"] = ok
        return {"ok": ok, "log": _tail(blob)}

    if op == "smoke":
        with cpu_ledger.timed("broker_smoke", cores=1) as info:
            ok, blob = _run_smoke(ctx)
            info["ok"] = ok
        return {"ok": ok, "log": _tail(blob)}

    if op == "replay_time":
        raw = req.get("repeats", DEFAULT_REPLAY_REPEATS)
        if isinstance(raw, bool) or not isinstance(raw, int):
            return {"ok": False, "error": "repeats must be an integer"}
        repeats = max(1, min(raw, MAX_REPLAY_REPEATS))
        with cpu_ledger.timed("broker_replay", cores=1) as info:
            result = _run_replay(ctx, repeats)
            info["repeats"] = repeats
        if result is None:
            return {"ok": False, "error": "replay did not complete"}
        # Agent-facing reply stays a single number; the bracketing detail
        # (raw vs corrected, reference time) is recorded host-side only.
        return {"ok": True, "seconds": result["seconds"], "repeats": repeats}

    return {"ok": False, "error": f"unknown op: {op}"}


def serve(socket_path: str, ctx: BrokerContext) -> None:
    """Serve requests until interrupted. One JSON object per connection."""
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(socket_path)
    os.chmod(socket_path, 0o666)
    srv.listen(4)
    logger.info("broker listening on %s", socket_path)
    try:
        while True:
            conn, _ = srv.accept()
            with conn:
                try:
                    chunks = []
                    while True:
                        b = conn.recv(65536)
                        if not b:
                            break
                        chunks.append(b)
                        if b.endswith(b"\n"):
                            break
                    req = json.loads(b"".join(chunks).decode("utf-8", "replace") or "{}")
                except (ValueError, OSError) as e:
                    conn.sendall(json.dumps(
                        {"ok": False, "error": f"bad request: {e}"}).encode() + b"\n")
                    continue
                try:
                    reply = handle_request(req, ctx)
                    conn.sendall(json.dumps(reply).encode() + b"\n")
                except OSError as e:
                    # The CLIENT went away (BrokenPipeError/ECONNRESET) -- the
                    # agent abandoned a slow build or replay. Without this the
                    # exception escapes the accept loop, `finally` closes the
                    # listener and UNLINKS the socket, and the broker is gone for
                    # the rest of the agent session: every later build/smoke/
                    # replay fails with ENOENT and the round produces nothing.
                    # One disconnected client must not end the service.
                    logger.warning("client disconnected mid-reply: %s", e)
                    continue
    finally:
        srv.close()
        if os.path.exists(socket_path):
            os.unlink(socket_path)
