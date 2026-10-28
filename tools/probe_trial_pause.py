#!/usr/bin/env python3
"""Live AFL++ pause experiment; uses an existing image, never pulls or builds one.

Runs disposable test containers on one CPU, compiles a small normal/persistent
target and the shipped mutator in that image, and records counter evidence.
No benchmark trial, existing corpus, target source, or production image changes.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
import shutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import docker_util
from lib.trial_pause import PauseError, TrialPause, cancel_container

TARGET = r"""
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#ifdef PERSISTENT
__AFL_FUZZ_INIT();
#endif
static void exercise(const unsigned char *buf, int n) {
  FILE *f = fopen("/probe/inflight", "w");
  if (f) { fprintf(f, "%ld\n", (long)getpid()); fclose(f); }
  usleep(40000);
  unlink("/probe/inflight");
  f = fopen("/probe/completions", "a");
  if (f) { fputc('x', f); fclose(f); }
  if (n > 0 && buf[0] == 'z') write(1, "z", 1);
}
int main(void) {
#ifdef PERSISTENT
  __AFL_INIT();
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
  while (__AFL_LOOP(1000)) exercise(buf, __AFL_FUZZ_TESTCASE_LEN);
#else
  unsigned char buf[4096];
  int n = read(0, buf, sizeof(buf));
  exercise(buf, n);
#endif
  return 0;
}
"""


def docker(*args, check=True, timeout=30):
    p = subprocess.run(["docker", *map(str, args)], text=True, capture_output=True,
                       timeout=timeout, check=check)
    return p.stdout.strip()


def wait_for(predicate, timeout=15):
    end = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= end:
            raise RuntimeError("probe condition timed out")
        time.sleep(0.005)


def size(path):
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def stats(path):
    return {k.strip(): v.strip() for line in path.read_text().splitlines()
            if ":" in line for k, v in [line.split(":", 1)]}


def cpu_work(cpu, seconds):
    # CPU-time duration, pinned to the SAME logical CPU as the trial. The
    # controller remains on the host so it can renew the pause lease.
    code = (f"import os,time; os.sched_setaffinity(0,{{{cpu}}}); "
            f"end=time.process_time()+{seconds!r};\n"
            "while time.process_time()<end: pass\n")
    subprocess.run([sys.executable, "-c", code], check=True, timeout=seconds * 5 + 10)


def run_case(args, mode, persistent):
    label = f"{mode}-{'persistent' if persistent else 'forkserver'}"
    work = args.output / label
    work.mkdir()
    (work / "seeds").mkdir()
    (work / "seeds" / "seed").write_bytes(b"abc")
    (work / "control").mkdir()
    (work / "target.c").write_text(TARGET)
    compile_cmd = (
        "AFL_CC=clang-18 /src/aflplusplus/afl-cc -O1 "
        + ("-DPERSISTENT " if persistent else "")
        + "-o /probe/target /probe/target.c && "
        "clang-18 -O2 -shared -fPIC -o /probe/shim.so /shim.c && "
        "cp /src/aflplusplus/afl-fuzz /probe/afl-fuzz"
    )
    docker("run", "--rm", "--cpuset-cpus", args.cpu, "--user", f"{os.getuid()}:{os.getgid()}",
           "-v", f"{work}:/probe", "-v", f"{ROOT / 'mutation_dump_afl.c'}:/shim.c:ro",
           "--entrypoint", "/bin/bash", args.image, "-c", compile_cmd, timeout=90)
    name = "fuzz-opt-pause-" + uuid.uuid4().hex[:12]
    controller = TrialPause(work / "control", lease_seconds=0.5)
    launch = ["run", "-d", "--name", name, "--cpuset-cpus", str(args.cpu),
              "--user", f"{os.getuid()}:{os.getgid()}", "--ulimit", "core=0",
              "-v", f"{work}:/probe"]
    for value in ("HOME=/tmp", "AFL_NO_AFFINITY=1", "AFL_SKIP_CPUFREQ=1",
                  "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1", "AFL_NO_UI=1",
                  "AFL_AUTORESUME=1", "AFL_NO_WARN_INSTABILITY=1"):
        launch += ["-e", value]
    if mode == "cooperative":
        launch += ["-e", "AFL_CUSTOM_MUTATOR_LIBRARY=/probe/shim.so",
                   "-e", "TRIAL_PAUSE_DIR=/probe/control"]
    launch += ["--entrypoint", "/probe/afl-fuzz", args.image, "-i", "/probe/seeds",
               "-o", "/probe/out", "-m", "none", "-t", "300", "-d", "--", "/probe/target"]
    cid = None
    result = {"mode": mode, "persistent": persistent, "pause_seconds": args.pause_seconds,
              "cycles": args.cycles, "testcase_timeout_ms": 300}
    try:
        cid = docker(*launch)
        controller.started(cid)
        st = work / "out/default/fuzzer_stats"
        wait_for(lambda: st.exists() and size(work / "completions") >= 15)
        for i in range(args.cycles):
            wait_for(lambda: (work / "inflight").exists())
            if mode == "raw":
                docker("pause", cid)
                time.sleep(args.pause_seconds)
                docker("unpause", cid)
            else:
                with controller.paused(timeout=5, max_pause=10):
                    assert not (work / "inflight").exists(), "acknowledged an in-flight testcase"
                    n = size(work / "completions")
                    cpu_work(args.cpu, args.pause_seconds)
                    assert size(work / "completions") == n, "target ran while paused"
                wait_for(lambda: size(work / "completions") > n)
            print(f"{label}: pause {i + 1}/{args.cycles}", flush=True)
        if mode == "cooperative":
            try:
                with controller.paused():
                    n = size(work / "completions")
                    raise ValueError("simulated replay failure")
            except ValueError:
                pass
            wait_for(lambda: size(work / "completions") > n)
            result["exception_resumed"] = True
            result["same_core_cpu_work"] = True

            # Kill the actual owning Python process, not merely a helper thread.
            owner = work / "owner-ack"
            child_code = (
                "import sys,time; from pathlib import Path; "
                "from lib.trial_pause import TrialPause; "
                f"p=TrialPause({str(work / 'control')!r},lease_seconds=0.4); "
                f"p.started({cid!r});\n"
                f"with p.paused():\n Path({str(owner)!r}).write_text('ack'); time.sleep(30)\n"
            )
            child = subprocess.Popen([sys.executable, "-c", child_code], cwd=ROOT)
            try:
                wait_for(owner.exists)
                n = size(work / "completions")
                start = time.monotonic()
                child.kill()
                child.wait(timeout=5)
                wait_for(lambda: size(work / "completions") > n, timeout=2)
                result["owner_death_resume_seconds"] = round(time.monotonic() - start, 3)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()

            try:
                with controller.paused(deadline=time.time() + 0.25):
                    n = size(work / "completions")
                    time.sleep(0.5)
            except PauseError:
                result["deadline_invalidated_measurement"] = True
            else:
                raise AssertionError("expired pause was accepted")
            wait_for(lambda: size(work / "completions") > n)

            # Exercise the production stop-and-overwrite hot-swap helper while
            # paused. Use dummy binary files; never overwrite the probe target.
            import phase3_online
            from types import SimpleNamespace
            oldbin, newbin = work / "live-binary", work / "new-binary"
            oldbin.write_text("old")
            newbin.write_text("new")
            try:
                with controller.paused():
                    phase3_online._stop_one_and_overwrite(
                        SimpleNamespace(container_id=cid), oldbin, newbin, poll_sleep=0.01)
            except PauseError:
                result["swap_invalidated_measurement"] = True
            else:
                raise AssertionError("swap did not invalidate an active measurement")
            assert oldbin.read_text() == "new"
        else:
            docker("kill", "--signal", "SIGINT", cid)
        docker("wait", cid)
        first_stats = stats(st)
        result["stats"] = {k: first_stats.get(k) for k in
                           ("execs_done", "saved_hangs", "total_tmout", "saved_crashes",
                            "run_time", "slowest_exec_ms")}
        if mode == "cooperative":
            assert int(first_stats["total_tmout"]) == 0, result
            assert int(first_stats["saved_crashes"]) == 0, result
            oldcid = cid
            docker_util.remove_container(cid)
            cid = docker(*launch)
            controller.started(cid)
            wait_for(lambda: (work / "inflight").exists())
            with controller.paused():
                cancel_container(oldcid, "late cleanup from old container")
                n = size(work / "completions")
                time.sleep(0.1)
                assert size(work / "completions") == n
            result["replacement_ignores_old_cleanup"] = True
            try:
                with controller.paused():
                    docker_util.stop_container(cid, timeout=2)
            except PauseError:
                result["shutdown_invalidated_measurement"] = True
            else:
                raise AssertionError("shutdown did not invalidate pause")
            docker("wait", cid)
        return result
    finally:
        controller.cancel("probe cleanup")
        if cid:
            (work / "fuzzer.log").write_text(docker("logs", cid, check=False))
            docker_util.remove_container(cid)


def run_real_target(args):
    """Exercise the real trial launcher and its existing libxml2 + CmpLog binary."""
    import phase3_runner
    work = args.output / "libxml2-real"
    work.mkdir()
    for name in ("seeds", "afl_out", "crashes"):
        (work / name).mkdir()
    # Keep the recorded target and CmpLog binaries unchanged, but use the pinned
    # image's AFL++ driver. Old recorded drivers may omit timeout counters.
    shutil.copytree(args.real_bin_dir, work / "bin")
    docker("run", "--rm", "--cpuset-cpus", args.cpu,
           "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{work}:/probe",
           "--entrypoint", "/bin/cp", args.image,
           "/src/aflplusplus/afl-fuzz", "/probe/bin/afl-fuzz")
    (work / "seeds/seed").write_bytes(b"\0\0\0\0<a/>")
    trial = phase3_runner.Trial(
        project="libxml2", cve="pause-probe", variant="optimized", trial_id=0,
        seed=1337, cpu=args.cpu,
        entry={"project": "libxml2", "cve": "pause-probe", "kind": "fuzzbench"})
    trial._docker_image = args.image
    trial._bin_dir = str(work / "bin")
    trial._fuzz_target_name = "xml"
    trial._dirs = {"base": str(work), "corpus": str(work / "seeds"),
                   "afl_out": str(work / "afl_out"), "crashes": str(work / "crashes")}
    trial.capture_mutations = True
    trial.pause_control_dir = str(work / "control")
    result = {"mode": "cooperative-real-libxml2", "cycles": args.cycles,
              "cmplog": (args.real_bin_dir / "cmplog/xml").is_file()}
    cid = None
    try:
        assert phase3_runner._launch_container(trial, "pause-probe-" + uuid.uuid4().hex[:10], 90)
        cid = trial.container_id
        st = work / "afl_out/default/fuzzer_stats"
        wait_for(st.exists, timeout=30)
        controller = trial.pause_controller
        for _ in range(args.cycles):
            with controller.paused(timeout=10, max_pause=10):
                cpu_work(args.cpu, max(1.2, args.pause_seconds))
        result["same_container_after_pauses"] = trial.container_id == cid
        result["process_states_while_paused"] = None
        with controller.paused():
            result["process_states_while_paused"] = docker("top", cid, "-eo", "pid,stat,comm")
        # The benchmark launcher has a bash/tee PID1. Signal AFL itself so its
        # final counters are flushed, instead of inspecting stale periodic stats
        # after Docker eventually kills the shell's children.
        docker("exec", cid, "/bin/kill", "-INT", stats(st)["fuzzer_pid"])
        docker("wait", cid)
        result["stats"] = {k: v for k, v in stats(st).items() if k in
                           ("execs_done", "total_tmout", "saved_crashes", "saved_hangs", "stability",
                            "afl_version", "target_mode", "command_line")}
        if result["cmplog"]:
            assert "-c /out/cmplog/xml" in result["stats"]["command_line"]
        assert int(result["stats"]["total_tmout"]) == 0, result
        assert int(result["stats"]["execs_done"]) > 0, result
        print("real libxml2: pause cycles passed", flush=True)
        return result
    finally:
        if cid:
            (work / "fuzzer.log").write_text(docker("logs", cid, check=False))
            docker_util.remove_container(cid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="bench-aflpp/libxml2-arvo-1972")
    parser.add_argument("--cpu", type=int, default=2)
    parser.add_argument("--cycles", type=int, default=5)
    parser.add_argument("--pause-seconds", type=float, default=0.8)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--real-bin-dir", type=Path,
                        help="Optional existing libxml2 bin directory with xml, afl-fuzz and cmplog/xml")
    args = parser.parse_args()
    if args.cycles < 1 or args.pause_seconds <= 0.3:
        parser.error("use positive cycles and a pause longer than the 300ms testcase timeout")
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    docker("image", "inspect", args.image)  # Fail rather than pull an image.
    results = []
    for persistent in (False, True):
        for mode in ("raw", "cooperative"):
            results.append(run_case(args, mode, persistent))
            (args.output / "results.json").write_text(json.dumps({
                "image": args.image, "image_id": docker("image", "inspect", "--format", "{{.Id}}", args.image),
                "cpu": args.cpu, "results": results}, indent=2) + "\n")
    if args.real_bin_dir:
        results.append(run_real_target(args))
        (args.output / "results.json").write_text(json.dumps({
            "image": args.image, "image_id": docker("image", "inspect", "--format", "{{.Id}}", args.image),
            "cpu": args.cpu, "results": results}, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
