#!/usr/bin/env python3
"""Exercise real shared-core builds, smoke, perf profiling, and broker/final replay.

Uses disposable AFL++ trials and a CPU-bound stand-in agent, with no model API
calls. Requires an existing prework/profiler image; no experiment data is edited.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.probe_trial_pause import TARGET, docker, wait_for, size, stats
from lib import afl_replay, cpu_ledger, docker_util, online_resources as R
from sandbox import broker
import phase2_setup
import phase3_online
import phase3_runner


def check_agent_owner_death(image, cpu, work):
    name = "fuzz-opt-agent-watchdog-" + uuid.uuid4().hex[:10]
    marker = work / "guard-owner-ack"
    marker.unlink(missing_ok=True)
    child = None
    try:
        docker("run", "-d", "--name", name, "--cpuset-cpus", cpu,
               "--entrypoint", "/bin/sleep", image, "60")
        code = ("import os,time; from pathlib import Path; "
                "from lib.online_resources import freeze_agent; "
                f"os.sched_setaffinity(0,{{{cpu}}});\n"
                f"with freeze_agent({name!r},time.time()+15):\n"
                f" Path({str(marker)!r}).write_text('paused'); time.sleep(60)\n")
        child = subprocess.Popen([sys.executable, "-c", code], cwd=ROOT)
        wait_for(marker.exists)
        assert docker("inspect", "--format", "{{.State.Paused}}", name) == "true"
        child.kill()
        child.wait(timeout=5)
        wait_for(lambda: not docker_util.container_is_running(name), timeout=5)
        return True
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait()
        docker_util.remove_container(name)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", default="bench-aflpp/libxml2-arvo-1972")
    ap.add_argument("--cpu", type=int, default=2)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    work = args.output.resolve()
    work.mkdir(parents=True)
    docker("image", "inspect", args.image)
    for name in ("bin", "seeds", "afl_out", "crashes", "snapshot"):
        (work / name).mkdir()
    # Both trial and replay targets consume CPU, not just sleep. Only the
    # trial mounts /afl_out, so only it writes the progress counters there.
    target = '#include <time.h>\n' + TARGET.replace('/probe/', '/afl_out/').replace(
        'usleep(40000);',
        'struct timespec t; clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&t); '
        'double end=t.tv_sec+t.tv_nsec/1e9+0.04; '
        'do { clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&t); } '
        'while (t.tv_sec+t.tv_nsec/1e9 < end);')
    (work / "target.c").write_text(target)
    (work / "agent.c").write_text('''
#include <stdio.h>
#include <time.h>
int main(void) {
  struct timespec t; double last=0;
  for (;;) {
    clock_gettime(CLOCK_MONOTONIC,&t);
    double now=t.tv_sec+t.tv_nsec/1e9;
    if(now-last>0.05) { FILE*f=fopen("/probe/agent-progress","a");
      if(f) { fputc('x',f); fclose(f); } last=now; }
  }
}
''')
    build = ('AFL_CC=clang-18 /src/aflplusplus/afl-cc -g -O1 -o /probe/bin/probe /probe/target.c && '
             'clang-18 -O2 -o /probe/bin/agent /probe/agent.c && '
             'cp /src/aflplusplus/afl-fuzz /src/aflplusplus/afl-showmap /probe/bin/')
    docker("run", "--rm", "--cpuset-cpus", args.cpu,
           "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{work}:/probe",
           "--entrypoint", "/bin/bash", args.image, "-c", build, timeout=90)
    (work / "seeds/seed").write_bytes(b"abc")
    for i in range(4):
        (work / "snapshot" / f"input_{i}").write_bytes(bytes([65 + i]))
    trial = phase3_runner.Trial(project="pause", cve="shared-probe", variant="optimized",
                               trial_id=0, seed=1337, cpu=args.cpu,
                               entry={"project": "pause", "cve": "shared-probe"})
    trial._docker_image = args.image
    trial._bin_dir = str(work / "bin")
    trial._fuzz_target_name = "probe"
    trial._dirs = {"base": str(work), "corpus": str(work / "seeds"),
                   "afl_out": str(work / "afl_out"), "crashes": str(work / "crashes")}
    trial.capture_mutations = True
    trial.pause_control_dir = str(work / "optimized/online/trials/trial_00/pause_control")
    agent = "fuzz-opt-shared-agent-" + uuid.uuid4().hex[:10]
    report = {"cpu": args.cpu, "image": args.image, "checks": {}}
    old_ledger = cpu_ledger.ledger_path()
    cid = None
    try:
        assert phase3_runner._launch_container(trial, "shared-probe-" + uuid.uuid4().hex[:10], 180)
        cid = trial.container_id
        wait_for(lambda: (work / "afl_out/default/fuzzer_stats").exists())
        control = Path(trial.pause_control_dir)
        (control / "trial.json").write_text(json.dumps({"trial_id": 0, "wall_start": trial.start_time}))
        online = work / "optimized/online"
        (online / "campaign_provenance.json").write_text(json.dumps({"resource_policy": "shared-trial-core"}))
        docker("run", "-d", "--name", agent, "--cpuset-cpus", args.cpu,
               "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{work}:/probe",
               "--entrypoint", "/probe/bin/agent", args.image)
        wait_for(lambda: size(work / "agent-progress") > 2)
        resources = R.TrialResources(trial, deadline=trial.start_time + 180)
        resources.agent_container = agent
        cpu_ledger.set_ledger_path("")
        with R.bind(resources):
            assert os.sched_getaffinity(0) == {args.cpu}
            for container in (cid, agent):
                assert docker("inspect", "--format", "{{.HostConfig.CpusetCpus}}", container) == str(args.cpu)
            with cpu_ledger.timed("rebuild"):
                assert not (control / "ack").exists()
                docker("run", "--rm", "--cpuset-cpus", args.cpu,
                       "--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{work}:/probe",
                       "--entrypoint", "clang-18", args.image, "-O2", "-o", "/probe/rebuilt", "/probe/target.c")
            report["checks"]["build_competes_on_trial_cpu"] = True
            with cpu_ledger.timed("broker_smoke"):
                assert not (control / "ack").exists()
                smoke = afl_replay.find_crashers(out_dir=work / "bin", corpus_dir=work / "snapshot",
                                                fuzz_target="probe", image=args.image, cpu=args.cpu)
                assert smoke["ok"] and not smoke["crashers"], smoke
            report["checks"]["smoke_competes_on_trial_cpu"] = True
            with cpu_ledger.timed("crash_filter"):
                corpus = phase3_online.prepare_round_corpus(
                    mutations_dir=work / "snapshot", out_root=work / "corpus",
                    previous_best_bin=work / "bin", fuzz_target="probe", image=args.image,
                    cpu=args.cpu, seed=7)
                assert corpus is not None
            report["checks"]["split"] = [corpus["tuning_count"], corpus["gate_count"]]
            script = ROOT / "skills/profile-once-fuzz-folds/scripts/replay_fuzzer_profile.py"
            env = {"PHASE2_PROFILE_SOURCE_ROOT": "/probe", "PHASE2_PROFILE_SOURCE_TREE": str(work)}
            proc_env = {**os.environ, "FUZZ_SOURCE_FOLDS_RUNNER_IMAGE": args.image}
            with cpu_ledger.timed("profile_prebuild"):
                assert docker("inspect", "--format", "{{.State.Paused}}", agent) == "true"
                n = size(work / "afl_out/completions")
                a = size(work / "agent-progress")
                profile = phase2_setup.run_baseline_profile(
                    replay_profile=script, out_dir=work / "bin", corpus_dir=corpus["tuning"],
                    profile_dir=work / "profile_once", fuzz_target="probe", min_sample_seconds=2,
                    cpu=args.cpu, env=env, proc_env=proc_env, min_target_samples=1)
                assert profile[0], profile
                assert size(work / "afl_out/completions") == n
                assert size(work / "agent-progress") == a
            report["checks"]["actual_perf_profile_isolated"] = True
            ctx = broker.BrokerContext(image=args.image, source_dir=str(work), out_dir=str(work / "bin"),
                                      corpus_dir=corpus["tuning"], fuzz_target="probe", project="pause",
                                      cpu=args.cpu, resource_policy=resources)
            reply = broker.handle_request({"op": "replay_time", "repeats": 2}, ctx)
            assert reply["ok"], reply
            report["checks"]["broker_internal_replay"] = reply
            with cpu_ledger.timed("replay_gate"):
                assert docker("inspect", "--format", "{{.State.Paused}}", agent) == "true"
                assert (control / "ack").exists()
                replay = phase2_setup.run_replay_speedup(
                    diff_output_dir=work / "source_diff", baseline_bin_dir=work / "bin",
                    optimized_bin_dir=work / "bin", fuzz_target="probe", experiment_dir=work,
                    profile_cpu=args.cpu, image=args.image, corpus_dir=corpus["gate"], cap=False)
                assert replay is not None, "final replay failed"
            report["checks"]["final_heldout_replay"] = replay
            assert not (control / "ack").exists()
            assert docker("inspect", "--format", "{{.State.Paused}}", agent) == "false"
        # Gracefully stop AFL itself so counters are current (PID1 is bash/tee).
        st = work / "afl_out/default/fuzzer_stats"
        docker("exec", cid, "/bin/kill", "-INT", stats(st)["fuzzer_pid"])
        docker("wait", cid)
        report["wall_elapsed"] = time.time() - trial.start_time
        final = stats(st)
        report["fuzzer_stats"] = {k: final[k] for k in ("run_time", "execs_done", "total_tmout", "saved_hangs")}
        assert int(final["total_tmout"]) == 0, final
        assert not (online / "cpu_ledger.jsonl").exists()
        report["checks"]["no_cpu_cost_ledger"] = True
        report["checks"]["agent_owner_death_cleanup"] = check_agent_owner_death(args.image, args.cpu, work)
        events = [json.loads(line) for line in (control / "events.jsonl").read_text().splitlines()]
        report["pause_events"] = events
        assert len([e for e in events if e["event"] == "pause"]) >= 4
        (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    finally:
        cpu_ledger.set_ledger_path(old_ledger)
        resources = getattr(trial, "pause_controller", None)
        if resources:
            resources.cancel("probe cleanup")
        if cid:
            (work / "fuzzer.log").write_text(docker("logs", cid, check=False))
            docker_util.remove_container(cid)
        docker_util.remove_container(agent)


if __name__ == "__main__":
    main()
