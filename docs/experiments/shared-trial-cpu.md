# Online optimization with a shared trial CPU

On `experiment/aflpp-pause-resume`, `ONLINE_SHARED_TRIAL_CPU=1` is the default.
Each optimized trial, its optimizer worker, its agent container, and its local
build/profile/smoke/replay work use the **same logical CPU**. Baseline trials
retain their own CPUs. Startup rejects layouts that put two trials on the same
physical core or hyperthread siblings. No separate optimizer/agent pool is needed.

## Execution policy

| Work | Placement | Fuzzer and agent during work |
|---|---|---|
| Source analysis, compilation, smoke, PoC and final crash checks | Owning trial CPU | Compete for CPU normally |
| Profile preparation and baseline profiling | Owning trial CPU | Paused |
| Corpus crash-filter/rate calibration | Owning trial CPU | Paused |
| Internal replay, including all reference/candidate passes | Owning trial CPU | Paused |
| Final held-out baseline/candidate replay | Owning trial CPU | Paused |
| Remote model wait | Local agent remains on trial CPU | Fuzzer continues |

Host optimizer and broker threads are pinned too, so their subprocesses inherit
the same affinity. Docker workloads receive the explicit one-CPU cpuset. The
agent's own local commands therefore cannot use the former spare agent cores.
The sandbox checks that the agent and broker match their owning trial CPU.

Fuzzers use the cooperative testcase-boundary pause from the original
[pause experiment](aflpp-pause-resume.md). The agent container uses Docker's
freezer while the host broker measures. A separate guard removes a suspended
agent if its controller dies or its deadline expires. Normal completion thaws
it; exceptions also release the fuzzer pause. Lost leases, container replacement,
or deadline expiry invalidate the measurement. CLI Bash-tool bounds are set to
the configured `PHASE2_AGENT_BASH_TIMEOUT_MS` so long replay operations can finish.

Per-trial workers retain their own wall-clock deadlines. The existing source
scope, crash checks, replay acceptance thresholds, and 75/25 tuning/held-out
partition remain in force. Campaign setup still happens before trials start.

## CPU accounting

CPU-cost timers and CPU-ledger writes are bypassed in shared-core rounds. The
existing stage contexts route isolation policy but do not read the accounting
clock or record operation durations. Timings required for replay comparisons,
corpus sizing, and safety deadlines remain.

The result is coverage against actual wall time under a one-core allocation.
Compiler/agent work reduces fuzzing capacity directly; no estimated CPU charge
is subtracted later. `campaign_provenance.json` records
`resource_policy: shared-trial-core`, `cpu_cost_adjustment: false`, and each
trial's CPU mapping. Plotting ignores even stale cost files for these runs.

`ONLINE_SHARED_TRIAL_CPU=0` retains the legacy dedicated-core and charging path
for comparisons. Shared mode requires the sandbox, per-trial optimizers, and
the local backend. Standalone phase 2 keeps its previous placement policy.

## What the fuzzer logs show

AFL++'s `run_time`/`plot_data` relative time **already includes cooperative pause
duration**. Its process stays alive; the clock does not restart. AFL writes no
new samples while it is waiting, however, so connecting the observations can
visually hide the pause.

The host-owned shim now writes the actual pause/resume boundaries to
`optimized/online/trials/trial_NN/pause_control/events.jsonl`. The companion
`trial.json` records the trial's wall-clock origin. Plotting uses these intervals
to hold coverage flat and throughput at zero, without shifting later samples
or adding the paused duration again. Shared-core plots disable throughput
smoothing. Coverage plateaus use the last observed common-instrument coverage;
their precision remains limited by the original coverage sampling interval.
Hot-swap restart gaps still use the existing separate clock correction.

## Live validation on this server

The reproducible probe uses a real AFL++ fuzzer plus a CPU-bound stand-in agent,
real compilation, smoke execution, perf sampling, broker replay, and final
held-out replay. No model/API calls or optimization edits are involved.

- Fuzzer, agent, Docker CPU work, and host worker used CPU 2.
- Builds/smoke ran with fuzzing enabled. Profile/replay quiesced the fuzzer and agent.
- Perf recorded 1,706 samples, 1,616 attributed to the target's caused work.
- Internal replay used the three-input tuning set; final replay used the one-input holdout.
- AFL recorded 41 executions, zero timeouts, and zero saved hangs.
- AFL runtime was 16 seconds, including 13.829 seconds of recorded pauses;
  total wall elapsed including startup/stop was 17.251 seconds.
- Killing the process owning an agent pause caused its guard to remove the agent.
- No CPU-cost ledger was created.

[Recorded results and image identities](shared-trial-cpu-results.json) contain
the raw measurements. This is a functional integration check, not a claim of
long-run fuzzing speedup or coverage improvement.

## Run and reproduce

```sh
# The new policy is the default on this branch.
ONLINE_SHARED_TRIAL_CPU=1 ./run_online_pertrial.sh libxml2

# Bounded integration probe, with disposable containers and no model calls.
python tools/probe_shared_cpu.py --cpu 2 --output /tmp/new-shared-cpu-probe
```

Choose an unused output directory and an available CPU for the probe. It keeps
logs/results there and removes its test containers. It requires existing
`bench-aflpp/libxml2-arvo-1972` and `bench-sandbox/profiler` images. This server
lacked the profiler image; it was built locally from the existing Ubuntu 24.04
base plus the host kernel-matched perf 6.8.12 and its libraries, without pulling
images or installing packages. The same preparation is available as:

```sh
python tools/build_local_profiler.py
```
