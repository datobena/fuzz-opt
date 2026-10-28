# AFL++ testcase-boundary pause experiment

Branch: `experiment/aflpp-pause-resume`. Recorded on 2026-10-28 using the existing
`bench-aflpp/libxml2-arvo-1972` image and AFL++ 5.02c. No Docker images were
downloaded or modified. Containers were disposable and pinned to logical CPU 2.
The recorded libxml2 and CmpLog target binaries were copied unchanged; the
image's pinned AFL++ driver replaced the older driver in that temporary copy.

## Result

Freezing an arbitrary in-flight testcase with `docker pause` is unsafe. Its
wall-clock timeout can expire while the container is frozen. A cooperative
pause acknowledged before the next testcase avoids that failure in these tests.

| Target | Mechanism | Pauses | Pause length | AFL timeout events |
|---|---|---:|---:|---:|
| Synthetic forkserver | Docker freezer | 5 | 0.8 s | 3 |
| Synthetic forkserver | Cooperative | 5 | 0.8 s | 0 |
| Synthetic persistent | Docker freezer | 5 | 0.8 s | 1 |
| Synthetic persistent | Cooperative | 5 | 0.8 s | 0 |
| Real libxml2, persistent + CmpLog | Cooperative | 10 | 1.2 s | 0 |

Synthetic testcases normally take 40 ms and have a 300 ms timeout. The real
libxml2 run used its normal 1,000 ms timeout, executed 8,760 inputs, recorded no
saved hangs or crashes, and reported 100% coverage stability. It resumed in the
same container. This is a short functional experiment, not a long-run coverage
or throughput comparison.

During cooperative pauses, a separate CPU-bound process ran on the same CPU.
Synthetic target completion counters did not advance. The real trial's process
snapshot showed AFL sleeping, forkservers sleeping, and the persistent target
stopped. All runs' counters, image identity, and target hashes are recorded in
[the result file](aflpp-pause-resume-results.json).

## Protocol and recovery

The existing pass-through custom mutator checks an optional `TRIAL_PAUSE_DIR`
between executions, before starting the next testcase. A request contains a
unique token and a monotonic-clock lease deadline. The hook acknowledges the
token, waits without executing inputs, and resumes when the request disappears
or its lease expires. It never changes the input bytes.

`lib/trial_pause.py` owns the request and renews the lease. Its context manager:

- enters only after the hook acknowledges and the container is still running;
- resumes in `finally`, including after an operation raises;
- bounds a pause by both its maximum duration and the trial's wall-clock deadline;
- raises `PauseError` if a lease, acknowledgement, deadline, or container
  generation is lost, so the measurement must be discarded;
- rejects nested pauses and does not allow an expired token to be re-used.

Killing the actual controller process with SIGKILL resumed the synthetic fuzzers
in 0.444 s and 0.439 s with a 0.4 s test lease. The production default lease is
2 seconds. No frozen Docker container or external unfreezing watchdog is needed.

Container stop/removal invalidates any active pause before issuing Docker's
command. The existing stop-and-overwrite hot-swap helper was exercised while
paused; the measurement was rejected and replacement completed. Relaunch assigns
a new generation, and late cleanup for the old container cannot resume the new
one. The online monitor also stops an opted-in trial at its wall-clock budget
even if AFL is waiting inside the pause hook. Unit tests cover these cases and
missing hooks, exceptions, byte preservation, and stale container acknowledgements.

## Opt-in API and scope

For an experimental trial, set `trial.pause_control_dir` to a private host
directory before launching it. The launcher mounts that directory, loads the
host-owned shim even when mutation capture is disabled, and attaches a controller:

```python
trial.pause_control_dir = "/absolute/private/path/for/this/trial"
# launch the trial through phase3_runner
with trial.pause_controller.paused(timeout=10, max_pause=120):
    run_measurement_on_trial_cpu()
```

The controller inherits the launched segment's wall-clock deadline. The caller
must discard a measurement if the context raises `PauseError`.

The initial prototype (`68c20c7`) supplied this opt-in pause primitive. The branch
now also includes [shared-core online optimization](shared-trial-cpu.md), which
enables it for online trials, places their optimization work on their CPU, and
replaces estimated CPU charging with actual contention.

## Reproduce

The probe refuses to pull a missing image. Use an existing image containing
`/src/aflplusplus` and clang-18, plus an existing libxml2 binary directory:

```sh
python tools/probe_trial_pause.py \
  --image bench-aflpp/libxml2-arvo-1972 --cpu 2 \
  --output /tmp/new-pause-probe \
  --real-bin-dir /absolute/path/to/existing/libxml2/bin

python -m pytest -q tests/test_trial_pause.py tests/test_online_mutation_capture.py
```

Choose an unused output directory and a CPU available for this experiment. The
probe cleans up its containers and retains its logs and counters in that directory.
