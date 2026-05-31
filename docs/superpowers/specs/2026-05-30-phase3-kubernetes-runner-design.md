# Phase 3 Kubernetes Runner — Design

**Date:** 2026-05-30
**Status:** Approved (pending spec review)

## Context

Phase 3 of the fuzzing benchmark currently runs each fuzzing trial as a **local Docker
container**, CPU-pinned via a slot scheduler (`phase3_runner.py:run_all_trials_slot`). This caps
the experiment at one machine's cores. The project already contains a **manually-operated**
Kubernetes path under `k8s/phase3/` (Dockerfile, `entrypoint.sh`, `build-images.sh`,
`jobs.yaml`, `images.json`) that was used for a past 4-CVE run, but it is a set of **static
artifacts for one experiment** with no generic generator, and its results were analyzed through
a separate path (`report_kube*.md`), not the standard phase 4.

**Goal:** replace phase 3 so it launches the trials as **Indexed Jobs on a Kubernetes cluster**,
generically for whatever CVEs are in the current setup manifest, end-to-end, while keeping phase
4 unchanged.

## Decisions (confirmed with user)

- **Full lifecycle automation:** build+push images → generate Jobs → apply → wait → collect →
  transform → compute replay metric.
- **Backend toggle:** `config.PHASE3_BACKEND` = `"k8s"` (default) | `"local"`. The local Docker
  runner stays available for cluster-free debugging. Mirrors `OPTIMIZER_BACKEND`.
- **Scale:** `PHASE3_K8S_TRIALS` (default **100**) completions, `PHASE3_K8S_PARALLELISM`
  (default **10**) per Job — configurable.
- **Corpus handling:** baseline Jobs run `ARCHIVE_CORPUS=1`, optimized `ARCHIVE_CORPUS=0`. The
  entrypoint writes the corpus to a **separate** archive (`.../corpora/corpus-<id>-<pod>.zip`),
  distinct from the small trial archive (`.../trials/trial-<id>-<pod>.zip`), so collection can
  pull every small trial archive cheaply while leaving corpora on NFS. The replay-speed metric
  uses **only the single biggest baseline corpus per project**, chosen by `corpus_file_count`
  (read from the already-collected trial metadata, no corpus download), then `kubectl cp`-ing
  just that one corpus zip.
- **Collection = helper pod (approach A):** after Jobs finish, a short-lived collector pod mounts
  the `nfs` PVC; the host streams artifacts out via `kubectl exec -- tar` (scoped to this
  experiment's per-trial zips + the one chosen corpus). The host needs no NFS mount.
- **Cluster config reused as overridable defaults:** image prefix `dbenashv/benchmark`, PVC
  `nfs`, privileged pods, artifacts root `/artifacts/bena/phase3-kube`, 12Gi mem, RSS/malloc
  8192, ttl 432000. `kubectl` and `docker` are assumed authenticated on the benchmark host.
- **Paired seeds:** `seed = BASE_SEED + trial_id * SEED_MULTIPLIER` (same seed for baseline and
  optimized at a given `trial_id`), matching the existing `entrypoint.sh`/README. This is a
  deliberate difference from the local runner's variant-offset seeds.

## Architecture

New module **`phase3_k8s.py`**, dispatched from `run_benchmark.run_phase_trials` on
`config.PHASE3_BACKEND`. It returns the same result list and writes the same
`results/<exp>/<key>/<variant>/trial_XX/` layout as the local runner, so **phase 4 is untouched**.

### Stage 1 — Build & push images
For each `(project, cve, variant)` in the setup manifest, build a phase-3 image from the phase-2
binary dir `results/<exp>/<key>/<variant>/bin` using `k8s/phase3/Dockerfile` and a build context
of: the fuzz target binary, `<target>_seed_corpus.zip`/dict if present, `llvm-symbolizer` if
present, and the merged seed corpus. Tag
`{PHASE3_K8S_IMAGE_PREFIX}phase3-<project>-<variant>:<experiment_id>` and push.
Generalizes `build-images.sh`; emits a per-run `images.json`. Reuses `lib/docker_util` helpers
where possible.

### Stage 2 — Generate `jobs.yaml`
One baseline + one optimized **Indexed Job** per CVE. Per the existing contract
(`test_phase3_k8s_images.py`): `completionMode: Indexed`, `completions=PHASE3_K8S_TRIALS`,
`parallelism=PHASE3_K8S_PARALLELISM`, `backoffLimitPerIndex=0`, `maxFailedIndexes=completions`,
`ttlSecondsAfterFinished=432000`, PVC `nfs` mounted at `/artifacts`, `securityContext.privileged`,
`imagePullPolicy: Always`, 12Gi requests/limits. Env: `BASE_SEED`, `SEED_MULTIPLIER`,
`DURATION_SECONDS`, `RSS_LIMIT_MB`, `MALLOC_LIMIT_MB`, `ARTIFACTS_DIR`, `ARCHIVE_CORPUS`
(`1` baseline / `0` optimized), `PROJECT`/`VARIANT`/`EXPERIMENT_ID`/`FUZZ_TARGET`, and `TRIAL_ID`
from `metadata.annotations['batch.kubernetes.io/job-completion-index']`. Labels carry
`phase3-project` / `phase3-variant`.

### Stage 3 — Apply & wait
`kubectl apply -f <generated jobs.yaml>`, then poll each Job's status (complete/failed) until all
terminal. Surfaces per-Job completion/failure counts in logs.

### Stage 4 — Collect (helper pod)
Launch a transient collector pod that mounts the `nfs` PVC. Stream out every small **trial**
archive for this experiment with `kubectl exec <collector> -- tar c --exclude='*/corpora*'`
(corpora are skipped, so this stays cheap). Then, per project, choose the baseline trial with the
max `corpus_file_count` from the already-collected `metadata.env`, and `kubectl cp` only that one
`corpora/` zip. Delete the collector pod when done.

### Stage 5 — Transform to phase-4 layout
For each Job's completed trial index, unzip its archive into
`results/<exp>/<key>/<variant>/trial_<idx>/`:
- `fuzzer.log` ← `libfuzzer.log`
- `metadata.json` ← convert `metadata.env` to JSON; populate `final_stats` by parsing the log
  with the same regex the local runner / phase 4 use (`stat::number_of_executed_units`,
  `stat::average_exec_per_sec`, `stat::peak_rss_mb`, `exec/s:` progress lines). Map
  `duration_s=elapsed_seconds`, `seed`, `num_crashes`, exit codes.
- `crash_times.json` ← reconstructed per-crash `timestamp_s` (crash-artifact mtime − start_epoch).
  Requires a small **entrypoint enhancement**: emit `crash_times.json` into the archive at
  archive time (libFuzzer exits on first finding, so typically one entry ≈ `elapsed_seconds`).
- `crashes/` ← extracted crash artifacts.

### Stage 6 — Replay-speed metric
Run `replay_timing.py` (baseline `/out` vs optimized `/out`) on the one downloaded biggest
baseline corpus per project, locally via the base-runner Docker image. Write `replay_speedup`
(and times) into that CVE's `setup_metadata.json` `replay` field — the field phase 4 already
reads. Reuses the existing `replay_timing` module.

## Components & files
- **New:** `phase3_k8s.py` (stages 1–6), `test_phase3_k8s_runner.py`.
- **Edit:** `k8s/phase3/entrypoint.sh` — emit `crash_times.json` into the archive.
- **Edit:** `run_benchmark.py` `run_phase_trials` — dispatch on `PHASE3_BACKEND`.
- **Edit:** `config.py` — `PHASE3_BACKEND`, `PHASE3_K8S_TRIALS`, `PHASE3_K8S_PARALLELISM`,
  `PHASE3_K8S_IMAGE_PREFIX`, `PHASE3_K8S_PVC`, `PHASE3_K8S_NAMESPACE`, `PHASE3_K8S_ARTIFACTS_DIR`,
  `PHASE3_K8S_MEMORY`, `PHASE3_K8S_RSS_LIMIT_MB`, `PHASE3_K8S_TTL`.
- **Edit:** `test_phase3_k8s_images.py` — point the Job assertions at the **generated** manifest
  for a sample manifest (this also resolves the current `completions == 100` vs static
  `completions: 1` failure, since the static file becomes a generated artifact).
- **Reuse:** `replay_timing.py`, `phase3_runner.parse_fuzzer_stats`, `lib/docker_util`.

## Error handling
- Missing `kubectl`/`docker`, unreachable cluster, or image-push failure → fail the phase with a
  clear message; do not silently fall back to local.
- A Job index that fails (infra) is recorded as a failed trial and skipped in transform; phase 4
  tolerates missing trials.
- Collector/transform failures for one CVE don't abort the others.
- If no baseline corpus was archived for a project, skip the replay metric for it (phase 4 still
  runs on time-to-bug).

## Testing / verification
- **Unit:** `jobs.yaml` generation matches the Indexed-Job contract (extend
  `test_phase3_k8s_images.py` against generated output); `metadata.env → metadata.json` conversion
  and `final_stats` parsing; biggest-corpus selection by `corpus_file_count`; `crash_times.json`
  reconstruction; dispatch in `run_phase_trials` honors `PHASE3_BACKEND`.
- **Entrypoint:** shell assertions that `crash_times.json` is produced.
- **End-to-end (manual, needs cluster):** run a 1–2 CVE experiment with a short
  `DURATION_SECONDS`, confirm Jobs complete, artifacts collect, `trial_XX/` dirs materialize, and
  phase 4 produces a report with `replay_speedup` populated.

## Open assumptions (correct me if wrong)
- The benchmark host's `kubectl` context points at the target cluster and `docker` is logged into
  the `dbenashv/benchmark` registry.
- The `nfs` PVC exists in the target namespace.
- The image-name convention concatenates prefix + `phase3-...` directly (as the current test
  encodes); `PHASE3_K8S_IMAGE_PREFIX` carries any needed separator.
