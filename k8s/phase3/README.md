# Phase3 Kubernetes Images

This directory packages the latest complete phase3 experiment for:

- `selinux` / `CVE-2021-36084`
- `gpac` / `CVE-2022-1441`
- `librawspeed` / `CVE-2018-25017`
- `unrar` / `CVE-2017-20006`

The source artifacts are the verified `baseline` and `optimized` binaries from
`results/codex-4`. The image entrypoint mirrors `phase3_runner.py`:

- fuzzer binary under `/out`
- writable corpus at `/corpus`
- writable crash artifacts at `/crashes`
- persistent per-trial archives under `/artifacts/bena/phase3-kube`
- `-detect_leaks=0`
- `-max_total_time=${DURATION_SECONDS}`
- `-verbosity=${LIBFUZZER_VERBOSITY:-1}`
- `-rss_limit_mb=${RSS_LIMIT_MB}`
- `-malloc_limit_mb=${MALLOC_LIMIT_MB:-RSS_LIMIT_MB}`
- `-artifact_prefix=/crashes/`
- `-print_final_stats=1`
- `-print_corpus_stats=1`
- `-print_funcs=1`
- `-report_slow_units=${REPORT_SLOW_UNITS:-10}`

## Build

```bash
k8s/phase3/build-images.sh
```

To load the images into kind while building:

```bash
kind create cluster --name phase3
k8s/phase3/build-images.sh --kind-cluster phase3
```

To tag for a registry:

```bash
k8s/phase3/build-images.sh --image-prefix registry.example.com/bench/ --push
```

By default the build context includes only the configured fuzz target,
`llvm-symbolizer` when present, matching dictionaries/seed zips when present,
the merged phase3 seed corpus, and the PoC directory. Set `COPY_ALL_BIN=1` if
you want each image to contain the whole phase3 `bin/` directory.

## Run

Long-running pods use the six-hour phase3 duration:

```bash
kubectl apply -f k8s/phase3/pods.yaml
```

For the real experiment, use the indexed Jobs. They create 100 trial indexes
per project/variant and use paired seeds:

```text
seed = 1337 + TRIAL_ID * 1000
```

The baseline and optimized Job for a project get the same `TRIAL_ID` values, so
trial `37` uses the same seed in both variants.

```bash
kubectl apply -f k8s/phase3/jobs.yaml
```

The Jobs default to `parallelism: 10`, `completions: 100`, and
`ttlSecondsAfterFinished: 432000` (5 days). Each indexed trial requests and
limits memory at `12Gi`; libFuzzer remains capped at `8192` MB RSS/malloc to
leave runtime headroom. Adjust `parallelism` to fit cluster CPU and memory
capacity.

Each Job mounts the namespace `nfs` PVC at `/artifacts` and writes a zip archive
for every completed fuzzer process:

```text
/artifacts/bena/phase3-kube/<project>/<variant>/<job-name>/trial-<id>-<pod>.zip
```

The trial archive contains `libfuzzer.log`, `metadata.env`, `crash_times.json`,
and `/crashes`. The generated `/corpus` is archived **separately** (per-file
mtimes preserved) under `.../<job-name>/corpora/corpus-<id>-<pod>.zip`.

By **default both variants archive their corpus** so the generated corpora
survive for offline analysis without a re-run (baseline corpora feed the
replay-timing metric; optimized corpora feed differential coverage studies —
`run_covdiff_pertrial.py` and `run_covtime.py`, which replay each variant's
corpus on the baseline binary and compare edge coverage / coverage-over-time).
Set `PHASE3_ARCHIVE_BASELINE_ONLY=1` to archive baseline only and save NFS space
(optimized corpora roughly double per-project corpus storage).

Optional live diagnostic: set `COVERAGE_SNAPSHOT=1` (interval
`COVERAGE_SNAPSHOT_INTERVAL`, default 1800s) to have the entrypoint periodically
replay the current corpus and stage a `coverage_over_time.json`. This is measured
on the **in-pod (generating) binary**, so it is a per-variant diagnostic, not the
common-baseline comparison — for that, use `run_covtime.py` offline.
The entrypoint preserves the original libFuzzer exit code in `metadata.env`, but
normalizes sanitizer/libFuzzer findings to pod exit code `0`, so Kubernetes marks
crash-finding trials as `Completed`. Infrastructure/setup failures and artifact
save failures still exit nonzero.

To copy archives later:

```bash
kubectl run -n davit phase3-artifact-copy --image=busybox:1.36 --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"phase3-artifact-copy","image":"busybox:1.36","command":["sh","-c","sleep 3600"],"volumeMounts":[{"name":"artifacts","mountPath":"/artifacts"}]}],"volumes":[{"name":"artifacts","persistentVolumeClaim":{"claimName":"nfs"}}]}}'
kubectl wait -n davit --for=condition=Ready pod/phase3-artifact-copy --timeout=90s
kubectl cp -n davit phase3-artifact-copy:/artifacts/bena/phase3-kube ./phase3-kube-artifacts
kubectl delete pod -n davit phase3-artifact-copy
```

Short smoke pods use `-runs=1` so they validate pod startup without fuzzing long
enough to trip the known vulnerabilities:

```bash
kubectl apply -f k8s/phase3/smoke-pods.yaml
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod -l app=phase3-fuzzer-smoke --timeout=180s
```

The pod manifests use `imagePullPolicy: IfNotPresent`, so kind-loaded images are
used without pushing to a registry.
