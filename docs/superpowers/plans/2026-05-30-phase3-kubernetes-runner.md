# Phase 3 Kubernetes Runner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace phase 3 so trials run as Kubernetes Indexed Jobs (generically, from the current setup manifest) end-to-end, while keeping phase 4 unchanged.

**Architecture:** A new `phase3_k8s.py` module performs build+push images → generate Jobs → apply → wait → collect (helper pod) → transform to the `trial_XX/` layout → compute the replay-speed metric on the biggest baseline corpus. `run_benchmark.run_phase_trials` dispatches to it when `config.PHASE3_BACKEND == "k8s"` (default), else the existing local runner. Pure command/manifest builders are unit-tested; subprocess calls are injected for testability.

**Tech Stack:** Python 3.11, PyYAML, `kubectl`/`docker` CLIs, libFuzzer, OSS-Fuzz base-runner image, pytest.

**Spec:** `docs/superpowers/specs/2026-05-30-phase3-kubernetes-runner-design.md`

---

## File Structure

- **Create** `phase3_k8s.py` — all six stages; pure builders + thin subprocess wrappers + `run_all_trials_k8s` orchestrator.
- **Create** `test_phase3_k8s_runner.py` — unit tests for builders/transform/selection/dispatch.
- **Modify** `config.py` — phase-3 k8s config knobs.
- **Modify** `run_benchmark.py` — dispatch in `run_phase_trials`.
- **Modify** `k8s/phase3/entrypoint.sh` — emit `crash_times.json` into the archive.
- **Modify** `test_phase3_k8s_images.py` — validate generated Jobs (resolves the stale `completions: 1` static-file failure).
- **Reuse** `phase3_runner.parse_fuzzer_stats`, `replay_timing.measure_binary`, `lib/docker_util`.

---

## Task 1: Config knobs

**Files:**
- Modify: `config.py`
- Test: `test_phase3_k8s_runner.py`

- [ ] **Step 1: Write the failing test**

```python
# test_phase3_k8s_runner.py
import config


def test_phase3_k8s_config_defaults():
    assert config.PHASE3_BACKEND in ("k8s", "local")
    assert config.PHASE3_K8S_TRIALS == 100
    assert config.PHASE3_K8S_PARALLELISM == 10
    assert config.PHASE3_K8S_IMAGE_PREFIX == "dbenashv/benchmark"
    assert config.PHASE3_K8S_PVC == "nfs"
    assert config.PHASE3_K8S_ARTIFACTS_DIR == "/artifacts/bena/phase3-kube"
    assert config.PHASE3_K8S_RSS_LIMIT_MB == 8192
    assert config.PHASE3_K8S_TTL_SECONDS == 432000
    assert config.PHASE3_K8S_MEMORY == "12Gi"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_phase3_k8s_runner.py::test_phase3_k8s_config_defaults -v`
Expected: FAIL with `AttributeError: module 'config' has no attribute 'PHASE3_BACKEND'`

- [ ] **Step 3: Add config (append after `PHASE3_REPLAY_REPEATS` block in `config.py`)**

```python
# Phase 3 execution backend: "k8s" (Indexed Jobs on a cluster) or "local"
# (Docker containers on this host). Overridable with the PHASE3_BACKEND env var.
PHASE3_BACKEND = os.environ.get("PHASE3_BACKEND", "k8s").lower()

# Phase 3 Kubernetes runner settings (used when PHASE3_BACKEND == "k8s").
PHASE3_K8S_TRIALS = int(os.environ.get("PHASE3_K8S_TRIALS", "100"))
PHASE3_K8S_PARALLELISM = int(os.environ.get("PHASE3_K8S_PARALLELISM", "10"))
PHASE3_K8S_IMAGE_PREFIX = os.environ.get("PHASE3_K8S_IMAGE_PREFIX", "dbenashv/benchmark")
PHASE3_K8S_PVC = os.environ.get("PHASE3_K8S_PVC", "nfs")
PHASE3_K8S_NAMESPACE = os.environ.get("PHASE3_K8S_NAMESPACE", "")  # "" = current context default
PHASE3_K8S_ARTIFACTS_DIR = os.environ.get(
    "PHASE3_K8S_ARTIFACTS_DIR", "/artifacts/bena/phase3-kube"
)
PHASE3_K8S_MEMORY = os.environ.get("PHASE3_K8S_MEMORY", "12Gi")
PHASE3_K8S_RSS_LIMIT_MB = int(os.environ.get("PHASE3_K8S_RSS_LIMIT_MB", "8192"))
PHASE3_K8S_TTL_SECONDS = int(os.environ.get("PHASE3_K8S_TTL_SECONDS", "432000"))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest test_phase3_k8s_runner.py::test_phase3_k8s_config_defaults -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add config.py test_phase3_k8s_runner.py
git commit -m "feat(phase3): add k8s runner config knobs"
```

---

## Task 2: Job manifest generation

**Files:**
- Create: `phase3_k8s.py`
- Test: `test_phase3_k8s_runner.py`

- [ ] **Step 1: Write the failing test**

```python
# test_phase3_k8s_runner.py
import phase3_k8s


def _manifest():
    return [{"project": "gpac", "cve": "CVE-2022-1441", "fuzz_target": "fuzz_parse"}]


def test_build_job_spec_matches_indexed_contract():
    job = phase3_k8s.build_job_spec(
        project="gpac", cve="CVE-2022-1441", variant="baseline",
        fuzz_target="fuzz_parse", experiment_id="exp1",
        image="dbenashv/benchmarkphase3-gpac-baseline:exp1",
        trials=100, parallelism=10, duration=21600,
    )
    assert job["apiVersion"] == "batch/v1"
    assert job["kind"] == "Job"
    assert job["spec"]["completions"] == 100
    assert job["spec"]["parallelism"] == 10
    assert job["spec"]["completionMode"] == "Indexed"
    assert job["spec"]["backoffLimitPerIndex"] == 0
    assert job["spec"]["maxFailedIndexes"] == 100
    assert job["spec"]["ttlSecondsAfterFinished"] == 432000

    tmpl = job["spec"]["template"]
    assert tmpl["metadata"]["labels"]["phase3-project"] == "gpac"
    assert tmpl["metadata"]["labels"]["phase3-variant"] == "baseline"
    c = tmpl["spec"]["containers"][0]
    assert c["image"] == "dbenashv/benchmarkphase3-gpac-baseline:exp1"
    assert c["imagePullPolicy"] == "Always"
    assert c["securityContext"] == {"privileged": True}
    assert c["resources"]["requests"]["memory"] == "12Gi"
    assert c["resources"]["limits"]["memory"] == "12Gi"
    env = {e["name"]: e for e in c["env"]}
    assert env["BASE_SEED"]["value"] == "1337"
    assert env["SEED_MULTIPLIER"]["value"] == "1000"
    assert env["DURATION_SECONDS"]["value"] == "21600"
    assert env["RSS_LIMIT_MB"]["value"] == "8192"
    assert env["MALLOC_LIMIT_MB"]["value"] == "8192"
    assert env["ARCHIVE_CORPUS"]["value"] == "1"  # baseline archives corpus
    assert env["FUZZ_TARGET"]["value"] == "fuzz_parse"
    assert env["PROJECT"]["value"] == "gpac"
    assert env["VARIANT"]["value"] == "baseline"
    assert env["EXPERIMENT_ID"]["value"] == "exp1"
    assert env["ARTIFACTS_DIR"]["value"] == "/artifacts/bena/phase3-kube/exp1"  # scoped per experiment
    assert env["TRIAL_ID"]["valueFrom"]["fieldRef"]["fieldPath"] == (
        "metadata.annotations['batch.kubernetes.io/job-completion-index']"
    )
    assert {"name": "artifacts", "mountPath": "/artifacts"} in c["volumeMounts"]
    assert {
        "name": "artifacts",
        "persistentVolumeClaim": {"claimName": "nfs"},
    } in tmpl["spec"]["volumes"]
    assert "SEED" not in env


def test_optimized_job_does_not_archive_corpus():
    job = phase3_k8s.build_job_spec(
        project="gpac", cve="CVE-2022-1441", variant="optimized",
        fuzz_target="fuzz_parse", experiment_id="exp1",
        image="img:opt", trials=100, parallelism=10, duration=21600,
    )
    env = {e["name"]: e for e in job["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["ARCHIVE_CORPUS"]["value"] == "0"


def test_generate_jobs_emits_two_jobs_per_cve():
    jobs = phase3_k8s.generate_jobs(
        _manifest(), experiment_id="exp1", duration=21600,
        image_for=lambda p, v: f"img-{p}-{v}",
    )
    assert len(jobs) == 2
    assert {j["spec"]["template"]["metadata"]["labels"]["phase3-variant"] for j in jobs} == {
        "baseline", "optimized",
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k job -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'phase3_k8s'`

- [ ] **Step 3: Create `phase3_k8s.py` with the manifest builders**

```python
"""Phase 3 runner that executes trials as Kubernetes Indexed Jobs.

Stages: build+push images -> generate Jobs -> apply -> wait -> collect (helper
pod) -> transform to the trial_XX/ layout -> replay-speed metric. Pure builders
are unit-tested; subprocess calls are injected so they can be faked in tests.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path

import config

logger = logging.getLogger(__name__)


def cve_key(project: str, cve: str) -> str:
    return f"{project}-{cve}"


def image_name(project: str, variant: str, experiment_id: str) -> str:
    # The image-name convention concatenates the prefix directly (matches the
    # existing k8s/phase3 contract); set PHASE3_K8S_IMAGE_PREFIX with any
    # needed separator.
    return f"{config.PHASE3_K8S_IMAGE_PREFIX}phase3-{project}-{variant}:{experiment_id}"


def job_name(project: str, variant: str) -> str:
    # DNS-1123: lowercase, no underscores.
    return f"phase3-{project}-{variant}".lower().replace("_", "-")


def build_job_spec(
    *, project: str, cve: str, variant: str, fuzz_target: str,
    experiment_id: str, image: str, trials: int, parallelism: int, duration: int,
) -> dict:
    archive_corpus = "1" if variant == "baseline" else "0"
    env = [
        {"name": "FUZZ_TARGET", "value": fuzz_target},
        {"name": "PROJECT", "value": project},
        {"name": "VARIANT", "value": variant},
        {"name": "EXPERIMENT_ID", "value": experiment_id},
        {"name": "BASE_SEED", "value": str(config.BASE_SEED)},
        {"name": "SEED_MULTIPLIER", "value": str(config.SEED_MULTIPLIER)},
        {"name": "DURATION_SECONDS", "value": str(duration)},
        {"name": "RSS_LIMIT_MB", "value": str(config.PHASE3_K8S_RSS_LIMIT_MB)},
        {"name": "MALLOC_LIMIT_MB", "value": str(config.PHASE3_K8S_RSS_LIMIT_MB)},
        {"name": "ARTIFACTS_DIR",
         "value": f"{config.PHASE3_K8S_ARTIFACTS_DIR}/{experiment_id}"},
        {"name": "ARCHIVE_CORPUS", "value": archive_corpus},
        {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
        {"name": "JOB_NAME", "valueFrom": {"fieldRef": {
            "fieldPath": "metadata.labels['job-name']"}}},
        {"name": "TRIAL_ID", "valueFrom": {"fieldRef": {
            "fieldPath": "metadata.annotations['batch.kubernetes.io/job-completion-index']"}}},
    ]
    container = {
        "name": "fuzzer",
        "image": image,
        "imagePullPolicy": "Always",
        "securityContext": {"privileged": True},
        "env": env,
        "resources": {
            "requests": {"memory": config.PHASE3_K8S_MEMORY},
            "limits": {"memory": config.PHASE3_K8S_MEMORY},
        },
        "volumeMounts": [{"name": "artifacts", "mountPath": "/artifacts"}],
    }
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": job_name(project, variant)},
        "spec": {
            "completions": trials,
            "parallelism": parallelism,
            "completionMode": "Indexed",
            "backoffLimitPerIndex": 0,
            "maxFailedIndexes": trials,
            "ttlSecondsAfterFinished": config.PHASE3_K8S_TTL_SECONDS,
            "template": {
                "metadata": {"labels": {
                    "phase3-project": project, "phase3-variant": variant}},
                "spec": {
                    "restartPolicy": "Never",
                    "containers": [container],
                    "volumes": [{
                        "name": "artifacts",
                        "persistentVolumeClaim": {"claimName": config.PHASE3_K8S_PVC},
                    }],
                },
            },
        },
    }


def generate_jobs(manifest, experiment_id, duration, image_for=None, *,
                  trials=None, parallelism=None):
    if image_for is None:
        image_for = lambda p, v: image_name(p, v, experiment_id)
    trials = config.PHASE3_K8S_TRIALS if trials is None else trials
    parallelism = config.PHASE3_K8S_PARALLELISM if parallelism is None else parallelism
    jobs = []
    for entry in manifest:
        project, cve = entry["project"], entry["cve"]
        fuzz_target = entry.get("fuzz_target", "")
        for variant in ("baseline", "optimized"):
            jobs.append(build_job_spec(
                project=project, cve=cve, variant=variant,
                fuzz_target=fuzz_target, experiment_id=experiment_id,
                image=image_for(project, variant),
                trials=trials, parallelism=parallelism, duration=duration,
            ))
    return jobs
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k job -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add phase3_k8s.py test_phase3_k8s_runner.py
git commit -m "feat(phase3): generate k8s Indexed Job manifests"
```

---

## Task 3: metadata.env → metadata.json conversion

**Files:**
- Modify: `phase3_k8s.py`
- Test: `test_phase3_k8s_runner.py`

- [ ] **Step 1: Write the failing test**

```python
def test_metadata_env_to_json_maps_fields_and_parses_stats(tmp_path):
    env_text = (
        "project=gpac\nvariant=baseline\ntrial_id=7\nseed=8337\n"
        "elapsed_seconds=120\nduration_seconds=21600\n"
        "fuzzer_exit_code=1\npod_exit_code=0\noutcome=finding\n"
        "corpus_file_count=4212\ncorpus_du_bytes=99999\n"
    )
    log_text = (
        "#1000 NEW exec/s: 500\n"
        "stat::number_of_executed_units: 60000\n"
        "stat::average_exec_per_sec:     500\n"
        "stat::peak_rss_mb:              321\n"
    )
    meta = phase3_k8s.metadata_env_to_json(env_text, log_text, num_crashes=1)
    assert meta["variant"] == "baseline"
    assert meta["trial_id"] == 7
    assert meta["seed"] == 8337
    assert meta["duration_s"] == 120.0
    assert meta["duration_seconds"] == 21600
    assert meta["num_crashes"] == 1
    assert meta["final_stats"]["total_execs"] == 60000
    assert meta["final_stats"]["final_exec_s"] == 500
    assert meta["corpus_file_count"] == 4212
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k metadata_env -v`
Expected: FAIL with `AttributeError: module 'phase3_k8s' has no attribute 'metadata_env_to_json'`

- [ ] **Step 3: Add the converter (append to `phase3_k8s.py`)**

```python
import phase3_runner


def parse_metadata_env(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def metadata_env_to_json(env_text: str, log_text: str, num_crashes: int) -> dict:
    env = parse_metadata_env(env_text)
    final_stats = phase3_runner.parse_fuzzer_stats(log_text)

    def _int(key, default=0):
        try:
            return int(env.get(key, default))
        except (TypeError, ValueError):
            return default

    return {
        "trial_name": (
            f"{env.get('project','')}-{env.get('variant','')}-"
            f"trial_{_int('trial_id'):02d}"
        ),
        "variant": env.get("variant", ""),
        "trial_id": _int("trial_id"),
        "seed": _int("seed"),
        "duration_s": float(_int("elapsed_seconds")),
        "duration_seconds": _int("duration_seconds", config.TRIAL_DURATION_SECS),
        "num_crashes": num_crashes,
        "final_stats": final_stats,
        "outcome": env.get("outcome", ""),
        "fuzzer_exit_code": _int("fuzzer_exit_code"),
        "pod_exit_code": _int("pod_exit_code"),
        "corpus_file_count": _int("corpus_file_count"),
        "corpus_du_bytes": _int("corpus_du_bytes"),
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k metadata_env -v`
Expected: PASS

NOTE: confirm `phase3_runner.parse_fuzzer_stats` returns a dict with `total_execs` and `final_exec_s`; if its key names differ, adapt the assertions and the converter to the real keys (read `phase3_runner.py:parse_fuzzer_stats`).

- [ ] **Step 5: Commit**

```bash
git add phase3_k8s.py test_phase3_k8s_runner.py
git commit -m "feat(phase3): convert k8s metadata.env to phase4 metadata.json"
```

---

## Task 4: Biggest-baseline-corpus selection

**Files:**
- Modify: `phase3_k8s.py`
- Test: `test_phase3_k8s_runner.py`

- [ ] **Step 1: Write the failing test**

```python
def test_pick_biggest_baseline_corpus_by_file_count():
    # (trial_id, corpus_file_count) per baseline trial for one project
    trials = [
        {"trial_id": 0, "corpus_file_count": 100},
        {"trial_id": 1, "corpus_file_count": 4212},
        {"trial_id": 2, "corpus_file_count": 3000},
    ]
    winner = phase3_k8s.pick_biggest_corpus(trials)
    assert winner["trial_id"] == 1


def test_pick_biggest_corpus_returns_none_for_empty():
    assert phase3_k8s.pick_biggest_corpus([]) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k biggest -v`
Expected: FAIL with `AttributeError`

- [ ] **Step 3: Add the selector (append to `phase3_k8s.py`)**

```python
def pick_biggest_corpus(baseline_trials: list[dict]) -> dict | None:
    """Pick the baseline trial whose corpus has the most files."""
    if not baseline_trials:
        return None
    return max(baseline_trials, key=lambda t: int(t.get("corpus_file_count", 0)))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k biggest -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add phase3_k8s.py test_phase3_k8s_runner.py
git commit -m "feat(phase3): select biggest baseline corpus for replay"
```

---

## Task 5: kubectl/docker command builders + wait loop

**Files:**
- Modify: `phase3_k8s.py`
- Test: `test_phase3_k8s_runner.py`

- [ ] **Step 1: Write the failing test**

```python
def test_kubectl_apply_and_wait_commands():
    assert phase3_k8s.kubectl_apply_cmd("/tmp/jobs.yaml", namespace="bench") == [
        "kubectl", "-n", "bench", "apply", "-f", "/tmp/jobs.yaml",
    ]
    assert phase3_k8s.kubectl_job_status_cmd("phase3-gpac-baseline", namespace="") == [
        "kubectl", "get", "job", "phase3-gpac-baseline",
        "-o", "jsonpath={.status.succeeded}/{.status.failed}",
    ]


def test_job_is_terminal_when_succeeded_plus_failed_reaches_completions():
    assert phase3_k8s.job_is_terminal(succeeded=100, failed=0, completions=100)
    assert phase3_k8s.job_is_terminal(succeeded=98, failed=2, completions=100)
    assert not phase3_k8s.job_is_terminal(succeeded=50, failed=0, completions=100)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k "kubectl or terminal" -v`
Expected: FAIL with `AttributeError`

- [ ] **Step 3: Add command builders + helpers (append to `phase3_k8s.py`)**

```python
def _ns_args(namespace: str) -> list[str]:
    return ["-n", namespace] if namespace else []


def kubectl_apply_cmd(path: str, namespace: str = "") -> list[str]:
    return ["kubectl", *_ns_args(namespace), "apply", "-f", path]


def kubectl_job_status_cmd(job: str, namespace: str = "") -> list[str]:
    return [
        "kubectl", *_ns_args(namespace), "get", "job", job,
        "-o", "jsonpath={.status.succeeded}/{.status.failed}",
    ]


def job_is_terminal(*, succeeded: int, failed: int, completions: int) -> bool:
    return (succeeded + failed) >= completions


def _run(cmd, *, timeout=None, check=False):
    logger.info("exec: %s", " ".join(cmd[:6]))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k "kubectl or terminal" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add phase3_k8s.py test_phase3_k8s_runner.py
git commit -m "feat(phase3): kubectl command builders and job-terminal check"
```

---

## Task 6: Collector helper-pod tar-stream command

**Files:**
- Modify: `phase3_k8s.py`
- Test: `test_phase3_k8s_runner.py`

- [ ] **Step 1: Write the failing test**

```python
def test_collector_exec_tar_cmd_excludes_corpora():
    cmd = phase3_k8s.collector_tar_cmd(
        pod="phase3-collector", namespace="bench",
        tar_dir="/artifacts/bena/phase3-kube/exp1",
        excludes=["*/corpora", "*/corpora/*"],
    )
    joined = " ".join(cmd)
    assert cmd[:2] == ["kubectl", "-n"]
    assert "exec" in cmd and "phase3-collector" in cmd
    assert "-C /artifacts/bena/phase3-kube/exp1" in joined
    # corpora are NOT streamed back wholesale (only the chosen one, separately)
    assert "--exclude=*/corpora" in joined


def test_collector_pod_spec_mounts_pvc():
    spec = phase3_k8s.collector_pod_spec(name="phase3-collector")
    c = spec["spec"]["containers"][0]
    assert {"name": "artifacts", "mountPath": "/artifacts"} in c["volumeMounts"]
    assert spec["spec"]["volumes"][0]["persistentVolumeClaim"]["claimName"] == "nfs"
    assert spec["spec"]["restartPolicy"] == "Never"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k collector -v`
Expected: FAIL with `AttributeError`

- [ ] **Step 3: Add collector builders (append to `phase3_k8s.py`)**

```python
def collector_pod_spec(*, name: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name},
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "collector",
                "image": "busybox:1.36",
                "command": ["sh", "-c", "sleep 3600"],
                "volumeMounts": [{"name": "artifacts", "mountPath": "/artifacts"}],
            }],
            "volumes": [{
                "name": "artifacts",
                "persistentVolumeClaim": {"claimName": config.PHASE3_K8S_PVC},
            }],
        },
    }


def collector_tar_cmd(*, pod: str, namespace: str, tar_dir: str,
                      excludes: list[str] | None = None) -> list[str]:
    # Stream a tar of tar_dir to stdout, skipping excluded globs (the bulky
    # corpora/ dirs). The caller pipes stdout into `tar x` on the host.
    exclude_args = [f"--exclude={pat}" for pat in (excludes or [])]
    return [
        "kubectl", *_ns_args(namespace), "exec", pod, "--",
        "tar", "c", *exclude_args, "-C", tar_dir, ".",
    ]


def kubectl_cp_cmd(*, pod: str, namespace: str, remote_path: str,
                   local_path: str) -> list[str]:
    src = f"{pod}:{remote_path}"
    if namespace:
        src = f"{namespace}/{src}"
    return ["kubectl", *_ns_args(namespace), "cp", src, local_path]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k collector -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add phase3_k8s.py test_phase3_k8s_runner.py
git commit -m "feat(phase3): collector pod spec, exclude-corpora tar, kubectl cp"
```

Why: `collect_artifacts` (Task 9) streams the whole experiment tree **minus** the `corpora/`
dirs (so all small trial archives come back cheaply); `compute_replay_metrics` then picks the
biggest baseline corpus from the already-collected `metadata.env` files and uses `kubectl cp` to
fetch **only that one** corpus zip from `corpora/`.

---

## Task 7: Transform a collected trial into the trial_XX/ layout

**Files:**
- Modify: `phase3_k8s.py`
- Test: `test_phase3_k8s_runner.py`

- [ ] **Step 1: Write the failing test**

```python
def test_write_trial_dir_produces_phase4_inputs(tmp_path):
    # Simulate an unpacked archive dir for one trial.
    unpacked = tmp_path / "unpacked"
    (unpacked / "crashes").mkdir(parents=True)
    (unpacked / "libfuzzer.log").write_text(
        "stat::number_of_executed_units: 60000\n"
        "stat::average_exec_per_sec:     500\n"
    )
    (unpacked / "metadata.env").write_text(
        "variant=baseline\ntrial_id=3\nseed=4337\nelapsed_seconds=120\n"
        "duration_seconds=21600\ncorpus_file_count=10\n"
    )
    (unpacked / "crashes" / "crash-abc").write_text("boom")
    (unpacked / "crash_times.json").write_text(
        '[{"timestamp_s": 119.5, "artifact": "crash-abc", "crash_type": "crash"}]'
    )

    out = tmp_path / "results" / "exp1" / "gpac-CVE-2022-1441" / "baseline"
    phase3_k8s.write_trial_dir(unpacked, out, trial_id=3)

    tdir = out / "trial_03"
    assert (tdir / "fuzzer.log").exists()
    meta = json.loads((tdir / "metadata.json").read_text())
    assert meta["seed"] == 4337
    assert meta["final_stats"]["total_execs"] == 60000
    assert meta["num_crashes"] == 1
    crash_times = json.loads((tdir / "crash_times.json").read_text())
    assert crash_times[0]["artifact"] == "crash-abc"
    assert (tdir / "crashes" / "crash-abc").exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k write_trial_dir -v`
Expected: FAIL with `AttributeError`

- [ ] **Step 3: Add the transform (append to `phase3_k8s.py`)**

```python
import shutil


def write_trial_dir(unpacked_dir: Path, variant_out_dir: Path, *, trial_id: int) -> Path:
    """Materialize results/<exp>/<key>/<variant>/trial_<id>/ from an unpacked archive."""
    unpacked_dir = Path(unpacked_dir)
    tdir = Path(variant_out_dir) / f"trial_{trial_id:02d}"
    crashes_src = unpacked_dir / "crashes"
    crashes_dst = tdir / "crashes"
    crashes_dst.mkdir(parents=True, exist_ok=True)

    log_text = ""
    log_src = unpacked_dir / "libfuzzer.log"
    if log_src.exists():
        log_text = log_src.read_text(errors="replace")
        (tdir / "fuzzer.log").write_text(log_text)

    crash_files = [p for p in crashes_src.glob("*") if p.is_file()] if crashes_src.is_dir() else []
    for p in crash_files:
        shutil.copy2(p, crashes_dst / p.name)

    env_text = ""
    env_src = unpacked_dir / "metadata.env"
    if env_src.exists():
        env_text = env_src.read_text(errors="replace")
    meta = metadata_env_to_json(env_text, log_text, num_crashes=len(crash_files))
    meta["trial_id"] = trial_id
    (tdir / "metadata.json").write_text(json.dumps(meta, indent=2))

    ct_src = unpacked_dir / "crash_times.json"
    if ct_src.exists():
        shutil.copy2(ct_src, tdir / "crash_times.json")
    else:
        (tdir / "crash_times.json").write_text("[]")
    return tdir
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k write_trial_dir -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add phase3_k8s.py test_phase3_k8s_runner.py
git commit -m "feat(phase3): transform collected k8s trial into phase4 layout"
```

---

## Task 8: Replay metric on the biggest corpus → setup_metadata.replay

**Files:**
- Modify: `phase3_k8s.py`
- Test: `test_phase3_k8s_runner.py`

- [ ] **Step 1: Write the failing test**

```python
def test_record_replay_into_setup_metadata(tmp_path):
    key_dir = tmp_path / "results" / "exp1" / "gpac-CVE-2022-1441"
    (key_dir).mkdir(parents=True)
    (key_dir / "setup_metadata.json").write_text(json.dumps({"entry": {"project": "gpac"}}))
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a").write_text("x")

    def fake_measure(*, out_dir, **kw):
        return {"median_time_s": 10.0 if "baseline" in str(out_dir) else 4.0}

    speedup = phase3_k8s.record_replay_metric(
        key_dir=key_dir,
        baseline_bin_dir=tmp_path / "baseline" / "bin",
        optimized_bin_dir=tmp_path / "optimized" / "bin",
        corpus_dir=corpus, fuzz_target="fuzz_parse", measure_fn=fake_measure,
    )
    assert speedup == 2.5
    meta = json.loads((key_dir / "setup_metadata.json").read_text())
    assert meta["replay"]["replay_speedup"] == 2.5
    assert meta["replay"]["corpus_source"] == "k8s_biggest_baseline"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k record_replay -v`
Expected: FAIL with `AttributeError`

- [ ] **Step 3: Add the replay recorder (append to `phase3_k8s.py`)**

```python
def _load_replay_module():
    import importlib.util
    script = Path(config.PHASE3_SKILL_SCRIPTS_DIR if hasattr(config, "PHASE3_SKILL_SCRIPTS_DIR")
                  else config.PHASE2_SKILL_SCRIPTS_DIR) / "replay_timing.py"
    spec = importlib.util.spec_from_file_location("replay_timing", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record_replay_metric(*, key_dir, baseline_bin_dir, optimized_bin_dir,
                         corpus_dir, fuzz_target, profile_cpu=None,
                         repeats=None, measure_fn=None) -> float | None:
    """Run deterministic replay on the biggest baseline corpus; write into setup_metadata."""
    try:
        measure = measure_fn or _load_replay_module().measure_binary
        if profile_cpu is None:
            profile_cpu = max(int(getattr(config, "RESERVED_CORES", 1)) - 1, 0)
        if repeats is None:
            repeats = int(getattr(config, "PHASE2_REPLAY_REPEATS", 3))
        common = dict(
            corpus_dir=str(corpus_dir), fuzz_target=fuzz_target, cpu=profile_cpu,
            repeats=repeats, seed=int(getattr(config, "BASE_SEED", 1337)),
            memory=getattr(config, "MEMORY_LIMIT", "4g"),
            shm_size=getattr(config, "DOCKER_SHM_SIZE", "2g"),
            run_timeout=int(getattr(config, "TRIAL_DURATION_SECS", 3600)),
        )
        baseline = measure(out_dir=str(baseline_bin_dir), **common)
        optimized = measure(out_dir=str(optimized_bin_dir), **common)
        b, o = baseline.get("median_time_s"), optimized.get("median_time_s")
        speedup = round(b / o, 4) if (b and o) else None

        meta_path = Path(key_dir) / "setup_metadata.json"
        meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        meta["replay"] = {
            "replay_speedup": speedup, "baseline": baseline, "optimized": optimized,
            "corpus_source": "k8s_biggest_baseline",
            "corpus_file_count": sum(1 for p in Path(corpus_dir).rglob("*") if p.is_file()),
        }
        meta_path.write_text(json.dumps(meta, indent=2))
        return speedup
    except Exception as exc:  # never let the metric break the run
        logger.warning("k8s replay metric failed for %s: %s", key_dir, exc)
        return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k record_replay -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add phase3_k8s.py test_phase3_k8s_runner.py
git commit -m "feat(phase3): replay metric on biggest k8s baseline corpus"
```

---

## Task 9: Orchestrator `run_all_trials_k8s`

**Files:**
- Modify: `phase3_k8s.py`
- Test: `test_phase3_k8s_runner.py`

- [ ] **Step 1: Write the failing test (stage functions injected)**

```python
def test_run_all_trials_k8s_invokes_stages_in_order(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(config, "RESULTS_DIR", str(tmp_path))
    monkeypatch.setattr(phase3_k8s, "build_and_push_images",
                        lambda *a, **k: calls.append("build") or {})
    monkeypatch.setattr(phase3_k8s, "apply_and_wait",
                        lambda *a, **k: calls.append("apply"))
    monkeypatch.setattr(phase3_k8s, "collect_artifacts",
                        lambda *a, **k: calls.append("collect") or {
                            "dir": tmp_path / "collected", "pod": "p",
                            "namespace": "", "exp_dir": "/artifacts/x"})
    monkeypatch.setattr(phase3_k8s, "transform_all",
                        lambda *a, **k: calls.append("transform") or [{"trial": "t0"}])
    monkeypatch.setattr(phase3_k8s, "compute_replay_metrics",
                        lambda *a, **k: calls.append("replay"))
    # absorb the finally-block collector-pod delete
    monkeypatch.setattr(phase3_k8s, "_run", lambda *a, **k: calls.append("cleanup"))

    manifest = [{"project": "gpac", "cve": "CVE-2022-1441", "fuzz_target": "fuzz_parse"}]
    results = phase3_k8s.run_all_trials_k8s(manifest, "exp1", duration=60)

    assert calls == ["build", "apply", "collect", "transform", "replay", "cleanup"]
    assert results == [{"trial": "t0"}]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k run_all_trials_k8s -v`
Expected: FAIL with `AttributeError`

- [ ] **Step 3: Add orchestrator + remaining stage wrappers (append to `phase3_k8s.py`)**

```python
import tempfile
import time

import yaml


def build_and_push_images(manifest, experiment_id):
    """Build+push a phase3 image per (project,cve,variant) from phase-2 binaries.

    Returns {(project, variant): image}. Uses k8s/phase3/Dockerfile with a build
    context = the variant bin dir. Shells out to docker; assumes docker login.
    """
    built = {}
    dockerfile = Path(__file__).resolve().parent / "k8s" / "phase3" / "Dockerfile"
    for entry in manifest:
        project, cve = entry["project"], entry["cve"]
        for variant in ("baseline", "optimized"):
            bin_dir = Path(config.RESULTS_DIR) / experiment_id / cve_key(project, cve) / variant / "bin"
            image = image_name(project, variant, experiment_id)
            build = ["docker", "build", "-f", str(dockerfile),
                     "--build-arg", f"FUZZ_TARGET={entry.get('fuzz_target','')}",
                     "-t", image, str(bin_dir)]
            if _run(build).returncode != 0:
                raise RuntimeError(f"docker build failed for {image}")
            if _run(["docker", "push", image]).returncode != 0:
                raise RuntimeError(f"docker push failed for {image}")
            built[(project, variant)] = image
    return built


def apply_and_wait(jobs, *, namespace="", poll_secs=30, clock=time.monotonic,
                   sleep=time.sleep):
    ns = namespace or config.PHASE3_K8S_NAMESPACE
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        yaml.safe_dump_all(jobs, f)
        path = f.name
    if _run(kubectl_apply_cmd(path, ns)).returncode != 0:
        raise RuntimeError("kubectl apply failed")
    pending = {j["metadata"]["name"]: j["spec"]["completions"] for j in jobs}
    while pending:
        for name, completions in list(pending.items()):
            out = _run(kubectl_job_status_cmd(name, ns)).stdout.strip()
            succeeded, _, failed = out.partition("/")
            s, fl = int(succeeded or 0), int(failed or 0)
            if job_is_terminal(succeeded=s, failed=fl, completions=completions):
                logger.info("job %s terminal: %d ok / %d failed", name, s, fl)
                del pending[name]
        if pending:
            sleep(poll_secs)


def collect_artifacts(manifest, experiment_id, *, namespace=""):
    """Start a collector pod, stream back all small trial archives (NOT corpora).

    Returns a handle dict {dir, pod, namespace, exp_dir} and leaves the pod
    running so compute_replay_metrics can `kubectl cp` the one chosen corpus.
    The orchestrator deletes the pod afterward.
    """
    ns = namespace or config.PHASE3_K8S_NAMESPACE
    pod_name = f"phase3-collector-{experiment_id}".lower().replace("_", "-")
    pod = collector_pod_spec(name=pod_name)
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        yaml.safe_dump(pod, f)
        pod_path = f.name
    _run(kubectl_apply_cmd(pod_path, ns), check=True)
    _run(["kubectl", *_ns_args(ns), "wait", "--for=condition=Ready",
          f"pod/{pod_name}", "--timeout=120s"])

    exp_dir = f"{config.PHASE3_K8S_ARTIFACTS_DIR}/{experiment_id}"
    dest = Path(tempfile.mkdtemp(prefix="phase3-collect-"))
    tar_cmd = collector_tar_cmd(pod=pod_name, namespace=ns, tar_dir=exp_dir,
                                excludes=["*/corpora", "*/corpora/*"])
    proc = subprocess.Popen(tar_cmd, stdout=subprocess.PIPE)
    subprocess.run(["tar", "x", "-C", str(dest)], stdin=proc.stdout, check=True)
    proc.wait()
    return {"dir": dest, "pod": pod_name, "namespace": ns, "exp_dir": exp_dir}


def transform_all(collected, manifest, experiment_id):
    """Unpack the small trial archives into trial_XX/ dirs. Returns result list."""
    import zipfile
    collected_dir = Path(collected["dir"])
    results = []
    for entry in manifest:
        project, cve = entry["project"], entry["cve"]
        key = cve_key(project, cve)
        for variant in ("baseline", "optimized"):
            jname = job_name(project, variant)
            zips_root = collected_dir / project / variant / jname / "trials"
            if not zips_root.is_dir():
                continue
            variant_out = Path(config.RESULTS_DIR) / experiment_id / key / variant
            for zpath in sorted(zips_root.glob("trial-*.zip")):
                trial_id = int(zpath.name.split("-")[1])  # trial-<id>-<pod>.zip
                with tempfile.TemporaryDirectory() as ud:
                    with zipfile.ZipFile(zpath) as zf:
                        zf.extractall(ud)
                    write_trial_dir(Path(ud), variant_out, trial_id=trial_id)
                results.append({"trial": f"{key}-{variant}-trial_{trial_id:02d}"})
    return results


def compute_replay_metrics(collected, manifest, experiment_id):
    """Per project: pick biggest baseline corpus from already-collected metadata,
    kubectl cp only that one corpus zip, replay it on both binaries."""
    import zipfile
    collected_dir = Path(collected["dir"])
    pod, ns, exp_dir = collected["pod"], collected["namespace"], collected["exp_dir"]
    for entry in manifest:
        project, cve = entry["project"], entry["cve"]
        key = cve_key(project, cve)
        jname = job_name(project, "baseline")
        trials_root = collected_dir / project / "baseline" / jname / "trials"
        if not trials_root.is_dir():
            logger.warning("no baseline trials for %s; skipping replay", key)
            continue
        trials = []
        for zpath in sorted(trials_root.glob("trial-*.zip")):
            with zipfile.ZipFile(zpath) as zf:
                if "metadata.env" not in zf.namelist():
                    continue
                env = parse_metadata_env(zf.read("metadata.env").decode("utf-8", "replace"))
            trials.append({
                "trial_id": int(env.get("trial_id", 0)),
                "corpus_file_count": int(env.get("corpus_file_count", 0)),
                "pod_suffix": zpath.name[len(f"trial-{env.get('trial_id','0')}-"):-4],
            })
        winner = pick_biggest_corpus(trials)
        if not winner or winner["corpus_file_count"] == 0:
            logger.warning("no baseline corpus for %s; skipping replay", key)
            continue
        remote = (f"{exp_dir}/{project}/baseline/{jname}/corpora/"
                  f"corpus-{winner['trial_id']}-{winner['pod_suffix']}.zip")
        with tempfile.TemporaryDirectory() as ud:
            local_zip = os.path.join(ud, "corpus.zip")
            if _run(kubectl_cp_cmd(pod=pod, namespace=ns, remote_path=remote,
                                   local_path=local_zip)).returncode != 0:
                logger.warning("kubectl cp corpus failed for %s; skipping replay", key)
                continue
            corpus = Path(ud) / "corpus"
            corpus.mkdir()
            with zipfile.ZipFile(local_zip) as zf:
                zf.extractall(corpus)
            if not any(corpus.rglob("*")):
                logger.warning("empty corpus for %s; skipping replay", key)
                continue
            key_dir = Path(config.RESULTS_DIR) / experiment_id / key
            record_replay_metric(
                key_dir=key_dir,
                baseline_bin_dir=key_dir / "baseline" / "bin",
                optimized_bin_dir=key_dir / "optimized" / "bin",
                corpus_dir=corpus, fuzz_target=entry.get("fuzz_target", ""),
            )


def run_all_trials_k8s(manifest, experiment_id, duration=None, **_kwargs):
    duration = config.TRIAL_DURATION_SECS if duration is None else duration
    images = build_and_push_images(manifest, experiment_id)
    jobs = generate_jobs(manifest, experiment_id, duration,
                         image_for=lambda p, v: images[(p, v)])
    apply_and_wait(jobs)
    collected = collect_artifacts(manifest, experiment_id)
    try:
        results = transform_all(collected, manifest, experiment_id)
        compute_replay_metrics(collected, manifest, experiment_id)
    finally:
        _run(["kubectl", *_ns_args(collected["namespace"]), "delete", "pod",
              collected["pod"], "--wait=false"])
    return results
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest test_phase3_k8s_runner.py -k run_all_trials_k8s -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add phase3_k8s.py test_phase3_k8s_runner.py
git commit -m "feat(phase3): orchestrate full k8s phase3 lifecycle"
```

---

## Task 10: entrypoint.sh — split corpus archive + emit crash_times.json

**Why:** with `ARCHIVE_CORPUS=1`, the current entrypoint bundles the (large) corpus into the
same zip as the trial artifacts. Pulling all 100 baseline zips back would copy every corpus —
the bandwidth blowup we must avoid. Split them so the small trial archive (log, metadata,
crashes, crash_times) lives under `trials/` and the corpus lives in a separate archive under
`corpora/`. Collection pulls all of `trials/` (small) and only the single chosen `corpora/` zip.

New per-job artifact layout (under `ARTIFACTS_DIR`, which now includes the experiment id):
```
<ARTIFACTS_DIR>/<project>/<variant>/<job_name>/trials/trial-<id>-<pod>.zip     # always, small
<ARTIFACTS_DIR>/<project>/<variant>/<job_name>/corpora/corpus-<id>-<pod>.zip   # baseline only, big
```

**Files:**
- Modify: `k8s/phase3/entrypoint.sh`
- Test: `test_phase3_k8s_images.py`

- [ ] **Step 1: Write the failing test (append to `test_phase3_k8s_images.py`)**

```python
def test_entrypoint_emits_crash_times_and_splits_corpus():
    entrypoint = (K8S_DIR / "entrypoint.sh").read_text()
    # crash timing reconstructed relative to start
    assert "collect_crash_times" in entrypoint
    assert "crash_times.json" in entrypoint
    assert "start_epoch" in entrypoint
    # corpus is archived separately from the trial artifacts
    assert "/trials/" in entrypoint
    assert "/corpora/" in entrypoint
    assert "save_corpus_archive" in entrypoint
    # the trial staging never copies the corpus into the trial zip
    assert "staging_dir}/corpus" not in entrypoint
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_phase3_k8s_images.py::test_entrypoint_emits_crash_times_and_splits_corpus -v`
Expected: FAIL

- [ ] **Step 3: Edit `k8s/phase3/entrypoint.sh`**

3a. Add `collect_crash_times` near `collect_corpus_stats`:

```bash
collect_crash_times() {
  local out_json="$1"
  python3 - "$crashes_dir" "$start_epoch" "$out_json" <<'PY'
import json, os, sys
crashes_dir, start_epoch, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
events = []
if os.path.isdir(crashes_dir):
    for name in sorted(os.listdir(crashes_dir)):
        p = os.path.join(crashes_dir, name)
        if not os.path.isfile(p):
            continue
        ctype = ("oom" if name.startswith("oom-")
                 else "timeout" if name.startswith("timeout-")
                 else "crash" if name.startswith("crash-")
                 else "unknown")
        ts = max(0.0, round(os.path.getmtime(p) - start_epoch, 2))
        events.append({"timestamp_s": ts, "artifact": name, "crash_type": ctype})
with open(out, "w") as f:
    json.dump(events, f)
PY
}
```

3b. Replace the body of `save_artifacts` so it builds a **trial-only** archive (no corpus) and
emits crash_times.json into it:

```bash
save_artifacts() {
  local archive_path="$1"
  if [ -z "${artifacts_dir}" ]; then
    echo "ARTIFACTS_DIR is unset; skipping persistent artifact archive" >&2
    return 0
  fi
  local archive_dir staging_dir archive_tmp
  archive_dir="$(dirname "${archive_path}")"
  archive_tmp="${archive_path}.tmp"
  staging_dir="${work_dir}/artifact-staging"
  rm -rf "${staging_dir}"
  mkdir -p "${archive_dir}" "${staging_dir}/crashes"
  cp "${log_file}" "${staging_dir}/libfuzzer.log" 2>/dev/null || true
  cp "${metadata_file}" "${staging_dir}/metadata.env"
  cp -a "${crashes_dir}/." "${staging_dir}/crashes/" 2>/dev/null || true
  collect_crash_times "${staging_dir}/crash_times.json"
  rm -f "${archive_tmp}"
  ( cd "${staging_dir}" && zip -qry "${archive_tmp}" . )
  mv "${archive_tmp}" "${archive_path}"
  sha256sum "${archive_path}" >"${archive_path}.sha256"
  echo "Saved phase3 trial archive: ${archive_path}"
}
```

3c. Add a separate `save_corpus_archive` (only invoked when `archive_corpus=1`):

```bash
save_corpus_archive() {
  local archive_path="$1"
  local archive_dir archive_tmp
  archive_dir="$(dirname "${archive_path}")"
  archive_tmp="${archive_path}.tmp"
  mkdir -p "${archive_dir}"
  rm -f "${archive_tmp}"
  ( cd "${corpus_dir}" && zip -qry "${archive_tmp}" . )
  mv "${archive_tmp}" "${archive_path}"
  sha256sum "${archive_path}" >"${archive_path}.sha256"
  echo "Saved phase3 corpus archive: ${archive_path}"
}
```

3d. Replace the `archive_path=...`/`save_artifacts` block near the end of the file with the
split-path logic:

```bash
archive_path=""
corpus_archive_path=""
if [ -n "${artifacts_dir}" ]; then
  base="${artifacts_dir}/${project}/${variant}/${job_name}"
  archive_path="${base}/trials/trial-${trial_label}-${pod_name}.zip"
  corpus_archive_path="${base}/corpora/corpus-${trial_label}-${pod_name}.zip"
fi

write_metadata "${outcome}" "${fuzzer_exit}" "${pod_exit}" "${end_time}" "${elapsed_seconds}" "${archive_path}"

artifact_exit=0
set +e
save_artifacts "${archive_path}"
artifact_exit="$?"
if [ "${archive_corpus}" = "1" ] && [ -n "${corpus_archive_path}" ]; then
  save_corpus_archive "${corpus_archive_path}"
fi
set -e
```

(Remove the old single-archive `save_artifacts` body and the old `archive_path=...` block that
embedded corpus via `archive_corpus`.)

- [ ] **Step 4: Run test + shell syntax check**

Run: `python3 -m pytest test_phase3_k8s_images.py::test_entrypoint_emits_crash_times_and_splits_corpus -v`
Expected: PASS
Run: `bash -n k8s/phase3/entrypoint.sh`
Expected: exit 0

- [ ] **Step 5: Commit**

```bash
git add k8s/phase3/entrypoint.sh test_phase3_k8s_images.py
git commit -m "feat(phase3): split corpus archive + emit crash_times.json in entrypoint"
```

---

## Task 11: Dispatch in run_benchmark.run_phase_trials

**Files:**
- Modify: `run_benchmark.py` (inside `run_phase_trials`, at the `run_all_trials_slot` call)
- Test: `test_run_benchmark.py`

- [ ] **Step 1: Write the failing test (append to `test_run_benchmark.py`)**

```python
def test_run_phase_trials_dispatches_to_k8s(monkeypatch):
    import run_benchmark
    import config
    monkeypatch.setattr(config, "PHASE3_BACKEND", "k8s")
    called = {}

    import phase3_k8s
    monkeypatch.setattr(phase3_k8s, "run_all_trials_k8s",
                        lambda manifest, experiment_id, duration=None, **k:
                        called.setdefault("k8s", (experiment_id, duration)) or [])
    # local path must NOT be called
    import phase3_runner
    monkeypatch.setattr(phase3_runner, "run_all_trials_slot",
                        lambda *a, **k: called.setdefault("local", True))

    backend = run_benchmark._phase3_backend()
    assert backend == "k8s"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest test_run_benchmark.py::test_run_phase_trials_dispatches_to_k8s -v`
Expected: FAIL with `AttributeError: module 'run_benchmark' has no attribute '_phase3_backend'`

- [ ] **Step 3: Add a backend helper + dispatch**

Add near the top of `run_benchmark.py` (after imports):

```python
def _phase3_backend() -> str:
    import config
    return os.environ.get("PHASE3_BACKEND", getattr(config, "PHASE3_BACKEND", "k8s")).lower()
```

In `run_phase_trials`, replace the direct `run_all_trials_slot(...)` call with:

```python
    if _phase3_backend() == "k8s":
        import phase3_k8s
        results = phase3_k8s.run_all_trials_k8s(
            setup_manifest, experiment_id, duration=duration,
        )
    else:
        results = run_all_trials_slot(
            setup_manifest, experiment_id, duration, max_parallel, resume=resume,
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest test_run_benchmark.py::test_run_phase_trials_dispatches_to_k8s -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add run_benchmark.py test_run_benchmark.py
git commit -m "feat(phase3): dispatch run_phase_trials on PHASE3_BACKEND"
```

---

## Task 12: Point the Job-contract test at generated manifests

**Files:**
- Modify: `test_phase3_k8s_images.py`

- [ ] **Step 1: Replace the stale static-file Job test**

Replace `test_phase3_k8s_jobs_run_100_indexed_paired_seed_trials` (which reads the static `jobs.yaml` with `completions: 1`) with a test that validates `phase3_k8s.generate_jobs` output:

```python
def test_generated_jobs_match_indexed_contract():
    import phase3_k8s
    import config
    manifest = [{"project": "gpac", "cve": "CVE-2022-1441", "fuzz_target": "fuzz_parse"}]
    jobs = phase3_k8s.generate_jobs(
        manifest, experiment_id="exp1", duration=21600,
        image_for=lambda p, v: f"img-{p}-{v}", trials=100, parallelism=10,
    )
    assert len(jobs) == 2
    for job in jobs:
        assert job["spec"]["completions"] == 100
        assert job["spec"]["parallelism"] == 10
        assert job["spec"]["completionMode"] == "Indexed"
        assert job["spec"]["backoffLimitPerIndex"] == 0
        assert job["spec"]["ttlSecondsAfterFinished"] == 432000
        env = {e["name"]: e for e in job["spec"]["template"]["spec"]["containers"][0]["env"]}
        assert env["BASE_SEED"]["value"] == "1337"
        assert env["SEED_MULTIPLIER"]["value"] == "1000"
        assert "SEED" not in env
    # paired seeds: baseline and optimized share BASE_SEED/SEED_MULTIPLIER
    seeds = {}
    for job in jobs:
        v = job["spec"]["template"]["metadata"]["labels"]["phase3-variant"]
        env = {e["name"]: e for e in job["spec"]["template"]["spec"]["containers"][0]["env"]}
        seeds[v] = (env["BASE_SEED"]["value"], env["SEED_MULTIPLIER"]["value"])
    assert seeds["baseline"] == seeds["optimized"]
```

Keep `test_phase3_k8s_image_matrix_uses_codex4_artifacts` and `test_phase3_k8s_manifests_reference_every_image` as-is (they validate the historical static fixtures, which remain as examples).

- [ ] **Step 2: Run the test**

Run: `python3 -m pytest test_phase3_k8s_images.py -v`
Expected: PASS (the stale `completions: 1` failure is gone; generation is validated instead)

- [ ] **Step 3: Commit**

```bash
git add test_phase3_k8s_images.py
git commit -m "test(phase3): validate generated Indexed Jobs instead of static fixture"
```

---

## Final verification

- [ ] **Run the full benchmark test subset**

Run:
```bash
python3 -m pytest test_phase3_k8s_runner.py test_phase3_k8s_images.py \
  test_run_benchmark.py test_phase2_setup.py test_phase4_analysis.py \
  test_real_fuzzer_profile.py test_replay_timing.py -q
```
Expected: all PASS.

- [ ] **Shell syntax check**

Run: `bash -n k8s/phase3/entrypoint.sh`
Expected: exit 0.

- [ ] **End-to-end (manual, needs a cluster + registry):**
  1. `export PHASE3_BACKEND=k8s PHASE3_K8S_TRIALS=2 PHASE3_K8S_PARALLELISM=2`
  2. Run a 1-CVE experiment with a short `--duration` (e.g. 120).
  3. Confirm: images pushed; `kubectl get jobs` shows both jobs complete; `results/<exp>/<key>/<variant>/trial_00/` has `metadata.json`, `crash_times.json`, `fuzzer.log`; `setup_metadata.json` has a `replay` block.
  4. Run phase 4 and confirm the report renders with `replay_speedup` and time-to-bug.

---

## Notes for the implementer
- `phase3_runner.parse_fuzzer_stats` is the source of truth for `final_stats` keys — read it before Task 3 and match keys exactly.
- The image build (Task 9 `build_and_push_images`) passes `--build-arg FUZZ_TARGET=...`; confirm `k8s/phase3/Dockerfile` accepts that ARG and copies the binary + seed corpus from the build-context bin dir. If the Dockerfile expects a different context layout, stage a context dir (binary, `<target>_seed_corpus.zip`, merged corpus, `llvm-symbolizer`) before `docker build`, mirroring `k8s/phase3/build-images.sh`.
- `apply_and_wait`/`collect_artifacts` shell out to real `kubectl`; they are covered only by the injected-stage orchestrator test (Task 9). Exercise them in the manual end-to-end run.
- Paired seeds are intentional for k8s (matches `entrypoint.sh`), differing from the local runner's variant-offset seeds — documented in the spec.
