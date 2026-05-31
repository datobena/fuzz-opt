"""Phase 3 runner that executes trials as Kubernetes Indexed Jobs.

Stages: build+push images -> generate Jobs -> apply -> wait -> collect (helper
pod) -> transform to the trial_XX/ layout -> replay-speed metric. Pure builders
are unit-tested; subprocess calls are injected so they can be faked in tests.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path

import config
import phase3_runner

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


def pick_biggest_corpus(baseline_trials: list[dict]) -> dict | None:
    """Pick the baseline trial whose corpus has the most files."""
    if not baseline_trials:
        return None
    return max(baseline_trials, key=lambda t: int(t.get("corpus_file_count", 0)))


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
