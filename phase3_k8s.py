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
import tempfile
import time
import zipfile
from pathlib import Path

import config
import phase3_runner
import yaml

logger = logging.getLogger(__name__)


def cve_key(project: str, cve: str) -> str:
    return f"{project}-{cve}"


def image_name(project: str, variant: str, experiment_id: str) -> str:
    # The image-name convention concatenates the prefix directly (matches the
    # existing k8s/phase3 contract); set PHASE3_K8S_IMAGE_PREFIX with any
    # needed separator.
    # Docker repository names must be lowercase (e.g. PcapPlusPlus -> pcapplusplus).
    return (
        f"{config.PHASE3_K8S_IMAGE_PREFIX}phase3-{project.lower()}-{variant}"
        f":{experiment_id}"
    )


def job_name(project: str, variant: str, experiment_id: str = "") -> str:
    # DNS-1123: lowercase, no underscores. Scope by experiment_id so concurrent
    # experiments (and reruns) never collide on k8s Job names (e.g. a stale
    # phase3-selinux-baseline from a prior run).
    base = f"phase3-{project}-{variant}"
    if experiment_id:
        base = f"{base}-{experiment_id}"
    return base.lower().replace("_", "-")


def build_job_spec(
    *, project: str, cve: str, variant: str, fuzz_target: str,
    experiment_id: str, image: str, trials: int, parallelism: int, duration: int,
) -> dict:
    # Corpus archiving. Both variants are archived by DEFAULT so the generated
    # corpora survive for offline analysis without a re-run: baseline corpora feed
    # the replay-timing metric, and optimized corpora feed differential coverage
    # studies (covdiff / coverage-over-time — replay each variant's corpus on the
    # baseline binary and compare edge coverage; see tools/run_covtime.py).
    # PHASE3_ARCHIVE_BASELINE_ONLY=1 reverts to baseline-only to save NFS space
    # (optimized corpora roughly double per-project corpus storage).
    # PHASE3_ARCHIVE_ALL_CORPUS=1 is still honored as an explicit force-all.
    if os.environ.get("PHASE3_ARCHIVE_ALL_CORPUS") == "1":
        archive_corpus = "1"
    elif os.environ.get("PHASE3_ARCHIVE_BASELINE_ONLY") == "1":
        archive_corpus = "1" if variant == "baseline" else "0"
    else:
        archive_corpus = "1"
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
        "metadata": {"name": job_name(project, variant, experiment_id)},
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
                    # Kill a trial that runs past the fuzz duration + 1h buffer so a
                    # hung fuzzer is marked failed (the job still reaches terminal)
                    # instead of stalling the wave until the apply_and_wait deadline.
                    "activeDeadlineSeconds": duration + 3600,
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


def _load_replay_module():
    import importlib.util
    scripts_dir = getattr(config, "PHASE3_SKILL_SCRIPTS_DIR", None) or config.PHASE2_SKILL_SCRIPTS_DIR
    script = Path(scripts_dir) / "replay_timing.py"
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
            min_partial_units=int(getattr(config, "PHASE2_REPLAY_MIN_PARTIAL_UNITS", 500)),
        )
        baseline = measure(out_dir=str(baseline_bin_dir), **common)
        optimized = measure(out_dir=str(optimized_bin_dir), **common)
        b, o = baseline.get("median_time_s"), optimized.get("median_time_s")
        # rate-normalize when a crasher truncated the pass (see measure_binary)
        partial = bool(baseline.get("partial") or optimized.get("partial"))
        if partial:
            bu, ou = baseline.get("executed_units"), optimized.get("executed_units")
            speedup = round((ou / o) / (bu / b), 4) if (b and o and bu and ou) else None
        else:
            speedup = round(b / o, 4) if (b and o) else None

        meta_path = Path(key_dir) / "setup_metadata.json"
        meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        meta["replay"] = {
            "replay_speedup": speedup, "partial": partial,
            "baseline": baseline, "optimized": optimized,
            "corpus_source": "k8s_biggest_baseline",
            "corpus_file_count": sum(1 for p in Path(corpus_dir).rglob("*") if p.is_file()),
        }
        meta_path.write_text(json.dumps(meta, indent=2))
        return speedup
    except Exception as exc:
        logger.warning("k8s replay metric failed for %s: %s", key_dir, exc)
        return None


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


def stage_build_context(*, bin_dir, seed_corpus_dir, poc_dir, fuzz_target, dest):
    """Stage a Docker build context matching k8s/phase3/Dockerfile.

    Lays out out/ (fuzz target + companions), seed-corpus/, poc/, and entrypoint.sh.
    """
    dest = Path(dest)
    out_d, sc_d, poc_d = dest / "out", dest / "seed-corpus", dest / "poc"
    for d in (out_d, sc_d, poc_d):
        d.mkdir(parents=True, exist_ok=True)
    bin_dir = Path(bin_dir)
    target_bin = bin_dir / fuzz_target
    if not target_bin.is_file():
        raise FileNotFoundError(f"fuzz target missing: {target_bin}")
    shutil.copy2(target_bin, out_d / fuzz_target)
    for companion in ("llvm-symbolizer", f"{fuzz_target}.dict",
                      f"{fuzz_target}_seed_corpus.zip"):
        src = bin_dir / companion
        if src.is_file():
            shutil.copy2(src, out_d / companion)
    seed_corpus_dir = Path(seed_corpus_dir)
    if seed_corpus_dir.is_dir():
        for p in seed_corpus_dir.iterdir():
            if p.is_file():
                shutil.copy2(p, sc_d / p.name)
    poc_dir = Path(poc_dir)
    if poc_dir.is_dir():
        for p in poc_dir.iterdir():
            if p.is_file():
                shutil.copy2(p, poc_d / p.name)
    entrypoint = Path(__file__).resolve().parent / "k8s" / "phase3" / "entrypoint.sh"
    shutil.copy2(entrypoint, dest / "entrypoint.sh")
    return dest


def extract_initial_corpus(bin_dir, fuzz_target, dest) -> int:
    """Populate ``dest`` with the project's BUNDLED INITIAL seed corpus, i.e. the
    files inside ``<bin_dir>/<fuzz_target>_seed_corpus.zip`` (flattened).

    Policy: phase-3 fuzzing is seeded ONLY from the canonical bundled seed corpus
    -- the curated, crash-free starting point a real campaign begins from -- NOT
    from the accumulated public corpus (which for a vulnerable target contains the
    crash reproducer and yields an instant, meaningless time-to-bug). Targets that
    ship no ``_seed_corpus.zip`` start cold (return 0); a ``.dict`` companion, if
    any, still assists libFuzzer.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    zip_path = Path(bin_dir) / f"{fuzz_target}_seed_corpus.zip"
    if not zip_path.is_file():
        return 0
    n = 0
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            out = dest / Path(info.filename).name
            if out.exists():  # flattened name clash; keep first
                continue
            out.write_bytes(zf.read(info))
            n += 1
    return n


def build_and_push_images(manifest, experiment_id):
    """Build+push a phase3 image per (project,cve,variant) from phase-2 binaries.

    Returns {(project, variant): image}. Stages a context matching
    k8s/phase3/Dockerfile (out/, seed-corpus/, poc/, entrypoint.sh). Shells out
    to docker; assumes docker login. Phase-3 seeds come from the bundled INITIAL
    seed corpus (see extract_initial_corpus), never the accumulated public corpus.
    """
    built = {}
    dockerfile = Path(__file__).resolve().parent / "k8s" / "phase3" / "Dockerfile"
    for entry in manifest:
        project, cve = entry["project"], entry["cve"]
        fuzz_target = entry.get("fuzz_target", "")
        base = Path(config.RESULTS_DIR) / experiment_id / cve_key(project, cve)
        for variant in ("baseline", "optimized"):
            image = image_name(project, variant, experiment_id)
            with tempfile.TemporaryDirectory(prefix="phase3-ctx-") as ctx, \
                    tempfile.TemporaryDirectory(prefix="phase3-seed-") as seeddir:
                n_seed = extract_initial_corpus(
                    base / variant / "bin", fuzz_target, seeddir)
                logger.info("phase3 seeds for %s/%s: %d initial-corpus files%s",
                            project, variant, n_seed,
                            " (COLD START: no bundled seed corpus)" if n_seed == 0
                            else "")
                stage_build_context(
                    bin_dir=base / variant / "bin",
                    seed_corpus_dir=seeddir,
                    poc_dir=base / "poc",
                    fuzz_target=fuzz_target,
                    dest=ctx,
                )
                build = [
                    "docker", "build", "-f", str(dockerfile),
                    "--build-arg", f"PROJECT={project}",
                    "--build-arg", f"CVE={cve}",
                    "--build-arg", f"VARIANT={variant}",
                    "--build-arg", f"EXPERIMENT_ID={experiment_id}",
                    "--build-arg", f"FUZZ_TARGET={fuzz_target}",
                    "-t", image, ctx,
                ]
                if _run(build).returncode != 0:
                    raise RuntimeError(f"docker build failed for {image}")
            if _run(["docker", "push", image]).returncode != 0:
                raise RuntimeError(f"docker push failed for {image}")
            built[(project, variant)] = image
    return built


def apply_and_wait(jobs, *, namespace="", poll_secs=30, deadline_secs=None,
                   sleep=time.sleep, clock=time.monotonic):
    ns = namespace or config.PHASE3_K8S_NAMESPACE
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        yaml.safe_dump_all(jobs, f)
        path = f.name
    if _run(kubectl_apply_cmd(path, ns)).returncode != 0:
        raise RuntimeError("kubectl apply failed")
    pending = {j["metadata"]["name"]: j["spec"]["completions"] for j in jobs}
    start = clock()
    while pending:
        for name, completions in list(pending.items()):
            res = _run(kubectl_job_status_cmd(name, ns))
            if res.returncode != 0:
                logger.warning("status poll failed for %s: %s",
                               name, (res.stderr or "")[-200:])
                continue
            out = res.stdout.strip()
            succeeded, _, failed = out.partition("/")
            s, fl = int(succeeded or 0), int(failed or 0)
            if job_is_terminal(succeeded=s, failed=fl, completions=completions):
                logger.info("job %s terminal: %d ok / %d failed", name, s, fl)
                del pending[name]
        if pending:
            if deadline_secs is not None and (clock() - start) > deadline_secs:
                raise TimeoutError(
                    f"phase3 jobs not terminal after {deadline_secs}s: {sorted(pending)}")
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
    extract = subprocess.run(["tar", "x", "-C", str(dest)], stdin=proc.stdout)
    proc.stdout.close()
    rc = proc.wait()
    if rc != 0 or extract.returncode != 0:
        raise RuntimeError(
            f"collector tar stream failed (exec rc={rc}, extract rc={extract.returncode})")
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
            jname = job_name(project, variant, experiment_id)
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
        jname = job_name(project, "baseline", experiment_id)
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
                         image_for=lambda p, v: images.get((p, v)))
    import math
    waves = max(1, math.ceil(config.PHASE3_K8S_TRIALS / max(1, config.PHASE3_K8S_PARALLELISM)))
    apply_and_wait(jobs, deadline_secs=waves * duration * 2 + 3600)
    collected = collect_artifacts(manifest, experiment_id)
    try:
        results = transform_all(collected, manifest, experiment_id)
        compute_replay_metrics(collected, manifest, experiment_id)
    finally:
        _run(["kubectl", *_ns_args(collected["namespace"]), "delete", "pod",
              collected["pod"], "--wait=false"])
    return results
