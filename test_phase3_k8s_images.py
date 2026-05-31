import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent
K8S_DIR = ROOT / "k8s" / "phase3"
REMOTE_IMAGE_PREFIX = "dbenashv/benchmark"


def test_phase3_k8s_image_matrix_uses_codex4_artifacts():
    matrix_path = K8S_DIR / "images.json"
    images = json.loads(matrix_path.read_text())

    expected = {
        ("selinux", "CVE-2021-36084", "secilc-fuzzer"),
        ("gpac", "CVE-2022-1441", "fuzz_parse"),
        ("librawspeed", "CVE-2018-25017", "RawParserFuzzer-GetDecoder-Decode"),
        ("unrar", "CVE-2017-20006", "unrar_fuzzer"),
    }
    variants = {"baseline", "optimized"}

    assert len(images) == len(expected) * len(variants)
    assert {(i["project"], i["cve"], i["fuzz_target"]) for i in images} == expected
    assert {i["variant"] for i in images} == variants

    for item in images:
        artifact_dir = ROOT / item["artifact_dir"]
        fuzzer = artifact_dir / item["fuzz_target"]
        metadata_path = (
            ROOT
            / "results"
            / item["experiment_id"]
            / f"{item['project']}-{item['cve']}"
            / "setup_metadata.json"
        )
        metadata = json.loads(metadata_path.read_text())

        assert item["experiment_id"] == "codex-4"
        assert artifact_dir == (
            ROOT
            / "results"
            / "codex-4"
            / f"{item['project']}-{item['cve']}"
            / item["variant"]
            / "bin"
        )
        assert fuzzer.is_file()
        assert item["image"] == f"phase3-{item['project']}-{item['variant']}:codex-4"
        assert metadata["verification"][item["variant"]] is True
        assert metadata["verification"]["optimization_applied"] is True


def test_phase3_k8s_manifests_reference_every_image():
    images = json.loads((K8S_DIR / "images.json").read_text())
    pods = (K8S_DIR / "pods.yaml").read_text()
    smoke_pods = (K8S_DIR / "smoke-pods.yaml").read_text()
    build_script = (K8S_DIR / "build-images.sh").read_text()

    assert (K8S_DIR / "Dockerfile").is_file()
    assert "kind load docker-image" in build_script

    for item in images:
        assert item["image"] in pods
        assert item["image"] in smoke_pods
        assert f"name: phase3-{item['project']}-{item['variant']}" in pods
        assert f"name: phase3-{item['project']}-{item['variant']}-smoke" in smoke_pods

    assert pods.count("imagePullPolicy: IfNotPresent") == len(images)
    assert smoke_pods.count("DURATION_SECONDS") == len(images)
    assert pods.count("memory: 8Gi") == len(images)
    assert smoke_pods.count("memory: 8Gi") == len(images)
    assert pods.count('value: "8192"') >= len(images)
    assert smoke_pods.count('value: "8192"') >= len(images)
    assert pods.count("MALLOC_LIMIT_MB") == len(images)
    assert smoke_pods.count("MALLOC_LIMIT_MB") == len(images)
    assert "allowPrivilegeEscalation" not in pods
    assert "allowPrivilegeEscalation" not in smoke_pods


def test_phase3_k8s_jobs_run_100_indexed_paired_seed_trials():
    images = json.loads((K8S_DIR / "images.json").read_text())
    jobs_yaml = (K8S_DIR / "jobs.yaml").read_text()
    entrypoint = (K8S_DIR / "entrypoint.sh").read_text()
    dockerfile = (K8S_DIR / "Dockerfile").read_text()
    jobs = list(yaml.safe_load_all(jobs_yaml))

    assert len(jobs) == len(images)
    assert "allowPrivilegeEscalation" not in jobs_yaml
    assert "TRIAL_ID" in entrypoint
    assert "BASE_SEED" in entrypoint
    assert "SEED_MULTIPLIER" in entrypoint
    assert "seed=$((base_seed + trial_id * seed_multiplier))" in entrypoint
    assert "add_supported_flag" in entrypoint
    assert "verbosity" in entrypoint
    assert "print_corpus_stats" in entrypoint
    assert "print_funcs" in entrypoint
    assert "report_slow_units" in entrypoint
    assert "classify_fuzzer_exit" in entrypoint
    assert "save_artifacts" in entrypoint
    assert "PIPESTATUS[0]" in entrypoint
    assert 'tee "${log_file}"' in entrypoint
    assert "collect_corpus_stats" in entrypoint
    assert "corpus_file_count=" in entrypoint
    assert "corpus_du_bytes=" in entrypoint
    assert "corpus_du_human=" in entrypoint
    assert "corpus_archived=${archive_corpus}" in entrypoint
    assert "corpus_stats" in entrypoint
    assert 'exit "${pod_exit}"' in entrypoint
    assert 'exec "/out/${target}"' not in entrypoint
    assert not any(
        line.startswith("ENV SEED=") for line in dockerfile.splitlines()
    )

    image_by_project_variant = {
        (item["project"], item["variant"]): item["image"] for item in images
    }
    seeds_by_project = {}

    for job in jobs:
        assert job["apiVersion"] == "batch/v1"
        assert job["kind"] == "Job"
        assert job["spec"]["completions"] == 100
        assert job["spec"]["parallelism"] == 10
        assert job["spec"]["completionMode"] == "Indexed"
        assert job["spec"]["backoffLimitPerIndex"] == 0
        assert job["spec"]["maxFailedIndexes"] == 100
        assert job["spec"]["ttlSecondsAfterFinished"] == 432000

        container = job["spec"]["template"]["spec"]["containers"][0]
        labels = job["spec"]["template"]["metadata"]["labels"]
        project = labels["phase3-project"]
        variant = labels["phase3-variant"]
        env = {item["name"]: item for item in container["env"]}

        assert container["image"] == (
            REMOTE_IMAGE_PREFIX + image_by_project_variant[(project, variant)]
        )
        assert container["imagePullPolicy"] == "Always"
        assert container["securityContext"] == {"privileged": True}
        assert "SEED" not in env
        assert env["BASE_SEED"]["value"] == "1337"
        assert env["SEED_MULTIPLIER"]["value"] == "1000"
        assert env["DURATION_SECONDS"]["value"] == "21600"
        assert env["RSS_LIMIT_MB"]["value"] == "8192"
        assert env["MALLOC_LIMIT_MB"]["value"] == "8192"
        assert env["ARTIFACTS_DIR"]["value"] == "/artifacts/bena/phase3-kube"
        assert env["ARCHIVE_CORPUS"]["value"] == "0"
        assert env["POD_NAME"]["valueFrom"]["fieldRef"]["fieldPath"] == (
            "metadata.name"
        )
        assert env["JOB_NAME"]["valueFrom"]["fieldRef"]["fieldPath"] == (
            "metadata.labels['job-name']"
        )
        assert env["TRIAL_ID"]["valueFrom"]["fieldRef"]["fieldPath"] == (
            "metadata.annotations['batch.kubernetes.io/job-completion-index']"
        )
        assert container["resources"]["requests"]["memory"] == "12Gi"
        assert container["resources"]["limits"]["memory"] == "12Gi"
        assert {"name": "artifacts", "mountPath": "/artifacts"} in container[
            "volumeMounts"
        ]
        assert {
            "name": "artifacts",
            "persistentVolumeClaim": {"claimName": "nfs"},
        } in job["spec"]["template"]["spec"]["volumes"]

        seeds_by_project.setdefault(project, {})[variant] = (
            env["BASE_SEED"]["value"],
            env["SEED_MULTIPLIER"]["value"],
        )

    for variants in seeds_by_project.values():
        assert variants["baseline"] == variants["optimized"]
