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


def test_generated_jobs_match_indexed_contract():
    import phase3_k8s
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
    seeds = {}
    for job in jobs:
        v = job["spec"]["template"]["metadata"]["labels"]["phase3-variant"]
        env = {e["name"]: e for e in job["spec"]["template"]["spec"]["containers"][0]["env"]}
        seeds[v] = (env["BASE_SEED"]["value"], env["SEED_MULTIPLIER"]["value"])
    assert seeds["baseline"] == seeds["optimized"]


def test_entrypoint_emits_crash_times_and_splits_corpus():
    entrypoint = (K8S_DIR / "entrypoint.sh").read_text()
    assert "collect_crash_times" in entrypoint
    assert "crash_times.json" in entrypoint
    assert "start_epoch" in entrypoint
    assert "/trials/" in entrypoint
    assert "/corpora/" in entrypoint
    assert "save_corpus_archive" in entrypoint
    assert "staging_dir}/corpus" not in entrypoint
