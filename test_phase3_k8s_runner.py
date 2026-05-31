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
