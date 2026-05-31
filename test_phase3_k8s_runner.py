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


def test_pick_biggest_baseline_corpus_by_file_count():
    trials = [
        {"trial_id": 0, "corpus_file_count": 100},
        {"trial_id": 1, "corpus_file_count": 4212},
        {"trial_id": 2, "corpus_file_count": 3000},
    ]
    winner = phase3_k8s.pick_biggest_corpus(trials)
    assert winner["trial_id"] == 1


def test_pick_biggest_corpus_returns_none_for_empty():
    assert phase3_k8s.pick_biggest_corpus([]) is None


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
    assert "--exclude=*/corpora" in joined


def test_collector_pod_spec_mounts_pvc():
    spec = phase3_k8s.collector_pod_spec(name="phase3-collector")
    c = spec["spec"]["containers"][0]
    assert {"name": "artifacts", "mountPath": "/artifacts"} in c["volumeMounts"]
    assert spec["spec"]["volumes"][0]["persistentVolumeClaim"]["claimName"] == "nfs"
    assert spec["spec"]["restartPolicy"] == "Never"
