# test_phase3_k8s_runner.py
import json
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


def test_optimized_job_archives_corpus_by_default():
    # Both variants now archive by default so optimized corpora survive for
    # coverage-over-time / covdiff without a re-run.
    job = phase3_k8s.build_job_spec(
        project="gpac", cve="CVE-2022-1441", variant="optimized",
        fuzz_target="fuzz_parse", experiment_id="exp1",
        image="img:opt", trials=100, parallelism=10, duration=21600,
    )
    env = {e["name"]: e for e in job["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["ARCHIVE_CORPUS"]["value"] == "1"


def test_archive_baseline_only_opt_out(monkeypatch):
    monkeypatch.setenv("PHASE3_ARCHIVE_BASELINE_ONLY", "1")
    opt = phase3_k8s.build_job_spec(
        project="gpac", cve="CVE-2022-1441", variant="optimized",
        fuzz_target="fuzz_parse", experiment_id="exp1",
        image="img:opt", trials=100, parallelism=10, duration=21600,
    )
    base = phase3_k8s.build_job_spec(
        project="gpac", cve="CVE-2022-1441", variant="baseline",
        fuzz_target="fuzz_parse", experiment_id="exp1",
        image="img:base", trials=100, parallelism=10, duration=21600,
    )
    opt_env = {e["name"]: e for e in opt["spec"]["template"]["spec"]["containers"][0]["env"]}
    base_env = {e["name"]: e for e in base["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert opt_env["ARCHIVE_CORPUS"]["value"] == "0"
    assert base_env["ARCHIVE_CORPUS"]["value"] == "1"


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


def test_write_trial_dir_produces_phase4_inputs(tmp_path):
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
    monkeypatch.setattr(phase3_k8s, "_run", lambda *a, **k: calls.append("cleanup"))

    manifest = [{"project": "gpac", "cve": "CVE-2022-1441", "fuzz_target": "fuzz_parse"}]
    results = phase3_k8s.run_all_trials_k8s(manifest, "exp1", duration=60)

    assert calls == ["build", "apply", "collect", "transform", "replay", "cleanup"]
    assert results == [{"trial": "t0"}]


def test_stage_build_context_lays_out_dockerfile_dirs(tmp_path):
    bin_dir = tmp_path / "bin"; bin_dir.mkdir()
    (bin_dir / "fuzz_parse").write_text("ELF")
    (bin_dir / "llvm-symbolizer").write_text("x")
    (bin_dir / "fuzz_parse.dict").write_text("d")
    seed = tmp_path / "merged"; seed.mkdir(); (seed / "s0").write_text("a")
    poc = tmp_path / "poc"; poc.mkdir(); (poc / "poc_input").write_text("p")
    dest = tmp_path / "ctx"
    phase3_k8s.stage_build_context(
        bin_dir=bin_dir, seed_corpus_dir=seed, poc_dir=poc,
        fuzz_target="fuzz_parse", dest=dest,
    )
    assert (dest / "out" / "fuzz_parse").is_file()
    assert (dest / "out" / "llvm-symbolizer").is_file()
    assert (dest / "out" / "fuzz_parse.dict").is_file()
    assert (dest / "seed-corpus" / "s0").is_file()
    assert (dest / "poc" / "poc_input").is_file()
    assert (dest / "entrypoint.sh").is_file()


def test_stage_build_context_missing_target_raises(tmp_path):
    import pytest
    bin_dir = tmp_path / "bin"; bin_dir.mkdir()
    with pytest.raises(FileNotFoundError):
        phase3_k8s.stage_build_context(
            bin_dir=bin_dir, seed_corpus_dir=tmp_path / "x", poc_dir=tmp_path / "y",
            fuzz_target="missing", dest=tmp_path / "ctx",
        )


def test_apply_and_wait_raises_on_deadline(monkeypatch):
    jobs = [{"metadata": {"name": "j1"}, "spec": {"completions": 100}}]
    monkeypatch.setattr(phase3_k8s, "_run",
                        lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "0/0", "stderr": ""})())
    ticks = iter([0, 1, 10_000, 20_000])
    import pytest
    with pytest.raises(TimeoutError):
        phase3_k8s.apply_and_wait(jobs, deadline_secs=100, sleep=lambda s: None,
                                  clock=lambda: next(ticks))
