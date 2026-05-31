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
