"""Benchmark configuration constants."""

import os
from pathlib import Path

# Paths
OSS_FUZZ_DIR = "/home/sefcom/asu/project/oss-fuzz"
OSS_FUZZ_VULNS_DIR = "/home/sefcom/asu/project/oss-fuzz-vulns"
BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BENCHMARK_DIR, "results")
MANIFEST_PATH = os.path.join(BENCHMARK_DIR, "manifest.json")

# Trial parameters
NUM_TRIALS = 10
TRIAL_DURATION_SECS = 21600  # 6 hours
MEMORY_LIMIT = "4g"
MEMORY_LIMIT_RETRY = "8g"
RSS_LIMIT_MB = 3072
MAX_FAILED_TRIALS = 3  # If more than this many trials fail, exclude CVE

# Machine resources
TOTAL_CORES = 40
RESERVED_CORES = 4
USABLE_CORES = TOTAL_CORES - RESERVED_CORES  # 36
PHASE2_MAX_PARALLEL = 4
PHASE2_BASELINE_PROFILE_DURATION_SECS = 1200
PHASE2_REFRESH_PROFILE_DURATION_SECS = 300

# Deterministic corpus-replay speed measurement (replaces live exec/s as the
# headline throughput metric). Replay times the SAME frozen corpus snapshot on
# the baseline and optimized binaries, so the comparison is apples-to-apples and
# immune to the coverage-gradient divergence that makes live exec/s misleading.
PHASE2_REPLAY_REPEATS = 3

# Wall-clock cap on a single optimizer (claude/codex) invocation. A hung agent
# (e.g. waiting on an inner Docker step that never returns) is killed and
# recorded as timed-out instead of wedging the phase-2 worker indefinitely.
PHASE2_OPTIMIZER_TIMEOUT_SECS = int(
    os.environ.get("PHASE2_OPTIMIZER_TIMEOUT_SECS", "10800")  # 3 hours
)

# Which agent CLI drives the phase-2 source optimization: "claude" or "codex".
# Overridable per-run with the BENCHMARK_OPTIMIZER env var.
OPTIMIZER_BACKEND = os.environ.get("BENCHMARK_OPTIMIZER", "claude").lower()

# Skill helper scripts (real_fuzzer_profile.py, replay_timing.py, ...). The
# Claude and Codex skill trees carry identical copies; pick the one matching the
# active optimizer backend so the benchmark loads the same helpers the agent uses.
PHASE2_SKILL_SCRIPTS_DIR = (
    "/home/sefcom/.claude/skills/apply-fuzz-source-folds/scripts"
    if OPTIMIZER_BACKEND == "claude"
    else "/home/sefcom/.codex/skills/apply-profile-guided-folds/scripts"
)

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

# Seed generation
BASE_SEED = 1337
BASELINE_SEED_OFFSET = 0
OPTIMIZED_SEED_OFFSET = 500
SEED_MULTIPLIER = 1000
SHUFFLE_SEED = 42

# Coverage snapshot interval (seconds)
COVERAGE_SNAPSHOT_INTERVAL = 1800  # 30 minutes

# Docker
DOCKER_SHM_SIZE = "2g"
SANITIZER = "address"
ENGINE = "libfuzzer"
ARCHITECTURE = "x86_64"

# Crash types to include (exclude timeouts, OOM, leaks)
CRASH_TYPES = {
    "heap-buffer-overflow",
    "heap-use-after-free",
    "stack-buffer-overflow",
    "stack-use-after-free",
    "global-buffer-overflow",
    "use-after-free",
    "double-free",
    "null-dereference",
    "stack-overflow",
    "out-of-bounds",
    "heap-double-free",
    "integer-overflow",
    "type-confusion",
    "bad-cast",
    "container-overflow",
    "negative-size-param",
    "alloc-dealloc-mismatch",
    "use-after-poison",
    "use-after-scope",
    "memcpy-param-overlap",
    "buffer-overflow",
    "signed-integer-overflow",
    "unsigned-integer-overflow",
    "shift-exponent",
    "divide-by-zero",
}

# GCS corpus URL template
CORPUS_URL_TEMPLATE = (
    "https://storage.googleapis.com/"
    "{project}-backup.clusterfuzz-external.appspot.com/"
    "corpus/libFuzzer/{fuzz_target}/public.zip"
)

# Local seed-corpus cache, used as a fallback when the public GCS corpus is
# unavailable (e.g. HTTP 403) and the build ships no seed corpus. Layout:
#   <LOCAL_CORPUS_CACHE_DIR>/<project>/<fuzz_target>/<seed files>
LOCAL_CORPUS_CACHE_DIR = os.environ.get(
    "LOCAL_CORPUS_CACHE_DIR", os.path.join(BENCHMARK_DIR, "corpus_cache")
)

# Target number of CVEs to select
TARGET_CVE_COUNT = 10
MIN_CVE_COUNT = 3

# ARVO reproducer
ARVO_REPRODUCER_DIR = "/home/sefcom/asu/project/oss-fuzz/infra/experimental/contrib/arvo"
ARVO_OUT_DIR = Path("/tmp")
ARVO_BASELINE_DENYLIST_PATH = os.path.join(
    BENCHMARK_DIR, "arvo_baseline_denylist.json"
)

# PoC verification timeout (seconds)
QUICK_VERIFY_DURATION = 30

# Progress monitoring interval (seconds)
MONITOR_INTERVAL = 60

# State file for orchestrator
STATE_FILE = "state.json"
