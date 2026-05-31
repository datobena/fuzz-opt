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
