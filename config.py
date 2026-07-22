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
# profile-once-fuzz-folds: grow the corpus once by fuzzing the baseline binary for
# this many seconds, freeze it, then profile-on-replay + iterate hotspots with no
# re-profiling. Env-overridable so time-boxed runs can shrink the grow window.
PHASE2_CORPUS_BUILD_DURATION_SECS = int(
    os.environ.get("PHASE2_CORPUS_BUILD_DURATION_SECS", "3600")
)

# Phase-2 corpus policy: use ONLY the seed corpus provided with the project (the
# bundled <target>_seed_corpus.zip), never the GCS accumulated public corpus.
PHASE2_USE_GCS_CORPUS = os.environ.get("PHASE2_USE_GCS_CORPUS", "0") == "1"

# Mutation-augmented profiling: before freezing the fixed corpus, capture the
# mutations libFuzzer generates from the seed corpus (via the custom-mutator shim,
# see mutation_capture.py) and profile+gate on seed+mutations, so the optimizer
# targets the hotspots of the REAL fuzzing workload -- not just the seeds.
# ARVO-image build paths (gcr.io/oss-fuzz/<local_id>, n132/arvo) only.
PHASE2_MUTATION_ENABLED = os.environ.get("PHASE2_MUTATION_ENABLED", "1") == "1"
# Mutation-augmented profiling is the NORMAL, non-optional path -- there is NO
# silent fall-back to seed-only profiling. When mutation capture cannot run or
# yields 0 mutations (no ARVO builder image, shim build/link failure, generation
# crash, etc.) the target is HARD-FAILED at phase 2 (recorded stage=
# mutation_augmentation) rather than quietly optimized on the seeds alone. A
# target whose optimizer simply finds no bug-preserving fold under the mutation
# profile is a legitimate UNOPTIMIZED result (optimized == baseline), not a
# failure and not a reason to retry seed-only. Set 0 ONLY to restore the old
# best-effort seed-only degradation (legacy / OSV runs).
PHASE2_MUTATION_REQUIRED = os.environ.get("PHASE2_MUTATION_REQUIRED", "1") == "1"
PHASE2_MUTATION_CAP = int(os.environ.get("PHASE2_MUTATION_CAP", "20000"))
# Reservoir-sample the mutation stream over max(DURATION, time_for_one_queue) so the
# saved corpus is a UNIFORM sample of the whole run (not the opening prefix), plus a
# guaranteed one-pass over the seed queue. DURATION is the time-cap floor (10 min);
# ensure_one_queue_pass extends it when one queue traversal takes longer. Cap 20k
# keeps the reservoir representative while bounding the replay-gate cost.
PHASE2_MUTATION_DURATION_SECS = int(os.environ.get("PHASE2_MUTATION_DURATION_SECS", "600"))
PHASE2_MUTATION_EVERY = int(os.environ.get("PHASE2_MUTATION_EVERY", "1"))
# Skip build_corpus's probe-and-size step for the mutation-combined corpus (the
# generation cap already bounds it). Set 0 to RE-ENABLE sizing -- needed for slow-
# to-rebuild targets (e.g. wolfssl) that hit the 50k cap: a 51k-file replay gate
# per fold, on top of a slow rebuild, starves the single-turn optimizer of
# iterations, so it keeps no fold. Sizing caps the gate corpus to fit the budget.
PHASE2_MUTATION_SKIP_SIZING = os.environ.get("PHASE2_MUTATION_SKIP_SIZING", "1") == "1"

# Deterministic corpus-replay speed measurement (replaces live exec/s as the
# headline throughput metric). Replay times the SAME frozen corpus snapshot on
# the baseline and optimized binaries, so the comparison is apples-to-apples and
# immune to the coverage-gradient divergence that makes live exec/s misleading.
PHASE2_REPLAY_REPEATS = 3

# Wall-clock cap for each crash-filter container in build_corpus.py (bulk replay
# and, if needed, the per-unit pass). Previously only a getattr fallback.
PHASE2_CRASH_FILTER_TIMEOUT_SECS = int(
    os.environ.get("PHASE2_CRASH_FILTER_TIMEOUT_SECS", "14400")  # 4h
)
# Parallelism (and --cpus quota) for the per-unit crash-filter. >1 filters a
# large/slow-target corpus in ~1/N the wall-clock of a serial pass.
PHASE2_CRASH_FILTER_NCPU = int(os.environ.get("PHASE2_CRASH_FILTER_NCPU", "8"))

# Time-budgeted corpus sizing (build_corpus.py). A full -runs=0 pass costs
# N * T_unit; the replay gate runs 2*repeats such passes (the dominant cost), so
# capping the corpus to the largest N whose gate measurement fits this budget
# keeps profiling + gate + filter tractable even for a slow target (radare2,
# ~seconds/unit, whose unsized ~3k-unit corpus made one pass take tens of
# minutes to hours). A fast target keeps its full corpus. 0 = disabled.
PHASE2_CORPUS_REPLAY_BUDGET_SECS = int(
    os.environ.get("PHASE2_CORPUS_REPLAY_BUDGET_SECS", "1800")  # 30 min
)
PHASE2_CORPUS_PROBE_SAMPLE = int(os.environ.get("PHASE2_CORPUS_PROBE_SAMPLE", "100"))
PHASE2_CORPUS_SIZING_MARGIN = float(os.environ.get("PHASE2_CORPUS_SIZING_MARGIN", "0.7"))
PHASE2_CORPUS_N_MIN = int(os.environ.get("PHASE2_CORPUS_N_MIN", "200"))

# Wall-clock cap on a single optimizer (claude/codex) invocation. A hung agent
# (e.g. waiting on an inner Docker step that never returns) is killed and
# recorded as timed-out instead of wedging the phase-2 worker indefinitely.
PHASE2_OPTIMIZER_TIMEOUT_SECS = int(
    os.environ.get("PHASE2_OPTIMIZER_TIMEOUT_SECS", "18000")  # 5 hours
)

# Strict throughput gate: an accepted optimization MUST measurably speed up the
# deterministic replay of the fixed corpus by at least this factor. A fold whose
# replay speedup does not exceed this (including one whose replay could not be
# measured) is "not worth keeping" — it is reverted to baseline and dropped from
# phase 3. Default 1.02 = require a >2% speedup (a noise margin above run-to-run
# jitter); set 1.0 to accept any measured speedup.
PHASE2_MIN_REPLAY_SPEEDUP = float(
    os.environ.get("PHASE2_MIN_REPLAY_SPEEDUP", "1.02")  # require >2% (noise margin)
)

# Crash-tolerant ("partial") replay measurement. A deterministic, order/heap-
# dependent corpus crasher (one the per-unit filter can't catch, e.g. libjxl's
# StoreU overflow at unit 2616) aborts every full -runs=0 pass, which used to
# blank the speedup to None -> reverted as "unmeasurable". Instead we salvage a
# rate over the deterministic prefix both binaries reach (see
# replay_timing.measure_binary): keep the run if it executed >= this many units
# (below that ~startup dominates and the rate is noise).
PHASE2_REPLAY_MIN_PARTIAL_UNITS = int(
    os.environ.get("PHASE2_REPLAY_MIN_PARTIAL_UNITS", "500")
)
# A partial measurement is over a prefix, not the whole corpus, and its wall-clock
# is mildly startup-diluted, so require a wider margin than a clean full pass
# before keeping a fold on partial evidence.
PHASE2_MIN_REPLAY_SPEEDUP_PARTIAL = float(
    os.environ.get("PHASE2_MIN_REPLAY_SPEEDUP_PARTIAL", "1.05")  # require >5% when partial
)

# Which agent CLI drives the phase-2 source optimization: "claude" or "codex".
# Overridable per-run with the BENCHMARK_OPTIMIZER env var.
OPTIMIZER_BACKEND = os.environ.get("BENCHMARK_OPTIMIZER", "claude").lower()

# Which optimization skill phase 2 drives. The default profiles once on a fixed
# corpus and iterates hotspots without re-profiling; flip back to the old loop
# with PHASE2_OPTIMIZER_SKILL=apply-fuzz-source-folds.
PHASE2_OPTIMIZER_SKILL = os.environ.get(
    "PHASE2_OPTIMIZER_SKILL", "profile-once-fuzz-folds"
)

# Skill helper scripts (real_fuzzer_profile.py, replay_timing.py, ...). The
# Claude and Codex skill trees carry identical copies; pick the one matching the
# active optimizer backend so the benchmark loads the same helpers the agent uses.
# The profile-once-fuzz-folds tree is self-contained (its scripts/ holds a verbatim
# replay_timing.py, which is all _load_replay_timing_module() needs).
PHASE2_SKILL_SCRIPTS_DIR = (
    "/home/sefcom/.claude/skills/profile-once-fuzz-folds/scripts"
    if OPTIMIZER_BACKEND == "claude"
    else "/home/sefcom/.codex/skills/profile-once-fuzz-folds/scripts"
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
