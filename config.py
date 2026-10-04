"""Benchmark configuration constants."""

import os
from pathlib import Path

# Paths
OSS_FUZZ_DIR = "/home/sefcom/asu/project/oss-fuzz"
OSS_FUZZ_VULNS_DIR = "/home/sefcom/asu/project/oss-fuzz-vulns"
BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BENCHMARK_DIR, "results")
# Default is the ARVO manifest; override with BENCHMARK_MANIFEST_PATH to run a
# different set (e.g. manifest_fuzzbench.json for the FuzzBench coverage/bug
# benchmarks) without disturbing the ARVO default or merging the two files.
MANIFEST_PATH = os.environ.get(
    "BENCHMARK_MANIFEST_PATH", os.path.join(BENCHMARK_DIR, "manifest.json"))

# Trial parameters
# Env-overridable so parallel multi-project online runs can shrink trials-per-project
# to fit the core budget (e.g. 4 projects x (4 baseline + 4 online) on 40 cores).
NUM_TRIALS = int(os.environ.get("NUM_TRIALS", "10"))
TRIAL_DURATION_SECS = 21600  # 6 hours
MEMORY_LIMIT = "4g"
MEMORY_LIMIT_RETRY = "8g"
RSS_LIMIT_MB = 3072
MAX_FAILED_TRIALS = 3  # If more than this many trials fail, exclude CVE

# Machine resources
TOTAL_CORES = 80
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

# Restart the baseline arm's trials on this cadence, resuming from their own
# queue (AFL_AUTORESUME). 0 = never restart, the historical behaviour.
#
# Controls for a confound: the online arm is stopped and relaunched at every
# accepted fold, the baseline never was, so restart effects were attributed to
# optimization. A restart loses AFL's in-memory dedup bitmap (inflating raw
# crash-artifact counts) and re-calibrates the queue.
BASELINE_RESTART_INTERVAL_SECS = int(
    os.environ.get("BASELINE_RESTART_INTERVAL_SECS", "0"))
# Which arm the cadence applies to. "baseline" by default; "optimized" or a
# nonsense value simply means the baseline is never restarted.
BASELINE_RESTART_ARM = os.environ.get("BASELINE_RESTART_ARM", "baseline")

# Mirror the ONLINE arm's hot swaps onto the baseline instead of using a fixed
# cadence. Takes precedence over BASELINE_RESTART_INTERVAL_SECS.
#
# The fixed cadence cannot match the online arm because the swap count is not
# known in advance -- it is however many folds get accepted. At 3h that gave the
# b6 baseline 7 restarts against the online arm's 2, so the baseline took MORE
# restart penalty, not the same. Mirroring makes the counts equal by
# construction (one baseline restart per swap that reached running trials) and
# aligns them in time to within one monitor poll (<=10s).
#
# This equalises the restart COST. It deliberately leaves the asymmetry that
# matters: the online arm's restart also delivers a better binary, the
# baseline's is pure overhead. That is what the method actually does.
BASELINE_RESTART_MIRROR_SWAPS = os.environ.get(
    "BASELINE_RESTART_MIRROR_SWAPS", "0").strip().lower() not in ("0", "", "false", "no")

# Wall-clock budget for ONE replay pass (one binary, one repeat). 0 disables the
# time budget and falls back to PHASE2_REPLAY_MAX_UNITS alone.
#
# Sized automatically rather than as a unit count, because the right count is a
# property of the TARGET, not of the corpus: at assimp's ~53 exec/s a 22.8k-unit
# pass takes 21.6 min (measured), while PcapPlusPlus at ~3230 exec/s does the
# same work in 1.2 min. A fixed unit cap would either throttle the fast target
# for nothing or leave the slow one unbounded. _replay_unit_cap converts this
# budget into units using the target's own measured replay rate.
PHASE2_REPLAY_BUDGET_SECS = int(os.environ.get("PHASE2_REPLAY_BUDGET_SECS", "180"))

# Hard upper bound on units the replay gate times, per pass. 0 = no manual cap
# (the budget above still applies). Set this to pin a count and ignore the clock.
#
# Round cost is set by how fast the TARGET runs, not by its source size: assimp
# manages ~53 exec/s where PcapPlusPlus manages ~3230, so an identical ~22.8k
# unit snapshot x PHASE2_REPLAY_REPEATS x 2 binaries costs assimp ~43 min a round
# and PcapPlusPlus ~40 s. Over b5 that was the difference between 4 rounds in 24h
# and 8. Sizing this by the slowest target's throughput -- units ~= budget_secs *
# exec/s / repeats -- bounds the gate for slow targets and binds on nobody else.
#
# A capped snapshot is a SAMPLE, so run_replay_speedup marks the measurement
# partial: the comparison becomes rate-normalised and the fold must clear
# PHASE2_MIN_REPLAY_SPEEDUP_PARTIAL rather than the usual margin.
PHASE2_REPLAY_MAX_UNITS = int(os.environ.get("PHASE2_REPLAY_MAX_UNITS", "0"))

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
# 0 (or negative) means NO limit: let the optimizer run to completion. A round
# that overruns the swap interval simply delays the next one -- run_optimizer_loop
# waits the interval BETWEEN rounds, so the interval is a floor, not a schedule,
# and the next round harvests whatever mutations the trials have accumulated by
# then. Killing the session instead discards the whole round, including folds it
# had already validated, because the diff is only saved once the agent returns.
def _int_env(name: str, default: int) -> int:
    """int() an env var, tolerating empty/garbage rather than dying at import.

    `FOO= python3 ...` sets an EMPTY string, not an unset variable, so a bare
    int(os.environ.get(...)) raises ValueError before any logging exists and the
    run dies with a bare traceback from config import.
    """
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return int(str(raw).strip())
    except ValueError:
        return default


PHASE2_OPTIMIZER_TIMEOUT_SECS = _int_env(
    "PHASE2_OPTIMIZER_TIMEOUT_SECS", 18000  # 5 hours; <=0 disables the cap
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

# Confine the phase-2 optimizer to a container with no docker socket, no host
# filesystem, and egress allowlisted to the model API (see sandbox/session.py).
# ON by default and its absence is an error, not a fallback: with the
# bug-preservation gate removed, confinement is the only thing making a measured
# bug-survival rate meaningful. Set 0 only to debug the optimizer itself.
PHASE2_SANDBOX = os.environ.get("PHASE2_SANDBOX", "1") == "1"

# Which agent CLI drives the phase-2 source optimization: "claude" or "codex".
# Overridable per-run with the BENCHMARK_OPTIMIZER env var.
OPTIMIZER_BACKEND = os.environ.get("BENCHMARK_OPTIMIZER", "claude").lower()

# Optimizer model and effort, pinned HERE rather than left to an env var.
# c1/c2 recorded model_pinned=true while the sandboxed CLI actually ran the
# account default, because the only --model flag lived on the unconfined
# debug path; a config default survives whoever forgot to export.
#
# Opus 4.8 at xhigh: on GSO -- the public code-optimization benchmark --
# Opus 4.8 leads all 30 entries at 47.06 Opt@1 with a zero hack penalty
# (raw == hack-adjusted), and Opus 5 is not submitted there at all, so
# there is no evidence it is better at THIS task despite leading on general
# coding. Effort is pinned too because GSO shows it moving one model by
# ~8 points (Opus 4.6: 33.33 default vs 41.18 high) -- larger than the gap
# between adjacent model generations, so an unpinned effort would confound
# any model comparison.
PHASE2_CLAUDE_MODEL = os.environ.get("BENCHMARK_CLAUDE_MODEL", "claude-opus-4-8")
PHASE2_CLAUDE_EFFORT = os.environ.get("BENCHMARK_CLAUDE_EFFORT", "xhigh")

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

# Online (continuous) optimization during fuzzing (LOCAL backend only). While the
# phase-3 fuzzer runs, periodically snapshot one live trial's accumulated corpus,
# run the phase-2 machinery on it to produce a faster binary, then hot-swap that
# binary into all online trials and keep fuzzing. See phase3_online.py.
ONLINE_ENABLED = os.environ.get("ONLINE_ENABLED", "0") == "1"
# Minimum fuzz-time between binary swaps (rounds run sequentially; the optimizer
# itself can take up to PHASE2_OPTIMIZER_TIMEOUT_SECS, so this is a floor).
ONLINE_SWAP_INTERVAL_SECS = int(os.environ.get("ONLINE_SWAP_INTERVAL_SECS", "3600"))
# Stop attempting new rounds after this many consecutive rounds produce no accepted
# fold; fuzzing continues to the end of the budget regardless.
# 0 (the default) never stops early -- rounds run until the trials terminate. A
# stretch of rejects does not predict the next round: the optimizer profiles a
# corpus that is still growing, so a foldable hotspot can appear late.
ONLINE_CONVERGENCE_K = int(os.environ.get("ONLINE_CONVERGENCE_K", "0"))
# Cores pinned to the 20 fuzzing trials vs the disjoint pool reserved for the
# optimizer's docker work, so optimization does not steal (and bias) trial cycles.
ONLINE_TRIAL_CORES = os.environ.get("ONLINE_TRIAL_CORES", "4-23")
ONLINE_OPTIMIZER_CORES = os.environ.get("ONLINE_OPTIMIZER_CORES", "24-39")
# Which live trial's corpus feeds a round: "largest" live corpus (tie -> lowest id).
ONLINE_SNAPSHOT_TRIAL_SELECTOR = os.environ.get("ONLINE_SNAPSHOT_TRIAL_SELECTOR", "largest")
# Core the optimizer pins profiling / mutation-capture / replay-timing to. Distinct
# per project in a parallel multi-project run so the timing gates don't collide on one
# core. Default: the top reserved core. Empty -> RESERVED_CORES-1.
ONLINE_PROFILE_CPU = os.environ.get("ONLINE_PROFILE_CPU", "")
# (Removed) The soft attempt ledger's re-open thresholds. No mechanism skips or
# re-opens a function any more -- the optimizer sees the current profile and may
# retry any fold, including ones it previously reverted. See phase3_online.py.

# Live mutation capture: online trials carry the AFL custom-mutator shim and
# batch mutations in memory, so an optimization round consumes what the fuzzer
# already executed instead of re-fuzzing a snapshot to regenerate them (~600s per
# round, ~4h per target over a 24h run). Set 0 to fall back to the re-fuzz.
ONLINE_LIVE_MUTATION_CAPTURE = os.environ.get(
    "ONLINE_LIVE_MUTATION_CAPTURE", "1") == "1"
# reservoir = uniform over the whole inter-round window; prefix = first N only.
#
# Default is "prefix" as the initial configuration, with reservoir to be trialled
# as a comparison. Both cost the same (benchmarked 7743 vs 7764 execs/s, 0.3%
# apart against a ~30% within-mode spread), so this is a sampling-bias choice,
# not a performance one.
#
# The bias is worth stating: at ~7k exec/s a 20k buffer fills in roughly 3
# seconds, so prefix profiles the first ~3s of each inter-round window -- and
# those are the seconds just after a hot-swap, while AFL re-calibrates its queue.
# Over many rounds the sampled moments are spread across the campaign, which is
# the argument for it being acceptable. Switch with ONLINE_MUTATION_MODE=reservoir
# to compare hotspot rankings.
ONLINE_MUTATION_MODE = os.environ.get("ONLINE_MUTATION_MODE", "prefix")

# --- per-trial optimizer experiment (one project per experiment) -----------
# Each optimized trial runs its OWN optimizer against its OWN source tree and
# replaces only its OWN binary. The previous design ran a single optimizer and
# hot-swapped one shared binary into all 10 optimized trials, which made the
# arm a single sample dressed as ten: every trial fuzzed an identical binary,
# so trial-to-trial variance measured AFL's randomness alone and said nothing
# about the optimizer's. With this on, the 10 optimized trials are 10 genuinely
# independent optimizer draws.
ONLINE_PER_TRIAL_OPTIMIZER = os.environ.get("ONLINE_PER_TRIAL_OPTIMIZER", "1") == "1"

# Profiling corpus for optimizer i is trial i's OWN mutations, harvested once
# and then held FIXED for every round that optimizer runs. Two consequences,
# both intended: the "which trial do we snapshot" question disappears (it is
# always the optimizer's own trial), and a given optimizer profiles against a
# stationary workload, so a round-to-round speedup difference is attributable
# to the edit rather than to the corpus having moved underneath it.
ONLINE_FIXED_MUTATION_CORPUS = os.environ.get(
    "ONLINE_FIXED_MUTATION_CORPUS", "1") == "1"

# Optimization level for TARGET builds, applied identically to both arms.
# "" keeps the OSS-Fuzz default (-O1, see base-builder's CFLAGS). "O3" rebuilds
# both arms at -O3. This is a measurement-affecting knob, not a tuning one: the
# whole b1..b6 corpus was produced at -O1, so a run at -O3 is comparable only to
# other -O3 runs. Recorded in campaign provenance for exactly that reason.
BUILD_OPT_LEVEL = os.environ.get("BUILD_OPT_LEVEL", "")

# Seconds of offset between consecutive optimizers' first rounds. Without it all
# ten fire their agent sessions, rebuilds and replay gates at the same instant:
# ten concurrent sessions against one account invite rate-limiting, and ten
# simultaneous rebuild bursts spike the profile cores together. Staggering also
# keeps the ten optimizers' round boundaries desynchronised for the whole
# campaign, so their hot-swaps land at different times rather than in lockstep.
ONLINE_OPTIMIZER_STAGGER_SECS = int(
    os.environ.get("ONLINE_OPTIMIZER_STAGGER_SECS", "120"))

# How long a round waits for a trial's capture shim to write its mutation batch.
# The shim answers in ~5s on an idle box, but a dump writes 20k small files while
# other optimizers are snapshotting 6k-file corpora onto the same disk, and under
# that contention it can take far longer. At the old hard-coded 60s, trials 00
# and 01 of online-24h-c1 missed their batch and LOST round 1 outright -- there
# is no usable fallback, because phase 2's own capture is libFuzzer-based and
# would profile the wrong workload for an AFL campaign.
ONLINE_MUTATION_DUMP_TIMEOUT_SECS = int(
    os.environ.get("ONLINE_MUTATION_DUMP_TIMEOUT_SECS", "300"))

# Seed generation. Per-trial RNG seed = BASE_SEED + trial_id*SEED_MULTIPLIER
# + arm offset, passed to afl-fuzz as `-s <seed>` (AFL++ 5.02c: "use a fixed
# seed for the RNG").
#
# Both arms share the offset, so trial k of each arm runs the same seed. This is
# Common Random Numbers: it costs nothing and removes "the arms were given
# different randomness" as an objection. The variance-reduction benefit CRN
# normally provides is likely near zero here -- the arms execute different
# binaries, so coverage feedback, queue evolution and scheduling diverge from
# the first execution and the trajectories do not stay correlated -- but the
# reporting benefit is real and the cost is not.
#
# Note what a fixed seed does NOT buy: reproducibility. Per Schloegel et al.
# (S&P'24), scheduling order, getpid/time/rand, and shared filesystem state are
# all additional randomness sources, so `-s` pins the mutator PRNG only. These
# seeds LABEL trials and make the setup auditable; they do not make a campaign
# replayable. And no seed touches the per-trial optimizer agents, which are a
# larger randomness source than the mutator.
BASE_SEED = 1337
BASELINE_SEED_OFFSET = 0
OPTIMIZED_SEED_OFFSET = 0
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


# --------------------------------------------------------------------------- #
# Provenance: record what the run actually ran with, while it runs.
# --------------------------------------------------------------------------- #
# Replay each crash artifact once at trial end and record WHAT IT IS (sanitizer
# / assert / nocrash), instead of inferring "crash" from the filename. That
# inference made assimp's time-to-bug read 0.19-4.8s when the truth was 10.7s
# baseline vs 103.9s optimized -- the wrong direction -- because 67% of its
# artifacts were a libc++ linkage artifact and 31% were assertion aborts.
PROVENANCE_CLASSIFY_CRASHES = os.environ.get(
    "PROVENANCE_CLASSIFY_CRASHES", "1").strip().lower() not in ("0", "", "false", "no")

# Artifacts classified per trial, in TIMESTAMP order. Ordered, not sampled, so
# the first genuine sanitizer crash -- the only one time-to-bug needs -- is found
# even when a trial saves tens of thousands of artifacts (PcapPlusPlus b6 saved
# 23867; classifying all of them would cost hours per trial).
PROVENANCE_CLASSIFY_MAX = _int_env("PROVENANCE_CLASSIFY_MAX", 400)

# Sanitizer options for CLASSIFICATION replays. alloc_dealloc_mismatch is off:
# our targets link libc++/libc++abi dynamically while upstream ARVO links them
# statically, so every caught C++ exception reports a mismatch that belongs to
# our linkage, not the target. OSS-Fuzz's own runner disables it too.
PROVENANCE_CLASSIFY_ASAN_OPTIONS = os.environ.get(
    "PROVENANCE_CLASSIFY_ASAN_OPTIONS", "detect_leaks=0:alloc_dealloc_mismatch=0")


# Measure the target's build-to-build variance ONCE per campaign: rebuild the
# unmodified source a second time and replay-measure both. The gate accepts a
# fold when it beats the previous best, which is only meaningful against how far
# the measurement moves when nothing changes. PcapPlusPlus's optimizer found a
# 6.6% spread by hand and correctly rejected every 1-2% fold it had; without that
# number two campaigns of null results were uninterpretable.
# Cost: one extra pristine rebuild per campaign (42s on assimp, ~570s on
# graphicsmagick) plus two replay passes. Set 0 to skip.
PROVENANCE_NOISE_FLOOR = _int_env("PROVENANCE_NOISE_FLOOR", 2)
