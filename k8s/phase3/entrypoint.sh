#!/usr/bin/env bash
set -euo pipefail

target="${FUZZ_TARGET:?FUZZ_TARGET is required}"
duration="${DURATION_SECONDS:-21600}"
trial_id="${TRIAL_ID:-}"
base_seed="${BASE_SEED:-1337}"
seed_multiplier="${SEED_MULTIPLIER:-1000}"
rss_limit="${RSS_LIMIT_MB:-3072}"
malloc_limit="${MALLOC_LIMIT_MB:-${rss_limit}}"
corpus_dir="${CORPUS_DIR:-/corpus}"
crashes_dir="${CRASHES_DIR:-/crashes}"
work_dir="${WORK_DIR:-/work}"
artifacts_dir="${ARTIFACTS_DIR:-}"
archive_corpus="${ARCHIVE_CORPUS:-0}"
project="${PROJECT:-unknown-project}"
variant="${VARIANT:-unknown-variant}"
experiment_id="${EXPERIMENT_ID:-unknown-experiment}"
pod_name="${POD_NAME:-local}"
job_name="${JOB_NAME:-manual}"
# Optional live coverage-over-time diagnostic (OFF by default). When on, a
# background poller periodically replays the current corpus and records edge
# coverage. NOTE: this measures coverage on THIS pod's (in-pod) binary -- for an
# optimized trial that is the OPTIMIZED binary, a different edge map -- so it is a
# per-variant diagnostic, NOT the common-baseline comparison. For baseline-binary
# coverage-over-time (both variants on one yardstick) use run_covtime.py offline.
coverage_snapshot="${COVERAGE_SNAPSHOT:-0}"
coverage_snapshot_interval="${COVERAGE_SNAPSHOT_INTERVAL:-1800}"

mkdir -p "${corpus_dir}" "${crashes_dir}" "${work_dir}"

if [ ! -x "/out/${target}" ]; then
  echo "Fuzzer target is missing or not executable: /out/${target}" >&2
  exit 64
fi

if [ -d /seed-corpus ] && [ -z "$(find "${corpus_dir}" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  cp -a /seed-corpus/. "${corpus_dir}/" 2>/dev/null || true
fi

seed_zip="/out/${target}_seed_corpus.zip"
if [ -f "${seed_zip}" ] && [ -z "$(find "${corpus_dir}" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  unzip -q -n "${seed_zip}" -d "${corpus_dir}" 2>/dev/null || true
fi

if [ -n "${trial_id}" ]; then
  if ! [[ "${trial_id}" =~ ^[0-9]+$ ]]; then
    echo "TRIAL_ID must be a non-negative integer: ${trial_id}" >&2
    exit 65
  fi
  seed=$((base_seed + trial_id * seed_multiplier))
else
  seed="${SEED:-${base_seed}}"
fi

trial_label="${trial_id:-manual}"
log_file="${work_dir}/libfuzzer.log"
metadata_file="${work_dir}/metadata.env"
start_time="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
start_epoch="$(date -u +"%s")"

export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1}"
export MSAN_OPTIONS="${MSAN_OPTIONS:-exit_code=86}"

help_output="$("/out/${target}" -help=1 2>&1 || true)"
libfuzzer_flags=()

add_supported_flag() {
  local name="$1"
  local value="$2"
  if grep -Eq "(^|[[:space:]])${name}([[:space:]=]|$)" <<<"${help_output}"; then
    libfuzzer_flags+=("-${name}=${value}")
  elif [ "${LOG_UNSUPPORTED_LIBFUZZER_FLAGS:-0}" = "1" ]; then
    echo "Skipping unsupported libFuzzer flag: -${name}" >&2
  fi
}

add_supported_flag "verbosity" "${LIBFUZZER_VERBOSITY:-1}"
add_supported_flag "print_corpus_stats" "1"
add_supported_flag "print_funcs" "1"
add_supported_flag "report_slow_units" "${REPORT_SLOW_UNITS:-10}"
add_supported_flag "malloc_limit_mb" "${malloc_limit}"

classify_fuzzer_exit() {
  local exit_code="$1"
  local log_path="$2"

  if [ "${exit_code}" -eq 0 ]; then
    echo "clean"
    return
  fi

  if grep -Eiq \
    'Test unit written to|^SUMMARY:|^DEDUP_TOKEN:|ERROR: .*Sanitizer|LeakSanitizer|libFuzzer: (timeout|out-of-memory|deadly signal|crash)' \
    "${log_path}" 2>/dev/null; then
    echo "finding"
    return
  fi

  echo "infra_error"
}

collect_corpus_stats() {
  corpus_file_count="$(find "${corpus_dir}" -type f 2>/dev/null | wc -l | tr -d '[:space:]')"
  corpus_du_bytes="$(du -sb "${corpus_dir}" 2>/dev/null | awk '{print $1}')"
  corpus_du_human="$(du -sh "${corpus_dir}" 2>/dev/null | awk '{print $1}')"

  corpus_file_count="${corpus_file_count:-0}"
  corpus_du_bytes="${corpus_du_bytes:-0}"
  corpus_du_human="${corpus_du_human:-0}"
}

collect_crash_times() {
  local out_json="$1"
  python3 - "$crashes_dir" "$start_epoch" "$out_json" <<'PY'
import json, os, sys
crashes_dir, start_epoch, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
events = []
if os.path.isdir(crashes_dir):
    for name in sorted(os.listdir(crashes_dir)):
        p = os.path.join(crashes_dir, name)
        if not os.path.isfile(p):
            continue
        ctype = ("oom" if name.startswith("oom-")
                 else "timeout" if name.startswith("timeout-")
                 else "crash" if name.startswith("crash-")
                 else "unknown")
        ts = max(0.0, round(os.path.getmtime(p) - start_epoch, 2))
        events.append({"timestamp_s": ts, "artifact": name, "crash_type": ctype})
with open(out, "w") as f:
    json.dump(events, f)
PY
}

write_metadata() {
  local outcome="$1"
  local fuzzer_exit="$2"
  local pod_exit="$3"
  local end_time="$4"
  local elapsed_seconds="$5"
  local archive_path="$6"

  cat >"${metadata_file}" <<EOF
project=${project}
variant=${variant}
experiment_id=${experiment_id}
target=${target}
job_name=${job_name}
pod_name=${pod_name}
trial_id=${trial_label}
seed=${seed}
start_time=${start_time}
end_time=${end_time}
elapsed_seconds=${elapsed_seconds}
fuzzer_exit_code=${fuzzer_exit}
pod_exit_code=${pod_exit}
outcome=${outcome}
archive_path=${archive_path}
corpus_dir=${corpus_dir}
crashes_dir=${crashes_dir}
rss_limit_mb=${rss_limit}
malloc_limit_mb=${malloc_limit}
duration_seconds=${duration}
corpus_file_count=${corpus_file_count}
corpus_du_bytes=${corpus_du_bytes}
corpus_du_human=${corpus_du_human}
corpus_archived=${archive_corpus}
EOF
}

save_artifacts() {
  local archive_path="$1"
  if [ -z "${artifacts_dir}" ]; then
    echo "ARTIFACTS_DIR is unset; skipping persistent artifact archive" >&2
    return 0
  fi
  local archive_dir staging_dir archive_tmp
  archive_dir="$(dirname "${archive_path}")"
  archive_tmp="${archive_path}.tmp"
  staging_dir="${work_dir}/artifact-staging"
  rm -rf "${staging_dir}"
  mkdir -p "${archive_dir}" "${staging_dir}/crashes"
  cp "${log_file}" "${staging_dir}/libfuzzer.log" 2>/dev/null || true
  cp "${coverage_json:-}" "${staging_dir}/coverage_over_time.json" 2>/dev/null || true
  cp "${metadata_file}" "${staging_dir}/metadata.env"
  cp -a "${crashes_dir}/." "${staging_dir}/crashes/" 2>/dev/null || true
  collect_crash_times "${staging_dir}/crash_times.json"
  rm -f "${archive_tmp}"
  ( cd "${staging_dir}" && zip -qry "${archive_tmp}" . )
  mv "${archive_tmp}" "${archive_path}"
  sha256sum "${archive_path}" >"${archive_path}.sha256"
  echo "Saved phase3 trial archive: ${archive_path}"
}

save_corpus_archive() {
  local archive_path="$1"
  local archive_dir archive_tmp
  archive_dir="$(dirname "${archive_path}")"
  archive_tmp="${archive_path}.tmp"
  mkdir -p "${archive_dir}"
  rm -f "${archive_tmp}"
  ( cd "${corpus_dir}" && zip -qry "${archive_tmp}" . )
  mv "${archive_tmp}" "${archive_path}"
  sha256sum "${archive_path}" >"${archive_path}.sha256"
  echo "Saved phase3 corpus archive: ${archive_path}"
}

# Background poller: every ${interval}s replay the current corpus on the in-pod
# binary and append "elapsed_s edges" to a TSV. Diagnostic only (in-pod binary).
snapshot_coverage_loop() {
  local out_tsv="$1" interval="$2"
  set +e   # runs in a subshell (&); never let a crashing replay abort the poller
  while true; do
    sleep "${interval}"
    local now elapsed cov
    now="$(date -u +%s)"
    elapsed=$((now - start_epoch))
    cov="$( { ASAN_OPTIONS=detect_leaks=0 "/out/${target}" "${corpus_dir}" \
                -runs=0 -detect_leaks=0 -rss_limit_mb="${rss_limit}" \
                -print_final_stats=1 2>&1 || true; } \
            | grep -oE 'cov: [0-9]+' | tail -1 | grep -oE '[0-9]+' || true)"
    if [ -n "${cov}" ]; then
      echo "${elapsed} ${cov}" >>"${out_tsv}"
    fi
  done
}

# Convert the poller TSV into the coverage_over_time.json schema phase4 reads
# ([{"time_s","edges"}]), clamped to running-max (coverage is monotonic).
finalize_coverage_json() {
  local tsv="$1" out_json="$2"
  [ -s "${tsv}" ] || return 0
  python3 - "$tsv" "$out_json" <<'PY'
import json, sys
tsv, out = sys.argv[1], sys.argv[2]
rows = []
for line in open(tsv):
    parts = line.split()
    if len(parts) == 2:
        try:
            rows.append({"time_s": float(parts[0]), "edges": int(parts[1])})
        except ValueError:
            pass
rows.sort(key=lambda r: r["time_s"])
m = 0
for r in rows:
    if r["edges"] < m:
        r["edges"] = m
    else:
        m = r["edges"]
with open(out, "w") as f:
    json.dump(rows, f)
PY
}

fuzzer_cmd=(
  "/out/${target}" "${corpus_dir}"
  "-seed=${seed}"
  "${libfuzzer_flags[@]}"
  "-detect_leaks=0"
  "-max_total_time=${duration}"
  "-print_final_stats=1"
  "-rss_limit_mb=${rss_limit}"
  "-artifact_prefix=${crashes_dir}/"
  "$@"
)

coverage_json="${work_dir}/coverage_over_time.json"
coverage_tsv="${work_dir}/coverage.tsv"
snapshot_pid=""
if [ "${coverage_snapshot}" = "1" ]; then
  : >"${coverage_tsv}"
  snapshot_coverage_loop "${coverage_tsv}" "${coverage_snapshot_interval}" &
  snapshot_pid=$!
  echo "coverage snapshot poller started (pid ${snapshot_pid}, interval ${coverage_snapshot_interval}s; in-pod ${variant} binary -- diagnostic only)"
fi

set +e
"${fuzzer_cmd[@]}" 2>&1 | tee "${log_file}"
fuzzer_exit="${PIPESTATUS[0]}"
set -e

if [ -n "${snapshot_pid}" ]; then
  kill "${snapshot_pid}" 2>/dev/null || true
  wait "${snapshot_pid}" 2>/dev/null || true
  finalize_coverage_json "${coverage_tsv}" "${coverage_json}" || true
fi

end_time="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
end_epoch="$(date -u +"%s")"
elapsed_seconds=$((end_epoch - start_epoch))
outcome="$(classify_fuzzer_exit "${fuzzer_exit}" "${log_file}")"
collect_corpus_stats

case "${outcome}" in
  clean|finding)
    pod_exit=0
    ;;
  *)
    pod_exit="${fuzzer_exit}"
    ;;
esac

archive_path=""
corpus_archive_path=""
if [ -n "${artifacts_dir}" ]; then
  base="${artifacts_dir}/${project}/${variant}/${job_name}"
  archive_path="${base}/trials/trial-${trial_label}-${pod_name}.zip"
  corpus_archive_path="${base}/corpora/corpus-${trial_label}-${pod_name}.zip"
fi

write_metadata "${outcome}" "${fuzzer_exit}" "${pod_exit}" "${end_time}" "${elapsed_seconds}" "${archive_path}"

artifact_exit=0
set +e
save_artifacts "${archive_path}"
artifact_exit="$?"
if [ "${archive_corpus}" = "1" ] && [ -n "${corpus_archive_path}" ]; then
  save_corpus_archive "${corpus_archive_path}"
fi
set -e

if [ "${artifact_exit}" -ne 0 ]; then
  echo "Failed to save phase3 artifact archive; preserving pod failure" >&2
  pod_exit=66
fi

echo "phase3 outcome=${outcome} fuzzer_exit=${fuzzer_exit} pod_exit=${pod_exit} elapsed_seconds=${elapsed_seconds} corpus_stats files=${corpus_file_count} bytes=${corpus_du_bytes} human=${corpus_du_human} archived=${archive_corpus}"
exit "${pod_exit}"
