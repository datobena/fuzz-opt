#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMAGES_JSON="${SCRIPT_DIR}/images.json"

kind_cluster=""
image_prefix=""
push_images=0

usage() {
  cat <<'USAGE'
Usage: k8s/phase3/build-images.sh [options]

Build the codex-4 phase3 baseline/optimized Kubernetes images.

Options:
  --kind-cluster NAME   Load each built image into the named kind cluster.
  --image-prefix PREFIX Prefix image names, for example registry:5000/.
  --push                Push images after building.
  -h, --help            Show this help.

Environment:
  COPY_ALL_BIN=1        Copy the full phase3 bin directory instead of only
                        the configured fuzz target plus companion files.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --kind-cluster)
      kind_cluster="${2:?--kind-cluster requires a name}"
      shift 2
      ;;
    --image-prefix)
      image_prefix="${2:?--image-prefix requires a prefix}"
      shift 2
      ;;
    --push)
      push_images=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

copy_if_present() {
  local src="$1"
  local dst="$2"
  if [ -e "${src}" ]; then
    cp -a "${src}" "${dst}"
  fi
}

context_dir=""
trap 'if [ -n "${context_dir}" ]; then rm -rf "${context_dir}"; fi' EXIT

while IFS=$'\t' read -r project cve variant experiment_id fuzz_target artifact_dir seed_corpus_dir poc_dir image; do
  tag="${image_prefix}${image}"
  artifact_path="${REPO_ROOT}/${artifact_dir}"
  seed_path="${REPO_ROOT}/${seed_corpus_dir}"
  poc_path="${REPO_ROOT}/${poc_dir}"

  if [ ! -f "${artifact_path}/${fuzz_target}" ]; then
    echo "Missing fuzz target: ${artifact_path}/${fuzz_target}" >&2
    exit 1
  fi

  context_dir="$(mktemp -d)"

  mkdir -p "${context_dir}/out" "${context_dir}/seed-corpus" "${context_dir}/poc"
  cp "${SCRIPT_DIR}/entrypoint.sh" "${context_dir}/entrypoint.sh"

  if [ "${COPY_ALL_BIN:-0}" = "1" ]; then
    cp -a "${artifact_path}/." "${context_dir}/out/"
  else
    cp -a "${artifact_path}/${fuzz_target}" "${context_dir}/out/"
    copy_if_present "${artifact_path}/llvm-symbolizer" "${context_dir}/out/"
    copy_if_present "${artifact_path}/${fuzz_target}.dict" "${context_dir}/out/"
    copy_if_present "${artifact_path}/${fuzz_target}_seed_corpus.zip" "${context_dir}/out/"
  fi

  if [ -d "${seed_path}" ]; then
    cp -a "${seed_path}/." "${context_dir}/seed-corpus/"
  fi
  if [ -d "${poc_path}" ]; then
    cp -a "${poc_path}/." "${context_dir}/poc/"
  fi

  docker build \
    -f "${SCRIPT_DIR}/Dockerfile" \
    -t "${tag}" \
    --build-arg "PROJECT=${project}" \
    --build-arg "CVE=${cve}" \
    --build-arg "VARIANT=${variant}" \
    --build-arg "EXPERIMENT_ID=${experiment_id}" \
    --build-arg "FUZZ_TARGET=${fuzz_target}" \
    "${context_dir}"

  if [ -n "${kind_cluster}" ]; then
    kind load docker-image "${tag}" --name "${kind_cluster}"
  fi
  if [ "${push_images}" -eq 1 ]; then
    docker push "${tag}"
  fi
  rm -rf "${context_dir}"
  context_dir=""
done < <(python3 - "$IMAGES_JSON" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    images = json.load(f)

for item in images:
    fields = [
        item["project"],
        item["cve"],
        item["variant"],
        item["experiment_id"],
        item["fuzz_target"],
        item["artifact_dir"],
        item["seed_corpus_dir"],
        item["poc_dir"],
        item["image"],
    ]
    print("\t".join(fields))
PY
)
