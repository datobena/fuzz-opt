#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLUSTER="${KIND_CLUSTER:-phase3}"

if ! command -v kind >/dev/null 2>&1; then
  echo "kind is required" >&2
  exit 127
fi
if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required to create and wait for smoke pods" >&2
  exit 127
fi

if ! kind get clusters | grep -qx "${CLUSTER}"; then
  kind create cluster --name "${CLUSTER}"
fi

"${SCRIPT_DIR}/build-images.sh" --kind-cluster "${CLUSTER}"

kubectl --context "kind-${CLUSTER}" delete -f "${SCRIPT_DIR}/smoke-pods.yaml" --ignore-not-found=true
kubectl --context "kind-${CLUSTER}" apply -f "${SCRIPT_DIR}/smoke-pods.yaml"
kubectl --context "kind-${CLUSTER}" wait \
  --for=jsonpath='{.status.phase}'=Succeeded \
  pod -l app=phase3-fuzzer-smoke \
  --timeout=180s
kubectl --context "kind-${CLUSTER}" logs -l app=phase3-fuzzer-smoke --tail=20 --prefix=true
