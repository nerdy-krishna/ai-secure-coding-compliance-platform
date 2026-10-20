#!/usr/bin/env bash
# Build and publish the SCCAP pentest tool-runtime images, then print the
# digest map to paste into deploy/helm/sccap/values.yaml (pentestToolPack.runtimes).
#
# Usage:
#   REGISTRY=ghcr.io/nerdy-krishna/ai-secure-coding-compliance-platform \
#   VERSION=v1.0.0 \
#   bash scripts/build-tool-runtimes.sh
#
# Requires docker buildx and a logged-in registry (`docker login ghcr.io`).
# Nuclei/ZAP downloads are SHA-verified against the pinned values below.

set -euo pipefail

REGISTRY="${REGISTRY:-ghcr.io/nerdy-krishna/ai-secure-coding-compliance-platform}"
VERSION="${VERSION:-v1.0.0}"
CONTEXT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# SHA256 of the pinned tool archives. amd64 is the cloud default; arm64 nuclei
# needs its own archive digest (the ZAP tarball is arch-independent).
NUCLEI_VERSION="${NUCLEI_VERSION:-3.3.8}"
NUCLEI_AMD64_SHA256="1526650021ada87e9cfc2a30048c8e59f5db9eed079c7807d53b7e181009bfe4"
NUCLEI_ARM64_SHA256="${NUCLEI_ARM64_SHA256:-}"
ZAP_VERSION="${ZAP_VERSION:-2.16.0}"
ZAP_SHA256="a0779509e702ec53d41074eaa0ce41f2a964a822aa5be0380255a482e2e7fe8d"
PLAYWRIGHT_VERSION="${PLAYWRIGHT_VERSION:-1.52.0}"

# runtime-target -> image name. authorization/graphql/realtime share the
# pure-Python image; the chart points all three at its digest.
declare -A TARGETS=(
  [python]=sccap-tool-python
  [nmap]=sccap-tool-nmap
  [nuclei]=sccap-tool-nuclei
  [zap]=sccap-tool-zap
  [playwright]=sccap-tool-playwright
  [relay]=sccap-tool-relay
)

build_one() {
  local target="$1" name="$2"
  echo "==> building $name (target $target)"
  docker buildx build \
    --file runtimes/Dockerfile \
    --target "$target" \
    --platform linux/amd64 \
    --build-arg NUCLEI_VERSION="$NUCLEI_VERSION" \
    --build-arg NUCLEI_SHA256="$NUCLEI_AMD64_SHA256" \
    --build-arg ZAP_VERSION="$ZAP_VERSION" \
    --build-arg ZAP_SHA256="$ZAP_SHA256" \
    --build-arg PLAYWRIGHT_VERSION="$PLAYWRIGHT_VERSION" \
    --tag "$REGISTRY/$name:$VERSION" \
    --push \
    "$CONTEXT"
  local digest
  digest="$(docker buildx imagetools inspect "$REGISTRY/$name:$VERSION" --format '{{json .Manifest.Digest}}' | tr -d '"')"
  echo "    $REGISTRY/$name@$digest"
}

echo "Publishing to $REGISTRY at $VERSION"
declare -A DIGESTS=()
for target in python nmap nuclei zap playwright relay; do
  DIGESTS[$target]="$(build_one "$target" "${TARGETS[$target]}" | tail -1)"
done

echo
echo "=== paste into deploy/helm/sccap/values.yaml ==="
cat <<EOF
pentestToolPack:
  enabled: true
  runtimes:
    authorization: {image: "${DIGESTS[python]}"}
    graphql:       {image: "${DIGESTS[python]}"}
    realtime:      {image: "${DIGESTS[python]}"}
    nmap:          {image: "${DIGESTS[nmap]}"}
    nuclei:        {image: "${DIGESTS[nuclei]}"}
    zap:           {image: "${DIGESTS[zap]}"}
    playwright:    {image: "${DIGESTS[playwright]}"}
  runtimeManager:
    relayImage:    "${DIGESTS[relay]}"
EOF
