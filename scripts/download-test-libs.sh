#!/usr/bin/env bash

set -euo pipefail

LIBC="${1:?Usage: $0 <glibc|musl>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

case "${LIBC}" in
    glibc)
        DIR=glibcs
        IMAGE="${GLIBC_IMAGE:-ghcr.io/pwndbg/glibc-test-libs:latest}"
        ;;
    musl)
        DIR=musls
        IMAGE="${MUSL_IMAGE:-ghcr.io/pwndbg/musl-test-libs:latest}"
        ;;
    *)
        echo "FATAL: unknown libc '${LIBC}' (expected glibc or musl)" >&2
        exit 1
        ;;
esac

case "$(uname -m)" in
    aarch64) GLIBC_LD="ld-linux-aarch64.so.1" ;;
    *) GLIBC_LD="ld-linux-x86-64.so.2" ;;
esac
DOCKERFILE="${REPO_ROOT}/Dockerfile.${LIBC}-test-libs"
DEST="${REPO_ROOT}/tests/binaries/host/${DIR}"

sentinels() {
    local ver="$1"
    case "${LIBC}" in
        glibc) echo "${ver}/libc.so.6" "${ver}/${GLIBC_LD}" ;;
        musl) echo "${ver}/lib/libc.a" "${ver}/lib/libc.so" ;;
    esac
}

mapfile -t VERSIONS < <(sed -n 's/^FROM base-builder AS build-\([0-9][0-9.]*\).*/\1/p' "${DOCKERFILE}")
[ "${#VERSIONS[@]}" -gt 0 ] || {
    echo "ERROR: no versions parsed from ${DOCKERFILE}" >&2
    exit 1
}

have_all() {
    local ver f
    for ver in "${VERSIONS[@]}"; do
        for f in $(sentinels "${ver}"); do
            [ -f "${DEST}/${f}" ] || return 1
        done
        if [ "${LIBC}" = glibc ]; then
            [ -f "${REPO_ROOT}/tests/binaries/host/glibcs-nodebug/${ver}/${GLIBC_LD}" ] || return 1
        fi
    done
}

if have_all; then
    echo "All ${LIBC} test artifacts already present in ${DEST}/"
    exit 0
fi

if docker pull "${IMAGE}"; then
    IMG="${IMAGE}"
else
    echo "Image ${IMAGE} unavailable, building locally (this may take a while)..."
    docker buildx build -f "${DOCKERFILE}" -t "${LIBC}-test-libs:local" --load "${REPO_ROOT}"
    IMG="${LIBC}-test-libs:local"
fi

CID=$(docker create --entrypoint=/ "${IMG}")
trap 'docker rm -f "${CID}" >/dev/null 2>&1 || true' EXIT
mkdir -p "${DEST}"
docker cp "${CID}:/${DIR}/." "${DEST}/" 2> /dev/null || {
    echo "ERROR: failed to copy test libs from container (docker cp failed)" >&2
    exit 1
}
if [ "${LIBC}" = glibc ]; then
    ND="${REPO_ROOT}/tests/binaries/host/glibcs-nodebug"
    mkdir -p "${ND}"
    if docker cp "${CID}:/glibcs-nodebug/." "${ND}/" 2> /dev/null; then
        echo "also extracted the glibcs-nodebug tree"
    else
        echo "note: this image has no glibcs-nodebug tree; skipping"
    fi
fi

echo "${LIBC} test artifacts extracted to ${DEST}/"
missing=false
for ver in "${VERSIONS[@]}"; do
    ok=true
    for f in $(sentinels "${ver}"); do
        [ -f "${DEST}/${f}" ] || ok=false
    done
    if "${ok}"; then echo "  ${ver}: OK"; else
        echo "  ${ver}: MISSING"
        missing=true
    fi
    if [ "${LIBC}" = glibc ] \
        && [ ! -f "${REPO_ROOT}/tests/binaries/host/glibcs-nodebug/${ver}/${GLIBC_LD}" ]; then
        echo "  ${ver}: nodebug tree missing (the no-symbol heuristic tests will skip)"
    fi
done
if "${missing}"; then
    echo "ERROR: some ${LIBC} artifacts are missing." >&2
    echo "If you added a version, the pulled image won't have it; build it easily locally by running:" >&2
    echo "  ${LIBC^^}_IMAGE=${LIBC}-test-libs:local $0 ${LIBC}" >&2
    exit 1
fi
