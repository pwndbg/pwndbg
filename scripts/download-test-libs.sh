#!/usr/bin/env bash
# Pull a prebuilt libc test-libs image (or build it locally as a fallback) and
# extract its artifacts. Skips the pull/build if they are already present.
#
# Usage: ./scripts/download-test-libs.sh <glibc|musl|bionic>
#
# The artifacts are produced once in CI by Dockerfile.<libc>-test-libs (which runs
# build-one-<libc>.sh per version) and published to ghcr; this just fetches them so
# a local run does not have to rebuild from source. Override the image to pull with
# GLIBC_IMAGE / MUSL_IMAGE / BIONIC_IMAGE. (bionic ships prebuilt test binaries,
# since the NDK clang that builds them is not in the pwndbg test container.)
set -euo pipefail

LIBC="${1:?Usage: $0 <glibc|musl|bionic>}"
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
    bionic)
        DIR=bionics
        IMAGE="${BIONIC_IMAGE:-ghcr.io/pwndbg/bionic-test-libs:latest}"
        ;;
    *)
        echo "FATAL: unknown libc '${LIBC}' (expected glibc, musl, or bionic)" >&2
        exit 1
        ;;
esac

# The glibc loader name is arch-specific; derive it so the sentinel check matches
# whichever arch the :latest manifest resolved to on this host.
case "$(uname -m)" in
    aarch64) GLIBC_LD="ld-linux-aarch64.so.1" ;;
    *) GLIBC_LD="ld-linux-x86-64.so.2" ;;
esac
DOCKERFILE="${REPO_ROOT}/Dockerfile.${LIBC}-test-libs"
DEST="${REPO_ROOT}/tests/binaries/host/${DIR}"

# Sentinel files (relative to <DEST>/<ver>/) that must exist for a built version.
sentinels() {
    local ver="$1"
    case "${LIBC}" in
        glibc) echo "${ver}/libc.so.6" "${ver}/${GLIBC_LD}" ;;
        musl) echo "${ver}/lib/libc.a" "${ver}/lib/libc.so" ;;
        bionic) echo "${ver}/bionic_probe.bionic-${ver}-static.out" ;;
    esac
}

# Version / API list parsed from the Dockerfile's build-<n> stages (single source).
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
        # glibc also ships a parallel no-debug tree; count it as part of "all present"
        # so a stale tree without it gets re-extracted.
        if [ "${LIBC}" = glibc ]; then
            [ -f "${REPO_ROOT}/tests/binaries/host/glibcs-nodebug/${ver}/${GLIBC_LD}" ] || return 1
        fi
    done
}

if have_all; then
    echo "All ${LIBC} test artifacts already present in ${DEST}/"
    exit 0
fi

# Pull the prebuilt image; fall back to a local build only when the pull fails
# (image not published yet). A successful pull of a stale image wins, so when
# iterating on a Dockerfile or build script, point GLIBC_IMAGE/MUSL_IMAGE/
# BIONIC_IMAGE at an unpublished name to force the local build.
if docker pull "${IMAGE}"; then
    IMG="${IMAGE}"
else
    echo "Image ${IMAGE} unavailable, building locally (this may take a while)..."
    docker buildx build -f "${DOCKERFILE}" -t "${LIBC}-test-libs:local" --load "${REPO_ROOT}"
    IMG="${LIBC}-test-libs:local"
fi

# scratch image has no entrypoint, so give `docker create` one so it succeeds.
CID=$(docker create --entrypoint=/ "${IMG}")
trap 'docker rm -f "${CID}" >/dev/null 2>&1 || true' EXIT
mkdir -p "${DEST}"
docker cp "${CID}:/${DIR}/." "${DEST}/"
# glibc also ships a parallel no-debug tree (stripped, no symbols) for the
# heuristic-heap test; pull it too so that test can run locally as it does in CI.
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
    # Warn (not fail) on a missing nodebug tree, so images without one stay usable;
    # the no-symbol heuristic tests simply skip in that case.
    if [ "${LIBC}" = glibc ] \
        && [ ! -f "${REPO_ROOT}/tests/binaries/host/glibcs-nodebug/${ver}/${GLIBC_LD}" ]; then
        echo "  ${ver}: nodebug tree missing (the no-symbol heuristic tests will skip)"
    fi
done
if "${missing}"; then
    echo "ERROR: some ${LIBC} artifacts are missing" >&2
    exit 1
fi
