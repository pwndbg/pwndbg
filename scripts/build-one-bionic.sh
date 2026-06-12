#!/usr/bin/env bash

set -euo pipefail

API="${1:?Usage: $0 <api-level>}"

NDK_HOME="${NDK_HOME:?NDK_HOME must point at the unpacked Android NDK}"
CLANG="${NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
SRC="/bionic_probe.native.c"
OUT_DIR="/bionics/${API}"
OUT="${OUT_DIR}/bionic_probe.bionic-${API}-static.out"

echo "=== Building bionic probe (API ${API}) ==="

echo "[1/2] Compiling ${SRC} with NDK clang..."
mkdir -p "${OUT_DIR}"
"${CLANG}" --target="x86_64-linux-android${API}" -static -no-pie -g -O0 \
    -o "${OUT}" "${SRC}"

echo "[2/2] Verifying output..."
if [ ! -f "${OUT}" ]; then
    echo "FATAL: build produced no output for API ${API}"
    exit 1
fi

echo "=== file ==="
file "${OUT}"
echo "=== .note.android.ident (bionic fingerprint + build-target API) ==="
notes=$(readelf -n "${OUT}" 2> /dev/null) || true
echo "${notes}" | grep -iA3 android || true

case "${notes}" in
    *.note.android.ident*) ;;
    *)
        echo "FATAL: .note.android.ident missing from ${OUT}"
        exit 1
        ;;
esac

echo "=== bionic probe (API ${API}) built successfully ==="
ls -la "${OUT_DIR}/"
