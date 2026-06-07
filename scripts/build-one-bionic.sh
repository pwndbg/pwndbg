#!/usr/bin/env bash
# Build a single static Android-bionic test binary for a given API level and
# package it for pwndbg testing. Mirrors build-one-musl.sh.
#
# Usage: ./build-one-bionic.sh <api-level>
# Example: ./build-one-bionic.sh 21
#
# Output: /bionics/<API>/bionic_probe.bionic-<API>-static.out
#
# Built with the NDK clang as a fully-static, non-PIE x86_64 binary. A static
# bionic binary embeds its own startup and runs on stock x86_64 Linux, so it
# launches under gdb in CI without an Android device or emulator. Clang stamps a
# .note.android.ident ELF note carrying the build-target API level (android_api)
# and the NDK version string; the test reads that note to assert the API axis.

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

# Show the file type and the Android ident note for visibility in build logs.
echo "=== file ==="
file "${OUT}"
echo "=== .note.android.ident (bionic fingerprint + build-target API) ==="
notes=$(readelf -n "${OUT}" 2> /dev/null) || true
echo "${notes}" | grep -iA3 android || true

# Fail loud if the binary lacks the Android ident note; the version-axis test
# parses the android_api value out of that note's descriptor bytes. (readelf -n
# prints the note's section name and raw description bytes, not a literal
# "android_api" label, so we only check the note's presence here.)
case "${notes}" in
    *.note.android.ident*) ;;
    *)
        echo "FATAL: .note.android.ident missing from ${OUT}"
        exit 1
        ;;
esac

echo "=== bionic probe (API ${API}) built successfully ==="
ls -la "${OUT_DIR}/"
