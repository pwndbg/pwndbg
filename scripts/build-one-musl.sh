#!/usr/bin/env bash

set -euo pipefail

VERSION="${1:?Usage: $0 <musl-version> <sha256>}"
SHA256="${2:?Usage: $0 <musl-version> <sha256>}"

case "$(uname -m)" in
    x86_64) MUSL_LD="ld-musl-x86_64.so.1" ;;
    aarch64) MUSL_LD="ld-musl-aarch64.so.1" ;;
    *)
        echo "FATAL: unsupported arch $(uname -m)" >&2
        exit 1
        ;;
esac

SRC_DIR="/tmp/musl-src-${VERSION}"
INSTALL_DIR="/opt/musl-${VERSION}"
OUT_DIR="/musls/${VERSION}"

echo "=== Building musl ${VERSION} ==="

echo "[1/5] Downloading musl-${VERSION}..."
TARBALL="/tmp/musl-${VERSION}.tar.gz"
wget -q --https-only --retry-connrefused --retry-on-host-error --waitretry=15 --tries=5 --timeout=60 \
    "https://musl.libc.org/releases/musl-${VERSION}.tar.gz" -O "${TARBALL}" || {
    echo "ERROR: downloading musl ${VERSION} failed"
    exit 4
}

echo "${SHA256}  ${TARBALL}" | sha256sum -c - || {
    echo "FATAL: musl ${VERSION} sha256 mismatch"
    exit 1
}

mkdir -p "${SRC_DIR}"
tar xf "${TARBALL}" -C "${SRC_DIR}" --strip-components=1

echo "[2/5] Configuring..."
cd "${SRC_DIR}"
CONFIGURE_LOG="/tmp/musl-configure-${VERSION}.log"
if ! ./configure --prefix="${INSTALL_DIR}" --enable-debug > "${CONFIGURE_LOG}" 2>&1; then
    echo "CONFIGURE FAILED for musl ${VERSION}. Last 30 lines:"
    tail -30 "${CONFIGURE_LOG}"
    exit 2
fi

echo "[3/5] Building..."
BUILD_LOG="/tmp/musl-build-${VERSION}.log"
make -j"$(nproc)" > "${BUILD_LOG}" 2>&1 || {
    echo "BUILD FAILED for musl ${VERSION}. Last 30 lines:"
    tail -30 "${BUILD_LOG}"
    exit 3
}

echo "[4/5] Installing to ${INSTALL_DIR}..."
INSTALL_LOG="/tmp/musl-install-${VERSION}.log"
make install > "${INSTALL_LOG}" 2>&1 || {
    echo "INSTALL FAILED for musl ${VERSION}. Last 30 lines:"
    tail -30 "${INSTALL_LOG}"
    exit 5
}

echo "[5/5] Packaging artifacts..."
mkdir -p "${OUT_DIR}/lib" "${OUT_DIR}/include"
cp -a "${INSTALL_DIR}/lib/libc.a" "${OUT_DIR}/lib/"
cp -a "${INSTALL_DIR}/lib/libc.so" "${OUT_DIR}/lib/"
# SONAME so a linked binary's DT_NEEDED is a name, not an absolute path that musl maps as the interpreter (which leaves pwndbg no separate libc to detect).
patchelf --set-soname libc.so "${OUT_DIR}/lib/libc.so"
ln -sf "libc.so" "${OUT_DIR}/lib/${MUSL_LD}"
cp -a "${INSTALL_DIR}/lib/"crt1.o "${INSTALL_DIR}/lib/"Scrt1.o \
    "${INSTALL_DIR}/lib/"crti.o "${INSTALL_DIR}/lib/"crtn.o "${OUT_DIR}/lib/"
cp -a "${INSTALL_DIR}/include/." "${OUT_DIR}/include/"

symbols=$(nm "${OUT_DIR}/lib/libc.a" 2> /dev/null) || true
case "${symbols}" in
    *__libc_version*) ;;
    *)
        echo "FATAL: __libc_version missing from libc.a for musl ${VERSION}"
        exit 1
        ;;
esac

rm -rf "${SRC_DIR}" "${INSTALL_DIR}" "${TARBALL}"

echo "=== musl ${VERSION} built successfully ==="
ls -la "${OUT_DIR}/lib/"
