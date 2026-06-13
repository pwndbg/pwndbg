#!/usr/bin/env bash

set -euo pipefail

VERSION="${1:?Usage: $0 <musl-version>}"

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

# Add new versions here and as a stage in Dockerfile.musl-test-libs.
case "${VERSION}" in
    1.1.24) SHA256=1370c9a812b2cf2a7d92802510cca0058cc37e66a7bedd70051f0a34015022a3 ;;
    1.2.1) SHA256=68af6e18539f646f9c41a3a2bb25be4a5cfa5a8f65f0bb647fd2bbfdf877e84b ;;
    1.2.2) SHA256=9b969322012d796dc23dda27a35866034fa67d8fb67e0e2c45c913c3d43219dd ;;
    1.2.3) SHA256=7d5b0b6062521e4627e099e4c9dc8248d32a30285e959b7eecaa780cf8cfd4a4 ;;
    1.2.4) SHA256=7a35eae33d5372a7c0da1188de798726f68825513b7ae3ebe97aaaa52114f039 ;;
    1.2.5) SHA256=a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4 ;;
    1.2.6) SHA256=d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a ;;
    *)
        echo "FATAL: no known sha256 for musl ${VERSION}; add it to build-one-musl.sh"
        exit 1
        ;;
esac
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
