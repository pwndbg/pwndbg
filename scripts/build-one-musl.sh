#!/usr/bin/env bash
# Build a single musl libc version from source and package it for pwndbg testing.
#
# Usage: ./build-one-musl.sh <version>
# Example: ./build-one-musl.sh 1.2.5
#
# Output: /musls/<version>/ containing:
#   lib/libc.a              (static archive, for static test binaries)
#   lib/libc.so             (the real shared object = the dynamic loader; SONAME libc.so)
#   lib/ld-musl-<arch>.so.1 (symlink -> libc.so; musl's libc and ld are one file)
#   lib/{crt1,Scrt1,crti,crtn}.o
#   include/                (this version's headers)
#
# Built with --enable-debug and not stripped, so the internal __libc_version
# symbol survives; pwndbg's musl provider reads it for version detection.

set -euo pipefail

VERSION="${1:?Usage: $0 <musl-version>}"

# musl's loader symlink name is arch-specific; this script builds natively for the
# host arch (the x86-64 or aarch64 CI runner).
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

# Download source (random delay to avoid thundering herd when BuildKit runs stages
# in parallel)
DELAY=$((RANDOM % 10))
echo "[1/5] Downloading musl-${VERSION} (delay ${DELAY}s)..."
sleep "${DELAY}"
TARBALL="/tmp/musl-${VERSION}.tar.gz"
# Release tarball only: the git-snapshot is a different archive whose hash would not
# match the pinned one, so retry the release rather than fall back to it.
wget -q --https-only --retry-connrefused --retry-on-host-error --waitretry=15 --tries=5 --timeout=60 \
    "https://musl.libc.org/releases/musl-${VERSION}.tar.gz" -O "${TARBALL}" || {
    echo "ERROR: downloading musl ${VERSION} failed"
    exit 4
}

# Verify the download against the known-good sha256 (from musl.libc.org). Bump
# alongside the version list in Dockerfile.musl-test-libs.
case "${VERSION}" in
    1.1.24) SHA256=1370c9a812b2cf2a7d92802510cca0058cc37e66a7bedd70051f0a34015022a3 ;;
    1.2.1) SHA256=68af6e18539f646f9c41a3a2bb25be4a5cfa5a8f65f0bb647fd2bbfdf877e84b ;;
    1.2.2) SHA256=9b969322012d796dc23dda27a35866034fa67d8fb67e0e2c45c913c3d43219dd ;;
    1.2.3) SHA256=7d5b0b6062521e4627e099e4c9dc8248d32a30285e959b7eecaa780cf8cfd4a4 ;;
    1.2.4) SHA256=7a35eae33d5372a7c0da1188de798726f68825513b7ae3ebe97aaaa52114f039 ;;
    1.2.5) SHA256=a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4 ;;
    1.2.6) SHA256=d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a ;;
    *)
        if [ "${MUSL_CANARY:-0}" = "1" ]; then
            # Canary mode: this version is not pinned yet. Trust the official source on
            # first use, compute the checksum, and print the line to pin it when the
            # version is added for real.
            SHA256=$(sha256sum "${TARBALL}" | cut -c1-64)
            echo "CANARY: musl ${VERSION} is unpinned; computed sha256 ${SHA256}"
            echo "CANARY: to pin it, add '    ${VERSION}) SHA256=${SHA256} ;;' to build-one-musl.sh"
        else
            echo "FATAL: no known sha256 for musl ${VERSION}; add it to build-one-musl.sh"
            exit 1
        fi
        ;;
esac
echo "${SHA256}  ${TARBALL}" | sha256sum -c - || {
    echo "FATAL: musl ${VERSION} sha256 mismatch"
    exit 1
}

mkdir -p "${SRC_DIR}"
tar xf "${TARBALL}" -C "${SRC_DIR}" --strip-components=1

# Configure + build (musl builds in-tree)
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

# Package artifacts
echo "[5/5] Packaging artifacts..."
mkdir -p "${OUT_DIR}/lib" "${OUT_DIR}/include"
cp -a "${INSTALL_DIR}/lib/libc.a" "${OUT_DIR}/lib/"
# musl's libc and dynamic loader are one file. Package it as libc.so (the real
# shared object) with the arch's ld-musl-*.so.1 loader symlink, the layout
# distro musl uses. Crucially, give it a SONAME: a binary linked against it then
# records DT_NEEDED=libc.so (a name), not an absolute path. Without a SONAME the
# linker bakes in the absolute path, which musl resolves to the interpreter
# itself, so no separate libc maps at runtime and pwndbg can't detect it.
cp -a "${INSTALL_DIR}/lib/libc.so" "${OUT_DIR}/lib/"
patchelf --set-soname libc.so "${OUT_DIR}/lib/libc.so"
ln -sf "libc.so" "${OUT_DIR}/lib/${MUSL_LD}"
cp -a "${INSTALL_DIR}/lib/"crt1.o "${INSTALL_DIR}/lib/"Scrt1.o \
    "${INSTALL_DIR}/lib/"crti.o "${INSTALL_DIR}/lib/"crtn.o "${OUT_DIR}/lib/"
cp -a "${INSTALL_DIR}/include/." "${OUT_DIR}/include/"

# pwndbg's version() reads musl's internal __libc_version (const char
# __libc_version[] in src/internal/version.c); the static test binaries pull it
# from libc.a via -Wl,-u. Fail loud if a future musl version ever drops it.
# Capture nm's output instead of piping it, so the check can't misfire on nm's
# exit status under `set -o pipefail`.
symbols=$(nm "${OUT_DIR}/lib/libc.a" 2> /dev/null) || true
case "${symbols}" in
    *__libc_version*) ;;
    *)
        echo "FATAL: __libc_version missing from libc.a for musl ${VERSION}"
        exit 1
        ;;
esac

# Cleanup build artifacts to save space
rm -rf "${SRC_DIR}" "${INSTALL_DIR}" "${TARBALL}"

echo "=== musl ${VERSION} built successfully ==="
ls -la "${OUT_DIR}/lib/"
