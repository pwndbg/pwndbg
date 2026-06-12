#!/usr/bin/env bash

set -euo pipefail

VERSION="${1:?Usage: $0 <glibc-version>}"

case "$(uname -m)" in
    x86_64) GLIBC_LD="ld-linux-x86-64.so.2" ;;
    aarch64) GLIBC_LD="ld-linux-aarch64.so.1" ;;
    *)
        echo "FATAL: unsupported arch $(uname -m)" >&2
        exit 1
        ;;
esac

SRC_DIR="/tmp/glibc-src-${VERSION}"
BUILD_DIR="/tmp/glibc-build-${VERSION}"
INSTALL_DIR="/tmp/glibc-install-${VERSION}"
OUT_DIR="/glibcs/${VERSION}"

echo "=== Building glibc ${VERSION} ==="

echo "[1/5] Downloading glibc-${VERSION}..."
TARBALL="/tmp/glibc-${VERSION}.tar.gz"
MIRRORS=(
    "https://ftpmirror.gnu.org/glibc/glibc-${VERSION}.tar.gz"
    "https://mirrors.kernel.org/gnu/glibc/glibc-${VERSION}.tar.gz"
    "https://ftp.gnu.org/gnu/glibc/glibc-${VERSION}.tar.gz"
)
if [ "${GLIBC_CANARY:-0}" = "1" ]; then
    MIRRORS=("https://ftp.gnu.org/gnu/glibc/glibc-${VERSION}.tar.gz")
fi
downloaded=
for attempt in 1 2; do
    for url in "${MIRRORS[@]}"; do
        echo "Fetching ${url}"
        if wget -q --https-only --tries=1 --timeout=60 "${url}" -O "${TARBALL}"; then
            downloaded=1
            break 2
        fi
        echo "  mirror failed, trying next..."
    done
done
[ -n "${downloaded}" ] || {
    echo "ERROR: all glibc ${VERSION} mirrors failed"
    exit 4
}

# Add new versions here and as a stage in Dockerfile.glibc-test-libs.
case "${VERSION}" in
    2.35) SHA256=3e8e0c6195da8dfbd31d77c56fb8d99576fb855fafd47a9e0a895e51fd5942d4 ;;
    2.36) SHA256=02efa6ffbbaf3e10e88f16818a862608d04b0ef838c66f6025ae120530792c9c ;;
    2.37) SHA256=811f19f9200118ff94ede28a6e12307584152cdcbf3d366cd729ea2f855db255 ;;
    2.38) SHA256=16e51e0455e288f03380b436e41d5927c60945abd86d0c9852b84be57dd6ed5e ;;
    2.39) SHA256=97f84f3b7588cd54093a6f6389b0c1a81e70d99708d74963a2e3eab7c7dc942d ;;
    2.40) SHA256=2abc038f5022949cb67e996c3cae0e7764f99b009f0b9b7fd954dfc6577b599e ;;
    2.41) SHA256=c7be6e25eeaf4b956f5d4d56a04d23e4db453fc07760f872903bb61a49519b80 ;;
    2.42) SHA256=d4468d3e3267068c1b0623ca6424aac9a28766df774c8d8fb4978127fca7125a ;;
    2.43) SHA256=e1e622cbd635019090fa23260e5d9ec219b12f97ae7ae02f033d4ae42cf2c004 ;;
    *)
        if [ "${GLIBC_CANARY:-0}" = "1" ]; then
            SHA256=$(sha256sum "${TARBALL}" | cut -c1-64)
            echo "CANARY: glibc ${VERSION} is unpinned; computed sha256 ${SHA256} from ${url}"
            echo "CANARY: to pin it, add '    ${VERSION}) SHA256=${SHA256} ;;' to build-one-glibc.sh"
            echo "CANARY: then add a build-${VERSION} stage + COPY lines to Dockerfile.glibc-test-libs"
        else
            echo "FATAL: no known sha256 for glibc ${VERSION}; add it to build-one-glibc.sh"
            exit 1
        fi
        ;;
esac
echo "${SHA256}  ${TARBALL}" | sha256sum -c - || {
    echo "FATAL: glibc ${VERSION} sha256 mismatch"
    exit 1
}

mkdir -p "${SRC_DIR}"
tar xf "${TARBALL}" -C "${SRC_DIR}" --strip-components=1

echo "[2/5] Configuring..."
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"
CONFIGURE_LOG="/tmp/glibc-configure-${VERSION}.log"
# https://sourceware.org/glibc/manual/latest/html_node/Configuring-and-compiling.html
if ! "${SRC_DIR}/configure" \
    --prefix=/opt/glibc \
    --disable-werror \
    --enable-shared \
    --with-headers=/usr/include \
    CFLAGS="-g -O2" > "${CONFIGURE_LOG}" 2>&1; then
    echo "CONFIGURE FAILED for glibc ${VERSION}. Last 30 lines:"
    tail -30 "${CONFIGURE_LOG}"
    exit 2
fi
echo "Configure completed successfully."

echo "[3/5] Building (this takes a few minutes)..."
BUILD_LOG="/tmp/glibc-build-${VERSION}.log"
make -j"$(nproc)" -k > "${BUILD_LOG}" 2>&1 || echo "Build had non-fatal errors (expected for old glibc on newer host)."

if [ ! -f "${BUILD_DIR}/libc.so.6" ] && [ ! -f "${BUILD_DIR}/libc.so" ]; then
    echo "FATAL: libc.so not produced by build. Last 50 lines of build log:"
    tail -50 "${BUILD_LOG}"
    exit 1
fi
echo "Build completed."

echo "[4/5] Installing to staging..."
INSTALL_LOG="/tmp/glibc-install-${VERSION}.log"
make install -k DESTDIR="${INSTALL_DIR}" > "${INSTALL_LOG}" 2>&1 || true

echo "[5/5] Packaging artifacts..."
mkdir -p "${OUT_DIR}/.debug"

LIBC_SO=$(find "${INSTALL_DIR}" -name "libc.so.6" 2> /dev/null | head -1 || true)
if [ -n "${LIBC_SO}" ]; then
    LIBC_SO=$(readlink -f "${LIBC_SO}")
fi

LD_SO=$(find "${INSTALL_DIR}" -name "${GLIBC_LD}" 2> /dev/null | head -1 || true)
if [ -z "${LD_SO}" ]; then
    LD_SO=$(find "${INSTALL_DIR}" -name "ld-${VERSION}.so" 2> /dev/null | head -1 || true)
fi
if [ -z "${LD_SO}" ]; then
    echo "ld not found in install tree, checking build tree..."
    LD_SO="${BUILD_DIR}/elf/ld.so"
fi
if [ -n "${LD_SO}" ]; then
    LD_SO=$(readlink -f "${LD_SO}")
fi

if [ -z "${LIBC_SO}" ] || [ -z "${LD_SO}" ] || [ ! -f "${LIBC_SO}" ] || [ ! -f "${LD_SO}" ]; then
    echo "ERROR: Could not find libc or ld"
    echo "LIBC_SO=${LIBC_SO:-empty}"
    echo "LD_SO=${LD_SO:-empty}"
    find "${INSTALL_DIR}" -name "libc*" -o -name "ld*" 2> /dev/null | head -20 || true
    find "${BUILD_DIR}" -name "ld.so" -o -name "ld-linux*" 2> /dev/null | head -10 || true
    echo "Last 30 lines of the install log:"
    tail -30 "${INSTALL_LOG}" || true
    exit 1
fi

echo "Found libc: ${LIBC_SO}"
echo "Found ld: ${LD_SO}"
cp "${LD_SO}" "${OUT_DIR}/ld-${VERSION}.so"
ln -sf "ld-${VERSION}.so" "${OUT_DIR}/${GLIBC_LD}"

cp "${LIBC_SO}" "${OUT_DIR}/.debug/libc-${VERSION}.so"
objcopy --only-keep-debug "${OUT_DIR}/.debug/libc-${VERSION}.so"

cp "${LIBC_SO}" "${OUT_DIR}/libc-${VERSION}.so"
strip "${OUT_DIR}/libc-${VERSION}.so"
objcopy --add-gnu-debuglink="${OUT_DIR}/.debug/libc-${VERSION}.so" "${OUT_DIR}/libc-${VERSION}.so"

ln -sf "libc-${VERSION}.so" "${OUT_DIR}/libc.so.6"

# no-debug variant (GLIBC_BUILD_NODEBUG=1): *-nodebug heuristic tests
if [ "${GLIBC_BUILD_NODEBUG:-0}" = "1" ]; then
    ND_DIR="/glibcs-nodebug/${VERSION}"
    mkdir -p "${ND_DIR}"
    cp "${OUT_DIR}/ld-${VERSION}.so" "${ND_DIR}/ld-${VERSION}.so"
    ln -sf "ld-${VERSION}.so" "${ND_DIR}/${GLIBC_LD}"
    cp "${OUT_DIR}/libc-${VERSION}.so" "${ND_DIR}/libc-${VERSION}.so"
    objcopy --remove-section=.gnu_debuglink --strip-all "${ND_DIR}/libc-${VERSION}.so"
    ln -sf "libc-${VERSION}.so" "${ND_DIR}/libc.so.6"
    echo "=== glibc ${VERSION} no-debug variant ==="
    ls -la "${ND_DIR}/"
fi

rm -rf "${SRC_DIR}" "${BUILD_DIR}" "${INSTALL_DIR}" "${TARBALL}"

echo "=== glibc ${VERSION} built successfully ==="
ls -la "${OUT_DIR}/"
ls -la "${OUT_DIR}/.debug/"
