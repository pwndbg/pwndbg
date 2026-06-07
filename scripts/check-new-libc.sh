#!/usr/bin/env bash
# Detect the latest upstream glibc and musl release and compare against the versions
# already pinned in the test Dockerfiles. For each libc it prints the pinned and latest
# version and, when a newer release exists, emits it for the libc-canary workflow to
# build and test (via $GITHUB_OUTPUT when run in GitHub Actions).
#
# Usage: ./scripts/check-new-libc.sh
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"

fetch() {
    # Print a URL's body using whichever fetcher is available.
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL --proto '=https' --proto-redir '=https' "$1"
    else
        wget -q --https-only -O- "$1"
    fi
}

pinned_max() {
    # Highest "FROM base-builder AS build-<ver>" version declared in a Dockerfile.
    sed -n 's/^FROM base-builder AS build-\([0-9][0-9.]*\).*/\1/p' "$1" | sort -V | tail -1
}

latest_glibc() {
    fetch https://mirrors.kernel.org/gnu/glibc/ \
        | grep -oE 'glibc-[0-9]+\.[0-9]+(\.[0-9]+)?\.tar\.gz' \
        | sed -E 's/^glibc-([0-9.]+)\.tar\.gz$/\1/' | sort -V | tail -1
}

latest_musl() {
    fetch https://musl.libc.org/ \
        | grep -oiE 'musl-[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz' \
        | sed -E 's/^musl-([0-9.]+)\.tar\.gz$/\1/' | sort -V | tail -1
}

# Is $1 strictly newer than $2 by version sort?
newer() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

emit() {
    # Expose a value to later workflow steps when running under GitHub Actions.
    [ -n "${GITHUB_OUTPUT:-}" ] && echo "$1=$2" >> "$GITHUB_OUTPUT"
    return 0
}

glibc_pinned=$(pinned_max "$here/Dockerfile.glibc-test-libs")
glibc_latest=$(latest_glibc)
musl_pinned=$(pinned_max "$here/Dockerfile.musl-test-libs")
musl_latest=$(latest_musl)

echo "glibc: pinned=${glibc_pinned} latest=${glibc_latest}"
echo "musl:  pinned=${musl_pinned} latest=${musl_latest}"

if newer "$glibc_latest" "$glibc_pinned"; then
    echo "==> glibc ${glibc_latest} is NEWER than pinned ${glibc_pinned}"
    emit glibc_new "$glibc_latest"
else
    emit glibc_new ""
fi

if newer "$musl_latest" "$musl_pinned"; then
    echo "==> musl ${musl_latest} is NEWER than pinned ${musl_pinned}"
    emit musl_new "$musl_latest"
else
    emit musl_new ""
fi
