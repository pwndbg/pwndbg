#!/usr/bin/env bash
# Append a not-yet-pinned "canary" libc version to a test Dockerfile, so the existing
# build/test machinery (the makefile, helpers, and tests all re-parse the Dockerfile)
# exercises it with no other changes. Used by the libc-canary workflow; the edit is
# meant to be ephemeral (made in a throwaway CI checkout, never committed).
#
# Usage: ./scripts/add-canary-version.sh <glibc|musl> <version>
set -euo pipefail

LIBC="${1:?usage: $0 <glibc|musl> <version>}"
VERSION="${2:?usage: $0 <glibc|musl> <version>}"
here="$(cd "$(dirname "$0")/.." && pwd)"

case "${LIBC}" in
    glibc)
        dockerfile="${here}/Dockerfile.glibc-test-libs"
        build_script="/build-one-glibc.sh"
        canary_env="GLIBC_CANARY=1"
        copies=(
            "COPY --from=build-${VERSION} /glibcs/${VERSION} /glibcs/${VERSION}"
            "COPY --from=build-${VERSION} /glibcs-nodebug/${VERSION} /glibcs-nodebug/${VERSION}"
        )
        ;;
    musl)
        dockerfile="${here}/Dockerfile.musl-test-libs"
        build_script="/build-one-musl.sh"
        canary_env="MUSL_CANARY=1"
        copies=("COPY --from=build-${VERSION} /musls/${VERSION} /musls/${VERSION}")
        ;;
    *)
        echo "FATAL: unknown libc '${LIBC}' (expected glibc or musl)" >&2
        exit 1
        ;;
esac

if grep -q "AS build-${VERSION}$" "${dockerfile}"; then
    echo "add-canary-version: ${LIBC} ${VERSION} already in ${dockerfile##*/}; nothing to do"
    exit 0
fi

# Insert the build stage just before the final "FROM scratch" stage. It runs in canary
# mode, so build-one-*.sh computes the checksum on first use instead of requiring a
# pinned one.
tmp="$(mktemp)"
awk -v stage="FROM base-builder AS build-${VERSION}" \
    -v run="RUN ${canary_env} ${build_script} ${VERSION}" '
    /^FROM scratch/ && !inserted { print stage; print run; print ""; inserted = 1 }
    { print }
' "${dockerfile}" > "${tmp}"
mv "${tmp}" "${dockerfile}"

# Append the artifact COPY lines (the scratch stage is last, so EOF joins it).
for c in "${copies[@]}"; do
    echo "${c}" >> "${dockerfile}"
done

echo "add-canary-version: added ${LIBC} ${VERSION} to ${dockerfile##*/}"
