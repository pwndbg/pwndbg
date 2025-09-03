#!/usr/bin/env bash

source "$(dirname "$0")/scripts/common.sh"

# Use ldd to fetch the glibc version.
# Can help with diagnosing CI issues.
glibc_version=$(ldd --version | sed -n '1s/([^)]*)//g; s/.* \([0-9]\+\.[0-9]\+\)$/\1/p')
echo "glibc version: $glibc_version"

# Run integration tests
cd "${PWNDBG_ABS_PATH}"

$UV_RUN_TEST python3 -m tests.tests $@

exit_code=$?
exit $exit_code
