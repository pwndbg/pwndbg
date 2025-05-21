#!/usr/bin/env bash

# Use ldd to fetch the glibc version.
# Can help with diagnosing CI issues.
glibc_version=$(ldd --version | sed -n '1s/([^)]*)//g; s/.* \([0-9]\+\.[0-9]\+\)$/\1/p')
echo "glibc version: $glibc_version"

if [[ -z "${PWNDBG_VENV_PATH}" ]]; then
    PWNDBG_VENV_PATH="./.venv"
fi

TEST_CMD="${PWNDBG_VENV_PATH}/bin/uv run --group dev --group tests --all-extras"

# Run integration tests
(cd tests && $TEST_CMD python3 tests.py $@)
exit_code=$?
exit $exit_code
