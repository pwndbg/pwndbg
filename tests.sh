#!/usr/bin/env bash

# Use ldd to fetch the glibc version.
# Can help with diagnosing CI issues.
glibc_version=$(ldd --version | sed -n '1s/([^)]*)//g; s/.* \([0-9]\+\.[0-9]\+\)$/\1/p')
echo "glibc version: $glibc_version"

# Run integration tests
(cd tests && python3 tests.py $@)
exit_code=$?
exit $exit_code
