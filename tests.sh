#!/usr/bin/env bash

# Print ldd and so glibc version
echo "Running ldd to see ldd and so glibc version"
ldd --version

# Run integration tests
(cd tests && python3 tests.py $@)
exit_code=$?
exit $exit_code
