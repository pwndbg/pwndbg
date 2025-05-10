#!/usr/bin/env bash

# Print ldd and so glibc version
echo "Running ldd to see ldd and so glibc version"
ldd --version

# Run integration tests
(cd tests && python3 tests.py $@)
exit_code=$?

# Show coverage report if --cov is passed
for arg in "$@"; do
    if [ "$arg" == "--cov" ]; then
        coverage report
        break
    fi
done

exit $exit_code
