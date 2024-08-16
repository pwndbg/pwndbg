#!/usr/bin/env bash

COV=0
# Run unit tests
for arg in "$@"; do
    if [ "$arg" == "--cov" ]; then
        COV=1
        break
    fi
done

if [ $COV -eq 1 ]; then
    coverage run -m pytest tests/unit-tests
else
    pytest tests/unit-tests
fi

exit_code=$((exit_code + $?))

exit $exit_code
