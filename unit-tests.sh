#!/usr/bin/env bash

source "$(dirname "$0")/scripts/common.sh"

COV=0
# Run unit tests
for arg in "$@"; do
    if [ "$arg" == "--cov" ]; then
        COV=1
        break
    fi
done

if [ $COV -eq 1 ]; then
    $UV_RUN_TEST coverage run -m pytest tests/unit_tests
else
    $UV_RUN_TEST pytest tests/unit_tests
fi

exit_code=$((exit_code + $?))

exit $exit_code
