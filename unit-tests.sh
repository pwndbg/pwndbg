#!/usr/bin/env bash

if [[ -z "${PWNDBG_VENV_PATH}" ]]; then
    PWNDBG_VENV_PATH="./.venv"
fi

TEST_CMD="${PWNDBG_VENV_PATH}/bin/uv run --group dev --group tests --all-extras"

COV=0
# Run unit tests
for arg in "$@"; do
    if [ "$arg" == "--cov" ]; then
        COV=1
        break
    fi
done

if [ $COV -eq 1 ]; then
    $TEST_CMD coverage run -m pytest tests/unit-tests
else
    $TEST_CMD pytest tests/unit-tests
fi

exit_code=$((exit_code + $?))

exit $exit_code
