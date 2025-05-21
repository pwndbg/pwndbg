#!/usr/bin/env bash

if [[ -z "${PWNDBG_VENV_PATH}" ]]; then
    PWNDBG_VENV_PATH="./.venv"
fi

TEST_CMD="${PWNDBG_VENV_PATH}/bin/uv run --group dev --group tests --all-extras"

(cd tests && $TEST_CMD python3 tests.py -t cross-arch $@)
exit_code=$?
exit $exit_code
