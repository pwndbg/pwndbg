#!/usr/bin/env bash

source "$(dirname "$0")/scripts/common.sh"

cd "${PWNDBG_ABS_PATH}/tests"

$UV_RUN_TEST python3 tests.py -t cross-arch $@

exit_code=$?
exit $exit_code
