#!/usr/bin/env bash

# Run integration tests
(cd tests && python3 tests.py $@)
exit_code=$?

COV=0
RUN_PYTEST=1
# Run unit tests
for arg in "$@"; do
    if [ "$arg" == "--cov" ]; then
        COV=1
        break
    elif [ "$arg" == "cross-arch" ]; then
        RUN_PYTEST=0
    fi
done

if [ $RUN_PYTEST -eq 0 ]; then
    exit $exit_code
fi

if [ $COV -eq 1 ]; then
    coverage run -m pytest tests/unit-tests
else
    pytest tests/unit-tests
fi

exit_code=$((exit_code + $?))

exit $exit_code
