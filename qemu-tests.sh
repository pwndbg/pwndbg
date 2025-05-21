#!/usr/bin/env bash

TEST_CMD="./.venv/bin/uv run --group dev --group tests --all-extras"

(cd tests && $TEST_CMD python3 tests.py -t cross-arch $@)
exit_code=$?
exit $exit_code
