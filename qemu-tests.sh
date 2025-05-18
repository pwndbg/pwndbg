#!/usr/bin/env bash

(cd tests && uv run --group dev --all-extras python3 tests.py -t cross-arch $@)
exit_code=$?
exit $exit_code
