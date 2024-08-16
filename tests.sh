#!/usr/bin/env bash

# Run integration tests
(cd tests && python3 tests.py $@)
exit_code=$?
exit $exit_code
