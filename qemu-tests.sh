#!/usr/bin/env bash

(cd tests && python3 tests.py -t cross-arch $@)
exit_code=$?
exit $exit_code
