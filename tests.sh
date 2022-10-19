#!/bin/bash

# Run integration tests
(cd tests/gdb-tests && ./tests.sh $@)

# Run unit tests
# coverage run -m pytest tests/unit-tests
