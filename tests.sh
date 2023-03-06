#!/bin/bash

# Check some basic test dependencies
if ! command -v env_parallel &> /dev/null; then
    echo 'Error: The `env_parallel` command could not be found. You should run `setup-dev.sh` to install development dependencies.'
    echo '(Alternatively, run ./tests.sh with `--serial` to skip using parallel test running. However, if `env_parallel` is missing, it is likely that other dependencies like the `zig` compiler are also missing)'
    exit
fi

# Run integration tests
(cd tests/gdb-tests && ./tests.sh $@)

# Run unit tests
# coverage run -m pytest tests/unit-tests
