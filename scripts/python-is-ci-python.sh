#!/usr/bin/env bash

source "$(dirname "$0")/common.sh"

# This script should only be run in our ubuntu-latest CI

if [ "$($UV_RUN python -V 2>&1)" = "Python $CI_PYTHON" ]; then
    echo "The CI Python version ($CI_PYTHON) is set correctly."
else
    echo "The CI Python version ($CI_PYTHON) is NOT set correctly"
    echo "Actual: "
    $UV_RUN python -V
    exit 1
fi
