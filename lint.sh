#!/bin/bash

set -o xtrace
set -o errexit

isort --check-only --diff .
black --diff --check .
flake8 --show-source .

# Indents are four spaces, binary ops can start a line, and indent switch cases
shfmt -i 4 -bn -ci -d .
