#!/bin/bash

set -o xtrace
set -o errexit

isort --check-only --diff pwndbg tests
black --diff --check pwndbg tests
flake8 --show-source pwndbg tests

# Indents are four spaces, binary ops can start a line, and indent switch cases
shfmt -i 4 -bn -ci -d .