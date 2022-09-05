#!/bin/bash

set -o xtrace
set -o errexit

isort --check-only --diff pwndbg tests
black --diff --check pwndbg tests
flake8 --show-source pwndbg tests
