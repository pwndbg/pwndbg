#!/bin/bash

set -o errexit

help_and_exit() {
    echo "Usage: ./lint.sh [-f|--filter]"
    echo "  -f,  --filter         format code instead of just checking the format"
    exit 1
}

if [[ $# -gt 1 ]]; then
    help_and_exit
fi

FORMAT=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -f | --format)
            FORMAT=1
            shift
            ;;
        *)
            help_and_exit
            ;;
    esac
done

set -o xtrace

LINT_FILES="pwndbg tests *.py"

if [[ $FORMAT == 1 ]]; then
    isort ${LINT_FILES}
    black ${LINT_FILES}
else
    isort --check-only --diff ${LINT_FILES}
    black --check --diff ${LINT_FILES}
fi

flake8 --show-source ${LINT_FILES}

# Indents are four spaces, binary ops can start a line, and indent switch cases
shfmt -i 4 -bn -ci -d .

# Checking minimum python version
vermin -t=3.6 --violations --eval-annotations ./pwndbg/
