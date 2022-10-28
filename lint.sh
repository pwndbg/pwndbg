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
LINT_TOOLS="isort black flake8 vermin"

if ! type ${LINT_TOOLS} &> /dev/null; then
    PIP_CMD="pip install -Ur dev-requirements.txt"
    echo "Missing one of the following tools: ${LINT_TOOLS}"
    echo "Running '${PIP_CMD}'"

    $PIP_CMD
fi

if [[ $FORMAT == 1 ]]; then
    isort ${LINT_FILES}
    black ${LINT_FILES}
else
    isort --check-only --diff ${LINT_FILES}
    black --check --diff ${LINT_FILES}
fi

if [ -x "$(command -v shfmt)" ]; then
    # Indents are four spaces, binary ops can start a line, indent switch cases,
    # and allow spaces following a redirect
    shfmt -i 4 -bn -ci -sr -d .
else
    echo "shfmt not installed, skipping"
fi

# Checking minimum python version
vermin -q -t=3.6 --violations ./pwndbg/

flake8 --show-source ${LINT_FILES}
