#!/usr/bin/env bash

set -o errexit

source "$(dirname "$0")/scripts/common.sh"

cd $PWNDBG_ABS_PATH

help_and_exit() {
    echo "Usage: ./lint.sh [-f|--fix]"
    echo "  -f,  --fix         fix issues if possible"
    exit 1
}

if [[ $# -gt 1 ]]; then
    help_and_exit
fi

FIX=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -f | --fix)
            FIX=1
            shift
            ;;
        *)
            help_and_exit
            ;;
    esac
done

set -o xtrace

LINT_FILES="pwndbg pwndbginit tests *.py scripts"

call_shfmt() {
    local FLAGS=$1
    if [ -x "$(command -v shfmt)" ]; then
        local SHFMT_FILES=$(find . -name "*.sh" -not -path "./.venv/*")
        # Indents are four spaces, binary ops can start a line, indent switch cases,
        # and allow spaces following a redirect
        $UV_RUN_LINT shfmt ${FLAGS} -i 4 -bn -ci -sr -d ${SHFMT_FILES}
    else
        echo "shfmt not installed, please install it"
        exit 2
    fi
}

if [[ $FIX == 1 ]]; then
    $UV_RUN_LINT isort ${LINT_FILES}
    $UV_RUN_LINT ruff format ${LINT_FILES}
    $UV_RUN_LINT ruff check --fix --output-format=full ${LINT_FILES}
    call_shfmt -w
else
    $UV_RUN_LINT isort --check-only --diff ${LINT_FILES}
    $UV_RUN_LINT ruff format --check --diff ${LINT_FILES}
    call_shfmt

    if [[ -z "$GITHUB_ACTIONS" ]]; then
        RUFF_OUTPUT_FORMAT=full
    else
        RUFF_OUTPUT_FORMAT=github
    fi

    $UV_RUN_LINT ruff check --output-format="${RUFF_OUTPUT_FORMAT}" ${LINT_FILES}
fi

# Checking minimum python version
$UV_RUN_LINT vermin -vvv --no-tips -t=3.10- --eval-annotations --violations ${LINT_FILES}

# mypy is run in a separate step on GitHub Actions
if [[ -z "$GITHUB_ACTIONS" ]]; then
    $UV_RUN_MYPY mypy pwndbg pwndbginit tests/host
fi
