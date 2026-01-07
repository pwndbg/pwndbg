#!/usr/bin/env bash

set -o errexit

source "$(dirname "$0")/scripts/common.sh"

cd $PWNDBG_ABS_PATH

help_and_exit() {
    echo "Usage: ./lint.sh [-f|--fix] [--format] [--all]"
    echo "  -f,  --fix         fix issues if possible"
    echo "  --format           run only ruff, shfmt, and vermin checks (skip mypy)"
    echo "  --all              run all checks including mypy (default behavior)"
    echo ""
    echo "By default, all checks are run.  Use --format for a quick formatting-only check."
    exit 1
}

FIX=0
FORMAT_ONLY=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -f | --fix)
            FIX=1
            shift
            ;;
        --format)
            FORMAT_ONLY=1
            shift
            ;;
        --all)
            # Explicitly run all checks (default behavior)
            # do we want to require --format or --all instead?
            FORMAT_ONLY=0
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
    $UV_RUN_LINT ruff format ${LINT_FILES}
    $UV_RUN_LINT ruff check --fix --output-format=full ${LINT_FILES}
    call_shfmt -w
else
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

# Exit early if --format was specified
if [[ $FORMAT_ONLY == 1 ]]; then
    set +o xtrace
    echo ""
    echo "========================================="
    echo "NOTE: Only ruff, shfmt, and vermin were run."
    echo "      mypy was NOT run."
    echo "      Use --all or no flags to run all checks."
    echo "========================================="
    exit 0
fi

# mypy is run in a separate step on GitHub Actions
if [[ -z "$GITHUB_ACTIONS" ]]; then
    $UV_RUN_MYPY mypy $LINT_FILES
fi
