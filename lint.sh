#!/usr/bin/env bash

set -o errexit

source "$(dirname "$0")/scripts/common.sh"

cd $PWNDBG_ABS_PATH

help_and_exit() {
    echo "Usage: ./lint.sh [--check | -fo|--fix-only | -f|--fix-and-check]"
    echo "  --check                 run all checks without applying fixes (default behavior)"
    echo "  -fo, --fix-only         fix formatting only, without running checks"
    echo "  -f,  --fix-and-check    fix formatting first, then run checks"
    echo ""
    echo "By default, all checks are run. Fixes are not applied unless specified."
    exit 1
}

if [[ $# -gt 1 ]]; then
    help_and_exit
fi

CHECK_ONLY=1
FIX_ONLY=0
FIX_AND_CHECK=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --check)
            CHECK_ONLY=1
            FIX_ONLY=0
            FIX_AND_CHECK=0
            shift
            ;;
        -fo | --fix-only)
            CHECK_ONLY=0
            FIX_ONLY=1
            FIX_AND_CHECK=0
            shift
            ;;
        -f | --fix-and-check)
            CHECK_ONLY=0
            FIX_ONLY=0
            FIX_AND_CHECK=1
            shift
            ;;
        *)
            help_and_exit
            ;;
    esac
done

print_info() {
    set +o xtrace
    local MSG=$1
    echo ""
    echo "[info] ${MSG}"
    echo ""
    set -o xtrace
}

set -o xtrace

LINT_FILES="pwndbg pwndbginit tests *.py scripts"

call_shfmt() {
    local FLAGS=$1
    if [ -x "$(command -v shfmt)" ]; then
        local SHFMT_FILES=$(find . -name "*.sh" -not -path "./.venv/*")
        # Indents are four spaces, binary ops can start a line, indent switch cases,
        # and allow spaces following a redirect
        print_info "Running shfmt on .sh files..."
        $UV_RUN_LINT shfmt ${FLAGS} -i 4 -bn -ci -sr -d ${SHFMT_FILES}
    else
        echo "shfmt not installed, please install it"
        exit 2
    fi
}

print_info "Running ruff on python files..."

if [[ $FIX_ONLY == 1 ]]; then
    $UV_RUN_LINT ruff format ${LINT_FILES}
    $UV_RUN_LINT ruff check --fix --output-format=full ${LINT_FILES}
    call_shfmt -w
    set +o xtrace
    echo ""
    echo "========================================="
    echo "NOTE: Only ruff, shfmt were run."
    echo "      mypy and vermin were NOT run."
    echo "      Use -f or no flags to run all checks."
    echo "========================================="
    exit 0
elif [[ $FIX_AND_CHECK == 1 ]]; then
    $UV_RUN_LINT ruff format ${LINT_FILES}
    $UV_RUN_LINT ruff check --fix --output-format=full ${LINT_FILES}
    call_shfmt -w
else
    if ! $UV_RUN_LINT ruff format --check --diff ${LINT_FILES}; then
        set +o xtrace
        echo ""
        echo "========================================="
        echo "ERROR: Formatting issues detected by ruff."
        echo "       Exiting early. All checks were NOT run."
        echo "       Use -f to fix issues automatically."
        echo "========================================="
        exit 1
    fi

    if ! call_shfmt; then
        set +o xtrace
        echo ""
        echo "========================================="
        echo "ERROR: Formatting issues detected by shfmt."
        echo "       Exiting early. All checks were NOT run."
        echo "       Use -f to fix issues automatically."
        echo "========================================="
        exit 1
    fi

    if [[ -z "$GITHUB_ACTIONS" ]]; then
        RUFF_OUTPUT_FORMAT=full
    else
        RUFF_OUTPUT_FORMAT=github
    fi

    $UV_RUN_LINT ruff check --output-format="${RUFF_OUTPUT_FORMAT}" ${LINT_FILES}
fi

# Checking minimum python version
print_info "Using vermin to check that the code is compatible with the lowest supported python version..."
# We have to use `--backport typing_extensions` because we use `override`, and the modern way to do it is
# `from typing import override`, but that only became available in 3.12 .
$UV_RUN_LINT vermin -vvv --no-tips -t=3.10- --eval-annotations --backport typing_extensions --violations ${LINT_FILES}

# Check our custom rules.
print_info "Checking custom Pwndbg lint rules..."
$UV_RUN_LINT scripts/custom-lint.py

# mypy is run in a separate step on GitHub Actions
if [[ -z "$GITHUB_ACTIONS" ]]; then
    print_info "Running mypy to check for type errors in python files..."
    $UV_RUN_MYPY mypy $LINT_FILES
fi

set +o xtrace
echo ""
echo "[success] Lint passed!"
set -o xtrace
