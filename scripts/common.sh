#!/usr/bin/env bash

COMMON_ABS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PWNDBG_ABS_PATH="${COMMON_ABS_DIR}/.."

if [[ -z "${PWNDBG_VENV_PATH}" ]]; then
    PWNDBG_VENV_PATH="${PWNDBG_ABS_PATH}/.venv"
fi

if [[ "$PWNDBG_VENV_PATH" == "PWNDBG_PLEASE_SKIP_VENV" ]]; then
    # We are using the dependancies as installed on the system
    # so we shouldn't use uv (and can't, since it's not installed).
    UV=""
    UV_RUN=""
    UV_RUN_TEST=""
    UV_RUN_LINT=""
    UV_RUN_DOCS=""
else
    # We are going to use uv.
    UV="${PWNDBG_VENV_PATH}/bin/uv"
    UV_RUN="${UV} run"
    UV_RUN_TEST="${UV_RUN} --group dev --group tests --all-extras"
    UV_RUN_LINT="${UV_RUN} --group dev --group lint"
    UV_RUN_DOCS="${UV_RUN} --group docs --extra gdb --extra lldb"
fi
