#!/usr/bin/env bash

_COMMON_ABS_DIR=$(realpath "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)")
# dirname of a directory gives the parent directory.
PWNDBG_ABS_PATH=$(dirname $_COMMON_ABS_DIR)

TESTING_KERNEL_IMAGES_DIR="${PWNDBG_ABS_PATH}/tests/library/qemu_system/kimages"

if [[ -z "${PWNDBG_VENV_PATH}" ]]; then
    PWNDBG_VENV_PATH="${PWNDBG_ABS_PATH}/.venv"
fi

if [[ "$PWNDBG_NO_UV" == "1" ]]; then
    # We are using the dependencies as installed on the system
    # so we shouldn't use uv (and can't, since it's not installed).
    UV=""
    UV_RUN=""
    UV_RUN_TEST=""
    UV_RUN_LINT=""
    UV_RUN_DOCS=""
    UV_RUN_MYPY=""
else
    # We are going to use uv.
    UV="${PWNDBG_VENV_PATH}/bin/uv"
    UV_RUN="${UV} run"
    UV_RUN_TEST="${UV_RUN} --group dev --group tests --all-extras"
    UV_RUN_LINT="${UV_RUN} --group lint"
    UV_RUN_DOCS="${UV_RUN} --group docs --extra gdb --extra lldb"
    UV_RUN_MYPY="${UV_RUN} --group dev --group lint --group tests --extra gdb --extra lldb"
fi
