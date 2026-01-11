#!/usr/bin/env bash

_COMMON_ABS_DIR=$(realpath "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)")
# dirname of a directory gives the parent directory.
PWNDBG_ABS_PATH=$(dirname $_COMMON_ABS_DIR)

TESTING_KERNEL_IMAGES_DIR="${PWNDBG_ABS_PATH}/tests/library/qemu_system/kimages"

# We run CI on ubuntu-latest which is currently 24.04
CI_PYTHON="3.12.3"

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
    if [ -x "${PWNDBG_VENV_PATH}/bin/uv" ]; then
        UV="${PWNDBG_VENV_PATH}/bin/uv"
    elif command -v uv > /dev/null 2>&1; then
        echo "Warning: Falling back to 'uv' found in PATH." >&2
        UV="$(command -v uv)"
    else
        echo "Error: 'uv' binary not found." >&2
        UV="${PWNDBG_VENV_PATH}/bin/uv"
    fi
    UV_RUN="${UV} run"
    UV_RUN_TEST="${UV_RUN} --group dev --group tests --all-extras"
    UV_RUN_LINT="${UV_RUN} --group lint"
    # If we don't do this, we get inconsistencies because argparse is unstable.
    UV_RUN_DOCS="${UV_RUN} --python ${CI_PYTHON} --group docs --extra gdb --extra lldb"
    # Ideally we would run this with `--python 3.10.12` (which is from ubuntu 22:04, which is
    # what we are actually running in the lint CI), but running that python version requires
    # an extra system dependancy on some distros (e.g. libxcrypt-compat on arch).
    # Requires `--all-groups --all-extras` because it needs to be able to resolve every import in
    # the project.
    UV_RUN_MYPY="${UV_RUN} --all-groups --all-extras"
fi
