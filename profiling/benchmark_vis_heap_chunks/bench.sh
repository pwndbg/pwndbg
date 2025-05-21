#!/bin/sh

if [[ -z "${PWNDBG_VENV_PATH}" ]]; then
    PWNDBG_VENV_PATH="./.venv"
fi

"${PWNDBG_VENV_PATH}/bin/uv" run gdb --batch --ex 'break exit' --ex 'run' --ex 'source gdbscript.py' --args $(which python3) -c 'import sys; sys.exit(0)'
