#!/usr/bin/env bash

if [[ -z "${PWNDBG_VENV_PATH}" ]]; then
    PWNDBG_VENV_PATH="./.venv"
fi

"${PWNDBG_VENV_PATH}/bin/uv" run --group docs mkdocs serve -a 0.0.0.0:8000
