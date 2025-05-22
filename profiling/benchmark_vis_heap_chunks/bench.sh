#!/usr/bin/env bash

source "$(dirname "$0")/../../scripts/common.sh"

$UV_RUN gdb --batch --ex 'break exit' --ex 'run' --ex 'source gdbscript.py' --args $(which python3) -c 'import sys; sys.exit(0)'
