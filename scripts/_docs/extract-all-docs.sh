#!/usr/bin/env bash

source "$(dirname "$0")/../common.sh"

cd $PWNDBG_ABS_PATH

# Extract from sources all the information necessary to build
# the documentation. Do this from each debugger.

export PWNDBG_DOCGEN_DBGNAME="gdb"
$UV_RUN_DOCS gdb --batch -nx -ix ./gdbinit.py \
    -iex "set exception-verbose on" \
    -ix ./scripts/_docs/extract_command_docs.py \
    -ix ./scripts/_docs/extract_configuration_docs.py \
    -ix ./scripts/_docs/extract_function_docs.py \
    -nx || exit 1

export PWNDBG_DOCGEN_DBGNAME="lldb"
{
    $UV_RUN_DOCS python pwndbg-lldb.py << EOF
set show-tips off
command script import ./scripts/_docs/extract_command_docs.py
command script import ./scripts/_docs/extract_configuration_docs.py
command script import ./scripts/_docs/extract_function_docs.py
EOF
} || exit 2
