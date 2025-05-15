#!/bin/sh

export PWNDBG_DOCGEN_DBGNAME="gdb"

uv run --group docs gdb --batch -nx -ix ./gdbinit.py \
    -iex "set exception-verbose on" \
    -ix ./scripts/_docs/extract_command_docs.py \
    -nx

export PWNDBG_DOCGEN_DBGNAME="lldb"

uv run --group docs --extra lldb python pwndbg-lldb.py <<EOF
set show-tips off
command script import ./scripts/_docs/extract_command_docs.py
EOF
