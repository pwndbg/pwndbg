#!/bin/sh

# Extract from sources all the information necessary to build
# the documentation. Do this from each debugger.

    # -ix ./scripts/_docs/extract_command_docs.py \
export PWNDBG_DOCGEN_DBGNAME="gdb"
uv run --group docs gdb --batch -nx -ix ./gdbinit.py \
    -iex "set exception-verbose on" \
    -ix ./scripts/_docs/extract_configuration_docs.py \
    -nx

# command script import ./scripts/_docs/extract_command_docs.py
export PWNDBG_DOCGEN_DBGNAME="lldb"
uv run --group docs --extra lldb python pwndbg-lldb.py <<EOF
set show-tips off
command script import ./scripts/_docs/extract_configuration_docs.py
EOF
