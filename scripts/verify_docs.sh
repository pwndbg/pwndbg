#!/bin/sh

# Tell the script to verify instead of generate files.
export PWNDBG_GEN_DOC_JUST_VERIFY=1
# Run the verifier inside gdb so everything resolves correctly.
uv run --group docs gdb --batch -nx -ix ./gdbinit.py \
    -iex "set exception-verbose on" \
    -ix ./scripts/_gen_command_docs.py \
    -ix ./scripts/_gen_configuration_docs.py \
    -ix ./scripts/_gen_function_docs.py \
    -nx
