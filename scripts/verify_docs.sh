#!/bin/sh

# Tell the script to verify instead of generate files.
export PWNDBG_GEN_DOC_JUST_VERIFY=1
# Run the verifier inside gdb so everything resolves correctly.
uv run --group docs gdb --batch -nx --ex "source ./gdbinit.py" \
    --ex "set exception-verbose on" \
    --ex "source ./scripts/_gen_command_docs.py" \
    --ex "source ./scripts/_gen_configuration_docs.py" \
    --ex "source ./scripts/_gen_function_docs.py" \
    --quiet
