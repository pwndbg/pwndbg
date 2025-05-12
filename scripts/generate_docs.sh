#!/bin/sh

# Run the generator inside gdb so everything resolves correctly.
uv run --group docs gdb --batch -nx -ix ./gdbinit.py \
    -iex "set exception-verbose on" \
    -ix ./scripts/_gen_command_docs.py \
    -ix ./scripts/_gen_configuration_docs.py \
    -ix ./scripts/_gen_function_docs.py \
    -nx
