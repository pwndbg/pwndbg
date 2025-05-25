#!/bin/sh

# This may perform verification instead of building
# depending on PWNDBG_DOCGEN_VERIFY.
uv run --group docs python ./scripts/_docs/build_command_docs.py || exit 1
uv run --group docs python ./scripts/_docs/build_configuration_docs.py || exit 2
uv run --group docs python ./scripts/_docs/build_function_docs.py || exit 3
