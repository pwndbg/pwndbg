#!/usr/bin/env bash

source "$(dirname "$0")/../common.sh"

cd $PWNDBG_ABS_PATH

# This may perform verification instead of building
# depending on PWNDBG_DOCGEN_VERIFY.
$UV_RUN_DOCS python ./scripts/_docs/build_command_docs.py || exit 1
$UV_RUN_DOCS python ./scripts/_docs/build_configuration_docs.py || exit 2
$UV_RUN_DOCS python ./scripts/_docs/build_function_docs.py || exit 3
