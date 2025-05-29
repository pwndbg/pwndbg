#!/usr/bin/env bash

source "$(dirname "$0")/common.sh"

cd $PWNDBG_ABS_PATH

$UV_RUN_DOCS mkdocs serve -a 0.0.0.0:8000
