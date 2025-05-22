#!/usr/bin/env bash

source "$(dirname "$0")/common.sh"

cd $PWNDBG_ABS_PATH

# Extract the documentation.
echo "Extracting docs.."
./scripts/_docs/extract-all-docs.sh || exit 1

# Build the documentation.
echo "Building docs.."
./scripts/_docs/build-all-docs.sh || exit 2
