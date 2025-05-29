#!/usr/bin/env bash

# Extract the documentation.
echo "Extracting docs.."
./scripts/_docs/extract-all-docs.sh || exit 1

# Verify the documentation.
echo "Verifying docs.."
export PWNDBG_DOCGEN_VERIFY=1
./scripts/_docs/build-all-docs.sh || exit 1
