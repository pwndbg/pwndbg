#!/bin/sh

# Extract the documentation.
echo "Extracting docs.."
./scripts/_docs/extract_all_docs.sh || exit 1

# Verify the documentation.
echo "Verifying docs.."
export PWNDBG_DOCGEN_VERIFY=1
./scripts/_docs/build_all_docs.sh || exit 1
