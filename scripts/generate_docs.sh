#!/bin/sh

# Extract the documentation.
echo "Extracting docs.."
./scripts/_docs/extract_all_docs.sh || exit 1

# Build the documentation.
echo "Building docs.."
./scripts/_docs/build_all_docs.sh || exit 1
