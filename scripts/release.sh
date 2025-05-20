#!/usr/bin/env bash

set -ex

OLD_VER="$1"
NEW_VER="$2"

portable_sed_replace() {
    local arg1="$1"
    local arg2="$2"
    shift 2
    local files=("$@")

    if sed --version 2> /dev/null | grep -q "GNU"; then
        for file in "${files[@]}"; do
            sed -i "s@$arg1@$arg2@g" "$file"
        done
    else
        for file in "${files[@]}"; do
            sed -i '' "s@$arg1@$arg2@g" "$file"
        done
    fi
}

# Replace version in all places
portable_sed_replace $OLD_VER $NEW_VER ./pyproject.toml
portable_sed_replace $OLD_VER $NEW_VER ./pwndbg/lib/version.py
portable_sed_replace $OLD_VER $NEW_VER ./README.md
portable_sed_replace $OLD_VER $NEW_VER ./docs/setup.md
portable_sed_replace $OLD_VER $NEW_VER ./docs/install.sh

# Rebuild uv.lock file after version change
uv lock
