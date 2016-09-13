#!/bin/sh

git fetch --all

LAST_TAG=$(git log --tags -1 --pretty='%h')
COMMITS=$(git log $LAST_TAG..origin/master)
TAG=$(date '+%Y.%m.%d')

if [ -n "$COMMITS" ]; then
    git tag $TAG origin/master
    git push origin $TAG
fi

