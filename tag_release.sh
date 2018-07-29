#!/bin/sh

set -ex

DATE=$(which gdate || which date)

git fetch --all

TAG=$($DATE '+%Y.%m.%d')

if git tag -a $TAG -m "Add release $TAG" origin/stable; then
    git push origin $TAG
fi

