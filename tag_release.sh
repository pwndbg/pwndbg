#!/bin/sh

DATE=$(which gdate || which date)

git fetch --all

TAG=$($DATE -d "$(git log --tags -1 --format='%aD')" '+%Y.%m.%d')

if git tag $TAG origin/master; then
    git push origin $TAG
fi

