#!/usr/bin/env bash

rm ./docs/index.md
echo "---
hide:
  - navigation
---
" > ./docs/index.md

cat ./README.md >> ./docs/index.md
