#!/bin/bash

futurize --all-imports --stage1 --print-function --write --unicode-literals pwndbg tests
isort --recursive pwndbg tests
