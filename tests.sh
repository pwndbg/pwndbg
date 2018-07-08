#!/bin/bash

cd tests/binaries && make && cd ../..
PWNDBG_DISABLE_COLORS=1 PWNDBG_TESTSERVER_PORT=8719 python3 ./pytests_launcher.py
