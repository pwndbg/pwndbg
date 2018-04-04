#!/bin/bash

PWNDBG_DISABLE_COLORS=1 gdb --silent --nx --nh --command gdbinit.py --command pytests_launcher.py
