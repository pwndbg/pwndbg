#!/bin/bash

PWNDBG_TESTS_DISABLE_COLORS=yes gdb --silent --nx --nh --command gdbinit.py --command pytests_launcher.py
