#!/bin/bash


# NOTE: We run tests under GDB sessions and because of some cleanup/tests dependencies problems
# we decided to run each test in a separate GDB session
TESTS_LIST=$(gdb --silent --nx --nh --command gdbinit.py --command pytests_collect.py | grep -o "tests/.*::.*")

for test_case in ${TESTS_LIST}; do
    PWNDBG_LAUNCH_TEST="${test_case}" PWNDBG_DISABLE_COLORS=1 gdb --silent --nx --nh --command gdbinit.py --command pytests_launcher.py
done