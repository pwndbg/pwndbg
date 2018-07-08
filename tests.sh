#!/bin/bash

cd tests/binaries && make && cd ../..

# NOTE: We run tests under GDB sessions and because of some cleanup/tests dependencies problems
# we decided to run each test in a separate GDB session
TESTS_LIST=$(gdb --silent --nx --nh --command gdbinit.py --command pytests_collect.py --eval-command quit | grep -o "tests/.*::.*")

tests_passed_or_skipped=0
tests_failed=0

for test_case in ${TESTS_LIST}; do
    PWNDBG_LAUNCH_TEST="${test_case}" PWNDBG_DISABLE_COLORS=1 gdb --silent --nx --nh --command gdbinit.py --command pytests_launcher.py --eval-command quit

    exit_status=$?

    if [ ${exit_status} -eq 0 ]; then
        (( ++tests_passed_or_skipped ))
    else
        (( ++tests_failed ))
    fi
done

echo ""
echo "*********************************"
echo "********* TESTS SUMMARY *********"
echo "*********************************"
echo "Tests passed or skipped: ${tests_passed_or_skipped}"
echo "Tests failed: ${tests_failed}"

if [ ${tests_failed} -ne 0 ]; then
    exit 1
fi
