#!/bin/bash

ROOT_DIR="$(pwd)"
GDB_INIT_PATH="$ROOT_DIR/gdbinit.py"

help_and_exit() {
    echo "Usage: ./tests.sh [-p|--pdb] [<test-name-filter>]"
    echo "  -p,  --pdb         enable pdb (Python debugger) post mortem debugger on failed tests"
    echo "  <test-name-filter> run only tests that match the regex"
    exit 1
}

if [[ $# -gt 2 ]]; then
    help_and_exit
fi

USE_PDB=0
TEST_NAME_FILTER=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -p | --pdb)
            USE_PDB=1
            echo "Will run tests with Python debugger"
            shift
            ;;
        -h | --help)
            help_and_exit
            ;;
        *)
            if [[ ! -z "${TEST_NAME_FILTER}" ]]; then
                help_and_exit
            fi
            TEST_NAME_FILTER="$1"
            shift
            ;;
    esac
done

if [[ -z "$ZIGPATH" ]]; then
    # If ZIGPATH is not set, set it to $pwd/.zig
    # In Docker environment this should by default be set to /opt/zig
    export ZIGPATH="$ROOT_DIR/.zig"
fi
echo "ZIGPATH set to $ZIGPATH"

cd ./tests/binaries || exit 1
make clean && make all || exit 2
cd ../../

run_gdb() {
    gdb --silent --nx --nh "$@" --eval-command quit
}

# NOTE: We run tests under GDB sessions and because of some cleanup/tests dependencies problems
# we decided to run each test in a separate GDB session
gdb_args=(--command $GDB_INIT_PATH --command pytests_collect.py)
TESTS_COLLECT_OUTPUT=$(run_gdb "${gdb_args[@]}")

if [ $? -eq 1 ]; then
    echo -E "$TESTS_COLLECT_OUTPUT"
    exit 1
fi

TESTS_LIST=$(echo -E "$TESTS_COLLECT_OUTPUT" | grep -o "tests/.*::.*" | grep "${TEST_NAME_FILTER}")

tests_passed_or_skipped=0
tests_failed=0

for test_case in ${TESTS_LIST}; do
    gdb_args=(-ex 'py import coverage;coverage.process_startup()' --command $GDB_INIT_PATH --command pytests_launcher.py)
    COVERAGE_PROCESS_START=.coveragerc \
        USE_PDB="${USE_PDB}" \
        PWNDBG_LAUNCH_TEST="${test_case}" \
        PWNDBG_DISABLE_COLORS=1 \
        run_gdb "${gdb_args[@]}"

    exit_status=$?
    if [ ${exit_status} -eq 0 ]; then
        ((++tests_passed_or_skipped))
    else
        ((++tests_failed))
    fi
done

echo ""
echo "*********************************"
echo "********* TESTS SUMMARY *********"
echo "*********************************"
echo "Tests passed or skipped: ${tests_passed_or_skipped}"
echo "Tests failed: ${tests_failed}"

if [ "${tests_failed}" -ne 0 ]; then
    exit 1
fi
