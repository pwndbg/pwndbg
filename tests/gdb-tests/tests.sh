#!/bin/bash

ROOT_DIR="$(readlink -f ../../)"
GDB_INIT_PATH="$ROOT_DIR/gdbinit.py"
COVERAGERC_PATH="$ROOT_DIR/pyproject.toml"

help_and_exit() {
    echo "Usage: ./tests.sh [-p|--pdb] [-c|--cov] [<test-name-filter>]"
    echo "  -p,  --pdb         enable pdb (Python debugger) post mortem debugger on failed tests"
    echo "  -c,  --cov         enable codecov"
    echo "  -v,  --verbose     display all test output instead of just failing test output"
    echo "  -k,  --keep        don't delete the temporary files containing the command output"
    echo "  -s,  --serial      run tests one at a time instead of in parallel"
    echo " --collect-only      only show the output of test collection, don't run any tests"
    echo "  <test-name-filter> run only tests that match the regex"
    exit 1
}

if [[ $# -gt 3 ]]; then
    help_and_exit
fi

USE_PDB=0
TEST_NAME_FILTER=""
RUN_CODECOV=0
KEEP=0
SERIAL=0
VERBOSE=0
COLLECT_ONLY=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -p | --pdb)
            USE_PDB=1
            SERIAL=1
            echo "Will run tests in serial and with Python debugger"
            shift
            ;;
        -c | --cov)
            echo "Will run codecov"
            RUN_CODECOV=1
            shift
            ;;
        -v | --verbose)
            VERBOSE=1
            shift
            ;;
        -k | --keep)
            KEEP=1
            shift
            ;;
        -s | --serial)
            SERIAL=1
            shift
            ;;
        --collect-only)
            COLLECT_ONLY=1
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

(cd ./tests/binaries && make clean && make all) || exit 1

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
elif [ $COLLECT_ONLY -eq 1 ]; then
    echo "$TESTS_COLLECT_OUTPUT"
    exit 0
fi

TESTS_LIST=($(echo -E "$TESTS_COLLECT_OUTPUT" | grep -o "tests/.*::.*" | grep "${TEST_NAME_FILTER}"))

run_test() {
    test_case="$1"

    gdb_args=(--command $GDB_INIT_PATH --command pytests_launcher.py)
    if [ ${RUN_CODECOV} -ne 0 ]; then
        gdb_args=(-ex 'py import coverage;coverage.process_startup()' "${gdb_args[@]}")
    fi
    SRC_DIR=$ROOT_DIR \
        COVERAGE_FILE=$ROOT_DIR/.cov/coverage \
        COVERAGE_PROCESS_START=$COVERAGERC_PATH \
        USE_PDB="${USE_PDB}" \
        PWNDBG_LAUNCH_TEST="${test_case}" \
        PWNDBG_DISABLE_COLORS=1 \
        run_gdb "${gdb_args[@]}"
    retval=$?

    if [ "$SERIAL" -ne 1 ]; then
        exit $retval
    fi
}

parse_output_file() {
    output_file="$1"

    read -r testname result < <(
        grep -Po '(^tests/[^ ]+)|(\x1b\[3.m(PASSED|FAILED|SKIPPED|XPASS|XFAIL)\x1b\[0m)' "$output_file" \
            | tr '\n' ' ' \
            | cut -d ' ' -f 1,2
    )
    testfile=${testname%::*}
    testname=${testname#*::}

    printf '%-70s %s\n' $testname $result

    # Only show the output of failed tests unless the verbose flag was used
    if [[ $VERBOSE -eq 1 || "$result" =~ FAIL ]]; then
        echo ""
        cat "$output_file"
        echo ""
    fi

    if [[ $KEEP -ne 1 ]]; then
        # Delete the temporary file created by `parallel`
        rm "$output_file"
    else
        echo "$output_file"
    fi
}

JOBLOG_PATH="$(mktemp)"
echo ""
echo -n "Running tests in parallel and using a joblog in $JOBLOG_PATH"

if [[ $KEEP -ne 1 ]]; then
    echo " (use --keep it to persist it)"
else
    echo ""
fi

. $(which env_parallel.bash)

start=$(date +%s)

if [ $SERIAL -eq 1 ]; then
    for t in "${TESTS_LIST[@]}"; do
        run_test "$t"
    done
else
    env_parallel --output-as-files --joblog $JOBLOG_PATH run_test ::: "${TESTS_LIST[@]}" | env_parallel parse_output_file {}
fi

end=$(date +%s)
seconds=$((end - start))
echo "Tests completed in ${seconds} seconds"

# TODO: This doesn't work with serial
# The seventh column in the joblog is the exit value and the tenth is the test name
FAILED_TESTS=($(awk '$7 == "1" { print $10 }' "${JOBLOG_PATH}"))

num_tests_failed=${#FAILED_TESTS[@]}
num_tests_passed_or_skipped=$((${#TESTS_LIST[@]} - $num_tests_failed))

echo ""
echo "*********************************"
echo "********* TESTS SUMMARY *********"
echo "*********************************"
echo "Tests passed or skipped: ${num_tests_passed_or_skipped}"
echo "Tests failed: ${num_tests_failed}"

if [ "${num_tests_failed}" -ne 0 ]; then
    echo ""
    echo "Failing tests: ${FAILED_TESTS[@]}"
    exit 1
fi

if [[ $KEEP -ne 1 ]]; then
    # Delete the temporary joblog file
    rm "${JOBLOG_PATH}"
else
    echo "Not removing the ${JOBLOG_PATH} since --keep was passed"
fi
