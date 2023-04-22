#!/bin/bash

#set -o errexit
set -o pipefail

ROOT_DIR="$(readlink -f ../../)"
GDB_INIT_PATH="$ROOT_DIR/gdbinit.py"
COVERAGERC_PATH="$ROOT_DIR/pyproject.toml"

ARCH=""
KERNEL_TYPE=""
VMLINUX=""

PLATFORMS=(
    # ARCH KERNEL_TYPE [QEMU_ARGS]
    "x86_64 linux"
    "x86_64 ack"
    "arm64 linux"
    "arm64 ack"
)

CWD=$(dirname -- "$0")
IMAGE_DIR="${CWD}/images"

ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope)
if [[ $ptrace_scope -ne 0 && $(id -u) -ne 0 ]]; then
    cat << EOF
WARNING: You are not running as root and ptrace_scope is not set to zero. If you
run into issues when using pwndbg or gdb-pt-dump, rerun this script as root, or
alternatively run the following command:

    echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

EOF
fi

help_and_exit() {
    echo "Usage: ./tests.sh [-p|--pdb] [-c|--cov] [<test-name-filter>]"
    echo "  -p,  --pdb         enable pdb (Python debugger) post mortem debugger on failed tests"
    echo "  -c,  --cov         enable codecov"
    echo "  -v,  --verbose     display all test output instead of just failing test output"
    echo " --collect-only      only show the output of test collection, don't run any tests"
    echo "  <test-name-filter> run only tests that match the regex"
    exit 1
}

handle_sigint() {
    echo "Exiting..." >&2
    pkill qemu-system
    exit 1
}
trap handle_sigint SIGINT

if [[ $# -gt 3 ]]; then
    help_and_exit
fi

USE_PDB=0
TEST_NAME_FILTER=""
RUN_CODECOV=0
VERBOSE=0
COLLECT_ONLY=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -p | --pdb)
            USE_PDB=1
            echo "Will run tests with Python debugger"
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

gdb_load_pwndbg=(--command "$GDB_INIT_PATH" -ex "set exception-verbose on")
run_gdb() {
    if [[ "$ARCH" == x86_64 ]]; then
        GDB=gdb
    else
        GDB=gdb-multiarch
    fi

    $GDB --silent --nx --nh "${gdb_load_pwndbg[@]}" "$@" -ex "quit" 2> /dev/null
    return $?
}

# NOTE: We run tests under GDB sessions and because of some cleanup/tests dependencies problems
# we decided to run each test in a separate GDB session
gdb_args=(--command pytests_collect.py)
TESTS_COLLECT_OUTPUT=$(run_gdb "${gdb_args[@]}")

if [ $? -eq 1 ]; then
    echo -E "$TESTS_COLLECT_OUTPUT"
    exit 1
elif [ $COLLECT_ONLY -eq 1 ]; then
    echo "$TESTS_COLLECT_OUTPUT"
    exit 0
fi

TESTS_LIST=($(echo -E "$TESTS_COLLECT_OUTPUT" | grep -o "tests/.*::.*" | grep "${TEST_NAME_FILTER}"))

init_gdb() {
    gdb_connect_qemu=(-ex "file ${VMLINUX}" -ex "target remote :1234")
    gdb_args=("${gdb_connect_qemu[@]}" -ex 'break start_kernel' -ex 'continue')
    run_gdb "${gdb_args[@]}" > /dev/null 2>&1
}

run_test() {
    test_case="$1"

    gdb_connect_qemu=(-ex "file ${VMLINUX}" -ex "target remote :1234")
    gdb_args=("${gdb_connect_qemu[@]}" --command pytests_launcher.py)
    if [ ${RUN_CODECOV} -ne 0 ]; then
        gdb_args=(-ex 'py import coverage;coverage.process_startup()' "${gdb_args[@]}")
    fi
    SRC_DIR=$ROOT_DIR \
        COVERAGE_FILE=$ROOT_DIR/.cov/coverage \
        COVERAGE_PROCESS_START=$COVERAGERC_PATH \
        USE_PDB="${USE_PDB}" \
        PWNDBG_LAUNCH_TEST="${test_case}" \
        PWNDBG_DISABLE_COLORS=1 \
        PWNDBG_ARCH="$ARCH" \
        PWNDBG_KERNEL_TYPE="$KERNEL_TYPE" \
        run_gdb "${gdb_args[@]}"
    return $?
}

process_output() {
    output="$1"

    read -r testname result < <(
        echo "$output" | grep -Po '(^tests/[^ ]+)|(\x1b\[3.m(PASSED|FAILED|SKIPPED|XPASS|XFAIL)\x1b\[0m)' \
            | tr '\n' ' ' \
            | cut -d ' ' -f 1,2
    )
    testfile=${testname%::*}
    testname=${testname#*::}

    printf '%-70s %s\n' $testname $result

    if [[ "$result" =~ FAIL ]]; then
        FAILED_TESTS+=("$testname")
    fi

    # Only show the output of failed tests unless the verbose flag was used
    if [[ $VERBOSE -eq 1 || "$result" =~ FAIL ]]; then
        echo ""
        echo "$output"
        echo ""
    fi
}

test_system() {
    FAILED_TESTS=()
    echo "============================ Testing $KERNEL_TYPE-$ARCH ============================"

    if [[ ! -z ${QEMU_ARGS} ]]; then
        echo "Additional QEMU parameters used: '${QEMU_ARGS[*]}'"
    fi

    echo ""

    "${CWD}/run_qemu_system.sh" --arch="$ARCH" --type="$KERNEL_TYPE" -- "${QEMU_ARGS[@]}" > /dev/null 2>&1 &

    init_gdb
    start=$(date +%s)

    for t in "${TESTS_LIST[@]}"; do
        output=$(run_test "$t")
        process_output "$output"
    done

    end=$(date +%s)
    seconds=$((end - start))
    echo "Tests completed in ${seconds} seconds"

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
        echo ""
        exit 1
    fi

    pkill qemu-system
}

for platform in "${PLATFORMS[@]}"; do
    read -r arch kernel_type qemu_args <<< "$platform"

    ARCH="$arch"
    KERNEL_TYPE="$kernel_type"
    QEMU_ARGS=($qemu_args)
    VMLINUX="${IMAGE_DIR}/vmlinux-${KERNEL_TYPE}-${ARCH}"

    test_system
done
