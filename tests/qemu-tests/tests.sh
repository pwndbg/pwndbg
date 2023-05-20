#!/bin/bash

#set -o errexit
set -o pipefail

ROOT_DIR="$(readlink -f ../../)"
GDB_INIT_PATH="$ROOT_DIR/gdbinit.py"
COVERAGERC_PATH="$ROOT_DIR/pyproject.toml"

CWD=$(dirname -- "$0")
IMAGE_DIR="${CWD}/images"
VMLINUX_LIST=($(basename -a "${IMAGE_DIR}"/vmlinux*))

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
    local arch="$1"
    shift

    if [[ "${arch}" == x86_64 ]]; then
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
TESTS_COLLECT_OUTPUT=$(run_gdb "x86_64" "${gdb_args[@]}")

if [ $? -eq 1 ]; then
    echo -E "$TESTS_COLLECT_OUTPUT"
    exit 1
elif [ $COLLECT_ONLY -eq 1 ]; then
    echo "$TESTS_COLLECT_OUTPUT"
    exit 0
fi

TESTS_LIST=($(echo -E "$TESTS_COLLECT_OUTPUT" | grep -o "tests/.*::.*" | grep "${TEST_NAME_FILTER}"))

init_gdb() {
    local kernel_type="$1"
    local kernel_version="$2"
    local arch="$3"

    gdb_connect_qemu=(-ex "file ${IMAGE_DIR}/vmlinux-${kernel_type}-${kernel_version}-${arch}" -ex "target remote :1234")
    # using 'rest_init' instead of 'start_kernel' to make sure that kernel
    # initialization has progressed sufficiently for testing purposes
    gdb_args=("${gdb_connect_qemu[@]}" -ex 'break *rest_init' -ex 'continue')
    run_gdb "${arch}" "${gdb_args[@]}" > /dev/null 2>&1
}

run_test() {
    test_case="$1"
    local kernel_type="$2"
    local kernel_version="$3"
    local arch="$4"

    gdb_connect_qemu=(-ex "file ${IMAGE_DIR}/vmlinux-${kernel_type}-${kernel_version}-${arch}" -ex "target remote :1234")
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
        PWNDBG_ARCH="${arch}" \
        PWNDBG_KERNEL_TYPE="${kernel_type}" \
        PWNDBG_KERNEL_VERSION="${kernel_version}" \
        run_gdb "${arch}" "${gdb_args[@]}"
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
    local kernel_type="$1"
    local kernel_version="$2"
    local arch="$3"
    shift 3
    local qemu_args=("$@")

    FAILED_TESTS=()
    printf "============================ Testing %-20s  ============================\n" "${kernel_type}-${kernel_version}-${arch}"

    if [[ ! -z ${qemu_args} ]]; then
        echo "Additional QEMU parameters used: '${qemu_args[@]}'"
    fi
    echo ""

    "${CWD}/run_qemu_system.sh" --kernel="${kernel_type}-${kernel_version}-${arch}" -- "${qemu_args[@]}" > /dev/null 2>&1 &

    init_gdb "${kernel_type}" "${kernel_version}" "${arch}"
    start=$(date +%s)

    for t in "${TESTS_LIST[@]}"; do
        output=$(run_test "$t" "${kernel_type}" "${kernel_version}" "${arch}")
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

for vmlinux in "${VMLINUX_LIST[@]}"; do
    KERNEL=$(echo "${vmlinux}" | sed "s/vmlinux-//")
    # extract architecture as last dash-separated group of the kernels name
    ARCH="${KERNEL##*-}"
    KERNEL_VERSION=$(echo ${KERNEL} | grep -oP "\d+\.\d+(\.\d+)?(-lts)?")
    KERNEL_TYPE=$(echo ${KERNEL} | sed "s/-${KERNEL_VERSION}-${ARCH}//")
    QEMU_ARGS=()

    test_system "${KERNEL_TYPE}" "${KERNEL_VERSION}" "${ARCH}" ${QEMU_ARGS}

    if [[ "${ARCH}" == @("x86_64") ]]; then
        # additional test with extra QEMU flags
        QEMU_ARGS+=(-cpu qemu64,+la57)
        test_system "${KERNEL_TYPE}" "${KERNEL_VERSION}" "${ARCH}" "${QEMU_ARGS[@]}"
    fi
done
