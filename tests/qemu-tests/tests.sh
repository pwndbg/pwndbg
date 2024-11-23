#!/usr/bin/env bash

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
    echo "Usage: ./tests.sh [-p|--pdb] [-c|--cov] [--nix] [--gdb-port=<port>] [-Q|--preserve-qemu-image] [<test-name-filter>]"
    echo "  -p,  --pdb                  enable pdb (Python debugger) post mortem debugger on failed tests"
    echo "  -c,  --cov                  enable codecov"
    echo "  -v,  --verbose              display all test output instead of just failing test output"
    echo "  --nix                       run tests using built for nix environment"
    echo "  --gdb-port=<port>           specify debug port for gdb/QEMU (Default: 1234)"
    echo "  --collect-only              only show the output of test collection, don't run any tests"
    echo "  -Q,  --preserve-qemu-image  don't kill QEMU image after failed tests"
    echo "  <test-name-filter>          run only tests that match the regex"
    exit 1
}

handle_sigint() {
    echo "Exiting..." >&2
    echo "Killing QEMU process $QEMU_PID"... >&2
    pkill -P $QEMU_PID
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
PRESERVE_QEMU_IMAGE=0
GDB_PORT=1234
RUN_IN_NIX=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -p | --pdb)
            USE_PDB=1
            echo "Will run tests with Python debugger"
            ;;
        -c | --cov)
            echo "Will run codecov"
            RUN_CODECOV=1
            ;;
        -v | --verbose)
            VERBOSE=1
            ;;
        --nix)
            RUN_IN_NIX=1
            ;;
        --collect-only)
            COLLECT_ONLY=1
            ;;
        -Q | --preserve-qemu-image)
            PRESERVE_QEMU_IMAGE=1
            ;;
        --gdb-port=*)
            GDB_PORT="${1#--gdb-port=}"
            ;;
        -h | --help)
            help_and_exit
            ;;
        *)
            if [[ ! -z "${TEST_NAME_FILTER}" ]]; then
                help_and_exit
            fi
            TEST_NAME_FILTER="$1"
            ;;
    esac
    shift
done

# Test if the port is already listening, possibly by other qemu instance. This
# can cause unexpected test failures.
NETSTAT=$(which netstat)
if [[ -z "${NETSTAT}" ]]; then
    NETSTAT=$(which ss)
fi
if [[ -z "${NETSTAT}" ]]; then
    echo "WARNING: netstat/ss not found. Cannot check if port ${GDB_PORT} is already bound." >&2
    exit 1
else
    if [[ $(${NETSTAT} -tuln 2> /dev/null | grep ":${GDB_PORT}" | grep -c LISTEN) -ne 0 ]]; then
        echo "WARNING: Port ${GDB_PORT} appears already bound. Please specify a different port with --gdb-port=<port>" >&2
        exit 1
    fi
fi

run_gdb() {
    local arch="$1"
    shift

    if [ $RUN_IN_NIX -eq 1 ]; then
        gdb_load_pwndbg=()

        GDB="$ROOT_DIR/result/bin/pwndbg"
        if [ ! -x "$GDB" ]; then
            echo "ERROR: No nix-compatible pwndbg found. Run nix build .#pwndbg-dev"
            exit 1
        fi
    else
        gdb_load_pwndbg=(--command "$GDB_INIT_PATH")

        if [[ "${arch}" == x86_64 ]]; then
            GDB=gdb
        else
            GDB=gdb-multiarch
        fi
    fi

    $GDB --silent --nx --nh "${gdb_load_pwndbg[@]}" -ex "set exception-verbose on" "$@" -ex "quit" 2> /dev/null
    return $?
}

# NOTE: We run tests under GDB sessions and because of some cleanup/tests dependencies problems
# we decided to run each test in a separate GDB session
gdb_args=(--command ../pytests_collect.py)
TESTS_COLLECT_OUTPUT=$(TESTS_PATH="$ROOT_DIR/tests/qemu-tests/tests/system" run_gdb "x86_64" "${gdb_args[@]}")

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

    gdb_connect_qemu=(-ex "file ${IMAGE_DIR}/vmlinux-${kernel_type}-${kernel_version}-${arch}" -ex "target remote :${GDB_PORT}")
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

    gdb_connect_qemu=(-ex "file ${IMAGE_DIR}/vmlinux-${kernel_type}-${kernel_version}-${arch}" -ex "target remote :${GDB_PORT}")
    gdb_args=("${gdb_connect_qemu[@]}" --command ../pytests_launcher.py)
    if [ ${RUN_CODECOV} -ne 0 ]; then
        gdb_args=(-ex 'py import coverage;coverage.process_startup()' "${gdb_args[@]}")
    fi

    SRC_DIR=$ROOT_DIR \
        COVERAGE_FILE=$ROOT_DIR/.cov/coverage \
        COVERAGE_PROCESS_START=$COVERAGERC_PATH \
        USE_PDB="${USE_PDB}" \
        PWNDBG_LAUNCH_TEST="qemu-tests/${test_case}" \
        PWNDBG_DISABLE_COLORS=1 \
        PWNDBG_ARCH="${arch}" \
        PWNDBG_KERNEL_TYPE="${kernel_type}" \
        PWNDBG_KERNEL_VERSION="${kernel_version}" \
        run_gdb "${arch}" "${gdb_args[@]}"
    return $?
}

process_output() {
    output="$1"
    if [[ -z "$output" ]]; then
        return
    fi

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

    # NOTE: If you run simultaneous tests or left an image lying around via -Q, this
    # will hang due to failure to obtain lock. But will see the error message...
    "${CWD}/run_qemu_system.sh" --kernel="${kernel_type}-${kernel_version}-${arch}" --gdb-port="${GDB_PORT}" -- "${qemu_args[@]}" > /dev/null &
    QEMU_PID=$!
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
        if [ ${PRESERVE_QEMU_IMAGE} -eq 0 ]; then
            pkill -P $QEMU_PID
        else
            echo "Preserving qemu image for debugging purposes. Kill with 'pkill -P $QEMU_PID'"
        fi
        exit 1
    fi

    pkill -P $QEMU_PID

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
