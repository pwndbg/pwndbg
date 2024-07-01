#!/usr/bin/env bash

make -C binaries

ROOT_DIR="$(readlink -f ../../)"
GDB_INIT_PATH="$ROOT_DIR/gdbinit.py"
COVERAGERC_PATH="$ROOT_DIR/pyproject.toml"

handle_sigint() {
    echo "Exiting..." >&2
    pkill qemu-aarch64
    pkill qemu-riscv64
    exit 1
}
trap handle_sigint SIGINT

gdb_load_pwndbg=(--command "$GDB_INIT_PATH" -ex "set exception-verbose on")
run_gdb() {
    COVERAGE_FILE=$ROOT_DIR/.cov/coverage \
        COVERAGE_PROCESS_START=$COVERAGERC_PATH \
        PWNDBG_DISABLE_COLORS=1 \
        gdb-multiarch --silent --nx --nh "${gdb_load_pwndbg[@]}" "$@" -ex "quit" 2> /dev/null
    return $?
}

test_arch() {
    local arch="$1"

    qemu-${arch} \
        -g 1234 \
        -L /usr/${arch}-linux-gnu/ \
        ./binaries/reference-binary.${arch}.out &

    run_gdb \
        -ex "set sysroot /usr/${arch}-linux-gnu/" \
        -ex "file ./binaries/reference-binary.${arch}.out" \
        -ex 'py import coverage;coverage.process_startup()' \
        -ex "target remote :1234" \
        -ex "source ./tests/user/old/test_${arch}.py"
    local result=$?
    pkill qemu-${arch}
    return $result
}

ARCHS=("aarch64" "riscv64")

FAILED_TESTS=()
for arch in "${ARCHS[@]}"; do
    test_arch "$arch"
    if [ $? -ne 0 ]; then
        FAILED_TESTS+=("$arch")
    fi
done

if [ "${#FAILED_TESTS[@]}" -ne 0 ]; then
    echo ""
    echo "Failing tests: ${FAILED_TESTS[@]}"
    echo ""
    exit 1
fi
