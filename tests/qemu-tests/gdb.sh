#!/bin/bash

ARCH="$1"
KERNEL_TYPE="$2"

CWD=$(dirname -- "$0")
IMAGE_DIR="${CWD}/images"

if [[ -z "$ARCH" || -z "$KERNEL_TYPE" ]]; then
    echo "usage: $0 ARCH [ack | linux]"
    exit 1
fi

ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope)
if [[ $ptrace_scope -ne 0 && $(id -u) -ne 0 ]]; then
    cat << EOF
WARNING: You are not running as root and ptrace_scope is not set to zero. If you
run into issues when using pwndbg or gdb-pt-dump, rerun this script as root, or
alternatively run the following command:

    echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

EOF
fi

if [[ $ARCH == "arm64" ]]; then
    GDB=gdb-multiarch
else
    GDB=gdb
fi

VMLINUX="${IMAGE_DIR}/vmlinux-${KERNEL_TYPE}-${ARCH}"

exec "${GDB}" -q \
    -ex "file ${VMLINUX}" \
    -ex "target remote :1234" \
    -ex "source ${CWD}/tests/test_qemu_system.py" \
    -ex "quit" \
    "$@"
