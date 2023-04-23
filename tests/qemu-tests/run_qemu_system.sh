#!/bin/bash

ARCH=""
KERNEL_TYPE=""
CMDLINE=""

VALID_ARCHS=("x86_64" "arm64" "aarch64")
VALID_TYPES=("linux" "ack")

help_and_exit() {
    echo "Usage: $0 [options] [-- other qemu options]"
    echo ""
    echo "  --arch=<ARCH>      select the architecture to run"
    echo "          possible values: [${VALID_ARCHS[*]}]"
    echo ""
    echo "  --type=<TYPE>      select the kernel type to run"
    echo "          possible values: [${VALID_TYPES[*]}]"
    echo ""
    echo "  --append=<CMDLINE> append something to the kernel's cmdline."
    echo ""
    echo "Options after '--' will be passed to QEMU."
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch=*) ARCH="${1#--arch=}" ;;
        --type=*) KERNEL_TYPE="${1#--type=}" ;;
        --append=*) CMDLINE="${CMDLINE} ${1#--append=}" ;;
        -h | --help) help_and_exit ;;
        --)
            shift
            QEMU_ARGS_EXT=("$@")
            break
            ;;
    esac
    shift
done

CWD=$(dirname -- "$0")
IMAGE_DIR="${CWD}/images"

if [ -z "$ARCH" ]; then
    help_and_exit
fi

if [[ ! " ${VALID_ARCHS[*]} " =~ " ${ARCH} " ]]; then
    echo "Invalid arch '${ARCH}'"
    help_and_exit
fi

if [[ ! " ${VALID_TYPES[*]} " =~ " ${KERNEL_TYPE} " ]]; then
    echo "Invalid kernel type '${KERNEL_TYPE}'"
    help_and_exit
fi

if [[ "${ARCH}" == @(arm64|aarch64) ]]; then
    ARCH=arm64
    QEMU_BIN=qemu-system-aarch64
    KERNEL="${IMAGE_DIR}/Image-${KERNEL_TYPE}-arm64"
    ROOTFS="${IMAGE_DIR}/rootfs-arm64.img"

    QEMU_ARGS=(
        -cpu max
        -machine virt
        -append "console=ttyAMA0 root=/dev/vda nokaslr ${CMDLINE}"
    )
elif [ "$ARCH" == "x86_64" ]; then
    QEMU_BIN=qemu-system-x86_64
    KERNEL="${IMAGE_DIR}/bzImage-${KERNEL_TYPE}-x86_64"
    ROOTFS="${IMAGE_DIR}/rootfs-x86_64.img"

    QEMU_ARGS=(
        -append "8250.nr_uarts=1 console=ttyS0 root=/dev/vda nokaslr ${CMDLINE}"
    )
fi

QEMU_ARGS+=(
    -kernel $KERNEL
    -nographic
    -drive "file=$ROOTFS,if=virtio,format=qcow2"
    -S -s
    "${QEMU_ARGS_EXT[@]}"
)

echo "Waiting for GDB to attach (use 'ctrl-a x' to quit)"

$QEMU_BIN "${QEMU_ARGS[@]}"
