#!/usr/bin/env bash

ARCH=""
KERNEL_TYPE=""
CMDLINE=""

CWD=$(dirname -- "$0")
IMAGE_DIR="${CWD}/images"

KERNEL_LIST=($(basename -a "${IMAGE_DIR}"/vmlinux* | sed "s/vmlinux-//"))
GDB_PORT=1234
help_and_exit() {
    echo "Usage: $0 [options] [-- other qemu options]"
    echo ""
    echo "  --kernel=<KERNEL>       select kernel to run"
    echo "  --append=<CMDLINE>      append something to the kernel's cmdline."
    echo "  --gdb-port=<PORT>       specify gdb kernel port"
    echo ""
    echo "Options after '--' will be passed to QEMU."
    echo ""
    echo "Available kernels:"
    printf "\t%s\n" "${KERNEL_LIST[@]}"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel=*) KERNEL_NAME="${1#--kernel=}" ;;
        --append=*) CMDLINE="${CMDLINE} ${1#--append=}" ;;
        --gdb-port=*) GDB_PORT="${1#--gdb-port=}" ;;
        -h | --help) help_and_exit ;;
        --)
            shift
            QEMU_ARGS_EXT=("$@")
            break
            ;;
    esac
    shift
done

if [ -z "${KERNEL_NAME}" ]; then
    help_and_exit
fi

if [[ ! " ${KERNEL_LIST[*]} " =~ " ${KERNEL_NAME} " ]]; then
    echo "Invalid kernel '${KERNEL_NAME}'"
    help_and_exit
fi

# KERNEL_NAME = <KERNEL_TYPE>-<KERNEL_VERSION>-<ARCH>
# e.g. "linux-5.10.178-arm64" or "ack-android13-5.10-lts-x86_64"
ARCH="${KERNEL_NAME##*-}"
KERNEL_VERSION=$(echo ${KERNEL_NAME} | grep -oP "\d+\.\d+(\.\d+)?(-lts)?")
KERNEL_TYPE=$(echo ${KERNEL_NAME} | sed "s/-${KERNEL_VERSION}-${ARCH}//")

if [[ "${ARCH}" == @(arm64|aarch64) ]]; then
    ARCH=arm64
    QEMU_BIN=qemu-system-aarch64
    CMDLINE="console=ttyAMA0 root=/dev/vda nokaslr ${CMDLINE}"

    QEMU_ARGS=(
        -cpu max
        -machine virt
    )
elif [ "$ARCH" == "x86_64" ]; then
    QEMU_BIN=qemu-system-x86_64
    CMDLINE="8250.nr_uarts=1 console=ttyS0 root=/dev/vda nokaslr ${CMDLINE}"
    QEMU_ARGS=()
fi

KERNEL=$(echo ${IMAGE_DIR}/*Image-${KERNEL_NAME})
ROOTFS=$(echo ${IMAGE_DIR}/*-${ARCH}.img)

QEMU_ARGS+=(
    -kernel $KERNEL
    -nographic
    -drive "file=$ROOTFS,if=virtio,format=qcow2"
    -S -gdb tcp::${GDB_PORT}
    "${QEMU_ARGS_EXT[@]}"
)

echo "Waiting for GDB to attach (use 'ctrl-a x' to quit)"
$QEMU_BIN ${QEMU_ARGS[@]} -append "${CMDLINE}"
