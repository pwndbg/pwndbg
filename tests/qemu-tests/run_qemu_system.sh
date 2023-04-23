#!/bin/bash

ARCH=""
KERNEL_TYPE=""
CMDLINE=""

CWD=$(dirname -- "$0")
IMAGE_DIR="${CWD}/images"

KERNEL_LIST=($(basename -a "${IMAGE_DIR}"/vmlinux* | sed "s/vmlinux-//"))

help_and_exit() {
    echo "Usage: $0 [options] [-- other qemu options]"
    echo ""
    echo "  --kernel=<KERNEL>       select kernel to run"
    echo "  --append=<CMDLINE>      append something to the kernel's cmdline."
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

# extract architecture as last dash-separated group of the kernel's name
ARCH="${KERNEL_NAME##*-}"

if [[ "${ARCH}" == @(arm64|aarch64) ]]; then
    ARCH=arm64
    QEMU_BIN=qemu-system-aarch64

    QEMU_ARGS=(
        -cpu max
        -machine virt
        -append "console=ttyAMA0 root=/dev/vda nokaslr ${CMDLINE}"
    )
elif [ "$ARCH" == "x86_64" ]; then
    QEMU_BIN=qemu-system-x86_64

    QEMU_ARGS=(
        -append "8250.nr_uarts=1 console=ttyS0 root=/dev/vda nokaslr ${CMDLINE}"
    )
fi

KERNEL=$(echo ${IMAGE_DIR}/*Image-${KERNEL_NAME})
ROOTFS=$(echo ${IMAGE_DIR}/*-${ARCH}.img)

QEMU_ARGS+=(
    -kernel $KERNEL
    -nographic
    -drive "file=$ROOTFS,if=virtio,format=qcow2"
    -S -s
    "${QEMU_ARGS_EXT[@]}"
)

echo "Waiting for GDB to attach (use 'ctrl-a x' to quit)"

$QEMU_BIN "${QEMU_ARGS[@]}"
