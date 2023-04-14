#!/bin/bash

ARCH="$1"
KERNEL_TYPE="${2:-linux}"

CWD=$(dirname -- "$0")
IMAGE_DIR="${CWD}/images"

if [ -z "$ARCH" ]; then
    echo "usage: $0 ARCH [ack | linux]"
    exit 1
fi

if [[ "${ARCH}" != @(x86_64|arm64|aarch64) ]]; then
    echo "Invalid arch ${ARCH}"
    exit 1
fi

if [[ "${KERNEL_TYPE}" != @(ack|linux) ]]; then
    echo "Invalid kernel type ${KERNEL_TYPE}"
    exit 1
fi

if [[ "${ARCH}" == @(arm64|aarch64) ]]; then
    ARCH=arm64
    QEMU_BIN=qemu-system-aarch64
    KERNEL="${IMAGE_DIR}/Image-${KERNEL_TYPE}-arm64"
    ROOTFS="${IMAGE_DIR}/rootfs-arm64.img"

    QEMU_ARGS=(
        -cpu max
        -machine virt
        -append "console=ttyAMA0 root=/dev/vda nokaslr"
    )
elif [ "$ARCH" == "x86_64" ]; then
    QEMU_BIN=qemu-system-x86_64
    KERNEL="${IMAGE_DIR}/bzImage-${KERNEL_TYPE}-x86_64"
    ROOTFS="${IMAGE_DIR}/rootfs-x86_64.img"

    QEMU_ARGS=(
        -append "8250.nr_uarts=1 console=ttyS0 root=/dev/vda nokaslr"
    )
fi

QEMU_ARGS+=(
    -kernel $KERNEL
    -nographic
    -drive file=$ROOTFS,if=virtio,format=qcow2
    -S -s
)

echo "Waiting for GDB to attach (use 'ctrl-a x' to quit)"

$QEMU_BIN "${QEMU_ARGS[@]}"
