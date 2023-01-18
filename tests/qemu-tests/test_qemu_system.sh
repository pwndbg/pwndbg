#!/bin/bash

ARCH="$1"

if [ -z "$ARCH" ]; then
    echo "usage: $0 ARCH"
    exit 1
fi

if [ "$ACK" == 1 ]; then
    KERNEL_TYPE=ack
else
    KERNEL_TYPE=linux
fi

if [ "$ARCH" == arm64 ] || [ "$ARCH" == aarch64 ]; then
    QEMU_BIN=qemu-system-aarch64
    KERNEL=Image-${KERNEL_TYPE}-arm64
    ROOTFS=rootfs-arm64.img

    QEMU_ARGS=(
        -cpu cortex-a53
        -machine virt
        -append "console=ttyAMA0 root=/dev/vda nokaslr"
    )
elif [ "$ARCH" == "x86_64" ]; then
    QEMU_BIN=qemu-system-x86_64
    KERNEL=bzImage-${KERNEL_TYPE}-x86_64
    ROOTFS=rootfs-x86_64.img

    QEMU_ARGS=(
        -accel kvm
        -append "8250.nr_uarts=1 console=ttyS0 root=/dev/vda nokaslr"
    )
else
    echo "No arch specified"
    exit 1
fi

tmux splitw -h -p 60 gdb-multiarch -ex "target remote :1234" -ex continue

QEMU_ARGS+=(
    -kernel $KERNEL
    -nographic
    -drive file=$ROOTFS,if=virtio,format=qcow2
    -S -s
)

$QEMU_BIN "${QEMU_ARGS[@]}"
