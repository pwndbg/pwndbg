#!/bin/bash

ARCH="$1"

if [[ "$ARCH" == aarch64 ]]; then
    QEMU_BIN=qemu-system-aarch64
    KERNEL=Image-qemuarm64.bin
    ROOTFS=core-image-minimal-dev-qemuarm64-20221114170418.rootfs.ext4

    QEMU_ARGS=(
        -cpu cortex-a53
        -machine virt
        -append "console=ttyAMA0 root=/dev/vda"
    )

elif [[ "$ARCH" == "x86_64" ]]; then
    QEMU_BIN=qemu-system-x86_64
    KERNEL=bzImage-qemux86-64.bin
    ROOTFS=core-image-minimal-dev-qemux86-64-20221114164338.rootfs.ext4

    QEMU_ARGS=(
        -accel kvm
        -append "8250.nr_uarts=1 console=ttyS0 root=/dev/vda"
    )

else
    echo "No arch specified"
    exit 1
fi

tmux splitw -h -p 60 gdb-multiarch -ex "target remote :1234" -ex continue

QEMU_ARGS+=(
    -kernel $KERNEL
    -nographic
    -drive file=$ROOTFS,if=virtio,format=raw
    -S -s
)

$QEMU_BIN "${QEMU_ARGS[@]}"
