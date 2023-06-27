#!/bin/bash

make -C binaries

qemu-aarch64 \
    -g 1234 \
    -L /usr/aarch64-linux-gnu/ \
    ./binaries/reference-binary.aarch64.out &

gdb-multiarch \
    -ex "set sysroot /usr/aarch64-linux-gnu/" \
    -ex "file ./binaries/reference-binary.aarch64.out" \
    -ex "target remote :1234" \
    -ex "source ./tests/user/test_aarch64.py" \
    -ex "quit"

qemu-riscv64 \
    -g 1234 \
    -L /usr/riscv64-linux-gnu/ \
    ./binaries/reference-binary.rv64.out &

gdb-multiarch \
    -ex "set sysroot /usr/riscv64-linux-gnu/" \
    -ex "file ./binaries/reference-binary.rv64.out" \
    -ex "target remote :1234" \
    -ex "source ./tests/user/test_rv64.py" \
    -ex "quit"
