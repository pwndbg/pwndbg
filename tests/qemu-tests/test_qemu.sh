#!/bin/bash

make -C binaries

qemu-aarch64 \
    -g 1234 \
    -L /usr/aarch64-linux-gnu/ \
    ./binaries/reference-binary.aarch64.out &

gdb-multiarch \
    -ex "file ./binaries/reference-binary.aarch64.out" \
    -ex "target remote :1234" \
    -ex "source ./tests/user/test_aarch64.py" \
    -ex "quit"
