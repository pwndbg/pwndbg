#!/bin/bash

CWD=$(dirname -- "$0")

set -x

for kernel_type in linux ack; do
    for arch in x86_64 arm64; do
        "${CWD}/run_qemu_system.sh" $arch $kernel_type > /dev/null &

        "${CWD}/gdb.sh" $arch $kernel_type
        exit_code=$?

        if [ $exit_code -ne 0 ]; then
            exit $exit_code
        fi
        pkill qemu
    done
done
