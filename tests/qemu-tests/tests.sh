#!/bin/bash

CWD=$(dirname -- "$0")

set -x

for kernel_type in linux ack; do
    for arch in x86_64 arm64; do
        tmux splitw -h "${CWD}/run_qemu_system.sh" $arch $kernel_type
        pane_id=$(tmux display-message -p "#{pane_id}")

        "${CWD}/gdb.sh" $arch $kernel_type
        exit_code=$?

        tmux send-keys -t $pane_id ^A x
        if [ $exit_code -ne 0 ]; then
            exit $exit_code
        fi
    done
done
