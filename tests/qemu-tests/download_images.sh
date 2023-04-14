#!/bin/bash

set -o errexit

CWD=$(dirname -- "$0")
OUT_DIR="${CWD}/images"
URL="https://github.com/gsingh93/linux-exploit-dev-env/releases/latest/download"

mkdir -p "${OUT_DIR}"

for arch in x86_64 arm64; do
    file="rootfs-${arch}.img"
    wget "${URL}/${file}" -O "${OUT_DIR}/${file}"

    file="vmlinux-linux-${arch}"
    wget "${URL}/${file}" -O "${OUT_DIR}/${file}"

    file="vmlinux-ack-${arch}"
    wget "${URL}/${file}" -O "${OUT_DIR}/${file}"
done

for kernel_type in ack linux; do
    file="bzImage-${kernel_type}-x86_64"
    wget "${URL}/${file}" -O "${OUT_DIR}/${file}"

    file="Image-${kernel_type}-arm64"
    wget "${URL}/${file}" -O "${OUT_DIR}/${file}"
done
