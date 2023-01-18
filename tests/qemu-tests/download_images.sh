#!/bin/bash

set -o errexit

URL="https://github.com/gsingh93/linux-exploit-dev-env/releases/latest/download"

wget "$URL/rootfs-x86_64.img"
wget "$URL/rootfs-arm64.img"

wget "$URL/bzImage-linux-x86_64"
wget "$URL/bzImage-ack-x86_64"
wget "$URL/Image-linux-arm64"
wget "$URL/Image-ack-arm64"
