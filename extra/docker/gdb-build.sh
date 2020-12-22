#!/bin/bash
set -ex

: ${VERSION:=10.1}

sudo apt-get build-dep -y gdb

cd $(mktemp -d)

wget https://ftp.gnu.org/gnu/gdb/gdb-$VERSION.tar.xz
tar xf gdb-$VERSION.tar.xz

mkdir usr

gdb-$VERSION/configure \
    --prefix="/usr/local" \
    --enable-targets=all \
    --with-python=$(which python3) \
    --with-tui

make -j$(nproc)
sudo make install
