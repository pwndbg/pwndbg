#!/bin/bash
set -ex

if uname | grep -i Linux &>/dev/null; then
    sudo apt-get update || true
    sudo apt-get -y install python-dev python3-dev python-pip python3-pip libglib2.0-dev libc6-dbg

    if uname -m | grep x86_64 > /dev/null; then
        sudo apt-get install libc6-dbg:i386 || true
    fi
fi

# Update all submodules
git submodule update --init --recursive

# Check if GDB exists in current Path
command -v gdb >/dev/null 2>&1 || { echo >&2 "[ERROR]: I require gdb but it's not installed.  Aborting."; exit 1; }

# Find the Python version used by GDB.
PYVER=$(gdb -batch -q --nx -ex 'pi import platform; print(".".join(platform.python_version_tuple()[:2]))')
PYTHON=$(gdb -batch -q --nx -ex 'pi import sys; print(sys.executable)')
PYTHON="${PYTHON}${PYVER}"

# Install Python dependencies
sudo ${PYTHON} -m pip install -Ur requirements.txt

# Install both Unicorn and Capstone
for directory in capstone unicorn; do
    pushd $directory
    UNICORN_QEMU_FLAGS="--python=$(which python2)" ./make.sh
    sudo UNICORN_QEMU_FLAGS="--python=$(which python2)" ./make.sh install

    cd bindings/python
    sudo ${PYTHON} setup.py install
    popd
done

# Load Pwndbg into GDB on every launch.
if ! grep pwndbg ~/.gdbinit &>/dev/null; then
    echo "source $PWD/gdbinit.py" >> ~/.gdbinit
fi
