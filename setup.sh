#!/bin/bash -ex

if uname | grep -i Linux &>/dev/null; then
    sudo apt-get update
    sudo apt-get -y install python-dev python3-dev python-pip python3-pip libglib2.0-dev
fi

# Update all submodules
git submodule update --init --recursive

# Find the path to the Python interpreter used by GDB.
PYTHON=$(gdb -batch -q --nx -ex 'pi import platform; print("python%s.%s" % platform.python_version_tuple()[:2])')

# Install Python dependencies
sudo $PYTHON -m pip install -Ur requirements.txt

# Find the path to the Python2 interpreter needed by the Unicorn install process.
export UNICORN_QEMU_FLAGS="--python=$(which python2)"

# Install both Unicorn and Capstone
for directory in capstone unicorn; do
    pushd $directory
    git clean -xdf
    sudo ./make.sh install
    cd bindings/python
    sudo ${PYTHON} setup.py install
    popd
done

# Load Pwndbg into GDB on every launch.
if ! grep pwndbg ~/.gdbinit &>/dev/null; then
    echo "source $PWD/gdbinit.py" >> ~/.gdbinit
fi
