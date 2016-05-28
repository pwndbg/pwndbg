#!/bin/bash -ex

if uname | grep -i Linux &>/dev/null; then
    sudo apt-get update
    sudo apt-get -y install python-dev python3-dev python-pip python3-pip libglib2.0-dev
fi

# Update all submodules
git submodule update --init --recursive

# Find the Python version used by GDB.
PYVER=$(gdb -batch -q --nx -ex 'pi import platform; print(".".join(platform.python_version_tuple()[:2]))')
PYTHON=$(gdb -batch -q --nx -ex 'pi import sys; print(sys.executable)')
PYTHON="${PYTHON}${PYVER}"

# Find the Python site-packages that we need to use so that
# GDB can find the files once we've installed them.
SITE_PACKAGES=$(gdb -batch -q --nx -ex 'pi import site; print(site.getsitepackages()[0])')

# Install Python dependencies
sudo ${PYTHON} -m pip install --target ${SITE_PACKAGES} -Ur requirements.txt

# Find the path to the Python2 interpreter needed by the Unicorn install process.
export UNICORN_QEMU_FLAGS="--python=$(which python2)"

# Install both Unicorn and Capstone
for directory in capstone unicorn; do
    pushd $directory
    git clean -xdf
    sudo ./make.sh install
    cd bindings/python
    sudo ${PYTHON} -m pip install --target ${SITE_PACKAGES} .
    popd
done

# Load Pwndbg into GDB on every launch.
if ! grep pwndbg ~/.gdbinit &>/dev/null; then
    echo "source $PWD/gdbinit.py" >> ~/.gdbinit
fi
