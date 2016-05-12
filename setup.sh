#!/bin/bash -ex
sudo apt-get update
sudo apt-get install python-dev python3-dev python-pip python3-pip libglib2.0-dev

# Update all submodules
git submodule update --init --recursive

# Install Python dependencies
sudo pip install -Ur requirements.txt

PYTHON=$(gdb -batch -q --nx -ex 'pi import sys; print(sys.executable)')

for directory in capstone unicorn; do
    pushd $directory
    sudo ./make.sh install
    cd bindings/python
    sudo ${PYTHON} setup.py install
    popd
done

if ! grep pwndbg ~/.gdbinit &>/dev/null; then
    echo "source $PWD/pwndbg/gdbinit.py" >> ~/.gdbinit
fi
