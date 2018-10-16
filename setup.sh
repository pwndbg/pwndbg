#!/bin/bash
set -ex


# Helper functions
linux() {
    uname | grep -i Linux &>/dev/null
}
osx() {
    uname | grep -i Darwin &>/dev/null
}


PYTHON=''
INSTALLFLAGS=''

if osx || [ "$1" == "--user" ]; then
    INSTALLFLAGS="--user"
else
    PYTHON="sudo "
fi

if linux; then
    distro=$(cat /etc/os-release | grep "^ID=" | cut -d\= -f2 | sed -e 's/"//g')
    
    case $distro in
        "ubuntu")
            sudo apt-get update || true
            sudo apt-get -y install gdb python-dev python3-dev python-pip python3-pip libglib2.0-dev libc6-dbg

            if uname -m | grep x86_64 > /dev/null; then
                sudo apt-get install libc6-dbg:i386 || true
            fi
            ;;
        "fedora")
            sudo dnf update || true
            sudo dnf -y install gdb python-devel python3-devel python-pip python3-pip glib2-devel make
            sudo dnf -y debuginfo-install glibc
            ;;
        "arch")
            sudo pacman -Syu || true
            sudo pacman -Sy gdb python2 python3 python2-pip python-pip glib2 glibc
            ;;
        *) # we can add more install command for each distros.
            echo "\"$distro\" is not supported distro."
            exit
            ;;
    esac
fi

if ! hash gdb; then
    echo 'Could not find gdb in $PATH'
    exit
fi

# Update all submodules
git submodule update --init --recursive

# Find the Python version used by GDB.
PYVER=$(gdb -batch -q --nx -ex 'pi import platform; print(".".join(platform.python_version_tuple()[:2]))')
PYTHON+=$(gdb -batch -q --nx -ex 'pi import sys; print(sys.executable)')
PYTHON+="${PYVER}"

# Find the Python site-packages that we need to use so that
# GDB can find the files once we've installed them.
if linux && [ -z "$INSTALLFLAGS" ]; then
    SITE_PACKAGES=$(gdb -batch -q --nx -ex 'pi import site; print(site.getsitepackages()[0])')
    INSTALLFLAGS="--target ${SITE_PACKAGES}"
fi

# Make sure that pip is available
if ! ${PYTHON} -m pip -V; then
    ${PYTHON} -m ensurepip ${INSTALLFLAGS} --upgrade
fi

# Upgrade pip itself
${PYTHON} -m pip install ${INSTALLFLAGS} --upgrade pip

# Install Python dependencies
${PYTHON} -m pip install ${INSTALLFLAGS} -Ur requirements.txt

# Load Pwndbg into GDB on every launch.
if ! grep pwndbg ~/.gdbinit &>/dev/null; then
    echo "source $PWD/gdbinit.py" >> ~/.gdbinit
fi
