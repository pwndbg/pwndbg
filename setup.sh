#!/bin/bash
set -ex

# If we are a root in a Docker container and `sudo` doesn't exist
# lets overwrite it with a function that just executes things passed to sudo
# (yeah it won't work for sudo executed with flags)
if [ -f /.dockerenv ]  && ! hash sudo 2>/dev/null && whoami | grep root; then
    sudo() {
        $*
    }
fi

# Helper functions
linux() {
    uname | grep -i Linux &>/dev/null
}
osx() {
    uname | grep -i Darwin &>/dev/null
}

install_apt() {
    sudo apt-get update || true
    sudo apt-get -y install gdb python-dev python3-dev python-pip python3-pip libglib2.0-dev libc6-dbg

    if uname -m | grep x86_64 > /dev/null; then
        sudo apt-get install libc6-dbg:i386 || true
    fi
}

install_dnf() {
    sudo dnf update || true
    sudo dnf -y install gdb python-devel python3-devel python-pip python3-pip glib2-devel make
    sudo dnf -y debuginfo-install glibc
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
            install_apt
            ;;
        "fedora")
            install_dnf
            ;;
        "arch")
            echo "Install Arch linux using a community package. See:"
            echo " - https://www.archlinux.org/packages/community/any/pwndbg/"
            echo " - https://aur.archlinux.org/packages/pwndbg-git/"
            exit 1
            ;;
        "manjaro")
            echo "Pwndbg is not avaiable on Manjaro's repositories."
            echo "But it can be installed using Arch's AUR community package. See:"
            echo " - https://www.archlinux.org/packages/community/any/pwndbg/"
            echo " - https://aur.archlinux.org/packages/pwndbg-git/"
            exit 1
            ;;
        *) # we can add more install command for each distros.
            echo "\"$distro\" is not supported distro. Will search for 'apt' or 'dnf' package managers."
            if hash apt; then
                install_apt
            elif hash dnf; then
                install_dnf
            else
                echo "\"$distro\" is not supported and your distro don't have apt or dnf that we support currently."
                exit
            fi
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
