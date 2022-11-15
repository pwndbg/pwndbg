#!/bin/bash
set -ex

# If we are a root in a container and `sudo` doesn't exist
# lets overwrite it with a function that just executes things passed to sudo
# (yeah it won't work for sudo executed with flags)
if ! hash sudo 2> /dev/null && whoami | grep root; then
    sudo() {
        ${*}
    }
fi

# Helper functions
linux() {
    uname | grep -i Linux &> /dev/null
}
osx() {
    uname | grep -i Darwin &> /dev/null
}

install_apt() {
    sudo apt-get update || true
    sudo apt-get install -y git gdb python3-dev python3-pip python3-setuptools libglib2.0-dev libc6-dbg

    if uname -m | grep x86_64 > /dev/null; then
        sudo dpkg --add-architecture i386 || true
        sudo apt-get update || true
        sudo apt-get install -y libc6-dbg:i386 || true
    fi
}

install_dnf() {
    sudo dnf update || true
    sudo dnf -y install gdb gdb-gdbserver python-devel python3-devel python-pip python3-pip glib2-devel make
    sudo dnf -y debuginfo-install glibc
}

install_xbps() {
    sudo xbps-install -Su
    sudo xbps-install -Sy gdb gcc python-devel python3-devel python-pip python3-pip glibc-devel make
    sudo xbps-install -Sy glibc-dbg
}

install_swupd() {
    sudo swupd update || true
    sudo swupd bundle-add gdb python3-basic make c-basic
}

install_zypper() {
    sudo zypper mr -e repo-debug
    sudo zypper refresh || true
    sudo zypper install -y gdb gdbserver python-devel python3-devel python2-pip python3-pip glib2-devel make glibc-debuginfo

    if uname -m | grep x86_64 > /dev/null; then
        sudo zypper install -y glibc-32bit-debuginfo || true
    fi
}

install_emerge() {
    emerge --oneshot --deep --newuse --changed-use --changed-deps dev-lang/python dev-python/pip sys-devel/gdb
}

install_pacman() {
    sudo pacman -Syy --noconfirm || true
    sudo pacman -S --noconfirm git gdb python python-pip python-capstone python-unicorn python-pycparser python-psutil python-ptrace python-pyelftools python-six python-future python-pygments which debuginfod
    echo "set debuginfod enabled on" >> ~/.gdbinit
}

PYTHON=''
INSTALLFLAGS=''

if osx || [ "$1" == "--user" ]; then
    INSTALLFLAGS="--user"
else
    PYTHON="sudo "
fi

if linux; then
    distro=$(grep "^ID=" /etc/os-release | cut -d'=' -f2 | sed -e 's/"//g')

    case $distro in
        "ubuntu")
            install_apt
            ;;
        "fedora")
            install_dnf
            ;;
        "clear-linux-os")
            install_swupd
            ;;
        "opensuse-leap")
            install_zypper
            ;;
        "arch" | "endeavouros" | "manjaro")
            install_pacman
            echo "Logging off and in or conducting a power cycle is required to get debuginfod to work."
            echo "Alternatively you can manually set the environment variable: DEBUGINFOD_URLS=https://debuginfod.archlinux.org"
            ;;
        "void")
            install_xbps
            ;;
        "gentoo")
            install_emerge
            if ! hash sudo 2> /dev/null && whoami | grep root; then
                sudo() {
                    ${*}
                }
            fi
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
    echo "Could not find gdb in $PATH"
    exit
fi

# Update all submodules
git submodule update --init --recursive

# Find the Python version used by GDB.
PYVER=$(gdb -batch -q --nx -ex 'pi import platform; print(".".join(platform.python_version_tuple()[:2]))')
PYTHON+=$(gdb -batch -q --nx -ex 'pi import sys; print(sys.executable)')
if ! osx; then
    PYTHON+="${PYVER}"
fi

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
if ! grep pwndbg ~/.gdbinit &> /dev/null; then
    echo "source $PWD/gdbinit.py" >> ~/.gdbinit
fi
