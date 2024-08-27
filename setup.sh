#!/usr/bin/env bash
set -e

# If we are a root in a container and `sudo` doesn't exist
# lets overwrite it with a function that just executes things passed to sudo
# (yeah it won't work for sudo executed with flags)
if ! hash sudo 2> /dev/null && whoami | grep -q root; then
    sudo() {
        ${*}
    }
fi

# Helper functions
linux() {
    uname | grep -iqs Linux
}
osx() {
    uname | grep -iqs Darwin
}

install_apt() {
    sudo apt-get update || true
    sudo apt-get install -y git gdb gdbserver python3-dev python3-venv python3-setuptools libglib2.0-dev libc6-dbg curl

    if uname -m | grep -q x86_64; then
        sudo dpkg --add-architecture i386 || true
        sudo apt-get update || true
        sudo apt-get install -y libc6-dbg:i386 libgcc-s1:i386 || true
    fi
}

install_dnf() {
    sudo dnf update || true
    sudo dnf -y install gdb gdb-gdbserver python-devel python3-devel glib2-devel make curl
    sudo dnf -y debuginfo-install glibc
}

install_xbps() {
    sudo xbps-install -Su
    sudo xbps-install -Sy gdb gcc python-devel python3-devel glibc-devel make curl
    sudo xbps-install -Sy glibc-dbg
}

install_swupd() {
    sudo swupd update || true
    sudo swupd bundle-add gdb python3-basic make c-basic curl
}

install_zypper() {
    sudo zypper mr -e repo-oss-debug || sudo zypper mr -e repo-debug
    sudo zypper refresh || true
    sudo zypper install -y gdb gdbserver python-devel python3-devel glib2-devel make glibc-debuginfo curl
    sudo zypper install -y python2-pip || true # skip py2 installation if it doesn't exist

    if uname -m | grep -q x86_64; then
        sudo zypper install -y glibc-32bit-debuginfo || true
    fi
}

install_emerge() {
    sudo emerge --oneshot --deep --newuse --changed-use --changed-deps dev-lang/python dev-debug/gdb
}

install_oma() {
    sudo oma refresh || true
    sudo oma install -y gdb gdbserver python-3 glib make glibc-dbg curl

    if uname -m | grep -q x86_64; then
        sudo oma install -y glibc+32-dbg || true
    fi
}

install_pacman() {
    read -p "Do you want to do a full system update? (y/n) [n] " answer
    # user want to perform a full system upgrade
    answer=${answer:-n} # n is default
    if [[ "$answer" == "y" ]]; then
        sudo pacman -Syu || true
    fi
    sudo pacman -S --noconfirm --needed git gdb python python-capstone python-unicorn python-pycparser python-psutil python-ptrace python-pyelftools python-six python-pygments which debuginfod curl
    if ! grep -qs "^set debuginfod enabled on" ~/.gdbinit; then
        echo "set debuginfod enabled on" >> ~/.gdbinit
    fi
}

install_freebsd() {
    sudo pkg install git gdb python py39-pip cmake gmake curl
    which rustc || sudo pkg install rust
}

usage() {
    echo "Usage: $0 [--update]"
    echo "  --update: Install/update dependencies without checking ~/.gdbinit"
}

UPDATE_MODE=
for arg in "$@"; do
    case $arg in
        --update)
            UPDATE_MODE=1
            ;;
        -h | --help)
            set +x
            usage
            exit 0
            ;;
        *)
            set +x
            echo "Unknown argument: $arg"
            usage
            exit 1
            ;;
    esac
done

PYTHON=''

# Check for the presence of the initializer line in the user's ~/.gdbinit file
if [ -z "$UPDATE_MODE" ] && grep -qs '^[^#]*source.*pwndbg/gdbinit.py' ~/.gdbinit; then
    # Ask the user if they want to proceed and override the initializer line
    read -p "A Pwndbg initializer line was found in your ~/.gdbinit file. Do you want to proceed and override it? (y/n) " answer

    # If the user does not want to proceed, exit the script
    if [[ "$answer" != "y" ]]; then
        exit 0
    fi
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
        "opensuse-leap" | "opensuse-tumbleweed")
            install_zypper
            ;;
        "arch" | "archarm" | "endeavouros" | "manjaro" | "garuda" | "cachyos" | "archcraft" | "artix")
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
        "freebsd")
            install_freebsd
            ;;
        "aosc")
            install_oma
            ;;
        *) # we can add more install command for each distros.
            echo "\"$distro\" is not supported distro. Will search for 'apt', 'dnf' or 'pacman' package managers."
            if hash apt; then
                install_apt
            elif hash dnf; then
                install_dnf
            elif hash pacman; then
                install_pacman
            else
                echo "\"$distro\" is not supported and your distro don't have a package manager that we support currently."
                exit
            fi
            ;;
    esac
fi

if ! hash gdb; then
    echo "Could not find gdb in $PATH"
    exit
fi

# Find the Python version used by GDB.
PYVER=$(gdb -batch -q --nx -ex 'pi import platform; print(".".join(platform.python_version_tuple()[:2]))')
PYTHON+=$(gdb -batch -q --nx -ex 'pi import sys; print(sys.executable)')

if ! osx; then
    PYTHON+="${PYVER}"
fi

# Install Poetry
if ! command -v poetry &> /dev/null; then
    echo "Poetry not found. Installing Poetry..."
    curl -sSL https://install.python-poetry.org | python3 -
    export PATH="$HOME/.local/bin:$PATH"
else
    echo "Poetry is already installed."
fi

# Create the Python virtual environment and install dependencies using poetry
if [[ -z "${PWNDBG_VENV_PATH}" ]]; then
    PWNDBG_VENV_PATH="./.venv"
fi
echo "Creating virtualenv in path: ${PWNDBG_VENV_PATH}"

${PYTHON} -m venv -- ${PWNDBG_VENV_PATH}
source ${PWNDBG_VENV_PATH}/bin/activate
poetry install

if [ -z "$UPDATE_MODE" ]; then
    # Comment old configs out
    if grep -qs '^[^#]*source.*pwndbg/gdbinit.py' ~/.gdbinit; then
        if ! osx; then
            sed -i '/^[^#]*source.*pwndbg\/gdbinit.py/ s/^/# /' ~/.gdbinit
        else
            # In BSD sed we need to pass ' ' to indicate that no backup file should be created
            sed -i ' ' '/^[^#]*source.*pwndbg\/gdbinit.py/ s/^/# /' ~/.gdbinit
        fi
    fi

    # Load Pwndbg into GDB on every launch.
    echo "source $PWD/gdbinit.py" >> ~/.gdbinit
    echo "[*] Added 'source $PWD/gdbinit.py' to ~/.gdbinit so that Pwndbg will be loaded on every launch of GDB."
fi
