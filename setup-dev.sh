#!/usr/bin/env bash
set -e

echo "# --------------------------------------"
echo "# Install testing tools."
echo "# Only works with Ubuntu / APT or Arch / Pacman."
echo "# --------------------------------------"

help_and_exit() {
    echo "Usage: ./setup-dev.sh [--install-only]"
    echo "  --install-only              install only distro dependencies without installing python-venv"
    exit 1
}

USE_INSTALL_ONLY=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --install-only)
            USE_INSTALL_ONLY=1
            ;;
        -h | --help)
            help_and_exit
            ;;
        *)
            help_and_exit
            ;;
    esac
    shift
done

hook_script_path=".git/hooks/pre-push"
hook_script=$(
    cat << 'EOF'
#!/usr/bin/env bash

diff_command="git diff --no-ext-diff --ignore-submodules"

old_diff=$($diff_command)

./lint.sh -f
exit_code=$?

new_diff=$($diff_command)

if [[ "$new_diff" != "$old_diff" ]]; then
   echo "Files were modified by the linter, amend your commit and try again"
   exit 1
fi

exit $exit_code
EOF
)

if [ -t 1 ] && [ ! -f $hook_script_path ]; then
    echo "Install a git hook to automatically lint files before pushing? (y/N)"
    read yn
    if [[ "$yn" == [Yy]* ]]; then
        echo "$hook_script" > "$hook_script_path"
        # make the hook executable
        chmod ug+x "$hook_script_path"
        echo "pre-push hook installed to $hook_script_path and made executable"
    fi
fi

# If we are a root in a container and `sudo` doesn't exist
# lets overwrite it with a function that just executes things passed to sudo
# (yeah it won't work for sudo executed with flags)
if ! hash sudo 2> /dev/null && whoami | grep root; then
    sudo() {
        ${*}
    }
fi

linux() {
    uname | grep -i Linux &> /dev/null
}
osx() {
    uname | grep -iqs Darwin
}

set_zigpath() {
    if [[ -z "$ZIGPATH" ]]; then
        # If ZIGPATH is not set, set it
        # In Docker environment this should by default be set to /opt/zig (APT) or /usr/bin (Pacman)
        export ZIGPATH="$1"
    fi
    echo "ZIGPATH set to $ZIGPATH"
}

download_zig_binary() {
    # Install zig to current directory
    # We use zig to compile some test binaries as it is much easier than with gcc

    TARGET_ZIG_VERSION="0.13.0"
    ZIG_TAR_URL="https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz"
    ZIG_TAR_SHA256="d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea"

    if command -v "${ZIGPATH}"/zig &> /dev/null; then
        ZIG_VERSION=$("$ZIGPATH/zig" version)

        if [ "${ZIG_VERSION}" = "${TARGET_ZIG_VERSION}" ]; then
            echo "Zig is already installed. Skipping build and install."
            return
        else
            echo "Old version of Zig installed (${ZIG_VERSION}). Installing version ${TARGET_ZIG_VERSION}."
        fi
    fi

    echo "Downloading and installing Zig..."
    curl --output /tmp/zig.tar.xz "${ZIG_TAR_URL}"
    ACTUAL_SHA256=$(sha256sum /tmp/zig.tar.xz | cut -d' ' -f1)
    if [ "${ACTUAL_SHA256}" != "${ZIG_TAR_SHA256}" ]; then
        echo "Zig binary checksum mismatch"
        echo "Expected: ${ZIG_TAR_SHA256}"
        echo "Actual: ${ACTUAL_SHA256}"
        exit 1
    fi

    tar -C /tmp -xJf /tmp/zig.tar.xz

    # Delete previous installation
    rm -rf "${ZIGPATH}"

    mv /tmp/zig-linux-x86_64-* ${ZIGPATH} &> /dev/null || true
    echo "Zig installed to ${ZIGPATH}"
}

install_apt() {
    set_zigpath "$(pwd)/.zig"

    sudo apt-get update || true
    sudo apt-get install -y \
        nasm \
        gcc \
        libc6-dev \
        curl \
        wget \
        build-essential \
        gdb \
        gdb-multiarch \
        parallel \
        qemu-system-x86 \
        qemu-system-arm \
        qemu-user

    # Some tests require i386 libc/ld, eg: test_smallbins_sizes_32bit_big
    if uname -m | grep -q x86_64; then
        sudo dpkg --add-architecture i386
        sudo apt-get update
        sudo apt-get install -y libc6-dbg:i386 libgcc-s1:i386
    fi

    if [[ "$1" != "" ]]; then
        sudo apt install shfmt
    fi

    command -v go &> /dev/null || sudo apt-get install -y golang

    download_zig_binary
}

install_pacman() {
    set_zigpath "$(pwd)/.zig"

    # add debug repo for glibc-debug if it doesn't already exist
    if ! grep -q "\[core-debug\]" /etc/pacman.conf; then
        cat << EOF | sudo tee -a /etc/pacman.conf
        [core-debug]
        Include = /etc/pacman.d/mirrorlist
EOF
    fi

    if ! grep -q "\[extra-debug\]" /etc/pacman.conf; then
        cat << EOF | sudo tee -a /etc/pacman.conf
        [extra-debug]
        Include = /etc/pacman.d/mirrorlist
EOF
    fi

    if ! grep -q "\[multilib-debug\]" /etc/pacman.conf; then
        cat << EOF | sudo tee -a /etc/pacman.conf
        [multilib-debug]
        Include = /etc/pacman.d/mirrorlist
EOF
    fi

    sudo pacman -Syu --noconfirm || true
    sudo pacman -S --needed --noconfirm \
        nasm \
        gcc \
        glibc-debug \
        curl \
        wget \
        base-devel \
        gdb \
        parallel

    command -v go &> /dev/null || sudo pacman -S --noconfirm go

    download_zig_binary
}

install_dnf() {
    set_zigpath "$(pwd)/.zig"

    sudo dnf upgrade || true
    sudo dnf install -y \
        nasm \
        gcc \
        curl \
        wget \
        gdb \
        parallel \
        qemu-system-arm \
        qemu-user

    command -v go &> /dev/null || sudo dnf install -y go

    if [[ "$1" != "" ]]; then
        sudo dnf install shfmt
    fi

    download_zig_binary
}

install_jemalloc() {

    # Check if jemalloc is already installed
    if command -v jemalloc-config &> /dev/null; then
        echo "Jemalloc already installed. Skipping build and install."
    else
        echo "Jemalloc not found in system. Downloading, configuring, building, and installing..."

        # Install jemalloc version 5.3.0
        JEMALLOC_TAR_URL="https://github.com/jemalloc/jemalloc/releases/download/5.3.0/jemalloc-5.3.0.tar.bz2"
        JEMALLOC_TAR_SHA256="2db82d1e7119df3e71b7640219b6dfe84789bc0537983c3b7ac4f7189aecfeaa"
        JEMALLOC_TAR_PATH="/tmp/jemalloc-5.3.0.tar.bz2"
        JEMALLOC_EXTRACT_PATH="/tmp/jemalloc-5.3.0"

        # Check if jemalloc tarball already exists and has the correct checksum
        if [ -f "${JEMALLOC_TAR_PATH}" ]; then
            ACTUAL_SHA256=$(sha256sum "${JEMALLOC_TAR_PATH}" | cut -d' ' -f1)
            if [ "${ACTUAL_SHA256}" != "${JEMALLOC_TAR_SHA256}" ]; then
                echo "Jemalloc tarball exists but has incorrect checksum. Re-downloading..."
                curl --location --output "${JEMALLOC_TAR_PATH}" "${JEMALLOC_TAR_URL}"
                ACTUAL_SHA256=$(sha256sum "${JEMALLOC_TAR_PATH}" | cut -d' ' -f1)
                if [ "${ACTUAL_SHA256}" != "${JEMALLOC_TAR_SHA256}" ]; then
                    echo "Jemalloc binary checksum mismatch after re-download."
                    echo "Expected: ${JEMALLOC_TAR_SHA256}"
                    echo "Actual: ${ACTUAL_SHA256}"
                    exit 1
                fi
            else
                echo "Jemalloc tarball already exists and has correct checksum. Skipping download."
            fi
        else
            echo "Downloading jemalloc..."
            curl --location --output "${JEMALLOC_TAR_PATH}" "${JEMALLOC_TAR_URL}"
            ACTUAL_SHA256=$(sha256sum "${JEMALLOC_TAR_PATH}" | cut -d' ' -f1)
            if [ "${ACTUAL_SHA256}" != "${JEMALLOC_TAR_SHA256}" ]; then
                echo "Jemalloc binary checksum mismatch"
                echo "Expected: ${JEMALLOC_TAR_SHA256}"
                echo "Actual: ${ACTUAL_SHA256}"
                exit 1
            fi
        fi

        # Check if jemalloc source code has already been extracted
        if [ -d "${JEMALLOC_EXTRACT_PATH}" ]; then
            echo "Jemalloc source code already extracted. Skipping extraction."
        else
            echo "Extracting jemalloc..."
            tar -C /tmp -xf "${JEMALLOC_TAR_PATH}"
        fi

        pushd "${JEMALLOC_EXTRACT_PATH}"
        ./configure
        make
        sudo make install
        popd

        echo "Jemalloc installation complete."
    fi

    # TODO: autoconf needs to be installed with script as well?
}

configure_venv() {
    if [[ -z "${PWNDBG_VENV_PATH}" ]]; then
        PWNDBG_VENV_PATH="./.venv"
    fi
    echo "Using virtualenv from path: ${PWNDBG_VENV_PATH}"

    source "${PWNDBG_VENV_PATH}/bin/activate"
    uv sync --all-groups --extra gdb

    # Create a developer marker file
    DEV_MARKER_PATH="${PWNDBG_VENV_PATH}/dev.marker"
    touch "${DEV_MARKER_PATH}"
    echo "Developer marker created at ${DEV_MARKER_PATH}"
}

if osx; then
    echo "Not supported on macOS. Please use one of the alternative methods listed at:"
    echo "https://github.com/pwndbg/pwndbg?tab=readme-ov-file#installing-gdb"
    exit 1
fi

if linux; then
    distro=$(
        . /etc/os-release
        echo ${ID}
    )

    case $distro in
        "ubuntu")
            ubuntu_version=$(
                . /etc/os-release
                echo ${VERSION_ID}
            )
            install_apt $ubuntu_version
            ;;
        "arch")
            install_pacman
            ;;
        "fedora")
            fedora_version=$(
                . /etc/os-release
                echo ${VERSION_ID} version
            )
            install_dnf $fedora_version
            ;;
        *) # we can add more install command for each distros.
            echo "\"$distro\" is not supported distro. Will search for 'apt' or 'pacman' package managers."
            if hash apt; then
                install_apt
            elif hash pacman; then
                install_pacman
            else
                echo "\"$distro\" is not supported and your distro don't have apt or pacman that we support currently."
                exit
            fi
            ;;
    esac

    install_jemalloc

    if [ $USE_INSTALL_ONLY -eq 0 ]; then
        configure_venv
    fi
fi
