#!/bin/bash -e

echo "# --------------------------------------"
echo "# Install testing tools."
echo "# Only works with Ubuntu / APT."
echo "# --------------------------------------"

if [[ -z "$ZIGPATH" ]]; then
    # If ZIGPATH is not set, set it to $pwd/.zig
    # In Docker environment this should by default be set to /opt/zig
    export ZIGPATH="$(pwd)/.zig"
fi
echo "ZIGPATH set to $ZIGPATH"

# If we are a root in a container and `sudo` doesn't exist
# lets overwrite it with a function that just executes things passed to sudo
# (yeah it won't work for sudo executed with flags)
if ! hash sudo 2>/dev/null && whoami | grep root; then
    sudo() {
        ${*}
    }
fi

linux() {
    uname | grep -i Linux &>/dev/null
}

install_apt() {
    sudo apt-get update || true
    sudo apt-get install -y \
        nasm \
        gcc \
        libc6-dev \
        curl \
        build-essential \
        gdb
    test -f /usr/bin/go || sudo apt-ge\t install -y golang

    # Install zig to current directory
    # We use zig to compile some test binaries as it is much easier than with gcc

    ZIG_TAR_URL="https://ziglang.org/builds/zig-linux-x86_64-0.10.0-dev.3685+dae7aeb33.tar.xz"
    ZIG_TAR_SHA256="dfc8f5ecb651342f1fc2b2828362b62f74fadac9931bda785b80bf7ecfcfabb2"
    curl --output /tmp/zig.tar.xz "${ZIG_TAR_URL}"
    ACTUAL_SHA256=$(sha256sum /tmp/zig.tar.xz | cut -d' ' -f1)
    if [ "${ACTUAL_SHA256}" != "${ZIG_TAR_SHA256}" ]; then
        echo "Zig binary checksum mismatch"
        echo "Expected: ${ZIG_TAR_SHA256}"
        echo "Actual: ${ACTUAL_SHA256}"
        exit 1
    fi

    tar -C /tmp -xJf /tmp/zig.tar.xz

    mv /tmp/zig-linux-x86_64-* ${ZIGPATH} 2>/dev/null >/dev/null || true
    echo "Zig installed to ${ZIGPATH}"
}

if linux; then
    distro=$(grep "^ID=" /etc/os-release | cut -d'=' -f2 | sed -e 's/"//g')

    case $distro in
        "ubuntu")
            install_apt
            ;;
        *) # we can add more install command for each distros.
            echo "\"$distro\" is not supported distro. Will search for 'apt' or 'dnf' package managers."
            if hash apt; then
                install_apt
            else
                echo "\"$distro\" is not supported and your distro don't have apt or dnf that we support currently."
                exit
            fi
            ;;
    esac

    python3 -m pip install -r dev-requirements.txt
fi
