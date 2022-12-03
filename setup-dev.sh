#!/bin/bash -e

echo "# --------------------------------------"
echo "# Install testing tools."
echo "# Only works with Ubuntu / APT or Arch / Pacman."
echo "# --------------------------------------"

hook_script_path=".git/hooks/pre-push"
hook_script=$(
    cat << 'EOF'
#!/bin/bash

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

if [ -t 1 ]; then
    echo "Install a git hook to automatically lint files before pushing? (y/N)"
    read yn
    if [[ "$yn" == [Yy]* ]]; then
        echo "$hook_script" > "$hook_script_path"
        echo "pre-push hook installed to $hook_script_path"
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
        build-essential \
        gdb \
        parallel \
        netcat-openbsd

    if [[ "$1" == "22.04" ]]; then
        sudo apt install shfmt
    fi

    test -f /usr/bin/go || sudo apt-get install -y golang

    download_zig_binary
}

install_pacman() {
    set_zigpath "$(pwd)/.zig"

    # add debug repo for glibc-debug
    cat << EOF | sudo tee -a /etc/pacman.conf
[core-debug]
Include = /etc/pacman.d/mirrorlist

[extra-debug]
Include = /etc/pacman.d/mirrorlist

[community-debug]
Include = /etc/pacman.d/mirrorlist

[multilib-debug]
Include = /etc/pacman.d/mirrorlist
EOF

    sudo pacman -Syu --noconfirm || true
    sudo pacman -S --noconfirm \
        nasm \
        gcc \
        glibc-debug \
        curl \
        base-devel \
        gdb \
        parallel \
        gnu-netcat

    test -f /usr/bin/go || sudo pacman -S --noconfirm go

    download_zig_binary
}

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

    python3 -m pip install -r dev-requirements.txt
fi
