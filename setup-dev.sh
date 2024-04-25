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

    ZIG_TAR_URL="https://ziglang.org/download/0.10.1/zig-linux-x86_64-0.10.1.tar.xz"
    ZIG_TAR_SHA256="6699f0e7293081b42428f32c9d9c983854094bd15fee5489f12c4cf4518cc380"
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
        gdb-multiarch \
        parallel \
        netcat-openbsd \
        qemu-system-x86 \
        qemu-system-arm \
        qemu-user \
        gcc-aarch64-linux-gnu \
        gcc-riscv64-linux-gnu

    if [[ "$1" != "" && "$1" != "20.04" ]]; then
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
        base-devel \
        gdb \
        parallel

    # check if netcat exists first, as it might it may be installed from some other netcat packages
    if [ ! -f /usr/bin/nc ]; then
        sudo pacman -S --needed --noconfirm gnu-netcat
    fi

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
            install_dnf $fedora_verion
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

    if [[ -z "${PWNDBG_VENV_PATH}" ]]; then
        PWNDBG_VENV_PATH="./.venv"
    fi
    echo "Using virtualenv from path: ${PWNDBG_VENV_PATH}"

    # Install poetry if not already installed
    if ! hash poetry 2> /dev/null; then
        curl -sSL https://install.python-poetry.org | python3 -
    fi

    source "${PWNDBG_VENV_PATH}/bin/activate"
    ~/.local/bin/poetry install --with dev
fi
