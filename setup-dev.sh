#!/bin/bash -e

echo "# --------------------------------------"
echo "# Install testing tools."
echo "# Only works with Ubuntu / APT."
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

if [[ -z "$ZIGPATH" ]]; then
    # If ZIGPATH is not set, set it to $pwd/.zig
    # In Docker environment this should by default be set to /opt/zig
    export ZIGPATH="$(pwd)/.zig"
fi
echo "ZIGPATH set to $ZIGPATH"

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

install_apt() {
    sudo apt-get update || true
    sudo apt-get install -y \
        nasm \
        gcc \
        libc6-dev \
        curl \
        build-essential \
        gdb \
        parallel

    if [[ "$1" == "22.04" ]]; then
        sudo apt install shfmt
    fi

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

    mv /tmp/zig-linux-x86_64-* ${ZIGPATH} &> /dev/null || true
    echo "Zig installed to ${ZIGPATH}"
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
