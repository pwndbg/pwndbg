#!/bin/sh
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo() {
    printf "$@\n"
}

echoinfo() {
    echo "${BLUE}$@${NC}"
}

echowarn() {
    echo "${YELLOW}$@${NC}"
}

echoerr() {
    echo "${RED}$@${NC}"
}

get_distro_name() {
    if [ "$OS" = "Darwin" ]; then
        if command -v sw_vers > /dev/null 2>&1; then
            version=$(sw_vers -productVersion)
            echo "macos@$version"
        else
            echo "macos@unknown"
        fi
    elif [ -f /etc/os-release ]; then
        distro=$(
            . /etc/os-release
            echo "${ID}@${VERSION_ID}"
        )
        echo "$distro"
    else
        echo "Unknown"
    fi
}

download() {
    url=$1
    outfile=$2

    fail_download() {
        echoerr "Problem with downloading the file. Please check your internet connection or try again."
        exit 1
    }

    user_agent="pwndbg-installer ($DISTRO_NAME; $ARCH; $OS)"
    if command -v curl > /dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 --progress-bar -LSf -A "$user_agent" "$url" -o "$outfile" || fail_download
        return 0
    fi

    if command -v wget > /dev/null 2>&1; then
        # 'wget' on BusyBox don't support progress options
        if wget --help 2>&1 | grep -qi 'busybox'; then
            WGET_CMD="wget -q"
        else
            WGET_CMD="wget --https-only --secure-protocol=TLSv1_2 -q --show-progress"
        fi

        $WGET_CMD -U "$user_agent" "$url" -O "$outfile" || fail_download
        return 0
    fi

    # Should be unreachable
    echoerr "Neither 'curl' nor 'wget' is installed. Please install one of them to proceed."
    exit 1
}

missing=""
for cmd in tar xz uname mktemp rm mkdir ln grep; do
    if ! command -v $cmd > /dev/null 2>&1; then
        missing="$missing$cmd "
    fi
done

found_downloader=0
for cmd in wget curl; do
    if command -v "$cmd" > /dev/null 2>&1; then
        found_downloader=1
        break
    fi
done
if [ $found_downloader -eq 0 ]; then
    missing="$missing""wget/curl"
fi

if [ -n "$missing" ]; then
    echoerr "Error: The following required commands are missing: ${YELLOW}$missing"
    echoerr "Please install the missing commands and try again."
    exit 1
fi

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"
DISTRO_NAME=$(get_distro_name)

VERSION="2026.02.18"
TYPE=""
ROOTLESS=false

show_usage() {
    echo "${YELLOW}Usage:${NC} $0 [-v <version>] [-u] -t <type>"
    echo "${YELLOW}Options:${NC}"
    echo "  -u             Install without root permissions"
    echo "  -v <version>   Specify the version to install (default: ${GREEN}$VERSION${NC})"
    echo "  -t <type>      Specify the debugger type (required)"
    echo "                 ${CYAN}Available options:${NC} ${GREEN}pwndbg-gdb${NC}, ${GREEN}pwndbg-lldb${NC}"
    echo
    echo "${YELLOW}Example Usage:${NC}"
    echo "  $0 ${CYAN}-t pwndbg-gdb${NC}   # Install Pwndbg for GDB"
    echo "  $0 ${CYAN}-v $VERSION -t pwndbg-lldb${NC}   # Install a specific version for LLDB"
    exit 1
}

# Parse command-line arguments for VERSION and TYPE
while getopts "v:t:u" opt; do
    case ${opt} in
        v)
            VERSION="${OPTARG}"
            ;;
        t)
            TYPE="${OPTARG}"
            ;;
        u)
            ROOTLESS=true
            ;;
        *)
            show_usage
            ;;
    esac
done

# Check if running inside TTY
if [ -t 0 ]; then
    # Check if TYPE is empty
    if [ -z "$TYPE" ]; then
        echo "Please choose the type of Pwndbg installation:"
        echo "  ${YELLOW}1) ${CYAN}pwndbg-gdb${NC}"
        echo "  ${YELLOW}2) ${CYAN}pwndbg-lldb${NC}"

        # Read user input
        while true; do
            read -r -p "Enter the number (1 or 2): " choice
            case "$choice" in
                1)
                    TYPE="pwndbg-gdb"
                    break
                    ;;
                2)
                    TYPE="pwndbg-lldb"
                    break
                    ;;
                *) echoerr "Invalid option. Please enter 1 or 2." ;;
            esac
        done
    fi
fi

case "$TYPE" in
    pwndbg-gdb) BINARY_NAME="pwndbg" ;;
    pwndbg-lldb) BINARY_NAME="pwndbg-lldb" ;;
    *)
        echoerr "Please choose the type of Pwndbg installation."
        show_usage
        ;;
esac

if [ "$ROOTLESS" = "true" ]; then
    echoinfo "Installing rootless..."
    INSTALL_DIR="$HOME/.local/lib/${TYPE}"
    BINARY_DIR="$HOME/.local/bin"
    BINARY_SRC_PATH="${INSTALL_DIR}/bin/${BINARY_NAME}"
    BINARY_DST_PATH="${BINARY_DIR}/${BINARY_NAME}"

    # Skip sudo in rootless installation
    sudo() {
        ${*}
    }
else
    echoinfo "Installing system-wide..."
    INSTALL_DIR="/usr/local/lib/${TYPE}"
    BINARY_DIR="/usr/local/bin"
    BINARY_SRC_PATH="${INSTALL_DIR}/bin/${BINARY_NAME}"
    BINARY_DST_PATH="${BINARY_DIR}/${BINARY_NAME}"

    # If we are a root in a container and `sudo` doesn't exist
    if ! command -v sudo > /dev/null 2>&1 && whoami | grep -q root; then
        sudo() {
            ${*}
        }
    else
        # Before prompting, check if the user can run sudo without password,
        # or if the credentials are already cached
        if ! sudo -n true 2> /dev/null; then
            echoinfo "Requesting 'sudo' privileges. You may be prompted for your password..."
            sudo -v
        fi
    fi
fi

case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64) FILE="${BINARY_NAME}_${VERSION}_x86_64-portable.tar.xz" ;;
            i686) FILE="${BINARY_NAME}_${VERSION}_x86_32-portable.tar.xz" ;;
            aarch64) FILE="${BINARY_NAME}_${VERSION}_arm64-portable.tar.xz" ;;
            armv7l) FILE="${BINARY_NAME}_${VERSION}_armv7-portable.tar.xz" ;;
            armv8l) FILE="${BINARY_NAME}_${VERSION}_armv7-portable.tar.xz" ;;
            riscv64) FILE="${BINARY_NAME}_${VERSION}_riscv64-portable.tar.xz" ;;
            ppc64) FILE="${BINARY_NAME}_${VERSION}_powerpc64-portable.tar.xz" ;;
            ppc64le) FILE="${BINARY_NAME}_${VERSION}_powerpc64le-portable.tar.xz" ;;
            s390x) FILE="${BINARY_NAME}_${VERSION}_s390x-portable.tar.xz" ;;
            loongarch64) FILE="${BINARY_NAME}_${VERSION}_loongarch64-portable.tar.xz" ;;
            *)
                echoerr "Unsupported architecture: $ARCH"
                exit 1
                ;;
        esac
        ;;
    Darwin)
        case "$ARCH" in
            arm64) FILE="${BINARY_NAME}_${VERSION}_macos_arm64-portable.tar.xz" ;;
            x86_64) FILE="${BINARY_NAME}_${VERSION}_macos_amd64-portable.tar.xz" ;;
            *)
                echoerr "Unsupported architecture: $ARCH"
                exit 1
                ;;
        esac
        ;;
    *)
        echoerr "Unsupported operating system: $OS"
        exit 1
        ;;
esac

# Ensure "/usr/local/bin" is in $PATH
if ! echo "$PATH" | grep -q "$BINARY_DIR"; then
    echowarn "⚠️ ${GREEN}$BINARY_DIR${YELLOW} is not in your ${GREEN}\$PATH${YELLOW}"
    echowarn "⚠️ After installation, your binary won't be found by default."
    echowarn "⚠️ To fix this, add ${GREEN}$BINARY_DIR${YELLOW} to your ${GREEN}\$PATH${YELLOW} in your shell configuration file (e.g., .bashrc, .zshrc)."
    echowarn "⚠️ For example, add the following line:"
    echowarn "⚠️   ${GREEN}export PATH=\$PATH:$BINARY_DIR${NC}"
    echo
fi

# Create a temporary directory for downloading the file
TEMP_DIR=$(mktemp -d)
URL="https://releases.pwndbg.re/releases/${VERSION}/${FILE}"

# Ensure the temporary directory is cleaned up on script exit (even in case of an error)
trap "rm -rf $TEMP_DIR" EXIT

echoinfo "Downloading... ${URL}"

download "$URL" "$TEMP_DIR/$FILE"

if [ -d "$INSTALL_DIR" ]; then
    echoinfo "Removing... old installation from $INSTALL_DIR"
    sudo rm -rf "$INSTALL_DIR"
fi

echoinfo "Installing... $TYPE in ${INSTALL_DIR}"
sudo mkdir -p "$INSTALL_DIR"
sudo tar -xf "$TEMP_DIR/$FILE" -C "$INSTALL_DIR" --strip-components=2

echoinfo "Creating... symlink in ${BINARY_DST_PATH}"
sudo mkdir -p $BINARY_DIR
sudo ln -sf $BINARY_SRC_PATH $BINARY_DST_PATH

echoinfo "Installation complete."
echo "🚀 Run binary with: ${GREEN}${BINARY_NAME}${NC}"
