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

missing=""
for cmd in wget tar xz uname mktemp rm mkdir ln grep; do
    if ! command -v $cmd > /dev/null 2>&1; then
        missing="$missing$cmd "
    fi
done

if [ -n "$missing" ]; then
    echoerr "Error: The following required commands are missing: $missing"
    echoerr "Please install the missing commands and try again."
    exit 1
fi

VERSION="2025.04.18"
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

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

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
        echoinfo "Requesting 'sudo' privileges. You may be prompted for your password..."
        sudo -v
    fi
fi

case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64) FILE="${BINARY_NAME}_${VERSION}_x86_64-portable.tar.xz" ;;
            i686) FILE="${BINARY_NAME}_${VERSION}_x86_32-portable.tar.xz" ;;
            aarch64) FILE="${BINARY_NAME}_${VERSION}_arm64-portable.tar.xz" ;;
            armv7*) FILE="${BINARY_NAME}_${VERSION}_armv7-portable.tar.xz" ;;
            riscv64) FILE="${BINARY_NAME}_${VERSION}_riscv64-portable.tar.xz" ;;
            powerpc64) FILE="${BINARY_NAME}_${VERSION}_powerpc64-portable.tar.xz" ;;
            powerpc64le) FILE="${BINARY_NAME}_${VERSION}_powerpc64le-portable.tar.xz" ;;
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
URL="https://github.com/pwndbg/pwndbg/releases/download/${VERSION}/${FILE}"

# Ensure the temporary directory is cleaned up on script exit (even in case of an error)
trap "rm -rf $TEMP_DIR" EXIT

echoinfo "Downloading... ${URL}"
wget -q --show-progress "$URL" -O "$TEMP_DIR/$FILE" || {
    echoerr "Problem with downloading the file. Please check your internet connection or try again."
    exit 1
}

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
