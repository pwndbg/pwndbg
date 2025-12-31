#!/usr/bin/env bash

source "$(dirname "$0")/scripts/common.sh"

cd "${PWNDBG_ABS_PATH}/tests/library/qemu_system"

# Check if we have correct ptrace_scope
ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope)
if [[ $ptrace_scope -ne 0 && $(id -u) -ne 0 ]]; then
    echo "Setting ptrace_scope to zero..."
    echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
fi

# Check if we need to download kernel images
VMLINUX_LIST=($(basename -a "${TESTING_KERNEL_IMAGES_DIR}"/vmlinux*))

if [ ! -d "$TESTING_KERNEL_IMAGES_DIR" ] || [ "$VMLINUX_LIST" = "vmlinux*" ]; then
    echo "No kernel images found. Downloading to ${TESTING_KERNEL_IMAGES_DIR}..."
    echo "(This may take some time.)"
    echo "(You can always run the download yourself with ./tests/library/qemu_system/download-kernel-images.sh .)"
    echo ""
    ./download-kernel-images.sh
    echo "Download finished."
fi

echo "Running tests..."
./system-tests.sh $@

exit_code=$?
exit $exit_code
