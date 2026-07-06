#!/usr/bin/env bash

set -o errexit
set -o pipefail

source "$(dirname "$0")/../../../scripts/common.sh"

OUT_DIR=$TESTING_KERNEL_IMAGES_DIR
URL=${URL:-"https://github.com/pwndbg/linux-exploit-dev-env/releases/latest/download"}

mkdir -p "${OUT_DIR}"

download() {
    local file="$1"
    hash_old=$(grep "${file}" "${OUT_DIR}/hashsums.txt.old" 2> /dev/null || true)
    hash_new=$(grep "${file}" "${OUT_DIR}/hashsums.txt" 2> /dev/null)
    # only download file if it doesn't exist or its hashsum has changed
    if [ ! -f "${OUT_DIR}/${file}" ] || [ "${hash_new}" != "${hash_old}" ]; then
        wget --no-verbose --show-progress --progress=bar:force:noscroll "${URL}/${file}" -O "${OUT_DIR}/${file}"
    fi
}

if [ -f "${OUT_DIR}/hashsums.txt" ]; then
    mv -f "${OUT_DIR}/hashsums.txt" "${OUT_DIR}/hashsums.txt.old"
fi

wget --no-verbose --show-progress --progress=bar:force:noscroll "${URL}/hashsums.txt" -O "${OUT_DIR}/hashsums.txt"

pids=()
while read -r hash file; do
    echo "Downloading ${file}..."
    download "${file}" &
    pids+=($!)
done < "${OUT_DIR}/hashsums.txt"

failed=0
for pid in "${pids[@]}"; do
    wait "$pid" || failed=1
done

if [ "$failed" -ne 0 ]; then
    echo "One or more downloads failed."
    exit 1
fi
