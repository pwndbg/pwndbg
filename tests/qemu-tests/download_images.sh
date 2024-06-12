#!/usr/bin/env bash

set -o errexit

CWD=$(dirname -- "$0")
OUT_DIR="${CWD}/images"
URL=${URL:-"https://github.com/pwndbg/linux-exploit-dev-env/releases/latest/download"}

mkdir -p "${OUT_DIR}"

download() {
    local file="$1"
    hash_old=$(grep "${file}" "${OUT_DIR}/hashsums.txt.old" || true)
    hash_new=$(grep "${file}" "${OUT_DIR}/hashsums.txt")
    # only download file if it doesn't exist or its hashsum has changed
    if [ ! -f "${OUT_DIR}/${file}" ] || [ "${hash_new}" != "${hash_old}" ]; then
        wget --no-verbose --show-progress --progress=bar:force:noscroll "${URL}/${file}" -O "${OUT_DIR}/${file}"
    fi
}

if [ -f "${OUT_DIR}/hashsums.txt" ]; then
    mv -f "${OUT_DIR}/hashsums.txt" "${OUT_DIR}/hashsums.txt.old"
fi

wget --no-verbose --show-progress --progress=bar:force:noscroll "${URL}/hashsums.txt" -O "${OUT_DIR}/hashsums.txt"

while read -r hash file; do
    echo "Downloading ${file}..."
    download "${file}"
done < "${OUT_DIR}/hashsums.txt"
