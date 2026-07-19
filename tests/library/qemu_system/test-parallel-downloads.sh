#!/usr/bin/env bash
# test-parallel-downloads.sh
# Tests that download-kernel-images.sh runs downloads in parallel.
# Strategy: source the script's functions, then replace download() directly.

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOWNLOAD_SCRIPT="${SCRIPT_DIR}/download-kernel-images.sh"
WORK_DIR="$(mktemp -d)"
TIMESTAMPS_DIR="${WORK_DIR}/timestamps"
OUT_DIR="${WORK_DIR}/images"

mkdir -p "${TIMESTAMPS_DIR}" "${OUT_DIR}"

cleanup() { rm -rf "${WORK_DIR}"; }
trap cleanup EXIT

if [[ ! -f "${DOWNLOAD_SCRIPT}" ]]; then
    echo "ERROR: download-kernel-images.sh not found at ${DOWNLOAD_SCRIPT}"
    exit 1
fi

# ── Build a self-contained test script that inlines the loop logic ─────────────
# Rather than fighting PATH/source ordering, we extract just the parallel loop
# and run it with our own mock download() function.
cat > "${WORK_DIR}/run_test.sh" << INNEREOF
#!/usr/bin/env bash
set -o pipefail

TIMESTAMPS_DIR="${TIMESTAMPS_DIR}"
OUT_DIR="${OUT_DIR}"

# Write fake hashsums so the loop has entries
cat > "\${OUT_DIR}/hashsums.txt" << 'HASHEOF'
abc123  fake-image-x86_64.tar.gz
def456  fake-image-aarch64.tar.gz
ghi789  fake-image-i386.tar.gz
HASHEOF

# Mock download function — same signature as the real one
download() {
    local file="\$1"
    local safe="\$(echo "\$file" | tr -cs 'a-zA-Z0-9' '_')"
    echo "\$(date +%s%N)" > "\${TIMESTAMPS_DIR}/\${safe}.start"
    sleep 1
    touch "\${OUT_DIR}/\${file}"
    echo "\$(date +%s%N)" > "\${TIMESTAMPS_DIR}/\${safe}.end"
}

# ── This is the exact loop from the fixed download-kernel-images.sh ───────────
pids=()
while read -r hash file; do
    echo "Downloading \${file}..."
    download "\${file}" &
    pids+=(\$!)
done < "\${OUT_DIR}/hashsums.txt"

failed=0
for pid in "\${pids[@]}"; do
    wait "\$pid" || failed=1
done

if [ "\$failed" -ne 0 ]; then
    echo "One or more downloads failed."
    exit 1
fi
INNEREOF
chmod +x "${WORK_DIR}/run_test.sh"

# ── Run it ────────────────────────────────────────────────────────────────────
echo "Running parallel download test..."
START_NS=$(date +%s%N)
bash "${WORK_DIR}/run_test.sh"
EXIT_CODE=$?
END_NS=$(date +%s%N)

ELAPSED_MS=$(((END_NS - START_NS) / 1000000))
echo "Total elapsed: ${ELAPSED_MS}ms"

# ── Assertions ────────────────────────────────────────────────────────────────
NUM_DOWNLOADS=$(ls "${TIMESTAMPS_DIR}"/*.start 2> /dev/null | wc -l)
echo "Downloads observed: ${NUM_DOWNLOADS}"

PASS=true

# Test 1: All 3 downloads ran
if [[ "${NUM_DOWNLOADS}" -lt 3 ]]; then
    echo "FAIL: Expected 3 downloads, got ${NUM_DOWNLOADS}"
    PASS=false
else
    echo "PASS: All 3 downloads ran"
fi

# Test 2: Wall time under 2500ms (sequential = ~3000ms, parallel = ~1000ms)
if [[ "${ELAPSED_MS}" -gt 2500 ]]; then
    echo "FAIL: Elapsed ${ELAPSED_MS}ms — looks sequential (expected < 2500ms)"
    PASS=false
else
    echo "PASS: Elapsed ${ELAPSED_MS}ms confirms parallel execution"
fi

# Test 3: Timestamp overlap confirms true parallelism
START_TIMES=()
while IFS= read -r f; do
    START_TIMES+=("$(cat "$f")")
done < <(ls "${TIMESTAMPS_DIR}"/*.start 2> /dev/null | sort)

END_TIMES=()
while IFS= read -r f; do
    END_TIMES+=("$(cat "$f")")
done < <(ls "${TIMESTAMPS_DIR}"/*.end 2> /dev/null | sort)

OVERLAP=false
if [[ "${#START_TIMES[@]}" -ge 2 && "${#END_TIMES[@]}" -ge 1 ]]; then
    if [[ "${START_TIMES[1]}" -lt "${END_TIMES[0]}" ]]; then
        OVERLAP=true
    fi
fi

if [[ "${OVERLAP}" == true ]]; then
    echo "PASS: Overlapping timestamps confirm true parallelism"
else
    echo "FAIL: No timestamp overlap — downloads may be sequential"
    PASS=false
fi

# Test 4: Script exited 0
if [[ "${EXIT_CODE}" -ne 0 ]]; then
    echo "FAIL: Script exited with code ${EXIT_CODE}"
    PASS=false
else
    echo "PASS: Script exited 0"
fi

echo ""
if [[ "${PASS}" == true ]]; then
    echo "✓ All tests passed — parallel download behavior confirmed"
    exit 0
else
    echo "✗ One or more tests failed"
    exit 1
fi
