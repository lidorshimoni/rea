#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "==> Compiling baseline target binary..."
gcc -O2 -fno-pie -no-pie -fomit-frame-pointer -fno-asynchronous-unwind-tables target_src/main.c -o target.bin

TARGET_SHA="$(sha256sum target.bin | awk '{print $1}')"
echo "==> Baseline target.bin built successfully:"
echo "    Path:   ${SCRIPT_DIR}/target.bin"
echo "    SHA256: ${TARGET_SHA}"

# Update decomp.yaml with the calculated SHA256
if [ -f "decomp.yaml" ]; then
    sed -i "s/sha256: .*/sha256: ${TARGET_SHA}/" decomp.yaml
    echo "==> Updated decomp.yaml target sha256 to ${TARGET_SHA}"
fi
