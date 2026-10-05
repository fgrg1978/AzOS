#!/bin/zsh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Build all 5 kernel configurations.
# Usage: /Users/azor/Library/Mobile\ Documents/com~apple~CloudDocs/Development/ia/azos/tools/build.sh
set -e

CARGO="$HOME/.cargo/bin/cargo"
REPO="/Users/azor/Library/Mobile Documents/com~apple~CloudDocs/Development/ia/azos"

# crates/core/ota/build.rs (OT05) is compiled for the host and needs cc/SDKROOT
# even though the kernel itself targets riscv64. Add Apple CLI tools to PATH
# so cargo can link build scripts on macOS.
export PATH="/Library/Developer/CommandLineTools/usr/bin:/opt/homebrew/bin:$PATH"
export SDKROOT="/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"

cd "$REPO"

echo "=== QEMU (default) ==="
"$CARGO" build --release --features qemu 2>&1 | /usr/bin/tail -3

echo "=== vf2 ==="
"$CARGO" build --release --features vf2 2>&1 | /usr/bin/tail -3

echo "=== k1 ==="
"$CARGO" build --release --features k1 2>&1 | /usr/bin/tail -3

echo "=== no-ml ==="
"$CARGO" build --release --features no-ml 2>&1 | /usr/bin/tail -3

echo "=== no-mmu ==="
"$CARGO" build --release --features no-mmu 2>&1 | /usr/bin/tail -3

echo ""
echo "All 5 configs built."
