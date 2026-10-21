#!/bin/zsh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# OT01 — run host-side OTA pure logic tests.
#
# Wraps the env setup so you don't have to remember the incantation.
# (The workspace's .cargo/config.toml forces a riscv target with build-std;
#  this script overrides both to run on the host.)
set -e

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CARGO="$HOME/.cargo/bin/cargo"
XCRUN="/usr/bin/xcrun"
TOOLCHAIN_BIN="/Library/Developer/CommandLineTools/usr/bin"

export PATH="$TOOLCHAIN_BIN:$PATH"
export SDKROOT="$($XCRUN --show-sdk-path)"

# Outputs live under $AZOS_OUT (tools/out_dir.py), never in the checkout.
AZOS_OUT="${AZOS_OUT:-$(python3 "$(dirname "$0")/out_dir.py")}"; export AZOS_OUT
cd "$REPO/tests/host/ota-tests"
export CARGO_TARGET_DIR="$AZOS_OUT/tgt/tests/host/ota-tests"
# Run with stable toolchain so the workspace's `build-std = ["core", "alloc"]`
# (used for the riscv kernel build) doesn't try to rebuild std for the host
# test target. Stable doesn't accept the unstable feature, so cargo skips it.
"$CARGO" +stable test --target aarch64-apple-darwin "$@"
