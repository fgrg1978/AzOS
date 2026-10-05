#!/bin/zsh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# OT01 — run host-side OTA pure logic tests.
#
# Wraps the env setup so you don't have to remember the incantation.
# (The workspace's .cargo/config.toml forces a riscv target with build-std;
#  this script overrides both to run on the host.)
set -e

REPO="/Users/azor/Library/Mobile Documents/com~apple~CloudDocs/Development/ia/azos"
CARGO="$HOME/.cargo/bin/cargo"
XCRUN="/usr/bin/xcrun"
TOOLCHAIN_BIN="/Library/Developer/CommandLineTools/usr/bin"

export PATH="$TOOLCHAIN_BIN:$PATH"
export SDKROOT="$($XCRUN --show-sdk-path)"

cd "$REPO/tests/host/ota-tests"
# Run with stable toolchain so the workspace's `build-std = ["core", "alloc"]`
# (used for the riscv kernel build) doesn't try to rebuild std for the host
# test target. Stable doesn't accept the unstable feature, so cargo skips it.
"$CARGO" +stable test --target aarch64-apple-darwin "$@"
