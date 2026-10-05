#!/bin/zsh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Run host-side regression tests.
# Each module locks down a specific bug previously fixed.
set -e

REPO="/Users/azor/Library/Mobile Documents/com~apple~CloudDocs/Development/ia/azos"
CARGO="$HOME/.cargo/bin/cargo"
XCRUN="/usr/bin/xcrun"
TOOLCHAIN_BIN="/Library/Developer/CommandLineTools/usr/bin"

export PATH="$TOOLCHAIN_BIN:$PATH"
export SDKROOT="$($XCRUN --show-sdk-path)"

cd "$REPO/tests/host/regression-tests"
"$CARGO" +stable test --target aarch64-apple-darwin "$@"
