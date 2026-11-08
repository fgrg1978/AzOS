#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Print the dated toolchain channel of rust-toolchain.toml: the one every `cargo +<channel>` uses.
sed -n 's/^channel *= *"\(.*\)".*/\1/p' "$(dirname "$0")/../../rust-toolchain.toml"
