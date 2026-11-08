#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Print the Linux image of one ISA from tools/bench/vsbench_linux.conf: `~/` is $HOME and
# `@OUT@/` is $AZOS_OUT (which the caller exports).
#   vsbench_linux_image.sh riscv64|aarch64|x86_64
v="$(sed -n "s/^$1=//p" "$(dirname "$0")/vsbench_linux.conf")"
case "$v" in
"~/"*) v="$HOME/${v#\~/}" ;;
"@OUT@/"*) v="$AZOS_OUT/${v#@OUT@/}" ;;
esac
printf '%s\n' "$v"
