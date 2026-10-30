#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Exit 0 when this host's qemu-system-aarch64 can run a guest under HVF. It asks
# QEMU itself: without the hypervisor entitlement QEMU ends at `-accel hvf`
# instead of moving on to the next `-accel`, so a chain is no fallback.
[ "$(uname -sm)" = "Darwin arm64" ] || exit 1
[ "$(sysctl -n kern.hv_support 2>/dev/null)" = 1 ] || exit 1
echo quit | qemu-system-aarch64 -M none -accel hvf -monitor stdio -display none -nodefaults >/dev/null 2>&1
