#!/bin/zsh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# DEV02 — USB DFU recovery for VF2 / K1.
#
# Lifeline for when a bad flash leaves the board in a bootloop or with no
# bootable kernel. Uses the Boot ROM (DFU/recovery) mode each SoC exposes over
# USB when a button is held at power-on:
#
# - VisionFive 2 (StarFive JH7110):
#     mode select switch GPIO0=1, GPIO1=0 → Boot ROM (USB DFU)
#     Tool: dfu-util (brew install dfu-util)
#
# - BananaPi BPI-F3 (SpacemiT K1):
#     hold BOOT button while powering on → BROM USB
#     Tool: titools (vendor-provided)
#
# Usage:
#   tools/dev_dfu_recovery.sh vf2  /path/to/u-boot-spl.bin /path/to/u-boot.itb
#   tools/dev_dfu_recovery.sh k1   /path/to/recovery_image.bin
set -e

PLATFORM="${1:-}"
shift || true

case "$PLATFORM" in
vf2)
    SPL="${1:?'Usage: dev_dfu_recovery.sh vf2 <u-boot-spl.bin> <u-boot.itb>'}"
    ITB="${2:?}"
    DFU_UTIL=/opt/homebrew/bin/dfu-util

    if [[ ! -x "$DFU_UTIL" ]]; then
        echo "ERROR: install dfu-util via 'brew install dfu-util'"
        exit 2
    fi
    echo "Looking for VF2 in DFU mode (vid:pid 0x046d:0x0001)..."
    "$DFU_UTIL" -l | /usr/bin/grep -i 'StarFive\|046d' || {
        echo "VF2 not detected in DFU mode."
        echo "Set boot mode switches to GPIO0=1 GPIO1=0 and reboot, then re-run."
        exit 1
    }
    echo "[1/2] Sending u-boot-spl.bin..."
    "$DFU_UTIL" -d 046d:0001 -a 0 -D "$SPL"
    echo "[2/2] Sending u-boot.itb..."
    "$DFU_UTIL" -d 046d:0001 -a 0 -D "$ITB"
    echo "Recovery complete. Set boot mode switches back to MMC and reboot."
    ;;

k1)
    IMG="${1:?'Usage: dev_dfu_recovery.sh k1 <recovery_image.bin>'}"
    TITOOLS="${TITOOLS:-/opt/homebrew/bin/titools}"

    if [[ ! -x "$TITOOLS" ]]; then
        echo "ERROR: SpacemiT 'titools' not installed."
        echo "       Get it from the BananaPi BPI-F3 vendor package."
        exit 2
    fi
    echo "Hold BOOT button on BPI-F3 and power on, then connect USB."
    echo "Press Enter when ready..."
    read -r _
    "$TITOOLS" -p "$IMG"
    echo "Recovery complete. Power-cycle without holding BOOT."
    ;;

*)
    echo "Usage: $0 {vf2|k1} <args>"
    echo "  vf2 <u-boot-spl.bin> <u-boot.itb>"
    echo "  k1  <recovery_image.bin>"
    exit 2
    ;;
esac
