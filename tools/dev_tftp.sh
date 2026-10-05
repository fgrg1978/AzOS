#!/bin/zsh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# DEV01 — TFTP fast-iteration helper for VF2/K1 hardware.
#
# Cuts the dev cycle from "yank SD card → flash → reinsert → boot" (3-5 min)
# down to ~5 s by serving the freshly-built kernel over TFTP. U-Boot on the
# board fetches it on every reboot.
#
# Usage:
#   tools/dev_tftp.sh          # build qemu kernel + serve forever
#   tools/dev_tftp.sh vf2      # build VF2 kernel + serve forever
#   tools/dev_tftp.sh k1       # build K1 kernel + serve forever
#
# On the board's U-Boot prompt (one-time setup):
#   setenv ipaddr 192.168.1.50
#   setenv serverip 192.168.1.10        # this Mac's IP
#   setenv loadaddr 0x80200000
#   setenv bootcmd "tftpboot ${loadaddr} kernel.bin; booti ${loadaddr} - ${fdt_addr}"
#   saveenv
#
# Then power-cycle the board to fetch the new kernel from this Mac.
#
# Requires: tftpd-hpa or macOS's built-in tftpd (launchctl load).
set -e

OS_DIR="/Users/azor/Library/Mobile Documents/com~apple~CloudDocs/Development/ia/azos"
CARGO="$HOME/.cargo/bin/cargo"
OBJCOPY="/opt/homebrew/opt/llvm/bin/llvm-objcopy"
TFTP_ROOT="${TFTP_ROOT:-/private/tftpboot}"
TARGET="${1:-qemu}"

export PATH="/Library/Developer/CommandLineTools/usr/bin:/opt/homebrew/bin:$PATH"
export SDKROOT="/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"

if [[ ! -d "$TFTP_ROOT" ]]; then
    echo "ERROR: $TFTP_ROOT does not exist."
    echo "       Create it and enable tftpd:"
    echo "         sudo mkdir -p $TFTP_ROOT && sudo chown nobody:nobody $TFTP_ROOT"
    echo "         sudo launchctl load -F /System/Library/LaunchDaemons/tftp.plist"
    echo "         sudo launchctl start com.apple.tftpd"
    exit 2
fi

case "$TARGET" in
    qemu) FEATURES="qemu" ;;
    vf2)  FEATURES="vf2" ;;
    k1)   FEATURES="k1" ;;
    *)    echo "unknown target: $TARGET"; exit 2 ;;
esac

cd "$OS_DIR"

build_and_publish() {
    echo "[$(date '+%H:%M:%S')] Building --features $FEATURES ..."
    if "$CARGO" build --release --features "$FEATURES" 2>&1 | /usr/bin/tail -3; then
        ELF="$OS_DIR/target/riscv64imac-unknown-none-elf/release/kernel"
        OUT="$TFTP_ROOT/kernel.bin"
        "$OBJCOPY" -O binary "$ELF" "$OUT"
        SIZE=$(/usr/bin/stat -f%z "$OUT")
        echo "[$(date '+%H:%M:%S')] Published $OUT ($SIZE bytes)."
    else
        echo "[$(date '+%H:%M:%S')] BUILD FAILED — keeping previous kernel.bin."
    fi
}

build_and_publish
echo
echo "Watching for source changes (Ctrl-C to stop)..."
echo "Power-cycle the board after each rebuild and U-Boot will TFTP the new kernel."
echo

# Use fswatch if available, otherwise fall back to a polling loop.
if command -v fswatch >/dev/null 2>&1; then
    /opt/homebrew/bin/fswatch -o "$OS_DIR/kernel" "$OS_DIR/crates" "$OS_DIR/domains" \
        --exclude '/target/' --exclude '/build/' \
        | while read -r _; do build_and_publish; done
else
    LAST_HASH=""
    while true; do
        HASH=$(/usr/bin/find "$OS_DIR/kernel" "$OS_DIR/crates" "$OS_DIR/domains" \
            -type f \( -name '*.rs' -o -name '*.toml' -o -name '*.S' \) \
            -not -path '*/target/*' -not -path '*/build/*' \
            -exec /sbin/md5 -q {} \; 2>/dev/null | /usr/bin/md5)
        if [[ "$HASH" != "$LAST_HASH" && -n "$LAST_HASH" ]]; then
            build_and_publish
        fi
        LAST_HASH=$HASH
        /bin/sleep 2
    done
fi
