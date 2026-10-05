#!/bin/zsh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# DEV01.A — Enable macOS built-in TFTP server for fast kernel iteration.
#
# After running this once, the macOS launchd service `com.apple.tftpd`
# will be active and will serve files from $TFTP_ROOT.
#
# Usage:
#   sudo ./tools/dev_setup_tftp.sh        # enable + start
#   sudo ./tools/dev_setup_tftp.sh stop   # stop + disable
#   sudo ./tools/dev_setup_tftp.sh status # query state
set -e

# ── Constants ──────────────────────────────────────────────────────────────
TFTP_ROOT="/private/tftpboot"
TFTPD_PLIST="/System/Library/LaunchDaemons/tftp.plist"
LAUNCHCTL="/bin/launchctl"
ACTION="${1:-start}"

if [[ "$EUID" -ne 0 ]]; then
    echo "error: this script needs root (uses launchctl + chown $TFTP_ROOT)."
    echo "       run as: sudo $0 $*"
    exit 1
fi

case "$ACTION" in
    start)
        echo "[1/4] Creating $TFTP_ROOT (if missing)..."
        /bin/mkdir -p "$TFTP_ROOT"
        /usr/sbin/chown root:wheel "$TFTP_ROOT"
        /bin/chmod 0755 "$TFTP_ROOT"

        echo "[2/4] Loading launchd service..."
        # -F forces re-load if already enabled with stale config
        "$LAUNCHCTL" load -F "$TFTPD_PLIST" 2>/dev/null || true

        echo "[3/4] Starting tftpd..."
        "$LAUNCHCTL" start com.apple.tftpd

        echo "[4/4] Verifying..."
        if "$LAUNCHCTL" list | /usr/bin/grep -q com.apple.tftpd; then
            echo ""
            echo "✓ TFTP server active. Serving from: $TFTP_ROOT"
            echo "  Test with: tftp localhost"
            echo "    > get <filename>"
            echo ""
            echo "  Drop kernel binaries here for board to fetch:"
            echo "    cp target/.../kernel.bin $TFTP_ROOT/kernel.bin"
        else
            echo "✗ tftpd not running. Check: sudo log show --predicate 'process == \"tftpd\"' --last 1m"
            exit 1
        fi
        ;;
    stop)
        echo "Stopping tftpd..."
        "$LAUNCHCTL" stop com.apple.tftpd 2>/dev/null || true
        "$LAUNCHCTL" unload "$TFTPD_PLIST" 2>/dev/null || true
        echo "✓ TFTP stopped."
        ;;
    status)
        if "$LAUNCHCTL" list | /usr/bin/grep -q com.apple.tftpd; then
            echo "✓ tftpd is loaded:"
            "$LAUNCHCTL" list | /usr/bin/grep com.apple.tftpd
            echo ""
            echo "Files in $TFTP_ROOT:"
            /bin/ls -la "$TFTP_ROOT" 2>/dev/null || echo "  (root not yet created)"
        else
            echo "✗ tftpd not loaded. Run: sudo $0 start"
            exit 1
        fi
        ;;
    *)
        echo "usage: $0 {start|stop|status}"
        exit 1
        ;;
esac
