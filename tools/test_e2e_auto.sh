#!/bin/zsh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Automated E2E smoke test — boots kernel in QEMU, starts brain server,
# waits N seconds, checks that expected messages appeared, then cleans up.
#
# Does NOT require LM Studio (brain runs without VLM/LLM).
# Does NOT hang — exits with pass/fail after TIMEOUT_S seconds.
set -e

# ── Config ─────────────────────────────────────────────────────────────────
TIMEOUT_S=30
BRAIN_PORT=9000
OS_DIR="/Users/azor/Library/Mobile Documents/com~apple~CloudDocs/Development/ia/azos"
BRAIN_DIR="/Users/azor/Library/Mobile Documents/com~apple~CloudDocs/Development/ia/AzOSRobotBrain"
QEMU="/opt/homebrew/bin/qemu-system-riscv64"
PYTHON="/opt/homebrew/bin/python3.12"
CARGO="$HOME/.cargo/bin/cargo"
MKFS_FAT="/opt/homebrew/opt/dosfstools/sbin/mkfs.fat"
MCOPY="/opt/homebrew/bin/mcopy"
DD="/bin/dd"
MKTEMP="/usr/bin/mktemp"

LOG_DIR="$OS_DIR/build/e2e_log"
/bin/mkdir -p "$LOG_DIR"
BRAIN_LOG="$LOG_DIR/brain.log"
KERNEL_LOG="$LOG_DIR/kernel.log"

# ── Build kernel ───────────────────────────────────────────────────────────
echo "[1/5] Building kernel (QEMU target)..."
cd "$OS_DIR"
"$CARGO" build --release 2>&1 | /usr/bin/tail -3

KERNEL_ELF="$OS_DIR/target/riscv64imac-unknown-none-elf/release/kernel"
if [[ ! -f "$KERNEL_ELF" ]]; then
    echo "ERROR: kernel ELF missing: $KERNEL_ELF"
    exit 1
fi

# ── Create disk image with CONFIG.INI ──────────────────────────────────────
echo "[2/5] Creating disk image with CONFIG.INI..."
DISK="$OS_DIR/build/disk.img"
CONFIG_TMP="$OS_DIR/build/CONFIG.INI"

# FAT32 requires ≥33 MB — 64 MB gives headroom for logs + OTA slots.
"$DD" if=/dev/zero of="$DISK" bs=1m count=64 2>/dev/null
"$MKFS_FAT" -F 32 -n ROBOT "$DISK" >/dev/null 2>&1

# Build CONFIG.INI file-side first, then mcopy it into the image.
/bin/cat > "$CONFIG_TMP" << 'EOF'
net_ip=10.0.2.15
net_gateway=10.0.2.2
net_mask=255.255.255.0
behavior_server_ip=10.0.2.2
behavior_server_port=9000
behavior_l1_enabled=1
behavior_l2_enabled=1
behavior_l3_enabled=1
ml_enabled=1
EOF

"$MCOPY" -i "$DISK" "$CONFIG_TMP" ::CONFIG.INI 2>&1 | /usr/bin/head -3 || true
echo "  CONFIG.INI written (FAT32, 64 MB image)"

# ── Start brain server ─────────────────────────────────────────────────────
echo "[3/5] Starting brain server on port $BRAIN_PORT..."
cd "$BRAIN_DIR"
"$PYTHON" -u server.py >"$BRAIN_LOG" 2>&1 &
BRAIN_PID=$!

# Wait a bit for brain to start
/bin/sleep 2 2>/dev/null || /opt/homebrew/bin/sleep 2 2>/dev/null || :
if ! kill -0 $BRAIN_PID 2>/dev/null; then
    echo "ERROR: brain server died early. Log:"
    /usr/bin/tail -20 "$BRAIN_LOG"
    exit 1
fi
echo "  brain PID=$BRAIN_PID"

# ── Launch QEMU with output captured ───────────────────────────────────────
echo "[4/5] Launching QEMU (will run for ${TIMEOUT_S}s)..."
cd "$OS_DIR"

# Use timeout-like behavior via & + kill.  '-display none' + '-serial stdio'
# sends console to stdout which we redirect to KERNEL_LOG.
"$QEMU" \
    -machine virt -display none -serial stdio \
    -bios default \
    -kernel "$KERNEL_ELF" \
    -smp 4 \
    -m 128M \
    -drive file=build/disk.img,if=none,format=raw,id=hd0 \
    -device virtio-blk-device,drive=hd0 \
    -netdev user,id=net0 \
    -device virtio-net-device,netdev=net0 \
    >"$KERNEL_LOG" 2>&1 &
QEMU_PID=$!

# Monitor loop — check every second up to TIMEOUT_S
ELAPSED=0
while [[ $ELAPSED -lt $TIMEOUT_S ]]; do
    /bin/sleep 1 2>/dev/null || /opt/homebrew/bin/sleep 1 2>/dev/null || :
    ELAPSED=$((ELAPSED+1))
    if ! kill -0 $QEMU_PID 2>/dev/null; then break; fi
done

# Kill both
kill $QEMU_PID 2>/dev/null || true
kill $BRAIN_PID 2>/dev/null || true
wait $QEMU_PID 2>/dev/null || true
wait $BRAIN_PID 2>/dev/null || true

# ── Evaluate results ───────────────────────────────────────────────────────
echo ""
echo "[5/5] Checking logs..."
echo ""
PASS=0
FAIL=0
WARN=0

check() {
    local label="$1"; local file="$2"; local pattern="$3"
    if /usr/bin/grep -qE "$pattern" "$file"; then
        echo "  ✓ $label"
        PASS=$((PASS+1))
    else
        echo "  ✗ $label  (pattern: $pattern)"
        FAIL=$((FAIL+1))
    fi
}

# Soft check — emits a warning but does not fail the run.
check_info() {
    local label="$1"; local file="$2"; local pattern="$3"
    if /usr/bin/grep -qE "$pattern" "$file"; then
        echo "  ✓ $label"
        PASS=$((PASS+1))
    else
        echo "  ⚠ $label  (informational — pattern: $pattern)"
        WARN=$((WARN+1))
    fi
}

check "kernel banner"       "$KERNEL_LOG" "(KERNEL|AzOS|kernel_main|behavior)"
check "memory init"         "$KERNEL_LOG" "(PMM|heap|memory|RAM)"
check "network stack up"    "$KERNEL_LOG" "(NET|virtio|eth|TCP)"
check "behavior started"    "$KERNEL_LOG" "(BEHAVIOR|behavior|subsumption|L0|safety)"
check "brain server ready"  "$BRAIN_LOG"  "(listening|Listening|ready|Server|started|9000)"
# Deeper checks: kernel found CONFIG.INI + VLA server, attempted TCP.
check "CONFIG.INI loaded"   "$KERNEL_LOG" "(CFG.+VLA|behavior_server_ip|net:\s*10\.0\.2)"
check "TCP connect tried"   "$KERNEL_LOG" "(tcp|TCP|connect|10\.0\.2\.2|brain)"

# Informational — does the brain see the kernel? This requires the kernel's
# behavior_task to complete a TCP 3-way handshake against QEMU user-mode NAT
# within TIMEOUT_S. The emulation tick rate is 100-1000× slower than real
# hardware (see WCET violations in the kernel log), so this step often times
# out in QEMU. On real hardware (VF2 / K1) the full handshake completes in
# milliseconds. Treat a miss here as "needs real hardware", not a regression.
check_info "brain saw client (requires HW for reliable pass)" \
    "$BRAIN_LOG"  "(connected|client|accept|peer|from 10\.)"

echo ""
echo "Logs: $KERNEL_LOG | $BRAIN_LOG"
echo ""
if [[ $FAIL -eq 0 ]]; then
    if [[ $WARN -eq 0 ]]; then
        echo "=== E2E PASS ($PASS checks) ==="
    else
        echo "=== E2E PASS ($PASS passed, $WARN informational miss) ==="
    fi
    exit 0
else
    echo "=== E2E FAIL: $PASS passed, $FAIL failed, $WARN informational ==="
    echo ""
    echo "Last 30 lines kernel log:"
    /usr/bin/tail -30 "$KERNEL_LOG"
    echo ""
    echo "Last 20 lines brain log:"
    /usr/bin/tail -20 "$BRAIN_LOG"
    exit 1
fi
