#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# QEMU shell command test — verify shell commands work via serial input.
#
# Sends commands to the kernel shell via QEMU serial and verifies output.
#
# Usage: ./tests/qemu_shell.sh
# Returns: 0 on success, 1 on failure.

set -e

OS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL_ELF="$OS_DIR/target/riscv64imac-unknown-none-elf/release/kernel"
TIMEOUT_S=20
OUTPUT="$OS_DIR/tests/qemu_shell_output.log"
INPUT_FIFO="$OS_DIR/tests/qemu_input.fifo"
PASSED=0
FAILED=0
TOTAL=0

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { PASSED=$((PASSED+1)); TOTAL=$((TOTAL+1)); echo -e "  ${GREEN}PASS${NC}: $1"; }
fail() { FAILED=$((FAILED+1)); TOTAL=$((TOTAL+1)); echo -e "  ${RED}FAIL${NC}: $1"; }

check() {
    if grep -q "$2" "$OUTPUT" 2>/dev/null; then pass "$1"; else fail "$1"; fi
}

echo "=== QEMU Shell Command Test ==="
echo ""

# Build
cd "$OS_DIR"
cargo build --release 2>&1 | grep "Finished" || true

if [ ! -f "$KERNEL_ELF" ]; then
    echo "ERROR: Kernel not found"
    exit 1
fi

# Create input FIFO for sending commands
rm -f "$INPUT_FIFO"
mkfifo "$INPUT_FIFO"

# Start QEMU in background with serial connected to FIFO
echo "[QEMU] Starting kernel..."
timeout ${TIMEOUT_S} qemu-system-riscv64 \
    -machine virt -nographic -bios default \
    -kernel "$KERNEL_ELF" \
    -smp 4 -m 128M \
    -no-reboot \
    -serial mon:stdio \
    < "$INPUT_FIFO" \
    2>&1 > "$OUTPUT" &
QEMU_PID=$!

# Wait for boot
sleep 5

# Send shell commands via FIFO
echo "[SHELL] Sending commands..."
(
    sleep 1
    echo "help"
    sleep 1
    echo "mem"
    sleep 1
    echo "tasks"
    sleep 1
    echo "gpio info"
    sleep 1
    echo "config list"
    sleep 1
    # Send Ctrl-A X to exit QEMU
    printf '\x01x'
) > "$INPUT_FIFO" &

# Wait for QEMU to finish
wait $QEMU_PID 2>/dev/null || true

echo "[QEMU] Captured $(wc -l < "$OUTPUT" | tr -d ' ') lines"
echo ""

# Check command outputs
echo "[TESTS] Checking shell responses..."

check "Shell accepts 'help'"        "help"
check "Memory info works"           "free"
check "Task list works"             "behavior\|shell\|net-poll"
check "GPIO info works"             "GPIO"

echo ""
echo "=== Results: $PASSED passed, $FAILED failed (of $TOTAL) ==="

# Cleanup
rm -f "$INPUT_FIFO" "$OUTPUT"

if [ $FAILED -gt 0 ]; then exit 1; fi
echo "All tests passed!"
exit 0
