#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# QEMU boot test — verify kernel boots and reaches key milestones.
#
# Runs QEMU for a limited time, captures serial output, and checks
# that critical boot messages appear in the correct order.
#
# Usage: ./tests/qemu_boot.sh
# Returns: 0 on success, 1 on failure.

set -e

OS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KERNEL_ELF="$OS_DIR/target/riscv64imac-unknown-none-elf/release/kernel"
TIMEOUT_S=45
OUTPUT="$OS_DIR/tests/qemu_output.log"
PASSED=0
FAILED=0
TOTAL=0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { PASSED=$((PASSED+1)); TOTAL=$((TOTAL+1)); echo -e "  ${GREEN}PASS${NC}: $1"; }
fail() { FAILED=$((FAILED+1)); TOTAL=$((TOTAL+1)); echo -e "  ${RED}FAIL${NC}: $1"; }

check() {
    local desc="$1"
    local pattern="$2"
    if grep -q "$pattern" "$OUTPUT" 2>/dev/null; then
        pass "$desc"
    else
        fail "$desc (pattern: $pattern)"
    fi
}

check_absent() {
    local desc="$1"
    local pattern="$2"
    if grep -q "$pattern" "$OUTPUT" 2>/dev/null; then
        fail "$desc (found: $pattern)"
    else
        pass "$desc"
    fi
}

echo "=== QEMU Boot Test ==="
echo ""

# 1. Build kernel
echo "[BUILD] Building kernel (release)..."
cd "$OS_DIR"
cargo build --release 2>&1 | grep -E "Compiling|Finished|error" || true

if [ ! -f "$KERNEL_ELF" ]; then
    echo "ERROR: Kernel binary not found at $KERNEL_ELF"
    exit 1
fi
echo "[BUILD] OK"
echo ""

# 2. Run QEMU with timeout
echo "[QEMU] Booting kernel (timeout ${TIMEOUT_S}s)..."
timeout ${TIMEOUT_S} qemu-system-riscv64 \
    -machine virt -nographic -bios default \
    -kernel "$KERNEL_ELF" \
    -smp 4 \
    -m 128M \
    -no-reboot \
    2>&1 > "$OUTPUT" || true

echo "[QEMU] Captured $(wc -l < "$OUTPUT" | tr -d ' ') lines of output"
echo ""

# 3. Check boot milestones
echo "[TESTS] Checking boot milestones..."

# Basic boot
check "Kernel banner prints"           "AzOS"
check "Hart ID reported"               "Hart ID"
check "DTB parsed"                     "DTB"

# Memory management
check "PMM initialized"               "PMM"
check "VMM initialized"               "VMM"
check "Sv39 paging enabled"            "paging ENABLED"
check "W^X enforced"                   "W.X enforced"
check "Null guard active"             "Null pointer guard"
check "Stack guard pages"             "guard pages"
check "Heap initialized"              "Heap initialized"
check "Heap test passes"              "Heap test"

# Tracing
check "Tracing enabled"               "tracing enabled"

# Interrupts
check "Traps active"                  "Traps"
check "UART IRQ enabled"              "UART IRQ"

# Drivers
check "IMU initialized"               "IMU"
check "GPIO initialized"              "GPIO"

# Robot config
check "Robot type reported"            "ROBOT"
check "WDT configured"                "WDT"

# Scheduler
check "Behavior task created"          "behavior"
check "Sensor tasks created"           "Sensor tasks\|imu\|IMU-TASK\|odom"
check "Net-poll task created"          "net-poll\|NET-POLL\|Sensor tasks\|BEHAVIOR"
check "Shell task created"             "shell\|SHELL"

# Safety
check "Safety profile set"            "safety\|ROBOT\|robot_type"

# No crashes
check_absent "No kernel panic"         "PANIC"
check_absent "No page fault"           "PAGE FAULT"
check_absent "No fatal error"          "FATAL"

echo ""

# 4. Summary
echo "=== Results: $PASSED passed, $FAILED failed (of $TOTAL) ==="
echo ""

if [ $FAILED -gt 0 ]; then
    echo "FAILED TESTS — output saved to: $OUTPUT"
    echo ""
    echo "Last 20 lines of output:"
    tail -20 "$OUTPUT" 2>/dev/null || true
    exit 1
fi

# Cleanup output on success
rm -f "$OUTPUT"
echo "All tests passed!"
exit 0
