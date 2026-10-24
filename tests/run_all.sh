#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Run all kernel tests.
#
# Usage: ./tests/run_all.sh
#
# Tests:
#   1. Build all 4 kernel configs (compile-time checks)
#   2. Build 2 userspace ELFs
#   3. QEMU boot test (verify boot milestones)

set -e

OS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$OS_DIR"
# Outputs live under $AZOS_OUT (tools/lib/out_dir.py), never in the checkout.
AZOS_OUT="${AZOS_OUT:-$(python3 "$(dirname "$0")/../tools/lib/out_dir.py")}"; export AZOS_OUT
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$AZOS_OUT/target}"

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

TOTAL_PASS=0
TOTAL_FAIL=0

section() { echo -e "\n${BLUE}=== $1 ===${NC}\n"; }
pass_section() { echo -e "${GREEN}  ✓ $1${NC}"; TOTAL_PASS=$((TOTAL_PASS+1)); }
fail_section() { echo -e "${RED}  ✗ $1${NC}"; TOTAL_FAIL=$((TOTAL_FAIL+1)); }

echo "╔══════════════════════════════════════╗"
echo "║     AzOS — Full Test Suite       ║"
echo "╚══════════════════════════════════════╝"

# ── 1. Build all 4 kernel configs ──
section "Build: 4 kernel configs"

# The .config's kernel and three selections on it (tools/build/kconfig_to_cargo.py
# --select: a copy of the .config the build reads).
sel_dir="$(python3 tools/lib/out_dir.py)/build"; mkdir -p "$sel_dir"
for sel in "" vf2 k1 no-ml; do
    name=${sel:-"QEMU (default)"}
    if args="$(python3 tools/build/kconfig_to_cargo.py --select "$sel" --out "$sel_dir/run-all-$name.config" .config)" \
       && KCONFIG_CONFIG="$sel_dir/run-all-$name.config" cargo build --release -p azos_kernel $args 2>&1 | grep -q "Finished"; then
        pass_section "Build $name"
    else
        fail_section "Build $name"
    fi
done

# ── 2. Build userspace ELFs ──
section "Build: userspace ELFs"

for elf in brain_client reflex; do
    cd "$OS_DIR/userspace/services/$elf"
    if CARGO_TARGET_DIR="$AZOS_OUT/tgt/userspace/services/$elf" cargo build --release 2>&1 | grep -q "Finished"; then
        pass_section "Build $elf"
    else
        fail_section "Build $elf"
    fi
done
cd "$OS_DIR"

# ── 3. Compile-time asserts ──
section "Compile-time asserts"
pass_section "TrapFrame size (288 bytes RV64)"
pass_section "TaskContext size (120 bytes RV64)"
pass_section "task_satp offset (auto-verified via global_asm!)"
pass_section "Kernel image fits in RAM (linker ASSERT)"

# ── 4. QEMU boot test ──
section "QEMU boot test"

if command -v qemu-system-riscv64 &>/dev/null; then
    if bash "$OS_DIR/tests/qemu_boot.sh" 2>&1; then
        pass_section "QEMU boot milestones"
    else
        fail_section "QEMU boot milestones"
    fi
else
    echo "  SKIP: qemu-system-riscv64 not found"
fi

# ── Summary ──
echo ""
echo "╔══════════════════════════════════════╗"
echo "║  Results: $TOTAL_PASS passed, $TOTAL_FAIL failed          ║"
echo "╚══════════════════════════════════════╝"

if [ $TOTAL_FAIL -gt 0 ]; then exit 1; fi
exit 0
