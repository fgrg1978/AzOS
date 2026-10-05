#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# End-to-end test: brain server (Python) ↔ kernel (QEMU)
#
# Prerequisites:
#   - QEMU riscv64 installed (brew install qemu)
#   - Python 3.10+ with deps (pip install openai pyyaml)
#   - LM Studio running (optional — brain works without it, just skips VLM/LLM)
#
# What happens:
#   1. Builds the kernel
#   2. Creates a disk image with CONFIG.INI (behavior_server_ip=10.0.2.2:9000)
#   3. Starts the brain server on port 9000
#   4. Launches QEMU with networking
#   5. The kernel's behavior_task connects to the brain server via TCP
#   6. Sensor packets flow kernel→brain, actuator commands flow brain→kernel
#
# Network architecture (QEMU user-mode NAT):
#   Guest (kernel):  10.0.2.15 → connects to → 10.0.2.2:9000 (host)
#   Host (macOS):    brain server listens on 0.0.0.0:9000

set -e

OS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BRAIN_DIR="$(cd "$OS_DIR/../AzOSRobotBrain" && pwd)"

echo "=== AzOS Robot Brain End-to-End Test ==="
echo "  OS dir:    $OS_DIR"
echo "  Brain dir: $BRAIN_DIR"
echo ""

# 1. Build kernel
echo "[1/4] Building kernel..."
cd "$OS_DIR"
cargo build --release

# 2. Create disk image with CONFIG.INI
echo "[2/4] Creating disk image with CONFIG.INI..."
mkdir -p build

# Create a 4MB FAT12 disk image
dd if=/dev/zero of=build/disk.img bs=1M count=4 2>/dev/null
# macOS uses newfs_msdos; Linux uses mkfs.vfat
if command -v newfs_msdos &>/dev/null; then
    newfs_msdos -F 12 build/disk.img 2>/dev/null
elif command -v mkfs.vfat &>/dev/null; then
    mkfs.vfat -F 12 build/disk.img 2>/dev/null
else
    echo "ERROR: No FAT formatter found (need newfs_msdos or mkfs.vfat)"
    exit 1
fi

# Mount and write CONFIG.INI
MOUNT_DIR=$(mktemp -d)
if [[ "$(uname)" == "Darwin" ]]; then
    hdiutil attach -mountpoint "$MOUNT_DIR" build/disk.img -nobrowse 2>/dev/null
else
    sudo mount -o loop build/disk.img "$MOUNT_DIR"
fi

cat > "$MOUNT_DIR/CONFIG.INI" << 'CONFIGEOF'
net_ip=10.0.2.15
net_gateway=10.0.2.2
net_mask=255.255.255.0
behavior_server_ip=10.0.2.2
behavior_server_port=9000
behavior_l1_enabled=1
behavior_l2_enabled=1
behavior_l3_enabled=1
ml_enabled=1
CONFIGEOF

if [[ "$(uname)" == "Darwin" ]]; then
    hdiutil detach "$MOUNT_DIR" 2>/dev/null
else
    sudo umount "$MOUNT_DIR"
fi
rmdir "$MOUNT_DIR"

echo "  CONFIG.INI written (server=10.0.2.2:9000)"

# 3. Start brain server in background
echo "[3/4] Starting brain server on port 9000..."
cd "$BRAIN_DIR"
python3 server.py &
BRAIN_PID=$!
sleep 2

# Check if brain started
if ! kill -0 $BRAIN_PID 2>/dev/null; then
    echo "ERROR: Brain server failed to start"
    exit 1
fi
echo "  Brain server PID: $BRAIN_PID"

# 4. Launch QEMU
echo "[4/4] Launching QEMU (Ctrl-A X to exit)..."
echo ""
echo "  Watch for: [BEHAVIOR] connecting to 10.0.2.2:9000"
echo "  Watch for: [BRAIN] Robot connected"
echo ""

cd "$OS_DIR"
KERNEL_ELF="target/riscv64imac-unknown-none-elf/release/azos_kernel"

# Cleanup on exit
cleanup() {
    echo ""
    echo "[TEST] Shutting down..."
    kill $BRAIN_PID 2>/dev/null || true
    wait $BRAIN_PID 2>/dev/null || true
    echo "[TEST] Done."
}
trap cleanup EXIT

qemu-system-riscv64 \
    -machine virt -nographic -bios default \
    -kernel "$KERNEL_ELF" \
    -smp 4 \
    -m 128M \
    -drive file=build/disk.img,if=none,format=raw,id=hd0 \
    -device virtio-blk-device,drive=hd0 \
    -netdev user,id=net0 \
    -device virtio-net-device,netdev=net0
