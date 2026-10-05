#!/bin/zsh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# OT01.E2E — automated OTA flow test (brain → kernel) in QEMU.
#
# Exercises the full path:
#   - kernel boots in QEMU (no brain server needed)
#   - CONFIG.INI sets ota_auto_recv_port=8080 → kernel spawns listener at boot
#   - host runs tools/ota_send.py to deliver a firmware image over TCP
#   - kernel validates header + CRC, writes KERN_B.TMP, promotes to KERN_B.BIN,
#     updates BOOTMETA.A with the new slot info (OT02.B dual-record format)
#
# Asserts on the kernel log:
#   ✓ "[OTA] Listening on port 8080"
#   ✓ "[OTA] Header OK — fw=2 …"
#   ✓ "[OTA] CRC OK"
#   ✓ "[OTA] Active slot → B"
#   ✓ NO "[OTA] CRC MISMATCH"
#
# Negative path (--negative flag): sends an oversized image and asserts
# that the kernel rejects it with "Header validation failed".
set -e

# ── Constants ──────────────────────────────────────────────────────────────
TIMEOUT_S=180
QEMU_HOST_PORT=18080         # macOS host port we forward to guest 8080
QEMU_GUEST_PORT=8080
OS_DIR="/Users/azor/Library/Mobile Documents/com~apple~CloudDocs/Development/ia/azos"
QEMU="/opt/homebrew/bin/qemu-system-riscv64"
PYTHON="/opt/homebrew/bin/python3.12"
CARGO="$HOME/.cargo/bin/cargo"
OBJCOPY="/opt/homebrew/opt/llvm/bin/llvm-objcopy"
MKFS_FAT="/opt/homebrew/opt/dosfstools/sbin/mkfs.fat"
MCOPY="/opt/homebrew/bin/mcopy"
DD="/bin/dd"

# crates/core/ota/build.rs needs cc + SDKROOT to compile its host script.
export PATH="/Library/Developer/CommandLineTools/usr/bin:/opt/homebrew/bin:$PATH"
export SDKROOT="/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"

LOG_DIR="$OS_DIR/build/e2e_ota_log"
/bin/mkdir -p "$LOG_DIR"
KERNEL_LOG="$LOG_DIR/kernel.log"
SEND_LOG="$LOG_DIR/ota_send.log"

NEGATIVE=0
if [[ "${1:-}" == "--negative" ]]; then
    NEGATIVE=1
fi

# U12-4: the oversized payload below must exceed the receiver's ACTUAL
# ceiling, `azos_limits::OTA_MAX_IMAGE_SIZE_BYTES` (Kconfig
# `OTA_MAX_IMAGE_SIZE_MB`), not a number that used to live next to it. This
# used to hardcode a 3 MB payload against a comment claiming the ceiling was
# 2 MB; Kconfig's own default was already 8 MB, so the negative case never
# exercised the reject path it claimed to. Read from the same `.config`
# `crates/core/limits/build.rs` reads (`$KCONFIG_CONFIG`, else the workspace
# `.config`), falling back to the Kconfig default (8) only if neither exists.
OTA_MAX_IMAGE_SIZE_MB="$(/usr/bin/sed -n 's/^CONFIG_OTA_MAX_IMAGE_SIZE_MB=//p' \
    "${KCONFIG_CONFIG:-$OS_DIR/.config}" 2>/dev/null | /usr/bin/sed -n 1p)"
OTA_MAX_IMAGE_SIZE_MB="${OTA_MAX_IMAGE_SIZE_MB:-8}"
OTA_OVERSIZE_MB=$((OTA_MAX_IMAGE_SIZE_MB + 1))

# ── Cleanup hook ───────────────────────────────────────────────────────────
cleanup() {
    /bin/kill "$QEMU_PID" 2>/dev/null || true
    /bin/wait "$QEMU_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── 1. Build kernel + extract flat binary for OTA payload ──────────────────
echo "[1/6] Building kernel (QEMU target)..."
cd "$OS_DIR"
# --features qemu relaxes WCET bounds for emulated environment (timer ISR ~100x slower).
"$CARGO" build --release --features qemu 2>&1 | /usr/bin/tail -3

KERNEL_ELF="$OS_DIR/target/riscv64imac-unknown-none-elf/release/kernel"
if [[ ! -f "$KERNEL_ELF" ]]; then
    echo "ERROR: kernel ELF missing: $KERNEL_ELF"
    exit 1
fi

OTA_PAYLOAD="$LOG_DIR/ota_payload.bin"
"$OBJCOPY" -O binary "$KERNEL_ELF" "$OTA_PAYLOAD"
PAYLOAD_SIZE=$(/usr/bin/stat -f%z "$OTA_PAYLOAD")
echo "  payload: $OTA_PAYLOAD ($PAYLOAD_SIZE bytes)"

# ── 2. Create FAT32 disk with CONFIG.INI ───────────────────────────────────
echo "[2/6] Creating disk image..."
DISK="$LOG_DIR/disk.img"
"$DD" if=/dev/zero of="$DISK" bs=1m count=64 2>/dev/null
"$MKFS_FAT" -F 32 -n ROBOT "$DISK" >/dev/null 2>&1

# CONFIG.INI — disable behavior server; enable OTA auto-recv at boot.
# ota_auto_recv_port causes the kernel to spawn an OTA listener task
# immediately after boot without needing a shell command.
CONFIG_TMP="$LOG_DIR/CONFIG.INI"
/bin/cat > "$CONFIG_TMP" << EOF
net_ip=10.0.2.15
net_gateway=10.0.2.2
net_mask=255.255.255.0
behavior_server_ip=10.0.2.2
behavior_server_port=9000
behavior_l1_enabled=0
behavior_l2_enabled=0
behavior_l3_enabled=0
ml_enabled=0
ota_auto_recv_port=${QEMU_GUEST_PORT}
EOF
"$MCOPY" -o -i "$DISK" "$CONFIG_TMP" ::CONFIG.INI

# ── 3. Spin up QEMU (stdin from /dev/null — no FIFO needed) ───────────────
echo "[3/6] Launching QEMU with hostfwd $QEMU_HOST_PORT→$QEMU_GUEST_PORT..."
/bin/rm -f "$KERNEL_LOG"

"$QEMU" \
    -machine virt -display none -serial stdio \
    -bios default \
    -kernel "$KERNEL_ELF" \
    -smp 4 \
    -m 128M \
    -drive file="$DISK",if=none,format=raw,id=hd0 \
    -device virtio-blk-device,drive=hd0 \
    -netdev user,id=net0,hostfwd=tcp::"$QEMU_HOST_PORT"-:"$QEMU_GUEST_PORT" \
    -device virtio-net-device,netdev=net0 \
    < /dev/null \
    > "$KERNEL_LOG" 2>&1 &
QEMU_PID=$!
echo "  QEMU PID=$QEMU_PID"

# ── 4. Wait for OTA listener ────────────────────────────────────────��───────
# Wait for "[OTA] Listening on port" in the log. If the message is garbled by
# concurrent SMP harts, the retry loop in cmd_ota_recv (which loops back to
# accept() after early disconnects) means we can still probe safely.
echo "[4/6] Waiting for OTA listener (boot + task schedule)..."

# First anchor: "[CFG] Loaded" appears single-threaded before SMP starts.
WAIT=0
while [[ $WAIT -lt $TIMEOUT_S ]]; do
    /bin/sleep 1 2>/dev/null || /opt/homebrew/bin/sleep 1
    WAIT=$((WAIT+1))
    if /usr/bin/grep -qF "[CFG] Loaded" "$KERNEL_LOG" 2>/dev/null; then break; fi
    if ! /bin/kill -0 $QEMU_PID 2>/dev/null; then
        echo "ERROR: QEMU exited early before config load"
        /usr/bin/tail -30 "$KERNEL_LOG"
        exit 1
    fi
done
if ! /usr/bin/grep -qF "[CFG] Loaded" "$KERNEL_LOG" 2>/dev/null; then
    echo "ERROR: kernel never loaded config. Last 30 lines:"
    /usr/bin/tail -30 "$KERNEL_LOG"
    exit 1
fi
echo "  ✓ config loaded (${WAIT}s)"

# Second anchor: "[OTA] Listening" — wait the remainder of the timeout.
while [[ $WAIT -lt $TIMEOUT_S ]]; do
    /bin/sleep 1 2>/dev/null || /opt/homebrew/bin/sleep 1
    WAIT=$((WAIT+1))
    if /usr/bin/grep -qE "\\[OTA\\] Listening on port" "$KERNEL_LOG" 2>/dev/null; then
        echo "  ✓ kernel listener up (${WAIT}s)"
        break
    fi
    if ! /bin/kill -0 $QEMU_PID 2>/dev/null; then
        echo "ERROR: QEMU exited early"
        /usr/bin/tail -30 "$KERNEL_LOG"
        exit 1
    fi
done
if ! /usr/bin/grep -qE "\\[OTA\\] Listening on port" "$KERNEL_LOG" 2>/dev/null; then
    echo "ERROR: OTA listener never started in ${TIMEOUT_S}s. Last 30 lines:"
    /usr/bin/tail -30 "$KERNEL_LOG"
    exit 1
fi

# ── 5. Send the OTA payload from the host ──────────────────────────────────
echo "[5/6] Sending OTA payload via tools/ota_send.py..."

if [[ "$NEGATIVE" -eq 1 ]]; then
    # Junk payload one MiB above the receiver's actual ceiling → header reject.
    NEG_PAYLOAD="$LOG_DIR/ota_payload_oversized.bin"
    "$DD" if=/dev/zero of="$NEG_PAYLOAD" bs=1m count="$OTA_OVERSIZE_MB" 2>/dev/null
    if "$PYTHON" "$OS_DIR/tools/ota_send.py" "$NEG_PAYLOAD" 127.0.0.1 \
            --port "$QEMU_HOST_PORT" --platform qemu --version 2 \
            > "$SEND_LOG" 2>&1; then
        # Sender does NOT validate locally; expects connection to succeed
        # and kernel to reject. It still exits 0 on send completion.
        :
    else
        echo "  (ota_send.py exited non-zero — that's OK for negative test)"
    fi
else
    "$PYTHON" "$OS_DIR/tools/ota_send.py" "$OTA_PAYLOAD" 127.0.0.1 \
        --port "$QEMU_HOST_PORT" --platform qemu --version 2 \
        > "$SEND_LOG" 2>&1
fi
/usr/bin/tail -5 "$SEND_LOG" | /usr/bin/sed 's/^/  /'

# ── 6. Wait for OTA completion in kernel log ───────────────────────────────
# Poll the kernel log until we see "CRC OK" (OTA done) or the full timeout
# expires.  Each poll waits 1s and then re-checks; gives the emulated kernel
# plenty of time to write 864 KB to virtual FAT32 and update BOOTMETA.
echo "[5b/6] Waiting for kernel to complete OTA write (up to ${TIMEOUT_S}s)..."
# Negative path completes quickly (header rejected); positive path needs to
# wait for the full FAT32 write.
if [[ "$NEGATIVE" -eq 1 ]]; then
    DONE_PATTERN="Header validation failed"
else
    DONE_PATTERN="\\[OTA\\] CRC OK"
fi
TIMEOUT_REMAINING=$TIMEOUT_S
while [[ $TIMEOUT_REMAINING -gt 0 ]]; do
    /bin/sleep 1 2>/dev/null || /opt/homebrew/bin/sleep 1
    TIMEOUT_REMAINING=$((TIMEOUT_REMAINING - 1))
    if ! /bin/kill -0 $QEMU_PID 2>/dev/null; then
        echo "  QEMU exited unexpectedly — asserting on partial log"
        break
    fi
    if /usr/bin/grep -qE "$DONE_PATTERN" "$KERNEL_LOG" 2>/dev/null; then
        echo "  ✓ OTA complete ($(( TIMEOUT_S - TIMEOUT_REMAINING ))s)"
        # Give kernel 3 more seconds to update BOOTMETA after CRC OK
        /bin/sleep 3 2>/dev/null || /opt/homebrew/bin/sleep 3
        break
    fi
done
if [[ $TIMEOUT_REMAINING -le 0 ]]; then
    echo "  ✗ OTA did not complete within ${TIMEOUT_S}s"
fi

# ── 7. Tear down + assert ──────────────────────────────────────────────────
echo "[6/6] Asserting on kernel log..."
/bin/kill $QEMU_PID 2>/dev/null || true
/bin/wait $QEMU_PID 2>/dev/null || true

PASS=0
FAIL=0

assert_log() {
    local label="$1"; local pattern="$2"
    if /usr/bin/grep -qE "$pattern" "$KERNEL_LOG"; then
        echo "  ✓ $label"
        PASS=$((PASS+1))
    else
        echo "  ✗ $label  (missing: $pattern)"
        FAIL=$((FAIL+1))
    fi
}

assert_no_log() {
    local label="$1"; local pattern="$2"
    if /usr/bin/grep -qE "$pattern" "$KERNEL_LOG"; then
        echo "  ✗ $label  (unexpected match: $pattern)"
        FAIL=$((FAIL+1))
    else
        echo "  ✓ $label"
        PASS=$((PASS+1))
    fi
}

if [[ "$NEGATIVE" -eq 1 ]]; then
    # Negative path: kernel must reject the oversized payload and not
    # commit anything to BOOTMETA.
    assert_log    "kernel listener up"          "\\[OTA\\] Listening on port"
    assert_log    "header rejected (oversize)"  "Header validation failed"
    assert_no_log "no spurious CRC OK"          "\\[OTA\\] CRC OK"
    assert_no_log "no slot switch"              "Active slot \\u2192 B"
else
    # Happy path
    assert_log    "kernel listener up"     "\\[OTA\\] Listening on port"
    assert_log    "header parsed"          "\\[OTA\\] Header OK"
    assert_log    "payload streamed"       "\\[OTA\\] Receiving"
    assert_log    "CRC matched"            "\\[OTA\\] CRC OK"
    assert_log    "slot switched to B"     "Active slot.*B"
    assert_no_log "no CRC mismatch"        "\\[OTA\\] CRC MISMATCH"
    assert_no_log "no incomplete xfer"     "\\[OTA\\] INCOMPLETE"
    assert_no_log "no header reject"       "Header validation failed"
fi

echo ""
echo "Logs: $KERNEL_LOG | $SEND_LOG"
if [[ $FAIL -eq 0 ]]; then
    echo "=== OTA E2E PASS ($PASS checks) ==="
    exit 0
else
    echo "=== OTA E2E FAIL: $PASS passed, $FAIL failed ==="
    echo ""
    echo "Last 40 kernel log lines:"
    /usr/bin/tail -40 "$KERNEL_LOG"
    exit 1
fi
