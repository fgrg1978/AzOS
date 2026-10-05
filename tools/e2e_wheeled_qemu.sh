#!/bin/zsh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Phase 1 minimum-path E2E: real kernel in QEMU + headless stub brain.
#
# Flow:
#   1. Build kernel + userspace if needed.
#   2. Launch tools/stub_brain.py on the host, listening on :9000
#      (matches `build/CONFIG.INI`'s `behavior_server_port`).
#   3. Launch `make qemu-full-smp` in the background.
#   4. The kernel boots, reads CONFIG.INI, dials 10.0.2.2:9000 (QEMU
#      user-net's alias for the host).
#   5. Stub brain receives SENSOR packets, replies with an
#      ActuatorCmd. After DURATION_S it self-terminates with exit 0
#      iff at least one sensor packet was received AND at least one
#      actuator command was sent. We then tear QEMU down.
#
# Exit code:
#   0  full loop closed (rx ≥ 1, tx ≥ 1)
#   1  loop incomplete (no packets, or only one direction)
#   2  no robot ever connected (kernel didn't dial us — boot failed,
#      bad CONFIG.INI, etc.)
#   anything else: setup error
#
# Usage:
#   tools/e2e_wheeled_qemu.sh                  # default 30s run
#   DURATION_S=15 tools/e2e_wheeled_qemu.sh    # shorter run

set -u
set -o pipefail

# The shell this script runs under (e.g. the harness) may not have
# /bin or /usr/bin in PATH — make + mkdir + tail need it explicitly.
# /opt/homebrew/bin is for qemu-system-* on Apple Silicon.
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"

REPO_KERNEL="/Users/azor/Library/Mobile Documents/com~apple~CloudDocs/Development/ia/azos"
REPO_BRAIN="/Users/azor/Library/Mobile Documents/com~apple~CloudDocs/Development/ia/AzOSRobotBrain"
DURATION_S="${DURATION_S:-30}"
ACCEPT_GRACE_S="${ACCEPT_GRACE_S:-10}"
STUB_PORT="${STUB_PORT:-9000}"

LOG_DIR="${REPO_KERNEL}/build/e2e_logs"
mkdir -p "$LOG_DIR"
STUB_LOG="${LOG_DIR}/stub_brain.log"
QEMU_LOG="${LOG_DIR}/qemu.log"

cleanup() {
    # Kill the QEMU group first so it doesn't keep the TCP port live.
    if [[ -n "${QEMU_PID:-}" ]]; then
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    if [[ -n "${STUB_PID:-}" ]]; then
        kill -TERM "$STUB_PID" 2>/dev/null || true
        wait "$STUB_PID" 2>/dev/null || true
    fi
}
trap cleanup INT TERM EXIT

cd "$REPO_KERNEL"

echo "[E2E] building kernel + userspace (this can take a minute)..."
/usr/bin/make build userspace build/disk.img >/dev/null 2>&1 || {
    echo "[E2E] build failed; see make output by running it manually"
    exit 10
}

echo "[E2E] launching stub_brain on :${STUB_PORT}"
/usr/bin/python3 "${REPO_BRAIN}/tools/stub_brain.py" \
    --port "$STUB_PORT" \
    --duration-s "$DURATION_S" \
    --accept-grace-s "$ACCEPT_GRACE_S" \
    --accept-tcp-only \
    >"$STUB_LOG" 2>&1 &
STUB_PID=$!

# Give the stub a moment to bind before QEMU boots.
sleep 1

if ! kill -0 "$STUB_PID" 2>/dev/null; then
    echo "[E2E] stub_brain failed to start; log follows:"
    cat "$STUB_LOG"
    exit 11
fi

echo "[E2E] launching QEMU (qemu-full-smp), log → ${QEMU_LOG}"
/usr/bin/make qemu-full-smp >"$QEMU_LOG" 2>&1 &
QEMU_PID=$!

# Wait for stub_brain to self-terminate (it has its own duration
# timer + accept grace). If it exits, the loop ran (or timed out).
wait "$STUB_PID"
STUB_RC=$?

echo "[E2E] stub_brain exited rc=${STUB_RC}"
echo "[E2E] tail of stub log:"
/usr/bin/tail -20 "$STUB_LOG" | sed 's/^/[STUB] /'

exit "$STUB_RC"
