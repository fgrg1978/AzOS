#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# bench_e2e.sh — End-to-end benchmark harness for the AZOS kernel.
#
# Boots the kernel in QEMU (SMP-4) and runs three measurement scenarios
# across N_RUNS iterations.  Median values across runs are written to a
# structured JSON file in bench/results/<sha>.json (in the brain repo).
#
# ── Reproducibility note ──────────────────────────────────────────────────────
# QEMU TCG SMP runs all four virtual harts on a single host thread, so
# `rdcycle` latency under SMP is inflated by other-hart scheduling time
# AND by host-side scheduling jitter.  Two knobs dampen this:
#
#   1. Median of N_RUNS=3 boots per scenario (single-run flakiness).
#   2. `QEMU_ICOUNT_SHIFT` env (default empty = off): when set (e.g. "5"),
#      QEMU advances virtual time per executed instruction instead of host
#      wall-clock, making `rdcycle` deterministic across runs at the cost
#      of slower execution.  Use for CI gating; leave off for fast local
#      iteration.  Recorded into the JSON output so each result is tagged
#      with the mode that produced it.
#
# The RTC is always pinned to a fixed base via `-rtc base=${QEMU_RTC_BASE}`
# so wall-clock timestamps inside the kernel don't drift run-to-run.
#
# The goal is to detect >= 5% regressions reliably (icount mode) or
# >= 10% regressions (default mode), NOT sub-percent precision.
#
# ── Scenarios ─────────────────────────────────────────────────────────────────
# 1. steady   — kernel connects, exchanges sensor↔actuator at 10 Hz.
#               Measures RTT distribution and steady msg/s.  RTT is likely
#               null under QEMU TCG (sensor pump issue #39).
# 2. burst    — brain sends 100 actuator commands as fast as possible.
#               Records sustained pkt/s + burst peak.
# 3. boot     — measures time from QEMU launch to first [NET] Stack ready
#               log line (with first inbound TCP packet as fallback).
#
# All three scenarios run during each QEMU boot, sequentially, using the
# stub_brain listening on port STUB_PORT.  WCET + jitter data is collected
# by injecting "wcet" and "wcet jitter" into the kernel shell via stdin.
#
# ── Output ────────────────────────────────────────────────────────────────────
# bench/results/<sha>.json    (in REPO_BRAIN)
#
# ── Usage ─────────────────────────────────────────────────────────────────────
# From anywhere:
#   tools/bench_e2e.sh                       # default 3 runs × 30s each
#   N_RUNS=1 SCENARIO_DURATION_S=15 tools/bench_e2e.sh
#   SKIP_BUILD=1 tools/bench_e2e.sh          # skip rebuild (faster iteration)
#   QEMU_ICOUNT_SHIFT=5 tools/bench_e2e.sh   # deterministic timing (CI mode)
#   QEMU_RTC_BASE=2025-01-01 tools/bench_e2e.sh  # override pinned VM clock base
#
# ── Exit codes ────────────────────────────────────────────────────────────────
#   0   success — JSON written, summary printed
#   1   QEMU crashed or stub never connected (all runs failed)
#   2   build failed
#  10+  internal error

set -uo pipefail

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"

# ── Repo paths ────────────────────────────────────────────────────────────────
REPO_KERNEL="${REPO_KERNEL:-/Users/azor/Library/Mobile Documents/com~apple~CloudDocs/Development/ia/azos}"
REPO_BRAIN="${REPO_BRAIN:-/Users/azor/Library/Mobile Documents/com~apple~CloudDocs/Development/ia/AzOSRobotBrain}"

# ── Tunable parameters ────────────────────────────────────────────────────────
N_RUNS="${N_RUNS:-3}"                    # number of QEMU boots (median taken)
SCENARIO_DURATION_S="${SCENARIO_DURATION_S:-40}"
ACCEPT_GRACE_S="${ACCEPT_GRACE_S:-30}"  # extra seconds to wait for kernel dial-in
                                         # (30s handles cold-JIT boot on first run;
                                         # total window = SCENARIO + GRACE ≥ 70s)
STUB_PORT="${STUB_PORT:-9000}"
# Python interpreter for the stub + collector. Defaults to the system one
# (unchanged behaviour); override (e.g. PYTHON=$(which python3)) when the stub
# needs packages the system Python lacks — RFC-0019 encryption needs the
# `cryptography` module on the stub side.
PYTHON="${PYTHON:-/usr/bin/python3}"
QEMU_SMP="${QEMU_SMP:-4}"              # pin to 4 so SMP path is always measured
QEMU_ICOUNT_SHIFT="${QEMU_ICOUNT_SHIFT:-}"  # empty = off; e.g. "5" enables -icount shift=5 (deterministic timing)
QEMU_RTC_BASE="${QEMU_RTC_BASE:-2020-01-01}"  # pinned VM clock base for run-to-run determinism
SKIP_BUILD="${SKIP_BUILD:-0}"
# bench_boot capture mode: skip the stub + scenarios; provision `bench_boot=1`
# into CONFIG.INI and capture the early-boot synthetic bench (task #73) — the
# cleanest `bench_synth` baseline under TCG (quiescent single-hart, timer off).
BENCH_BOOT="${BENCH_BOOT:-0}"
BENCH_BOOT_TIMEOUT_S="${BENCH_BOOT_TIMEOUT_S:-60}"

# ── Derived paths ─────────────────────────────────────────────────────────────
KERNEL_TARGET="riscv64imac-unknown-none-elf"
KERNEL_ELF="${REPO_KERNEL}/target/${KERNEL_TARGET}/release/kernel"
DISK_IMG="${REPO_KERNEL}/build/disk.img"
BENCH_LOG_ROOT="${REPO_KERNEL}/build/bench_logs"
BENCH_RESULTS="${REPO_BRAIN}/bench/results"
COLLECT_PY="${REPO_BRAIN}/tools/bench_e2e_collect.py"
BENCH_STUB_PY="${REPO_BRAIN}/tools/bench_stub.py"

# ── Git SHA ───────────────────────────────────────────────────────────────────
GIT_SHA=$(git -C "${REPO_KERNEL}" rev-parse HEAD 2>/dev/null | tr -d '[:space:]' || true)
GIT_SHA_SHORT="${GIT_SHA:0:12}"
if [[ -z "${GIT_SHA_SHORT}" ]]; then
    GIT_SHA_SHORT="unknown"
fi

# ── QEMU version ──────────────────────────────────────────────────────────────
QEMU_BIN="qemu-system-riscv64"
QEMU_VERSION=$(${QEMU_BIN} --version 2>/dev/null | grep "^QEMU" | tr -d '\n' || echo "unknown")

# ── Helpers ───────────────────────────────────────────────────────────────────

die() {
    echo "[BENCH] ERROR: $*" >&2
    exit 10
}

QEMU_PID=""
STUB_PID=""
FIFO_PATH=""
INJECT_PID=""

cleanup_run() {
    if [[ -n "${INJECT_PID:-}" ]]; then
        kill "${INJECT_PID}" 2>/dev/null || true
        wait "${INJECT_PID}" 2>/dev/null || true
        INJECT_PID=""
    fi
    if [[ -n "${QEMU_PID:-}" ]] && kill -0 "${QEMU_PID}" 2>/dev/null; then
        kill -TERM "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
        QEMU_PID=""
    fi
    if [[ -n "${STUB_PID:-}" ]] && kill -0 "${STUB_PID}" 2>/dev/null; then
        kill -TERM "${STUB_PID}" 2>/dev/null || true
        wait "${STUB_PID}" 2>/dev/null || true
        STUB_PID=""
    fi
    if [[ -n "${FIFO_PATH:-}" ]] && [[ -p "${FIFO_PATH}" ]]; then
        rm -f "${FIFO_PATH}"
        FIFO_PATH=""
    fi
}

cleanup_all() {
    cleanup_run
}
trap cleanup_all INT TERM EXIT

# qemu_launch <stdin_path> <stdout_path>
# Launches QEMU with -nographic, SMP-4, VirtIO net+disk, kernel ELF.
# stdin is read from stdin_path (use /dev/null or a named pipe).
# stdout+stderr appended to stdout_path.
# Sets global QEMU_PID.
qemu_launch() {
    local stdin_path="$1"
    local stdout_path="$2"
    # Build optional `-icount` args.  Empty QEMU_ICOUNT_SHIFT → no icount.
    # When set, align=off + sleep=off keep virtual time decoupled from
    # wall-clock so rdcycle is reproducible across runs.
    local icount_args=()
    if [[ -n "${QEMU_ICOUNT_SHIFT}" ]]; then
        icount_args=(-icount "shift=${QEMU_ICOUNT_SHIFT},align=off,sleep=off")
    fi
    # Invoke QEMU with all args quoted individually to survive spaces in paths.
    "${QEMU_BIN}" \
        -machine virt \
        -nographic \
        -bios default \
        -smp "${QEMU_SMP}" \
        -rtc "base=${QEMU_RTC_BASE},clock=vm" \
        ${icount_args[@]+"${icount_args[@]}"} \
        -global virtio-mmio.force-legacy=false \
        -drive "file=${DISK_IMG},if=none,format=raw,id=hd0" \
        -device virtio-blk-device,drive=hd0 \
        -netdev "user,id=net0,hostfwd=udp::5555-:5555,hostfwd=tcp::8080-:8080" \
        -device virtio-net-device,netdev=net0 \
        -kernel "${KERNEL_ELF}" \
        <"${stdin_path}" >>"${stdout_path}" 2>&1 &
    QEMU_PID=$!
}

# ── Step 1: Build ─────────────────────────────────────────────────────────────
if [[ "${SKIP_BUILD}" == "0" ]]; then
    echo "[BENCH] building kernel + userspace + disk.img..."
    make -C "${REPO_KERNEL}" build userspace build/disk.img >/dev/null 2>&1 || {
        echo "[BENCH] build failed; re-run manually: make -C '${REPO_KERNEL}' build userspace build/disk.img"
        exit 2
    }
    echo "[BENCH] build OK"
else
    echo "[BENCH] SKIP_BUILD=1: using existing kernel ELF"
fi

[[ -f "${KERNEL_ELF}" ]] || die "kernel ELF not found: ${KERNEL_ELF}"
[[ -f "${DISK_IMG}" ]]   || die "disk.img not found: ${DISK_IMG}"

# ── Step 1b: bench_boot capture mode (early-boot synthetic bench, no stub) ─────
# CFG_BENCH_BOOT runs `run_all_quiescent` in early boot — quiescent single-hart,
# timer-ISR off — the cleanest rdcycle measurement available under QEMU TCG
# (task #73; ~8% cross-run vs ~40% for the live behavior-task path). This mode
# provisions `bench_boot=1` into CONFIG.INI, boots ONCE (no stub, no scenarios),
# captures the [BENCH-RES] lines, and collects straight to the result JSON.
# The kernel `wfi`-halts right after emitting, so we stop QEMU on the marker.
if [[ "${BENCH_BOOT}" == "1" ]]; then
    echo "[BENCH] bench_boot capture mode (no stub; early-boot synthetic bench)"
    # mkfs.fat / mtools live under /opt/homebrew/sbin on this host.
    export PATH="/opt/homebrew/sbin:${PATH}"
    BB_CFG="$(mktemp)"
    mtype -i "${DISK_IMG}" ::CONFIG.INI > "${BB_CFG}" 2>/dev/null || true
    grep -q "bench_boot=1" "${BB_CFG}" || printf 'bench_boot=1\n' >> "${BB_CFG}"
    mcopy -o -i "${DISK_IMG}" "${BB_CFG}" ::CONFIG.INI \
        || die "mcopy CONFIG.INI failed (mtools on PATH?)"
    rm -f "${BB_CFG}"

    RUN_DIR="${BENCH_LOG_ROOT}/bench_boot"
    mkdir -p "${RUN_DIR}"
    QEMU_LOG="${RUN_DIR}/qemu.log"
    : > "${QEMU_LOG}"
    : > "${RUN_DIR}/stub.log"   # collector expects a stub.log per run dir
    qemu_launch /dev/null "${QEMU_LOG}"    # backgrounds QEMU, sets QEMU_PID
    for _ in $(seq 1 "${BENCH_BOOT_TIMEOUT_S}"); do
        grep -q "boot-bench complete" "${QEMU_LOG}" 2>/dev/null && break
        kill -0 "${QEMU_PID}" 2>/dev/null || break
        sleep 1
    done
    cleanup_run    # stop QEMU (kernel is in its wfi halt loop)
    BB_N=$(grep -c "\[BENCH-RES\]" "${QEMU_LOG}" 2>/dev/null || true)
    echo "[BENCH] bench_boot: ${BB_N} [BENCH-RES] lines captured"
    [[ "${BB_N}" -gt 0 ]] || die "no [BENCH-RES] captured (bench_boot=1 in CONFIG.INI? built --features qemu?)"

    mkdir -p "${BENCH_RESULTS}"
    OUT_JSON="${BENCH_RESULTS}/${GIT_SHA_SHORT}.json"
    "${PYTHON}" "${COLLECT_PY}" \
        --run-dirs "${RUN_DIR}" \
        --kernel-elf "${KERNEL_ELF}" \
        --sha "${GIT_SHA_SHORT}" \
        --out "${OUT_JSON}" \
        --qemu-version "${QEMU_VERSION}" \
        --qemu-smp "${QEMU_SMP}" \
        --qemu-icount-shift "${QEMU_ICOUNT_SHIFT}" \
        --qemu-rtc-base "${QEMU_RTC_BASE}" \
        --host "darwin-arm64" || die "collector failed"
    "${PYTHON}" -c "import json; json.load(open('${OUT_JSON}'))" || die "output JSON malformed"
    echo "[BENCH] bench_boot JSON written: ${OUT_JSON}"
    exit 0
fi

# ── Step 2: Announce run ──────────────────────────────────────────────────────
echo "[BENCH] SHA=${GIT_SHA_SHORT}  runs=${N_RUNS}  duration=${SCENARIO_DURATION_S}s each"
echo "[BENCH] ${QEMU_VERSION}"

# ── Step 3: Run N_RUNS steady-state iterations ────────────────────────────────
RUN_DIRS=()
FAILED_RUNS=0

for run_idx in $(seq 1 "${N_RUNS}"); do
    RUN_DIR="${BENCH_LOG_ROOT}/run${run_idx}"
    mkdir -p "${RUN_DIR}"
    QEMU_LOG="${RUN_DIR}/qemu.log"
    STUB_LOG="${RUN_DIR}/stub.log"
    FIFO_PATH="${BENCH_LOG_ROOT}/run${run_idx}_stdin.fifo"
    rm -f "${FIFO_PATH}"

    echo "[BENCH] ── run ${run_idx}/${N_RUNS} ────────────────────────────────────────────"

    # ── Launch stub brain ─────────────────────────────────────────────────────
    "${PYTHON}" "${BENCH_STUB_PY}" \
        --port           "${STUB_PORT}" \
        --scenario       steady \
        --duration-s     "${SCENARIO_DURATION_S}" \
        --accept-grace-s "${ACCEPT_GRACE_S}" \
        >"${STUB_LOG}" 2>&1 &
    STUB_PID=$!
    sleep 1

    if ! kill -0 "${STUB_PID}" 2>/dev/null; then
        echo "[BENCH] stub brain failed to start for run ${run_idx}; skipping"
        FAILED_RUNS=$((FAILED_RUNS + 1))
        STUB_PID=""
        rm -f "${FIFO_PATH}"
        FIFO_PATH=""
        continue
    fi

    # ── Create FIFO for kernel shell command injection ────────────────────────
    mkfifo "${FIFO_PATH}"

    # ── Write qemu.log header with launch timestamp ───────────────────────────
    LAUNCH_TS=$("${PYTHON}" -c "import time; print(f'{time.time():.6f}')")
    {
        printf '[BENCH-LAUNCH] %s\n' "${LAUNCH_TS}"
        printf '[BENCH] sha=%s run=%s/%s\n' "${GIT_SHA_SHORT}" "${run_idx}" "${N_RUNS}"
    } >"${QEMU_LOG}"

    # ── Start QEMU ────────────────────────────────────────────────────────────
    qemu_launch "${FIFO_PATH}" "${QEMU_LOG}"

    # ── Inject shell commands after kernel boots ──────────────────────────────
    # This subshell opens the FIFO write-end (unblocking QEMU's stdin read-open),
    # waits for the shell banner, then injects wcet commands.
    (
        SHELL_WAIT_MAX=25
        SHELL_FOUND=0
        for _i in $(seq 1 "${SHELL_WAIT_MAX}"); do
            sleep 1
            if grep -q "AzOS shell" "${QEMU_LOG}" 2>/dev/null; then
                SHELL_FOUND=1
                break
            fi
        done

        # Record [BENCH-NETREADY] timestamp when we see [NET] Stack ready.
        if grep -q "\[NET\] Stack ready" "${QEMU_LOG}" 2>/dev/null; then
            NET_TS=$("${PYTHON}" -c "import time; print(f'{time.time():.6f}')")
            printf '[BENCH-NETREADY] %s\n' "${NET_TS}" >> "${QEMU_LOG}"
        fi

        # Inject wcet + bench commands (2 extra seconds for shell to settle).
        # `bench all 1000` runs every enabled subsystem microbench, emitting
        # one [BENCH-RES] line per measurement.  Lower iters than the default
        # (1000) would speed up under TCG but ~1000 keeps signal/noise good
        # while still finishing in a couple of seconds.
        if [[ "${SHELL_FOUND}" == "1" ]]; then
            sleep 2
            printf 'wcet\r\n'
            sleep 1
            printf 'wcet jitter\r\n'
            sleep 1
            printf 'bench all 1000\r\n'
            sleep 5
        fi

        # Hold FIFO open for the rest of the scenario so QEMU doesn't get EOF.
        sleep $((SCENARIO_DURATION_S + 10))
    ) >"${FIFO_PATH}" &
    INJECT_PID=$!

    # ── Wait for stub_brain to finish ─────────────────────────────────────────
    wait "${STUB_PID}" 2>/dev/null
    STUB_RC=$?
    STUB_PID=""

    # ── Tear down QEMU + inject helper ────────────────────────────────────────
    if [[ -n "${QEMU_PID}" ]] && kill -0 "${QEMU_PID}" 2>/dev/null; then
        kill -TERM "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    fi
    QEMU_PID=""

    kill "${INJECT_PID}" 2>/dev/null || true
    wait "${INJECT_PID}" 2>/dev/null || true
    INJECT_PID=""

    rm -f "${FIFO_PATH}"
    FIFO_PATH=""

    if [[ "${STUB_RC}" -ne 0 ]]; then
        echo "[BENCH] run ${run_idx}: stub rc=${STUB_RC} (no connection or no packets — QEMU TCG sensor pump issue expected)"
        FAILED_RUNS=$((FAILED_RUNS + 1))
    else
        echo "[BENCH] run ${run_idx}: OK"
    fi
    RUN_DIRS+=("${RUN_DIR}")
    sleep 2
done

# ── Step 4: Burst scenario (one dedicated QEMU boot) ─────────────────────────
echo "[BENCH] ── burst scenario ───────────────────────────────────────────────"
BURST_DIR="${BENCH_LOG_ROOT}/burst"
mkdir -p "${BURST_DIR}"
BURST_QEMU_LOG="${BURST_DIR}/qemu.log"
BURST_STUB_LOG="${BURST_DIR}/stub.log"

"${PYTHON}" "${BENCH_STUB_PY}" \
    --port           "${STUB_PORT}" \
    --scenario       burst \
    --duration-s     30 \
    --burst-n        100 \
    --accept-grace-s "${ACCEPT_GRACE_S}" \
    >"${BURST_STUB_LOG}" 2>&1 &
STUB_PID=$!
sleep 1

if kill -0 "${STUB_PID}" 2>/dev/null; then
    BURST_LAUNCH_TS=$("${PYTHON}" -c "import time; print(f'{time.time():.6f}')")
    {
        printf '[BENCH-LAUNCH] %s\n' "${BURST_LAUNCH_TS}"
        printf '[BENCH] sha=%s scenario=burst\n' "${GIT_SHA_SHORT}"
    } >"${BURST_QEMU_LOG}"

    qemu_launch /dev/null "${BURST_QEMU_LOG}"

    wait "${STUB_PID}" 2>/dev/null
    STUB_PID=""

    if [[ -n "${QEMU_PID}" ]] && kill -0 "${QEMU_PID}" 2>/dev/null; then
        kill -TERM "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    fi
    QEMU_PID=""
    echo "[BENCH] burst done"
else
    echo "[BENCH] burst stub failed to start; burst metrics will be null"
    STUB_PID=""
fi

# Append [BENCH-BURST-PEAK] from burst stub.log into run1/stub.log so the
# collector can pick it up for the first run directory.
if [[ -f "${BURST_STUB_LOG}" ]] && [[ "${#RUN_DIRS[@]}" -gt 0 ]]; then
    BURST_PEAK_LINE=$(grep "\[BENCH-BURST-PEAK\]" "${BURST_STUB_LOG}" 2>/dev/null || true)
    if [[ -n "${BURST_PEAK_LINE}" ]]; then
        printf '%s\n' "${BURST_PEAK_LINE}" >> "${RUN_DIRS[0]}/stub.log"
    fi
fi

# ── Step 5: Collect metrics and write JSON ────────────────────────────────────
echo "[BENCH] ── collecting metrics ───────────────────────────────────────────"
mkdir -p "${BENCH_RESULTS}"
OUT_JSON="${BENCH_RESULTS}/${GIT_SHA_SHORT}.json"

if [[ "${#RUN_DIRS[@]}" -eq 0 ]]; then
    echo "[BENCH] ERROR: no run directories produced"
    exit 1
fi

"${PYTHON}" "${COLLECT_PY}" \
    --run-dirs    "${RUN_DIRS[@]}" \
    --kernel-elf  "${KERNEL_ELF}" \
    --sha         "${GIT_SHA_SHORT}" \
    --out         "${OUT_JSON}" \
    --qemu-version "${QEMU_VERSION}" \
    --qemu-smp    "${QEMU_SMP}" \
    --qemu-icount-shift "${QEMU_ICOUNT_SHIFT}" \
    --qemu-rtc-base "${QEMU_RTC_BASE}" \
    --host        "darwin-arm64"

COLLECT_RC=$?
if [[ "${COLLECT_RC}" -ne 0 ]]; then
    echo "[BENCH] collector script failed (rc=${COLLECT_RC})"
    exit 1
fi

echo "[BENCH] JSON written: ${OUT_JSON}"

# ── Step 6: Validate JSON ─────────────────────────────────────────────────────
"${PYTHON}" -c "import json; json.load(open('${OUT_JSON}'))" || {
    echo "[BENCH] ERROR: output JSON is malformed"
    exit 1
}
echo "[BENCH] JSON valid"

# ── Step 7: Print head of JSON for inspection ─────────────────────────────────
echo "[BENCH] first 30 lines of ${OUT_JSON}:"
"${PYTHON}" -c "
import json, sys
with open('${OUT_JSON}') as f:
    lines = f.read().splitlines()
for line in lines[:30]:
    print(line)
"

# ── Step 8: Exit code ─────────────────────────────────────────────────────────
if [[ "${FAILED_RUNS}" -ge "${N_RUNS}" ]]; then
    echo "[BENCH] ERROR: all ${N_RUNS} steady runs failed (no kernel→brain connection)"
    exit 1
fi
if [[ "${FAILED_RUNS}" -gt 0 ]]; then
    echo "[BENCH] WARNING: ${FAILED_RUNS}/${N_RUNS} runs had connection failures (partial data — expected under QEMU TCG)"
fi

exit 0
