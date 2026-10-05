# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Syscall test — exercises multiple system calls from user-space.
#
# Tests:
#   1. SYS_GETPID (10) — returns current task TID
#   2. SYS_WRITE  (23) — write banner to stdout (fd=1)
#   3. SYS_BRK   (400) — get current brk, then extend by 4096
#   4. SYS_WRITE  (23) — write pass/fail result
#   5. SYS_EXIT    (3) — exit with code 0 (all passed) or 1 (failure)
#
# Syscall ABI:
#   a7 = syscall number
#   a0..a5 = arguments
#   ecall
#   a0 = return value

.option arch, +m, +a, +c, +zicsr, +zifencei

.section .text
.align 2
.global _start

_start:
    # ── Test 1: SYS_GETPID ───────────────────────────────────────────
    li   a7, 10              # SYS_GETPID
    ecall
    mv   s0, a0              # save TID in s0

    # ── Test 2: SYS_WRITE (banner) ────────────────────────────────────
    li   a7, 23              # SYS_WRITE
    li   a0, 1               # fd = 1 (stdout)
    la   a1, msg_banner
    li   a2, 30              # length
    ecall
    # check return value: should be 30
    li   t0, 30
    bne  a0, t0, fail

    # ── Test 3: SYS_BRK (get current brk) ────────────────────────────
    li   a7, 400             # SYS_BRK
    li   a0, 0               # arg=0 → return current brk
    ecall
    mv   s1, a0              # save original brk in s1
    beqz s1, fail            # brk should not be 0

    # ── Test 4: SYS_BRK (extend by 4096) ─────────────────────────────
    li   a7, 400             # SYS_BRK
    li   t0, 4096
    add  a0, s1, t0           # request brk + 4096
    ecall
    # new brk should be >= s1 + 4096
    li   t0, 4096
    add  t0, s1, t0
    blt  a0, t0, fail

    # ── Test 5: SYS_WRITE (write to allocated page) ───────────────────
    # Store a test pattern in the newly allocated memory
    li   t1, 0x42            # 'B'
    sb   t1, 0(s1)
    lb   t2, 0(s1)
    bne  t1, t2, fail

    # ── All passed — write success message ────────────────────────────
    li   a7, 23              # SYS_WRITE
    li   a0, 1               # fd = 1
    la   a1, msg_pass
    li   a2, 32              # length
    ecall

    # ── SYS_EXIT(0) ──────────────────────────────────────────────────
    li   a7, 3               # SYS_EXIT
    li   a0, 0               # exit code 0 = success
    ecall
    j    spin                # should not reach here

fail:
    # Write failure message
    li   a7, 23              # SYS_WRITE
    li   a0, 1               # fd = 1
    la   a1, msg_fail
    li   a2, 26              # length
    ecall

    # SYS_EXIT(1) — failure
    li   a7, 3               # SYS_EXIT
    li   a0, 1               # exit code 1 = failure
    ecall

spin:
    j    spin

.section .rodata
msg_banner:
    .ascii "[SYSCALL_TEST] Starting...\n\0\0\0"
    # padded to 30 bytes

msg_pass:
    .ascii "[SYSCALL_TEST] ALL PASSED!\n\0\0\0\0\0"
    # padded to 32 bytes

msg_fail:
    .ascii "[SYSCALL_TEST] FAILED!\n\0\0\0\0"
    # padded to 26 bytes
