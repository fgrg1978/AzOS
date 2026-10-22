# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Syscall test — exercises multiple system calls from user-space.
#
# Tests:
#   1. SYS_GETPID — returns current task TID
#   2. the console handle (SYS_CAP_INFO), then its WRITE op (SYS_INVOKE):
#      write the banner
#   3. SYS_MO_MAP — one anonymous read-write page, then a store and a load
#      through it
#   4. the console WRITE: write the pass/fail result
#   5. SYS_EXIT — exit with code 0 (all passed) or 1 (failure)
#
# Syscall ABI:
#   a7 = syscall number
#   a0..a5 = arguments
#   ecall
#   a0 = return value
#
# The numbers are not restated here: the Makefile assembles this file with
# `tools/syscall_defs.py`, which reads them from crates/core/abi.

.option arch, +m, +a, +c, +zicsr, +zifencei

.section .text
.align 2
.global _azos_entry

# console_write MSG, LEN: the console handle, then the WRITE op on it. Leaves
# the bytes taken in a0; clobbers a1..a3 and a7.
.macro console_write msg, len
    li   a7, SYS_CAP_INFO
    li   a0, 0
    li   a1, 0               # CAP_INFO_LOOKUP
    li   a2, CONSOLE_TYPE
    li   a3, 0
    ecall
    li   a7, SYS_INVOKE
    li   a1, INVOKE_CONSOLE_WRITE
    la   a2, \msg
    li   a3, \len
    ecall
.endm

_azos_entry:
    # ── Test 1: SYS_GETPID ───────────────────────────────────────────
    li   a7, SYS_GETPID
    ecall
    mv   s0, a0              # save TID in s0

    # ── Test 2: SYS_WRITE (banner) ────────────────────────────────────
    console_write msg_banner, 30
    # check return value: should be 30
    li   t0, 30
    bne  a0, t0, fail

    # ── Test 3: SYS_MO_MAP (one anonymous page, read-write) ─────────────
    li   a7, SYS_MO_MAP
    li   a0, 0               # anonymous memory
    li   a1, 0               # address hint, ignored
    li   a2, 4096            # length
    li   a3, 3               # PROT_READ | PROT_WRITE
    li   a4, 0
    ecall
    mv   s1, a0              # the page's address in s1
    blez s1, fail            # an address, not -1

    # ── Test 4: store and load through the mapped page ──────────────────
    li   t1, 0x42            # 'B'
    sb   t1, 0(s1)
    lb   t2, 0(s1)
    bne  t1, t2, fail

    # ── All passed — write success message ────────────────────────────
    console_write msg_pass, 32

    # ── SYS_EXIT(0) ──────────────────────────────────────────────────
    li   a7, SYS_EXIT
    li   a0, 0               # exit code 0 = success
    ecall
    j    spin                # should not reach here

fail:
    # Write failure message
    console_write msg_fail, 26

    # SYS_EXIT(1) — failure
    li   a7, SYS_EXIT
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
