# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Minimal RISC-V 64-bit user-space test program.
# Loaded by the kernel shell with "exec /fat/HELLO.ELF".
#
# Syscall ABI:
#   a7 = syscall number
#   a0..a5 = arguments
#   ecall
#   a0 = return value
#
# The numbers are not restated here: the Makefile assembles this file with
# `tools/syscall_defs.py`, which reads them from crates/core/abi.
#
#   SYS_CAP_INFO   (a0 = 0, a1 = CAP_INFO_LOOKUP, a2 = CONSOLE_TYPE, a3 = 0) -> a0 = the console handle
#   SYS_INVOKE     (a0 = handle, a1 = INVOKE_CONSOLE_WRITE, a2 = buf, a3 = len)
#   SYS_EXIT       (a0 = exit code)

.option arch, +m, +a, +c, +zicsr, +zifencei

.section .text
.align 2
.global _start

_start:
    # --- the console handle ---
    li   a7, SYS_CAP_INFO
    li   a0, 0
    li   a1, 0              # CAP_INFO_LOOKUP
    li   a2, CONSOLE_TYPE
    li   a3, 0
    ecall

    # --- console write(msg, msg_len); a0 is the handle ---
    li   a7, SYS_INVOKE
    li   a1, INVOKE_CONSOLE_WRITE
    la   a2, msg            # buf ptr
    li   a3, 23             # length of "Hello from user-space!\n"
    ecall

    # --- exit(0) ---
    li   a7, SYS_EXIT
    li   a0, 0
    ecall

    # should never reach here
1:  j 1b

.section .rodata
msg:
    .ascii "Hello from user-space!\n"
