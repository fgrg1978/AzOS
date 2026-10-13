#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""syscall_defs.py NAME... : print `--defsym NAME=VALUE` for the hand-assembled
RISC-V test programs (userspace/tests/hello/hello.S, syscall_test/test.S), so
that no syscall number is restated in assembly.

NAME is a `SYS_*` constant of crates/core/abi/src/syscall_nr.rs, or one of the
derived words below (read from crates/core/abi/src/invoke.rs and cap.rs):

  INVOKE_CONSOLE_WRITE   INVOKE_REGS | LOG_CONSOLE_WRITE (the op word)
  CONSOLE_TYPE           ty::CONSOLE.raw() (pinned by tests/host/abi-tests)
  DOMAIN_SELF            the caller's own domain handle (pinned by tests/host/abi-tests)
  INVOKE_<OP>            INVOKE_REGS | the op constant <OP> of invoke.rs (any kind,
                         e.g. INVOKE_DOMAIN_BRK)
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NR = (ROOT / "crates/core/abi/src/syscall_nr.rs").read_text()
INV = (ROOT / "crates/core/abi/src/invoke.rs").read_text()


def const(src, name):
    m = re.search(r"^\s*pub const %s: u\d+ = ([^;]+);" % re.escape(name), src, re.M)
    if not m:
        sys.exit("syscall_defs: no constant %s" % name)
    e = m.group(1).strip()
    m2 = re.fullmatch(r"1 << (\d+)", e)
    return 1 << int(m2.group(1)) if m2 else int(e, 0)


KINDS = {"Endpoint": 1, "MemObj": 2, "Queue": 3, "Port": 4, "Domain": 5, "Node": 6, "Device": 7, "Log": 8}
CLASSES = {"CLASS_READ": 0, "CLASS_WRITE": 1, "CLASS_WAIT": 2, "CLASS_CTL": 3, "CLASS_ADMIN": 4,
           "CLASS_FS_OPEN": 5, "CLASS_FS_MUTATE": 6, "CLASS_MODULE": 7, "CLASS_NET": 8, "CLASS_DRIVER": 9}


def op_const(src, name):
    """`pub const NAME: u16 = op(CapKind::K, CLASS_C, N);`"""
    m = re.search(r"^pub const %s: u16 = op\(CapKind::(\w+), (CLASS_\w+), (\d+)\);" % re.escape(name), src, re.M)
    if not m:
        sys.exit("syscall_defs: no op constant %s" % name)
    return (KINDS[m.group(1)] << 12) | (CLASSES[m.group(2)] << 8) | int(m.group(3))


out = []
for n in sys.argv[1:]:
    if n.startswith("SYS_"):
        v = const(NR, n)
    elif n == "INVOKE_CONSOLE_WRITE":
        v = const(INV, "INVOKE_REGS") | op_const(INV, "LOG_CONSOLE_WRITE")
    elif n.startswith("INVOKE_"):
        v = const(INV, "INVOKE_REGS") | op_const(INV, n[len("INVOKE_"):])
    elif n == "DOMAIN_SELF":
        v = (21 << 26) | (0xF << 22)
    elif n == "CONSOLE_TYPE":
        v = 24
    else:
        sys.exit("syscall_defs: unknown name %s" % n)
    out.append("--defsym %s=%d" % (n, v))
print(" ".join(out))
