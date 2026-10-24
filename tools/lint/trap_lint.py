#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
"""The trap layer is written once (S2): dispatch logic stays out of entry/<isa>/.

`kernel/src/trap/` holds the syscall flow and its prologue, the page-fault and
exception policy, the fatal tail and the interrupt bracket. Each ISA's
`kernel/src/entry/<isa>/` keeps the asm stub, the register-frame decode, the
ISA's cause decode and its interrupt controller. This lint fails when:

  1. an `entry/<isa>/` source names a syscall number (`SYS_*`): a `match` on
     numbers, or any other use, is dispatch logic and belongs to the syscall
     flow or the syscall crate;
  2. an `entry/<isa>/` source calls the fault policy: COW and demand paging
     (`handle_cow_fault`, `handle_demand_fault`), the kill (`task_exit_by_signal`,
     `kill_current`), the fatal tail (`halt_begin`, `halt_report`,
     `set_panicked`, `motor_cmd_zero`), or the filter and dispatch entry points
     (`syscall_entry_fast`, `syscall_verdict`, `syscall_dispatch_checked`,
     `fastpath::entry`, `fastpath::wants`);
  3. a syscall number of `crates/core/abi/src/syscall_nr.rs` has no foundational
     case (a `t[SYS_X as usize] = CASE_*;` row of `SYSCALL_CASE`), or a row
     names a number that does not exist, or a row's case is not one of the two;
  4. one of the host-testable files of the trap layer (`frame.rs`, `syscall.rs`,
     `fault.rs`, `irq.rs`) names a kernel crate: they may name `core` and
     `azos_abi` only, so `tests/host/trap-tests` compiles them unchanged. What
     they need of the kernel is a method of a services trait (`frame.rs`),
     implemented once in `kernel.rs`.

Comments and string literals are not looked at. A line that is meant to break a
rule anyway says `trap-lint: ok` in a trailing comment.

    python3 tools/lint/trap_lint.py              lint the tree (exit 1 on a finding)
    python3 tools/lint/trap_lint.py --self-test  the canary: a synthetic violation of
                                            every rule must turn the lint red
"""

import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../lib"))
import azos_tools  # noqa: E402

ROOT = os.path.realpath(azos_tools.ROOT)
PRAGMA = "trap-lint: ok"
ISAS = ("riscv64", "aarch64", "x86_64")
SYSCALL_NR = "crates/core/abi/src/syscall_nr.rs"
HOST_TESTABLE = ("frame.rs", "syscall.rs", "fault.rs", "irq.rs")
CASES = {"CASE_AUTHORITY", "CASE_BLOCK_WAKE"}

SYS_TOKEN = re.compile(r"\bSYS_(?!NR_RESERVED_UPPER\b)[A-Z0-9_]+\b")
FAULT_POLICY = re.compile(
    r"\b(handle_cow_fault|handle_demand_fault|task_exit_by_signal|kill_current|halt_begin|halt_report|"
    r"set_panicked|motor_cmd_zero|syscall_entry_fast|syscall_verdict|syscall_dispatch_checked)\b"
    r"|\bfastpath::(entry|wants)\b")
KERNEL_CRATE = re.compile(r"\bazos_(?!abi\b)[a-z0-9_]+\s*::")


def scrub(text):
    """The source with comments and string literals blanked, line for line."""
    text = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)
    out = []
    for line in text.split("\n"):
        pragma = PRAGMA in line
        res, i, quote = [], 0, None
        while i < len(line):
            c = line[i]
            if quote:
                if c == "\\":
                    i += 2
                    res.append("  ")
                    continue
                if c == quote:
                    quote = None
                res.append(" ")
            elif c == '"':
                quote = '"'
                res.append(" ")
            elif c == "/" and line[i:i + 2] == "//":
                break
            else:
                res.append(c)
            i += 1
        out.append(("" if pragma else "".join(res)))
    return out


def rust_files(d):
    for base, _dirs, files in os.walk(d):
        for f in sorted(files):
            if f.endswith(".rs"):
                yield os.path.join(base, f)


def lint_entry(root):
    found = []
    for isa in ISAS:
        d = os.path.join(root, "kernel/src/entry", isa)
        if not os.path.isdir(d):
            continue
        for path in rust_files(d):
            rel = os.path.relpath(path, root)
            with open(path, encoding="utf-8") as fh:
                lines = scrub(fh.read())
            for n, line in enumerate(lines, 1):
                for m in SYS_TOKEN.finditer(line):
                    found.append(f"{rel}:{n}: syscall number {m.group(0)} in entry/{isa}/: "
                                 "dispatch logic belongs to kernel/src/trap or the syscall crate")
                for m in FAULT_POLICY.finditer(line):
                    found.append(f"{rel}:{n}: `{m.group(0)}` in entry/{isa}/: fault, kill and "
                                 "dispatch policy belongs to kernel/src/trap")
    return found


def lint_cases(root):
    path = os.path.join(root, SYSCALL_NR)
    if not os.path.isfile(path):
        return [f"{SYSCALL_NR}: missing"]
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    numbers = set(re.findall(r"^pub const (SYS_[A-Z0-9_]+): u64 = \d+;", src, flags=re.M))
    numbers.discard("SYS_NR_RESERVED_UPPER")
    rows = re.findall(r"^\s*t\[(SYS_[A-Z0-9_]+) as usize\] = (\w+);", src, flags=re.M)
    found = []
    seen = {}
    for name, case in rows:
        if name in seen:
            found.append(f"{SYSCALL_NR}: {name} has two case rows")
        seen[name] = case
        if name not in numbers:
            found.append(f"{SYSCALL_NR}: case row for {name}, which is not a syscall number")
        if case not in CASES:
            found.append(f"{SYSCALL_NR}: {name} has case `{case}`, not one of the two foundational cases")
    for name in sorted(numbers - set(seen)):
        found.append(f"{SYSCALL_NR}: {name} has no foundational case (add `t[{name} as usize] = CASE_*;` "
                     "to SYSCALL_CASE)")
    if not rows:
        found.append(f"{SYSCALL_NR}: no SYSCALL_CASE rows found")
    return found


def lint_host_testable(root):
    found = []
    d = os.path.join(root, "kernel/src/trap")
    for name in HOST_TESTABLE:
        path = os.path.join(d, name)
        if not os.path.isfile(path):
            found.append(f"kernel/src/trap/{name}: missing")
            continue
        with open(path, encoding="utf-8") as fh:
            lines = scrub(fh.read())
        for n, line in enumerate(lines, 1):
            for m in KERNEL_CRATE.finditer(line):
                found.append(f"kernel/src/trap/{name}:{n}: names `{m.group(0).strip()}`: the host-testable "
                             "files may name core and azos_abi only (use the services trait)")
    return found


def lint(root):
    return lint_entry(root) + lint_cases(root) + lint_host_testable(root)


# ── The canary ──────────────────────────────────────────────────────────────

CLEAN_NR = """\
pub const SYS_FOO: u64 = 1;
pub const SYS_BAR: u64 = 2;
pub const SYS_NR_RESERVED_UPPER: u64 = 3;
pub const SYSCALL_CASE: [u8; 3] = {
    let mut t = [0u8; 3];
    t[SYS_FOO as usize] = CASE_AUTHORITY;
    t[SYS_BAR as usize] = CASE_BLOCK_WAKE;
    t
};
"""
CLEAN_TRAP = "use azos_abi::exit_status;\nfn f() { let _ = core::mem::size_of::<u8>(); }\n"
CLEAN_ENTRY = "// SYS_GETPID is only named here, in a comment\nfn f() { let s = \"SYS_EXIT handle_cow_fault\"; let _ = s; }\n"


def fixture(root, nr=CLEAN_NR, entry=CLEAN_ENTRY, trap=CLEAN_TRAP, isa="riscv64", trap_file="syscall.rs"):
    def put(rel, text):
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    put(SYSCALL_NR, nr)
    put(f"kernel/src/entry/{isa}/trap.rs", entry)
    for name in HOST_TESTABLE:
        put(f"kernel/src/trap/{name}", CLEAN_TRAP)
    put(f"kernel/src/trap/{trap_file}", trap)


def self_test():
    cases = [
        ("a match on syscall numbers in an entry",
         dict(entry="fn f(n: u64) { match n { SYS_GETPID => {} _ => {} } }\n"), "syscall number SYS_GETPID"),
        ("a syscall number path in an entry",
         dict(entry="fn f() { let _ = azos_abi::syscall_nr::SYS_EXIT; }\n", isa="x86_64"), "syscall number SYS_EXIT"),
        ("the COW policy in an entry",
         dict(entry="fn f() { azos_mm::vmm::handle_cow_fault(1, 2); }\n", isa="aarch64"), "handle_cow_fault"),
        ("a kill in an entry",
         dict(entry="fn f() { azos_sched::scheduler::task_exit_by_signal(139); }\n"), "task_exit_by_signal"),
        ("the fatal tail in an entry",
         dict(entry="fn f() { crate::panic::halt_begin(); }\n"), "halt_begin"),
        ("the filter in an entry",
         dict(entry="fn f() { azos_syscall::syscall_entry_fast(1); }\n"), "syscall_entry_fast"),
        ("the fast path in an entry",
         dict(entry="fn f() { azos_syscall::fastpath::entry(1, r); }\n"), "fastpath::entry"),
        ("a syscall number with no case",
         dict(nr=CLEAN_NR.replace("    t[SYS_BAR as usize] = CASE_BLOCK_WAKE;\n", "")), "SYS_BAR has no foundational case"),
        ("a case row for a number that does not exist",
         dict(nr=CLEAN_NR.replace("    t\n", "    t[SYS_BAZ as usize] = CASE_AUTHORITY;\n    t\n")), "SYS_BAZ, which is not"),
        ("a case that is not one of the two",
         dict(nr=CLEAN_NR.replace("CASE_BLOCK_WAKE", "CASE_FIFTH")), "not one of the two"),
        ("a kernel crate in a host-testable trap file",
         dict(trap="fn f() { azos_sched::schedule(); }\n", trap_file="fault.rs"), "names `azos_sched::`"),
    ]
    bad = []
    with tempfile.TemporaryDirectory() as clean:
        fixture(clean)
        got = lint(clean)
        if got:
            bad.append(f"the clean fixture is not clean: {got}")
    for name, kw, needle in cases:
        with tempfile.TemporaryDirectory() as d:
            fixture(d, **kw)
            got = lint(d)
            if not any(needle in g for g in got):
                bad.append(f"{name}: not caught (wanted `{needle}`, got {got})")
    with tempfile.TemporaryDirectory() as d:
        fixture(d, entry="fn f() { crate::panic::halt_begin(); } // trap-lint: ok\n")
        if lint(d):
            bad.append("the pragma does not silence a line")
    if bad:
        print("trap_lint: self-test FAILED")
        for b in bad:
            print("  " + b)
        return 1
    print(f"trap_lint: self-test ok ({len(cases)} violations caught, clean fixture and pragma pass)")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    found = lint(ROOT)
    for f in found:
        print(f)
    if found:
        print(f"trap_lint: {len(found)} finding(s)")
        return 1
    print("trap_lint: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
