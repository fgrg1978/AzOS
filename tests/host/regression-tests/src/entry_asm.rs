// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! K1 (entry/trap review, 2026-10-22): the trap-entry and boot assembly
//! fixes, pinned on the real sources. Nothing here runs the asm (the boot
//! rows do); each test reads the shipped file and fails on the old shape.

use std::path::Path;

fn read(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The file's lines with their comments cut (`comment` starts one).
fn code(rel: &str, comment: &str) -> Vec<String> {
    read(rel)
        .lines()
        .map(|l| l.split(comment).next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// The code lines from the one equal to `from` up to (not including) the
/// first one starting with `to`.
fn span(lines: &[String], from: &str, to: &str) -> Vec<String> {
    let a = lines.iter().position(|l| l == from).unwrap_or_else(|| panic!("`{from}` is gone"));
    let n = lines[a + 1..].iter().position(|l| l.starts_with(to)).unwrap_or_else(|| panic!("no `{to}` after `{from}`"));
    lines[a..a + 1 + n].to_vec()
}

/// **M2: the riscv64 switch never loads `tp` from the incoming task.** `tp` is
/// the hart id and a switch never changes hart; `context.tp` is bookkeeping
/// (saved, never restored), as in context_switch_rvv.S.
#[test]
fn riscv64_context_switch_keeps_the_harts_tp() {
    for f in ["kernel/src/entry/riscv64/asm/context_switch.S", "kernel/src/entry/riscv64/asm/context_switch_rvv.S"] {
        let loads: Vec<_> = code(f, "#")
            .into_iter()
            .filter(|l| {
                let mut w = l.split(|c: char| c.is_whitespace() || c == ',').filter(|t| !t.is_empty());
                matches!((w.next(), w.next()), (Some("ld" | "lw" | "mv" | "li" | "la"), Some("tp" | "x4")))
            })
            .collect();
        assert!(loads.is_empty(), "{f} writes tp: {loads:?}");
    }
}

/// **M1: a frame the kernel rebuilt (a foreign resume, an exec) leaves the lean
/// x86_64 `syscall` return for `trap_return`'s full restore** before anything
/// loads rcx/r11 from RIP/RFLAGS, and the foreign resume marks its frame.
#[test]
fn x86_64_lean_syscall_return_sends_a_rebuilt_frame_to_the_full_restore() {
    let asm = code("kernel/src/entry/x86_64/asm/trap_entry.S", "//");
    let ret = span(&asm, "syscall_return:", "sysretq");
    let test = ret.iter().position(|l| l == "cmpq $SYSCALL_VEC, TF_VECTOR(%rsp)").expect("no vector test in syscall_return");
    assert_eq!(ret[test + 1], "jne trap_return", "the vector test must branch to trap_return");
    let rcx = ret.iter().position(|l| l == "movq TF_RIP(%rsp), %rcx").expect("rcx = RIP load");
    assert!(test < rcx, "the test must come before rcx/r11 are taken from RIP/RFLAGS: {ret:?}");

    let rs = read("kernel/src/entry/x86_64/trap.rs");
    let resume = &rs[rs.find("Some(Pending::Resume").expect("the Resume arm")..];
    let resume = &resume[..resume.find("None =>").expect("the Resume arm's end")];
    assert!(resume.contains("frame.vector = super::REBUILT_VECTOR"), "the Resume arm does not mark its frame: {resume}");
    let reflect = &rs[rs.find("Some(Pending::Reflect").expect("the Reflect arm")..];
    let reflect = &reflect[..reflect.find("foreign::reflect(&f)").expect("the reflect call")];
    assert!(reflect.contains("f.gpr[1] = frame.rip") && reflect.contains("f.gpr[11] = frame.rflags"),
        "the Reflect arm reports the lean frame's stale rcx/r11 slots: {reflect}");
}

/// **M5: the aarch64 boot CPU is whichever PE the loader started**: no MPIDR
/// test parks it, its `TPIDR_EL1` is the logical CPU 0, written at EL1 after
/// the EL2 drop (L12).
#[test]
fn aarch64_boot_takes_no_mpidr_gate_and_publishes_cpu_0_at_el1() {
    let asm = code("kernel/src/entry/aarch64/asm/boot.S", "//");
    let primary = span(&asm, "_entry_after_header:", "bl      kernel_main");
    assert!(!primary.iter().any(|l| l.contains("MPIDR_EL1")), "the primary path reads MPIDR_EL1: {primary:?}");
    assert!(!primary.iter().any(|l| l.contains("_secondary_park")), "the primary path can park the boot CPU");
    assert!(primary.iter().any(|l| l == "mov     x20, #0"), "the boot CPU's id is not the logical CPU 0");
    let drop = primary.iter().position(|l| l == "bl      _azos_drop_to_el1").expect("the EL2 drop");
    let tpidr = primary.iter().position(|l| l == "msr     TPIDR_EL1, x20").expect("the TPIDR_EL1 write");
    assert!(drop < tpidr, "TPIDR_EL1 is written at EL2, before the drop");
}

/// **M3: an aarch64 IRQ/FIQ never decodes the stale `ESR_EL1`**: `class()`
/// and the FP first-use arm both ask the vector first.
#[test]
fn aarch64_decodes_esr_only_for_a_synchronous_vector() {
    let rs = read("kernel/src/entry/aarch64/trap.rs");
    let class = &rs[rs.find("fn class(&self) -> TrapClass").expect("class()")..];
    let gate = class.find("if !syndrome_is_live(self)").expect("class() does not ask the vector");
    let ec = class.find("let ec = (self.esr_el1").expect("class()'s ESR decode");
    assert!(gate < ec, "class() decodes the ESR before asking the vector");
    let fp = &rs[rs.find("fn arch_exception(&mut self) -> Disposition").expect("arch_exception()")..];
    assert!(fp[..fp.find("fp::first_use()").expect("the FP arm")].contains("!syndrome_is_live(self)"),
        "the FP first-use arm decodes a stale EC");
    let live = &rs[rs.find("fn syndrome_is_live").expect("syndrome_is_live")..];
    let live = &live[..live.find('}').unwrap()];
    assert!(live.contains("VEC_SYNC_CURRENT_EL_SP0") && live.contains("VEC_SYNC_LOWER_EL") && !live.contains("IRQ"),
        "only the two synchronous vectors carry a live syndrome: {live}");
}
