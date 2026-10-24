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

/// **el0-state-audit: every aarch64 PE writes the whole `SCTLR_EL1` word**,
/// on both entry paths, before any compiled code (the first `bl`): entered at
/// EL1, nothing else defines it, and the firmware's SPAN and EL0 controls rode
/// through the MMU enable's read-OR. The EL2 drop defines `MDCR_EL2` and
/// `CPTR_EL2` before its `eret`.
#[test]
fn aarch64_entry_paths_write_sctlr_and_the_drop_defines_the_el2_traps() {
    let asm = code("kernel/src/entry/aarch64/asm/boot.S", "//");
    for (from, to) in [("_entry_after_header:", "bl      kernel_main"), ("_aarch64_secondary_entry:", "bl      secondary_main")] {
        let path = span(&asm, from, to);
        let w = path.iter().position(|l| l == "msr     SCTLR_EL1, x9").unwrap_or_else(|| panic!("{from}: no SCTLR_EL1 write"));
        let rust = path.iter().position(|l| l.starts_with("bl      aarch64_")).expect("the first call into Rust");
        assert!(w < rust, "{from}: SCTLR_EL1 is written after compiled code runs");
        assert!(path[..w].iter().any(|l| l == "movk    x9, #{sctlr_hi}, lsl #16"), "{from}: not the boot word");
    }
    let drop = between("crates/core/arch-aarch64/src/mmu/boot.rs", "//", "_azos_drop_to_el1:", "eret");
    for reg in ["CPTR_EL2", "MDCR_EL2", "SCTLR_EL1"] {
        assert!(drop.iter().any(|l| l.ends_with(&format!("msr     {reg}, x10"))), "the drop does not write {reg}");
    }
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

/// The code lines from the first one containing `from` up to (not
/// including) the next one containing `to` (comments cut by `comment`).
fn between(rel: &str, comment: &str, from: &str, to: &str) -> Vec<String> {
    let lines = code(rel, comment);
    let a = lines.iter().position(|l| l.contains(from)).unwrap_or_else(|| panic!("{rel}: `{from}` is gone"));
    let n = lines[a + 1..].iter().position(|l| l.contains(to)).unwrap_or_else(|| panic!("{rel}: no `{to}` after `{from}`"));
    lines[a..a + 1 + n].to_vec()
}

fn at(lines: &[String], what: &str) -> usize {
    lines.iter().position(|l| l.contains(what)).unwrap_or_else(|| panic!("no `{what}` in {lines:?}"))
}

/// **L14: riscv64 publishes the exec root before it installs it**, on both
/// returns, while `tp` is still the hart id (before the user's tp is loaded).
#[test]
fn riscv64_trap_returns_publish_the_root_before_csrw_satp() {
    let f = "kernel/src/entry/riscv64/asm/trap_entry.S";
    let ret = between(f, "#", "trap_return:", "restore_to_smode:");
    let publish = at(&ret, "sd   s2, 0(t3)");
    assert!(publish < at(&ret, "ld x4, 32(sp)"), "published after the user's tp was loaded");
    assert!(publish < at(&ret, "csrw satp, s2"), "trap_return installs before it publishes");
    let native = between(f, "#", "trap_native_return:", ".Lnative_no_pt_switch:");
    assert!(at(&native, "sd   a0, 0(t3)") < at(&native, "csrw satp, a0"), "the native return installs before it publishes");
}

/// **L15: x86_64 fences the conditional swapgs** where its two arms meet,
/// before the first `%gs:` use (Kconfig MITIGATION_SPECTRE_V1_INDEX).
#[test]
fn x86_64_trap_common_fences_the_swapgs_test() {
    let t = between("kernel/src/entry/x86_64/asm/trap_entry.S", "//", "trap_common:", "SAVE_REGS");
    let join = at(&t, "1:");
    assert!(join > at(&t, "swapgs"));
    assert_eq!(t[join + 1..join + 3], [".if MIT_SWAPGS".to_string(), "lfence".to_string()], "no fence at the join: {t:?}");
}

/// **L17: an x86_64 NMI takes no exception**: it is counted and returns
/// before any guard, decode or policy runs.
#[test]
fn x86_64_nmi_returns_before_any_guard() {
    let e = between("kernel/src/entry/x86_64/trap.rs", "//", "pub extern \"C\" fn x86_64_trap_entry", "match frame.class()");
    let nmi = at(&e, "if frame.vector as usize == idt::NMI");
    assert!(nmi < at(&e, "TrapBoundary"), "the NMI runs the QSBR guard: {e:?}");
    assert!(e[nmi + 1..nmi + 3].iter().any(|l| l == "return 0;"), "the NMI arm does not return at once: {e:?}");
}

/// **L2: an x86_64 secondary's GS base is its PerCpu before anything can
/// read `%gs:0`**: no provisional base (the CPU number) in ap_entry.S, and
/// `init_cpu` sets it first.
#[test]
fn x86_64_secondary_gs_is_its_percpu_first() {
    let ap = code("kernel/src/entry/x86_64/asm/ap_entry.S", "//");
    assert!(!ap.iter().any(|l| l.starts_with("wrmsr")), "ap_entry.S still writes a provisional GS base");
    let init = between("kernel/src/entry/x86_64/ext/cpu_init.rs", "//", "pub fn init_cpu(cpu: usize)", "build_idt();");
    assert!(at(&init, "cpu::set_percpu(cpu);") < at(&init, "irq_stack_base(cpu)"), "a check runs before the GS base: {init:?}");
}

/// **L10, L11: the aarch64 tick ends at its own EOI** (it no longer walks the
/// device ladder), and the uptime divisor is guarded as on the other paths.
#[test]
fn aarch64_tick_returns_after_its_eoi() {
    let t = between("kernel/src/entry/aarch64/irq.rs", "//", "if intid == INTID_EL1_VIRT_TIMER", "LPI_INTID_BASE {");
    let n = t.len();
    assert_eq!(t[n - 3..], ["azos_arch::irq::gic::eoir1(intid);".to_string(), "return;".to_string(), "}".to_string()],
        "the timer arm falls through to the device ladder: {:?}", &t[n - 6..]);
    assert!(t.iter().any(|l| l.contains("vdso_hz >= 1000")), "uptime divides by vdso_hz / 1000 without the 1 kHz guard");
}

/// **L9: an aarch64 secondary with no TTBR1 to attach parks** instead of
/// running on the RWX boot alias or on no upper half at all.
#[test]
fn aarch64_secondary_parks_without_a_ttbr1() {
    let s = code("kernel/src/entry/aarch64/asm/boot.S", "//");
    let call = at(&s, "bl      aarch64_secondary_ttbr1_attach");
    assert_eq!(s[call + 1], "cbz     x0, _secondary_park", "the attach's refusal is not acted on");
    let f = between("kernel/src/entry/aarch64/mod.rs", "//", "pub extern \"C\" fn aarch64_secondary_ttbr1_attach", "CORE_TTBR1.get(hart)");
    assert!(!f.iter().any(|l| l.contains("TTBR1_BOOT_VALUE")), "the attach still falls back to the boot alias: {f:?}");
}

/// **L5: a crash dump carries only the dying task's decisions**, not the
/// kernel's last N whatever their subject.
#[test]
fn crash_dump_decisions_are_the_tasks_own() {
    let rs = read("kernel/src/trap/crash.rs");
    let own = &rs[rs.find("fn own_decisions").expect("own_decisions")..];
    let own = &own[..own.find("\n}\n").unwrap()];
    assert!(own.contains("r.subject == \"tid\"") && own.contains("p.subject == tid || p.subject == proc"),
        "the filter is gone: {own}");
    let cap = &rs[rs.find("pub(super) fn capture").expect("capture")..];
    assert!(cap[..cap.find("read_stack").unwrap()].contains("own_decisions(tid, &mut decisions)"),
        "capture does not take the filtered decisions");
}
