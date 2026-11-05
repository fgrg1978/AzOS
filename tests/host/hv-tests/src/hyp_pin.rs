// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The pin's decode and numbers (crates/core/hyp-mon/src/arch/sysreg.rs): which
//! trapped register is which, which writes are refused, the `HFGWTR_EL2` and
//! `HCR_EL2` bits, and the `ESR_EL2` word the vector's fast path matches.
//!
//! WHY. The vector compares the whole syndrome against one constant and the
//! arming writes two registers by bit position: one place off, and either
//! every context switch takes the slow path or the pin traps the wrong register
//! (or none), with nothing to say so until a kernel runs under it.

#[allow(dead_code)]
#[path = "../../../../crates/core/hyp-mon/src/arch/sysreg.rs"]
mod sysreg;

use sysreg::*;

/// The `ESR_EL2` of `MSR <reg>, X<rt>` from a 32-bit instruction at EL1.
fn msr(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64, rt: u64) -> u64 {
    0x18 << 26 | 1 << 25 | op0 << 20 | op2 << 17 | op1 << 14 | crn << 10 | rt << 5 | crm << 1
}

fn reg_of_msr(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> Option<Reg> {
    reg_of(&sysreg_trap(msr(op0, op1, crn, crm, op2, 7)).unwrap())
}

#[test]
fn every_trapped_register_is_named_by_its_architected_encoding() {
    // Linux's `sys_reg(op0, op1, crn, crm, op2)` for each EL1 register.
    assert_eq!(reg_of_msr(3, 0, 1, 0, 0), Some(Reg::Sctlr));
    assert_eq!(reg_of_msr(3, 0, 2, 0, 0), Some(Reg::Ttbr0));
    assert_eq!(reg_of_msr(3, 0, 2, 0, 1), Some(Reg::Ttbr1));
    assert_eq!(reg_of_msr(3, 0, 2, 0, 2), Some(Reg::Tcr));
    assert_eq!(reg_of_msr(3, 0, 5, 1, 0), Some(Reg::Afsr0));
    assert_eq!(reg_of_msr(3, 0, 5, 1, 1), Some(Reg::Afsr1));
    assert_eq!(reg_of_msr(3, 0, 5, 2, 0), Some(Reg::Esr));
    assert_eq!(reg_of_msr(3, 0, 6, 0, 0), Some(Reg::Far));
    assert_eq!(reg_of_msr(3, 0, 10, 2, 0), Some(Reg::Mair));
    assert_eq!(reg_of_msr(3, 0, 10, 3, 0), Some(Reg::Amair));
    assert_eq!(reg_of_msr(3, 0, 13, 0, 1), Some(Reg::ContextId));
    // The EL12 aliases (Op1 5) and a neighbour of TTBR1 are none of them.
    assert_eq!(reg_of_msr(3, 5, 2, 0, 1), None);
    assert_eq!(reg_of_msr(3, 0, 2, 0, 3), None);
    assert_eq!(reg_of_msr(2, 0, 1, 0, 0), None);
}

#[test]
fn only_the_three_registers_the_kernel_never_writes_after_boot_are_refused() {
    for r in [Reg::Sctlr, Reg::Tcr, Reg::Ttbr1] {
        assert!(refused(r), "{r:?}");
    }
    // The user half switches on every context switch; the rest TVM drags in
    // are carried out unchanged.
    for r in [Reg::Ttbr0, Reg::Afsr0, Reg::Afsr1, Reg::Esr, Reg::Far, Reg::Mair, Reg::Amair, Reg::ContextId] {
        assert!(!refused(r), "{r:?}");
    }
}

#[test]
fn the_encoding_a_record_carries_is_linuxs_sys_reg() {
    let t = |op0, op1, crn, crm, op2| sysreg_trap(msr(op0, op1, crn, crm, op2, 0)).unwrap();
    // SYS_SCTLR_EL1, SYS_TTBR1_EL1, SYS_TCR_EL1: sys_reg(3, 0, 1|2, 0, 0|1|2).
    assert_eq!(encoding(&t(3, 0, 1, 0, 0)), 3 << 19 | 1 << 12);
    assert_eq!(encoding(&t(3, 0, 2, 0, 1)), 3 << 19 | 2 << 12 | 1 << 5);
    assert_eq!(encoding(&t(3, 0, 2, 0, 2)), 3 << 19 | 2 << 12 | 2 << 5);
}

#[test]
fn a_write_decodes_with_its_source_register_and_a_read_is_a_read() {
    let w = sysreg_trap(msr(3, 0, 2, 0, 1, 19)).unwrap();
    assert!(!w.read);
    assert_eq!(w.rt, 19);
    let r = sysreg_trap(msr(3, 0, 2, 0, 1, 19) | 1).unwrap();
    assert!(r.read);
    assert!(sysreg_trap(0x16 << 26).is_none(), "an HVC is no register access");
}

#[test]
fn the_fine_grained_trap_bits_are_the_architected_positions() {
    // HFGWTR_EL2 (Linux arch/arm64/tools/sysreg): SCTLR_EL1 29, TCR_EL1 32, TTBR1_EL1 37.
    assert_eq!(HFGWTR_SCTLR_EL1, 1 << 29);
    assert_eq!(HFGWTR_TCR_EL1, 1 << 32);
    assert_eq!(HFGWTR_TTBR1_EL1, 1 << 37);
    assert_eq!(HFGWTR_PIN, 1 << 29 | 1 << 32 | 1 << 37);
    assert_eq!(HFGWTR_PIN & (1 << 36), 0, "TTBR0_EL1 (bit 36) must not trap: a context switch writes it");
    // HCR_EL2.TVM is bit 26.
    assert_eq!(HCR_TVM, 1 << 26);
}

#[test]
fn fgt_is_read_from_bits_59_to_56_of_mmfr0() {
    assert!(!has_fgt(0));
    assert!(!has_fgt(!(0xf << 56)));
    assert!(has_fgt(1 << 56));
    assert!(has_fgt(2 << 56));
    assert!(!has_fgt(0x1 << 55 | 0x1 << 60), "neighbouring fields are not FGT");
}

#[test]
fn the_vectors_constant_is_a_ttbr0_write_with_any_source_register() {
    for rt in 0..32u64 {
        assert_eq!(msr(3, 0, 2, 0, 0, rt) & !RT_MASK, TTBR0_WRITE_ESR, "x{rt}");
    }
    assert_eq!(TTBR0_WRITE_ESR, 0x6230_0800);
    // The same syndrome for any other register, or a read, or a 16-bit
    // instruction, is another word.
    for other in [msr(3, 0, 2, 0, 1, 0), msr(3, 0, 1, 0, 0, 0), msr(3, 0, 2, 0, 0, 0) | 1, msr(3, 0, 2, 0, 0, 0) & !(1 << 25)] {
        assert_ne!(other & !RT_MASK, TTBR0_WRITE_ESR, "{other:#x}");
    }
}
