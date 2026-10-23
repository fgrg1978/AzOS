// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! I-13 on aarch64: which syndrome the trap entry hands to the control-tick
//! rollback (`sysregs::el1_alignment_fault`, called by
//! `kernel/src/entry/aarch64/trap.rs`'s `arch_page_fault`). Only an EL1 data
//! access that took an Alignment fault; every other abort keeps the
//! page-fault policy, and so does an EL0 one (the rollback restarts only the
//! armed task's own kernel-mode fault).
//!
//! Canary (by hand): drop the DFSC compare and
//! `only_the_alignment_status_is_taken` fails; drop the EC compare and
//! `an_el0_or_instruction_abort_is_never_taken` fails.

use crate::sysregs::{el1_alignment_fault, ESR_DFSC_ALIGNMENT, ESR_EC_DATA_ABORT_CUR};

/// A syndrome: EC, IL set (a 32-bit instruction), the ISS bits given.
const fn esr(ec: u64, iss: u64) -> u64 {
    (ec << 26) | (1 << 25) | iss
}

const WNR: u64 = 1 << 6;
const ISV: u64 = 1 << 24;

#[test]
fn an_el1_alignment_fault_is_taken() {
    assert_eq!(ESR_EC_DATA_ABORT_CUR, 0x25);
    assert_eq!(ESR_DFSC_ALIGNMENT, 0x21);
    // A load and a store (WnR), with and without a valid syndrome (ISV), and
    // the ESR_EL1 ISS2 bits above 32 set: none of it is the class.
    for iss in [0, WNR, ISV, ISV | WNR] {
        assert!(el1_alignment_fault(esr(0x25, iss | 0x21)));
        assert!(el1_alignment_fault(esr(0x25, iss | 0x21) | (0x1F << 32)));
    }
}

#[test]
fn only_the_alignment_status_is_taken() {
    // Translation (levels 0..3), access flag, permission, synchronous
    // external, TLB conflict, and the DFSC values next to 0b100001.
    for dfsc in [0x04, 0x05, 0x06, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x10, 0x20, 0x22, 0x30, 0x31] {
        assert!(!el1_alignment_fault(esr(0x25, dfsc)), "DFSC {dfsc:#x} is not an alignment fault");
        assert!(!el1_alignment_fault(esr(0x25, dfsc | WNR)), "DFSC {dfsc:#x} (write)");
    }
}

#[test]
fn an_el0_or_instruction_abort_is_never_taken() {
    // EL0 data abort, instruction aborts (EL0, EL1), PC and SP alignment
    // (their own classes), each with the alignment status in its low bits.
    for ec in [0x24, 0x20, 0x21, 0x22, 0x26, 0x15, 0x00] {
        assert!(!el1_alignment_fault(esr(ec, 0x21)), "EC {ec:#x} is not an EL1 data abort");
    }
    assert!(!el1_alignment_fault(0), "an empty syndrome");
}
