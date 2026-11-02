// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The machine-check record and the CPUID gates of `ext/mce.rs`: what the
//! #MC handler leaves, and when it may read IA32_MCG_STATUS.

use super::mce::{has_mce, has_mcg_status, Record, Seen};

#[test]
fn a_check_is_recorded_with_its_registers_and_counted() {
    let r = Record::new();
    assert_eq!(r.seen(), Seen::default());
    assert_eq!(r.note(2, 0xffff_8000_0010_0000, 0x08, 0x46, 0x5), 1);
    assert_eq!(
        r.seen(),
        Seen { count: 1, cpu: 2, rip: 0xffff_8000_0010_0000, cs: 0x08, rflags: 0x46, mcg_status: 0x5 }
    );
}

#[test]
fn a_second_check_overwrites_the_fields_and_counts() {
    let r = Record::new();
    r.note(0, 1, 2, 3, 4);
    assert_eq!(r.note(1, 5, 6, 7, 8), 2);
    let s = r.seen();
    assert_eq!((s.count, s.cpu, s.rip, s.mcg_status), (2, 1, 5, 8));
}

#[test]
fn mcg_status_is_read_only_with_both_mce_and_mca() {
    assert!(has_mce(1 << 7));
    assert!(!has_mce(1 << 14));
    assert!(has_mcg_status((1 << 7) | (1 << 14)));
    assert!(!has_mcg_status(1 << 7), "MCE without MCA has no MCG_STATUS: a read would #GP in the handler");
    assert!(!has_mcg_status(1 << 14));
}
