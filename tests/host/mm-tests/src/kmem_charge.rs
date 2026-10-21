// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host rows for the kernel-memory ledger (`KmemBudget`, KMEM-CHARGE) in the
//! real `crates/core/mm/src/budget.rs`, pulled with `#[path]`.
//!
//! The decision record a refusal leaves is written by `azos_sched::domain`
//! (this crate has no decision dependency); what these rows pin is the payload
//! it is written from: `KmemRefusal` is exactly the record's three numbers.
//! The record itself is read back in `tests/host/sched-wake-tests`
//! (`domain_tests`).

use crate::budget::{KmemBudget, KmemClass, KmemRefusal, KMEM_CLASSES};

const KIB: u64 = 1024;

/// Every class charges and discharges on its own: a charge shows in its class
/// and the sum and in no other class, and the discharge undoes exactly that.
#[test]
fn each_class_is_charged_and_discharged_on_its_own() {
    for c in KmemClass::ALL {
        let b = KmemBudget::new();
        assert_eq!(b.charge(c, 300), Ok(()));
        assert_eq!((b.used(), b.used_of(c)), (300, 300), "{c:?}");
        for other in KmemClass::ALL.into_iter().filter(|&o| o != c) {
            assert_eq!(b.used_of(other), 0, "{c:?} must not show in {other:?}");
        }
        assert_eq!(b.discharge(c, 300), 300);
        assert_eq!((b.used(), b.used_of(c)), (0, 0), "{c:?} given back");
    }
}

/// The class indices are the ones the kernel registers its hooks against.
#[test]
fn class_indices_round_trip() {
    assert_eq!(KmemClass::ALL.len(), KMEM_CLASSES);
    for (i, c) in KmemClass::ALL.into_iter().enumerate() {
        assert_eq!(c as usize, i);
        assert_eq!(KmemClass::from_index(i as u8), Some(c));
    }
    assert_eq!(KmemClass::from_index(KMEM_CLASSES as u8), None);
}

/// The limit is in KiB (`kmem_kib` of the row), counted over all classes. A
/// charge that would pass it is refused with the numbers of the record, and
/// changes nothing; one that lands exactly on it is granted.
#[test]
fn a_charge_past_the_limit_is_refused_with_the_record_numbers_and_charges_nothing() {
    let b = KmemBudget::new();
    b.set_limit_kib(4);
    assert_eq!(b.limit(), 4 * KIB);
    assert_eq!(b.charge(KmemClass::CapTable, 3 * KIB), Ok(()));
    let r = b.charge(KmemClass::EpQueue, 2 * KIB).unwrap_err();
    assert_eq!(
        r,
        KmemRefusal { class: KmemClass::EpQueue, bytes: 2 * KIB, used: 3 * KIB, limit: 4 * KIB },
        "bytes asked, bytes held, ceiling: the record's three numbers"
    );
    assert_eq!((b.used(), b.used_of(KmemClass::EpQueue)), (3 * KIB, 0), "a refusal charges nothing");
    assert_eq!(b.charge(KmemClass::EpQueue, KIB), Ok(()), "exactly at the limit is granted");
    assert!(b.charge(KmemClass::MemObjMeta, 1).is_err(), "and one byte more is not");
    assert_eq!(b.used(), 4 * KIB);
}

/// A refused charge is not a one-shot: the limit holds until something is
/// given back, and then the same charge goes through. This is "a free returns
/// the charge".
#[test]
fn a_free_returns_the_charge_and_the_refused_allocation_then_fits() {
    let b = KmemBudget::new();
    b.set_limit_kib(1);
    assert_eq!(b.charge(KmemClass::MemObjMeta, 600), Ok(()));
    assert!(b.charge(KmemClass::MemObjMeta, 600).is_err());
    assert!(b.charge(KmemClass::MemObjMeta, 600).is_err(), "still refused");
    assert_eq!(b.discharge(KmemClass::MemObjMeta, 600), 600);
    assert_eq!(b.used(), 0);
    assert_eq!(b.charge(KmemClass::MemObjMeta, 600), Ok(()), "the freed bytes can be taken again");
}

/// The limit counts every class together: one class cannot hide behind
/// another's headroom.
#[test]
fn the_limit_is_shared_by_the_classes() {
    let b = KmemBudget::new();
    b.set_limit_kib(2);
    assert_eq!(b.charge(KmemClass::PageTable, KIB), Ok(()));
    assert_eq!(b.charge(KmemClass::CapTable, KIB), Ok(()));
    for c in KmemClass::ALL {
        assert!(b.charge(c, 1).is_err(), "{c:?}: the ledger is full");
    }
}

/// No limit is the state of every row that does not declare `kmem_kib`.
#[test]
fn a_zero_limit_is_unlimited_and_a_zero_charge_is_a_no_op() {
    let b = KmemBudget::new();
    assert_eq!(b.charge(KmemClass::CapTable, u64::MAX / 2), Ok(()));
    assert_eq!(b.charge(KmemClass::CapTable, 0), Ok(()));
    b.set_limit_kib(1);
    assert!(b.charge(KmemClass::CapTable, 0).is_ok(), "zero bytes never trips a limit");
    assert_eq!(b.discharge(KmemClass::CapTable, 0), 0);
}

/// `kmem_kib` is a `u32`: its largest value, in bytes, does not fit 32 bits.
#[test]
fn the_largest_kmem_kib_does_not_overflow() {
    let b = KmemBudget::new();
    b.set_limit_kib(u32::MAX);
    assert_eq!(b.limit(), u64::from(u32::MAX) * KIB);
    assert_eq!(b.charge(KmemClass::PageTable, 5 << 30), Ok(()), "5 GiB fits under a 4 TiB limit");
}

/// Saturating, not wrapping: `overflow-checks` makes a plain add here a board
/// reset on the target.
#[test]
fn charging_saturates_instead_of_overflowing() {
    let b = KmemBudget::new();
    assert_eq!(b.charge(KmemClass::CapTable, u64::MAX), Ok(()));
    assert_eq!(b.charge(KmemClass::EpQueue, 10), Ok(()), "no limit: granted, saturated");
    assert_eq!(b.used(), u64::MAX);
    b.set_limit_kib(1);
    assert!(b.charge(KmemClass::EpQueue, u64::MAX).is_err());
}

/// An over-discharge gives back what the class holds and no more, so it cannot
/// eat another class's bytes, and `used` stays the sum of the classes.
#[test]
fn an_over_discharge_takes_nothing_from_another_class() {
    let b = KmemBudget::new();
    assert_eq!(b.charge(KmemClass::CapTable, 100), Ok(()));
    assert_eq!(b.charge(KmemClass::EpQueue, 50), Ok(()));
    assert_eq!(b.discharge(KmemClass::EpQueue, 80), 50, "only what the class held");
    assert_eq!((b.used(), b.used_of(KmemClass::CapTable), b.used_of(KmemClass::EpQueue)), (100, 100, 0));
    assert_eq!(b.discharge(KmemClass::EpQueue, 1), 0, "an empty class gives nothing back");
    assert_eq!(b.used(), 100);
}

/// A class whose objects all went at once (the page tables of an address space
/// an exec replaced) is given back whole, and the others are left.
#[test]
fn discharging_a_whole_class_leaves_the_others() {
    let b = KmemBudget::new();
    assert_eq!(b.charge(KmemClass::PageTable, 4096 * 3), Ok(()));
    assert_eq!(b.charge(KmemClass::CapTable, 700), Ok(()));
    assert_eq!(b.discharge_all(KmemClass::PageTable), 4096 * 3);
    assert_eq!((b.used(), b.used_of(KmemClass::PageTable), b.used_of(KmemClass::CapTable)), (700, 0, 700));
    assert_eq!(b.discharge_all(KmemClass::PageTable), 0);
}

/// A reused Domain slot starts from nothing: no bytes and no limit.
#[test]
fn a_reset_forgets_every_charge_and_the_limit() {
    let b = KmemBudget::new();
    b.set_limit_kib(2);
    assert_eq!(b.charge(KmemClass::MemObjMeta, KIB), Ok(()));
    b.reset();
    assert_eq!((b.used(), b.limit()), (0, 0));
    for c in KmemClass::ALL {
        assert_eq!(b.used_of(c), 0);
    }
}

/// Two harts charging the same headroom: the compare-and-swap lets exactly as
/// many through as fit, and `used` is the sum of the grants, with no update
/// lost (the check-then-store charge fails this row: see the ledger's twin in
/// `budget_tests`, canary `budget-racy-charge-canary`, for the frame budget).
#[test]
fn concurrent_charges_never_pass_the_limit_together() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    const LIMIT_KIB: u32 = 64;
    const UNIT: u64 = 64;
    let b = Arc::new(KmemBudget::new());
    b.set_limit_kib(LIMIT_KIB);
    let granted = Arc::new(AtomicU64::new(0));
    let hs: Vec<_> = (0..4)
        .map(|t| {
            let (b, granted) = (b.clone(), granted.clone());
            std::thread::spawn(move || {
                let c = KmemClass::ALL[t];
                for _ in 0..4096 {
                    if b.charge(c, UNIT).is_ok() {
                        granted.fetch_add(UNIT, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    assert_eq!(granted.load(Ordering::Relaxed), u64::from(LIMIT_KIB) * KIB, "granted up to exactly the limit");
    assert_eq!(b.used(), u64::from(LIMIT_KIB) * KIB);
    assert_eq!(KmemClass::ALL.iter().map(|&c| b.used_of(c)).sum::<u64>(), b.used());
}
