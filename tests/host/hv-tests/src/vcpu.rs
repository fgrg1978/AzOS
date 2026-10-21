// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The vCPU record: the harts it may use and the interrupt lines raised for it.

use azos_hv::vcpu::{allowed, BadIrq, Vcpu};

#[test]
fn a_vcpu_never_gets_a_hart_that_holds_a_deadline_reservation() {
    // Harts 0..3 online; 1 and 2 reserved; the vCPU asks for any.
    assert_eq!(allowed(!0, 0b1111, 0b0110), 0b1001);
    assert_eq!(allowed(!0, 0b1111, 0b0111), 0b1000);
    // Its affinity names only reserved harts: nowhere.
    assert_eq!(allowed(0b0110, 0b1111, 0b0110), 0);
    // An offline hart is not a place either.
    assert_eq!(allowed(0b1000, 0b0111, 0), 0);
    assert_eq!(allowed(0b1111, 0b0111, 0b0001), 0b0110);
}

#[test]
fn an_interrupt_line_is_remembered_until_the_vcpu_is_reset() {
    let mut v = Vcpu::new(0, 0, 0b0110);
    assert_eq!(v.pending(), 0);
    v.inject(0).unwrap();
    v.inject(63).unwrap();
    v.inject(0).unwrap();
    assert_eq!(v.pending(), 1 | 1 << 63);
    assert_eq!(v.inject(64), Err(BadIrq));
    assert_eq!(v.pending(), 1 | 1 << 63, "a refused line changes nothing");
}

#[test]
fn a_reset_gives_back_what_admission_made() {
    let mut v = Vcpu::new(1, 2, 0b0110);
    v.inject(7).unwrap();
    v.affinity = 0b0100;
    v.reset();
    assert_eq!((v.pending(), v.affinity), (0, 0b0110));
    assert_eq!((v.vm, v.index), (1, 2));
}

// ── fences and the timer, which hypercalls leave on a vCPU ──────────────

use azos_arch_api::RemoteFence;
use azos_hv::vcpu::TIMER_NEVER;

const WHOLE: RemoteFence = RemoteFence::Tlb { start: 0, size: u64::MAX, asid: None };

#[test]
fn fences_asked_of_a_vcpu_coalesce_and_are_taken_once() {
    let mut v = Vcpu::new(0, 1, 1);
    assert!(!v.fence_pending());
    assert_eq!(v.take_fence(), None);
    // Any number of ranged flushes are one flush of everything (a superset of
    // each), and instruction fences are one.
    v.request_fence(RemoteFence::Tlb { start: 0x4000, size: 0x1000, asid: Some(3) });
    v.request_fence(RemoteFence::Tlb { start: 0x9000, size: 0x2000, asid: None });
    v.request_fence(RemoteFence::Insn);
    v.request_fence(RemoteFence::Insn);
    assert!(v.fence_pending());
    assert_eq!(v.take_fence(), Some(RemoteFence::Insn));
    assert_eq!(v.take_fence(), Some(WHOLE));
    assert_eq!(v.take_fence(), None);
    assert!(!v.fence_pending(), "taken, so the vCPU that asked can go on");
}

#[test]
fn the_timer_line_is_a_level_while_the_deadline_has_passed() {
    let mut v = Vcpu::new(0, 0, 1);
    assert_eq!(v.timer_deadline(), TIMER_NEVER);
    assert_eq!(v.levels(u64::MAX), 0, "no deadline: never");
    v.arm_timer(1000, 6);
    assert_eq!((v.levels(999), v.levels(1000), v.levels(5000)), (0, 1 << 6, 1 << 6));
    // A later deadline withdraws the line; "never" does too.
    v.arm_timer(9000, 6);
    assert_eq!(v.levels(5000), 0);
    assert_eq!(v.levels(9000), 1 << 6);
    v.arm_timer(TIMER_NEVER, 6);
    assert_eq!(v.levels(u64::MAX), 0);
    // The line is the caller's to name, within the 64 a vCPU tracks.
    v.arm_timer(0, 3);
    assert_eq!(v.levels(0), 1 << 3);
}

#[test]
fn a_reset_drops_the_fence_and_the_timer() {
    let mut v = Vcpu::new(0, 0, 1);
    v.request_fence(WHOLE);
    v.arm_timer(5, 6);
    v.reset();
    assert!(!v.fence_pending());
    assert_eq!((v.timer_deadline(), v.levels(u64::MAX - 1)), (TIMER_NEVER, 0));
}
