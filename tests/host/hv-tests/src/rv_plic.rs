// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The PLIC's edge input (`Vplic::pulse`), the one vmmd's device models use:
//! they report that a device's interrupt went up and never that the guest's
//! acknowledgement took it down.
//!
//! WHY. With only a level input, the line the monitor holds stays high after
//! the guest completes its claim, so the source pends again at once and the
//! guest takes interrupts for ever. These tests are what separates the edge
//! from that storm.

use azos_hv::vplic::{Change, Vplic, PLIC_DEFAULT_BASE};

const B: u64 = PLIC_DEFAULT_BASE;

fn rd(p: &mut Vplic, off: u64) -> u32 {
    p.mmio_read(B + off, 4).unwrap().0
}
fn wr(p: &mut Vplic, off: u64, v: u32) -> Change {
    p.mmio_write(B + off, 4, v).unwrap()
}

/// Source 3 at priority 1, enabled for context 0, threshold 0.
fn plic() -> Vplic {
    let mut p = Vplic::new(B, 1);
    wr(&mut p, 4 * 3, 1);
    wr(&mut p, 0x2000, 1 << 3);
    p
}

const CLAIM: u64 = 0x20_0004;

#[test]
fn an_edge_pends_the_source_once_and_the_claim_takes_it() {
    let mut p = plic();
    assert_eq!(p.pulse(3), Change { raised: 1, lowered: 0 });
    assert!(p.line(0));
    assert_eq!(rd(&mut p, CLAIM), 3);
    assert!(!p.line(0));
    // The guest completes; nothing is left holding the line up.
    assert!(wr(&mut p, CLAIM, 3).is_none());
    assert!(!p.line(0));
    assert_eq!(rd(&mut p, CLAIM), 0, "no storm: the edge was spent by the claim");
}

#[test]
fn an_edge_during_the_claim_pends_the_source_at_the_completion() {
    let mut p = plic();
    p.pulse(3);
    assert_eq!(rd(&mut p, CLAIM), 3);
    // A second edge while the guest is in its handler: held, not pended.
    assert!(p.pulse(3).is_none());
    assert!(!p.line(0));
    assert_eq!(wr(&mut p, CLAIM, 3), Change { raised: 1, lowered: 0 });
    assert_eq!(rd(&mut p, CLAIM), 3);
    assert!(wr(&mut p, CLAIM, 3).is_none());
    assert_eq!(rd(&mut p, CLAIM), 0);
}

#[test]
fn edges_during_one_claim_collapse_into_one() {
    let mut p = plic();
    p.pulse(3);
    rd(&mut p, CLAIM);
    p.pulse(3);
    p.pulse(3);
    wr(&mut p, CLAIM, 3);
    assert_eq!(rd(&mut p, CLAIM), 3);
    wr(&mut p, CLAIM, 3);
    assert_eq!(rd(&mut p, CLAIM), 0);
}

#[test]
fn an_edge_waits_for_the_guest_to_enable_the_source() {
    let mut p = Vplic::new(B, 1);
    assert!(p.pulse(3).is_none(), "priority 0 and disabled: pending, no line");
    wr(&mut p, 4 * 3, 1);
    assert!(wr(&mut p, 0x2000, 1 << 3).raised == 1, "the edge is still there when the guest turns it on");
    assert_eq!(rd(&mut p, CLAIM), 3);
}

#[test]
fn sources_that_do_not_exist_change_nothing() {
    let mut p = plic();
    assert!(p.pulse(0).is_none());
    assert!(p.pulse(64).is_none());
    assert!(!p.line(0));
}

#[test]
fn the_level_input_is_unchanged_by_the_edge_one() {
    let mut p = plic();
    p.set_irq(3, true);
    assert_eq!(rd(&mut p, CLAIM), 3);
    // A level still asserted pends the source again at the completion.
    assert_eq!(wr(&mut p, CLAIM, 3), Change { raised: 1, lowered: 0 });
    p.set_irq(3, false);
    assert!(!p.line(0));
}
