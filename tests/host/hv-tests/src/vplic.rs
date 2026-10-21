// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The virtual PLIC of a RISC-V guest: claim and complete, priority and
//! threshold, per-context enables, and the `hvip.VSEIP` bit the context lines
//! become.
//!
//! The register offsets are written out by hand from the RISC-V PLIC
//! specification 1.0.0 (priority 0x0, pending 0x1000, enable 0x2000 + 0x80 per
//! context, threshold / claim 0x200000 + 0x1000 per context); the claim rules
//! follow QEMU's `sifive_plic.c`.

use azos_hv::vlapic::Fault;
use azos_hv::vplic::{Change, Vplic, PLIC_DEFAULT_BASE, PLIC_WINDOW};

use crate::glue::rv::csr::{VSEIP, VSSIP, VSTIP};
use crate::glue::rv::inject::{hvip_level, hvip_with, VsIrq};

const BASE: u64 = PLIC_DEFAULT_BASE;

fn prio(src: u64) -> u64 {
    BASE + 4 * src
}
fn pending(word: u64) -> u64 {
    BASE + 0x1000 + 4 * word
}
fn enable(ctx: u64, word: u64) -> u64 {
    BASE + 0x2000 + 0x80 * ctx + 4 * word
}
fn threshold(ctx: u64) -> u64 {
    BASE + 0x20_0000 + 0x1000 * ctx
}
fn claim(ctx: u64) -> u64 {
    threshold(ctx) + 4
}

fn rd(p: &mut Vplic, gpa: u64) -> u32 {
    p.mmio_read(gpa, 4).unwrap().0
}

fn wr(p: &mut Vplic, gpa: u64, v: u32) -> Change {
    p.mmio_write(gpa, 4, v).unwrap()
}

/// A claim through the register, with the lines it moved.
fn take(p: &mut Vplic, ctx: u64) -> (u32, Change) {
    p.mmio_read(claim(ctx), 4).unwrap()
}

/// A PLIC of `n` contexts with `srcs` at priority `pr` and enabled on every
/// context.
fn plic(n: usize, srcs: &[(u64, u32)]) -> Vplic {
    let mut p = Vplic::new(BASE, n);
    for &(s, pr) in srcs {
        wr(&mut p, prio(s), pr);
    }
    for c in 0..n as u64 {
        let (lo, hi) = srcs.iter().fold((0u32, 0u32), |(lo, hi), &(s, _)| {
            if s < 32 { (lo | 1 << s, hi) } else { (lo, hi | 1 << (s - 32)) }
        });
        wr(&mut p, enable(c, 0), lo);
        wr(&mut p, enable(c, 1), hi);
    }
    p
}

const UP0: Change = Change { raised: 1, lowered: 0 };
const DOWN0: Change = Change { raised: 0, lowered: 1 };

// ── claim / complete ────────────────────────────────────────────────────

#[test]
fn a_raised_source_is_claimed_once_and_completed() {
    let mut p = plic(1, &[(5, 3)]);
    assert!(!p.line(0));
    assert_eq!(p.set_irq(5, true), UP0);
    assert!(p.line(0));
    assert_eq!(rd(&mut p, pending(0)), 1 << 5);

    // The claim returns the id, clears the pending bit and drops the line.
    assert_eq!(take(&mut p, 0), (5, DOWN0));
    assert_eq!(rd(&mut p, pending(0)), 0);
    assert!(!p.line(0));
    // Nothing else is pending: a second claim is 0 and changes nothing.
    assert_eq!(take(&mut p, 0), (0, Change::NONE));

    // The device still holds its line, but the gateway is closed until the
    // completion: no new interrupt.
    assert_eq!(p.set_irq(5, true), Change::NONE);
    assert!(!p.line(0));

    // The completion re-opens it; the line is still asserted, so it pends
    // again at once.
    assert_eq!(wr(&mut p, claim(0), 5), UP0);
    assert!(p.line(0));
    assert_eq!(take(&mut p, 0), (5, DOWN0));

    // The driver quiesced the device before completing: nothing to re-pend.
    p.set_irq(5, false);
    assert_eq!(wr(&mut p, claim(0), 5), Change::NONE);
    assert_eq!(rd(&mut p, pending(0)), 0);
    assert!(!p.line(0));
}

#[test]
fn a_line_dropped_before_the_claim_withdraws_the_interrupt() {
    let mut p = plic(1, &[(2, 1)]);
    assert_eq!(p.set_irq(2, true), UP0);
    assert_eq!(p.set_irq(2, false), DOWN0);
    assert_eq!(rd(&mut p, pending(0)), 0);
    assert_eq!(take(&mut p, 0), (0, Change::NONE));
}

#[test]
fn the_claim_goes_to_the_highest_priority_then_the_lowest_id() {
    let mut p = plic(1, &[(3, 2), (9, 6), (4, 6), (7, 1)]);
    for s in [3, 9, 4, 7] {
        p.set_irq(s, true);
    }
    // 4 and 9 tie at 6: the lower id first.
    assert_eq!(take(&mut p, 0).0, 4);
    assert_eq!(take(&mut p, 0).0, 9);
    assert_eq!(take(&mut p, 0).0, 3);
    // The last claim takes the line down; the one before it did not.
    let (id, ch) = take(&mut p, 0);
    assert_eq!((id, ch), (7, DOWN0));
}

#[test]
fn a_line_stays_high_while_another_source_is_pending() {
    let mut p = plic(1, &[(1, 1), (2, 1)]);
    assert_eq!(p.set_irq(1, true), UP0);
    assert_eq!(p.set_irq(2, true), Change::NONE);
    assert_eq!(take(&mut p, 0), (1, Change::NONE));
    assert!(p.line(0));
    assert_eq!(take(&mut p, 0), (2, DOWN0));
}

#[test]
fn a_completion_that_is_not_owed_is_ignored() {
    let mut p = plic(1, &[(6, 2), (8, 2)]);
    p.set_irq(6, true);
    p.set_irq(8, true);
    assert_eq!(take(&mut p, 0).0, 6);
    // 8 is pending, not claimed; 0 and 64 are not sources: no effect, and 8
    // does not pend twice.
    assert_eq!(wr(&mut p, claim(0), 8), Change::NONE);
    assert_eq!(wr(&mut p, claim(0), 0), Change::NONE);
    assert_eq!(wr(&mut p, claim(0), 64), Change::NONE);
    assert_eq!(rd(&mut p, pending(0)), 1 << 8);
    // 6 was claimed, but the context disables it before completing: the
    // completion is silently dropped and the gateway stays closed.
    wr(&mut p, enable(0, 0), 1 << 8);
    assert_eq!(wr(&mut p, claim(0), 6), Change::NONE);
    wr(&mut p, enable(0, 0), 1 << 6 | 1 << 8);
    assert_eq!(p.set_irq(6, true), Change::NONE, "still claimed");
    assert_eq!(wr(&mut p, claim(0), 6), Change::NONE, "line high: pends again but 8 holds the line");
    assert_eq!(rd(&mut p, pending(0)), 1 << 6 | 1 << 8);
}

// ── priority and threshold ──────────────────────────────────────────────

#[test]
fn the_threshold_masks_priorities_up_to_and_including_it() {
    let mut p = plic(1, &[(1, 3)]);
    wr(&mut p, threshold(0), 3);
    // Pending, enabled, but priority 3 is not above threshold 3.
    assert_eq!(p.set_irq(1, true), Change::NONE);
    assert!(!p.line(0));
    assert_eq!(rd(&mut p, pending(0)), 1 << 1, "it pends; it just does not interrupt");
    assert_eq!(take(&mut p, 0), (0, Change::NONE), "the claim honours the threshold too");
    // Lowering the threshold lets it through.
    assert_eq!(wr(&mut p, threshold(0), 2), UP0);
    // Raising it again takes the line back down.
    assert_eq!(wr(&mut p, threshold(0), 3), DOWN0);
    wr(&mut p, threshold(0), 0);
    assert_eq!(take(&mut p, 0).0, 1);
}

#[test]
fn priority_zero_never_interrupts_and_a_write_changes_the_line() {
    let mut p = plic(1, &[(4, 0)]);
    assert_eq!(p.set_irq(4, true), Change::NONE);
    assert_eq!(take(&mut p, 0).0, 0);
    // Giving it a priority raises the line; taking it away lowers it.
    assert_eq!(wr(&mut p, prio(4), 1), UP0);
    assert_eq!(wr(&mut p, prio(4), 0), DOWN0);
    assert_eq!(wr(&mut p, prio(4), 7), UP0);
}

#[test]
fn a_lower_priority_source_is_passed_over_by_the_threshold() {
    let mut p = plic(1, &[(1, 2), (2, 5)]);
    wr(&mut p, threshold(0), 4);
    p.set_irq(1, true);
    assert!(!p.line(0));
    p.set_irq(2, true);
    assert!(p.line(0));
    assert_eq!(take(&mut p, 0), (2, DOWN0), "source 1 is pending but under the threshold");
}

#[test]
fn priorities_and_thresholds_are_three_bits() {
    let mut p = Vplic::new(BASE, 1);
    wr(&mut p, prio(10), 0xFFFF_FFFF);
    assert_eq!(rd(&mut p, prio(10)), 7);
    wr(&mut p, prio(10), 0x0A);
    assert_eq!(rd(&mut p, prio(10)), 2);
    wr(&mut p, threshold(0), 0x1F);
    assert_eq!(rd(&mut p, threshold(0)), 7);
    // Source 0 does not exist.
    wr(&mut p, prio(0), 5);
    assert_eq!(rd(&mut p, prio(0)), 0);
    // Past source 63 the priority page reads 0 and drops writes.
    wr(&mut p, prio(64), 5);
    assert_eq!(rd(&mut p, prio(64)), 0);
    assert_eq!(rd(&mut p, prio(1023)), 0);
}

// ── per-context enables ─────────────────────────────────────────────────

#[test]
fn a_source_interrupts_only_the_contexts_that_enabled_it() {
    let mut p = Vplic::new(BASE, 3);
    wr(&mut p, prio(2), 4);
    wr(&mut p, enable(1, 0), 1 << 2);
    wr(&mut p, enable(2, 0), 1 << 2);
    // vCPU 0 never sees it.
    assert_eq!(p.set_irq(2, true), Change { raised: 0b110, lowered: 0 });
    assert_eq!((p.line(0), p.line(1), p.line(2)), (false, true, true));
    assert_eq!(p.lines(), 0b110);
    assert_eq!(take(&mut p, 0), (0, Change::NONE));
    // One vCPU claims it: it is gone for the other (it is one interrupt).
    assert_eq!(take(&mut p, 1), (2, Change { raised: 0, lowered: 0b110 }));
    assert_eq!(take(&mut p, 2), (0, Change::NONE));
    // A context's threshold is its own.
    assert_eq!(wr(&mut p, claim(1), 2), Change { raised: 0b110, lowered: 0 });
    wr(&mut p, threshold(2), 4);
    assert_eq!(p.lines(), 0b010);
}

#[test]
fn enable_bits_cover_the_high_word_and_never_source_zero() {
    let mut p = Vplic::new(BASE, 1);
    wr(&mut p, prio(63), 1);
    wr(&mut p, enable(0, 1), 0xFFFF_FFFF);
    assert_eq!(rd(&mut p, enable(0, 1)), 0xFFFF_FFFF);
    assert_eq!(p.set_irq(63, true), UP0);
    assert_eq!(rd(&mut p, pending(1)), 1 << 31);
    assert_eq!(take(&mut p, 0), (63, DOWN0));
    wr(&mut p, enable(0, 0), 0xFFFF_FFFF);
    assert_eq!(rd(&mut p, enable(0, 0)), 0xFFFF_FFFE, "bit 0 is source 0: hardwired off");
    // Disabling a pending source lowers the line.
    p.set_irq(63, false);
    wr(&mut p, claim(0), 63);
    wr(&mut p, prio(9), 2);
    assert_eq!(p.set_irq(9, true), UP0);
    assert_eq!(wr(&mut p, enable(0, 0), 0), DOWN0);
}

#[test]
fn contexts_the_guest_does_not_have_read_zero() {
    let mut p = Vplic::new(BASE, 2);
    wr(&mut p, threshold(2), 5);
    assert_eq!(rd(&mut p, threshold(2)), 0);
    wr(&mut p, enable(2, 0), 0xFF);
    assert_eq!(rd(&mut p, enable(2, 0)), 0);
    assert_eq!(rd(&mut p, claim(2)), 0);
    assert!(!p.line(2));
    // Source ids and context pages of a bigger machine are not an error.
    assert_eq!(rd(&mut p, claim(63)), 0);
}

// ── the bus ─────────────────────────────────────────────────────────────

#[test]
fn only_aligned_32_bit_accesses_inside_the_window_are_served() {
    let mut p = Vplic::new(BASE, 1);
    for size in [1u8, 2, 8] {
        assert_eq!(p.mmio_read(prio(1), size), Err(Fault));
        assert_eq!(p.mmio_write(prio(1), size, 1), Err(Fault));
    }
    assert_eq!(p.mmio_read(prio(1) + 2, 4), Err(Fault));
    assert_eq!(p.mmio_read(BASE - 4, 4), Err(Fault));
    assert_eq!(p.mmio_read(BASE + PLIC_WINDOW, 4), Err(Fault));
    assert_eq!(p.mmio_write(BASE + PLIC_WINDOW - 4, 4, 1), Ok(Change::NONE));
    // A refused access changed nothing.
    assert_eq!(rd(&mut p, prio(1)), 0);
}

#[test]
fn the_pending_bits_are_read_only() {
    let mut p = plic(1, &[(3, 1)]);
    wr(&mut p, pending(0), 0xFFFF_FFFF);
    assert_eq!(rd(&mut p, pending(0)), 0);
    p.set_irq(3, true);
    wr(&mut p, pending(0), 0);
    assert_eq!(rd(&mut p, pending(0)), 1 << 3);
    assert_eq!(p.set_irq(0, true), Change::NONE);
    assert_eq!(p.set_irq(64, true), Change::NONE);
    assert_eq!(rd(&mut p, pending(0)), 1 << 3);
}

#[test]
fn a_window_elsewhere_is_served_where_it_was_put() {
    let base = 0x1000_0000;
    let mut p = Vplic::new(base, 1);
    assert_eq!(p.mmio_base(), base);
    p.mmio_write(base + 4, 4, 3).unwrap();
    assert_eq!(p.mmio_read(base + 4, 4).unwrap().0, 3);
    assert_eq!(p.mmio_read(BASE + 4, 4), Err(Fault));
}

// ── from a context line to hvip ─────────────────────────────────────────

/// What a vCPU entry does with the PLIC: bring `VSEIP` in line with the
/// context's external line, leave the other bits alone.
fn enter(p: &Vplic, ctx: usize, hvip: u64) -> u64 {
    hvip_level(hvip, VsIrq::External, p.line(ctx))
}

#[test]
fn vseip_follows_the_context_line_and_leaves_the_other_bits() {
    let mut p = plic(2, &[(1, 2)]);
    // A pending software interrupt from an SBI IPI and a pending timer.
    let mut hvip = hvip_with(hvip_with(0, VsIrq::Software), VsIrq::Timer);
    assert_eq!(hvip, VSSIP | VSTIP);

    assert_eq!(p.set_irq(1, true), Change { raised: 0b11, lowered: 0 });
    hvip = enter(&p, 0, hvip);
    assert_eq!(hvip, VSSIP | VSTIP | VSEIP, "set, others untouched");

    // vCPU 0 claims: its line drops, vCPU 1's does not (it is the same
    // interrupt, claimed): both lowered.
    let (_, ch) = take(&mut p, 0);
    assert_eq!(ch, Change { raised: 0, lowered: 0b11 });
    hvip = enter(&p, 0, hvip);
    assert_eq!(hvip, VSSIP | VSTIP, "cleared, others untouched");

    // The completion re-pends the held line and VSEIP comes back.
    let ch = wr(&mut p, claim(0), 1);
    assert_eq!(ch.raised, 0b11);
    assert_eq!(enter(&p, 0, hvip), VSSIP | VSTIP | VSEIP);
    // A second entry with no change is idempotent.
    assert_eq!(enter(&p, 0, enter(&p, 0, hvip)), VSSIP | VSTIP | VSEIP);
}

#[test]
fn each_transition_the_plic_reports_moves_hvip_the_same_way() {
    // Drive a sequence and keep one hvip per context, set from the reported
    // Change only (the kick path), and check it against the line (the entry
    // path): they must never differ.
    let mut p = plic(2, &[(1, 3), (2, 5)]);
    let mut hvip = [0u64; 2];
    let apply = |p: &Vplic, ch: Change, hvip: &mut [u64; 2]| {
        for c in 0..2 {
            if ch.raised >> c & 1 != 0 {
                hvip[c] = hvip_level(hvip[c], VsIrq::External, true);
            }
            if ch.lowered >> c & 1 != 0 {
                hvip[c] = hvip_level(hvip[c], VsIrq::External, false);
            }
            assert_eq!(hvip[c] & VSEIP != 0, p.line(c), "ctx {c}");
        }
    };
    p.mmio_write(enable(1, 0), 4, 0b100).unwrap(); // ctx 1 only takes source 2
    let steps: [Box<dyn Fn(&mut Vplic) -> Change>; 8] = [
        Box::new(|p| p.set_irq(1, true)),
        Box::new(|p| p.set_irq(2, true)),
        Box::new(|p| p.mmio_write(threshold(0), 4, 4).unwrap()),
        Box::new(|p| p.mmio_read(claim(1), 4).unwrap().1),
        Box::new(|p| p.mmio_write(claim(1), 4, 2).unwrap()),
        Box::new(|p| p.set_irq(2, false)),
        Box::new(|p| p.mmio_write(threshold(0), 4, 0).unwrap()),
        Box::new(|p| p.mmio_read(claim(0), 4).unwrap().1),
    ];
    for s in &steps {
        let ch = s(&mut p);
        apply(&p, ch, &mut hvip);
    }
}
