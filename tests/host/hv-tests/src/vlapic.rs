// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The virtual LAPIC and IOAPIC of an x86 guest: the x2APIC register
//! interface, interrupt priority and EOI, the timer in its three modes, the
//! IPI send, and the IOAPIC's routing into the vLAPICs.
//!
//! The expected values come from the Intel SDM vol. 3 chapter 12 (register
//! layout, divide encoding, PPR rule, x2APIC MSR numbers) and the 82093AA
//! datasheet (redirection entry layout), written out by hand.

use azos_hv::vioapic::{deliver_all, deliver_effect, Vioapic, IOAPIC_DEFAULT_BASE};
use azos_hv::vlapic::{
    route, Delivery, Effect, Event, Fault, Ipi, Lvt, Mode, Shorthand, Vlapic, APIC_DEFAULT_BASE, MSR_APIC_BASE,
    MSR_TSC_DEADLINE,
};

/// Guest TSC cycles per undivided timer tick in these tests.
const TPT: u64 = 10;

// x2APIC MSRs: 0x800 + (xAPIC offset >> 4).
const ID: u32 = 0x802;
const VER: u32 = 0x803;
const TPR: u32 = 0x808;
const PPR: u32 = 0x80A;
const EOI: u32 = 0x80B;
const LDR: u32 = 0x80D;
const DFR: u32 = 0x80E;
const SVR: u32 = 0x80F;
const ISR0: u32 = 0x810;
const IRR0: u32 = 0x820;
const ESR: u32 = 0x828;
const ICR: u32 = 0x830;
const LVT_TIMER: u32 = 0x832;
const LVT_LINT0: u32 = 0x835;
const LVT_ERROR: u32 = 0x837;
const INITIAL: u32 = 0x838;
const CURRENT: u32 = 0x839;
const DIVIDE: u32 = 0x83E;
const SELF_IPI: u32 = 0x83F;

const EN: u64 = 1 << 11;
const EXTD: u64 = 1 << 10;
const MASK: u64 = 1 << 16;

/// A vCPU's APIC in x2APIC mode, software-enabled.
fn x2(id: u32) -> Vlapic {
    let mut a = Vlapic::new(id, id == 0, TPT);
    a.msr_write(MSR_APIC_BASE, APIC_DEFAULT_BASE | EN | EXTD | if id == 0 { 1 << 8 } else { 0 }, 0).unwrap();
    a.msr_write(SVR, 0x1FF, 0).unwrap();
    a
}

fn vm(n: u32) -> Vec<Vlapic> {
    (0..n).map(x2).collect()
}

fn rd(a: &mut Vlapic, msr: u32) -> u64 {
    a.msr_read(msr, 0).unwrap()
}

fn wr(a: &mut Vlapic, msr: u32, v: u64) {
    assert_eq!(a.msr_write(msr, v, 0), Ok(Effect::None), "wrmsr {msr:#x}");
}

/// Take the pending vector, as the entry path does.
fn take(a: &mut Vlapic) -> Option<u8> {
    a.ack()
}

/// A vCPU `src` writes `icr`; what it asks of the VM is applied.
fn send(apics: &mut [Vlapic], io: &mut Vioapic, src: usize, icr: u64) -> u64 {
    let e = apics[src].msr_write(ICR, icr, 0).unwrap();
    deliver_effect(apics, io, src, e)
}

fn io() -> Vioapic {
    Vioapic::new(0, IOAPIC_DEFAULT_BASE)
}

// ── the register interface ───────────────────────────────────────────────

#[test]
fn x2apic_registers_read_what_the_manual_says() {
    let mut a = x2(0x23);
    assert_eq!(rd(&mut a, ID), 0x23, "x2APIC ID is 32 bits wide");
    // Version 0x14, LVT entries - 1 = 6 in bits 23:16.
    assert_eq!(rd(&mut a, VER), 0x0006_0014);
    // LDR: cluster (id >> 4) in the high half, one-hot (id & 15) in the low.
    assert_eq!(rd(&mut a, LDR), 0x0002_0008);
    assert_eq!(rd(&mut a, SVR), 0x1FF);
    wr(&mut a, TPR, 0x20);
    assert_eq!((rd(&mut a, TPR), rd(&mut a, PPR)), (0x20, 0x20));
}

#[test]
fn x2apic_refuses_what_the_manual_makes_a_gp() {
    let mut a = x2(1);
    // Write-only and absent registers read as #GP.
    assert_eq!(a.msr_read(EOI, 0), Err(Fault));
    assert_eq!(a.msr_read(DFR, 0), Err(Fault));
    assert_eq!(a.msr_read(SELF_IPI, 0), Err(Fault));
    assert_eq!(a.msr_read(0x831, 0), Err(Fault), "no ICR high half");
    assert_eq!(a.msr_read(0x809, 0), Err(Fault), "no APR");
    // Read-only registers refuse writes.
    for r in [ID, VER, PPR, LDR, ISR0, IRR0, CURRENT] {
        assert_eq!(a.msr_write(r, 0, 0), Err(Fault), "write of {r:#x}");
    }
    // Reserved values.
    assert_eq!(a.msr_write(TPR, 0x100, 0), Err(Fault));
    assert_eq!(a.msr_write(EOI, 1, 0), Err(Fault));
    assert_eq!(a.msr_write(ESR, 1, 0), Err(Fault));
    assert_eq!(a.msr_write(SELF_IPI, 0x100, 0), Err(Fault));
    // Outside the window, and the window of a mode the guest is not in.
    assert_eq!(a.msr_read(0x900, 0), Err(Fault));
    assert_eq!(a.msr_read(0x7FF, 0), Err(Fault));
    assert_eq!(a.msr_read(0x83A, 0), Err(Fault), "a gap in the layout");
}

#[test]
fn the_apic_base_msr_follows_the_mode_transitions_of_the_manual() {
    let mut a = Vlapic::new(0, true, TPT);
    assert_eq!(a.mode(), Mode::XApic);
    assert_eq!(a.mmio_base(), APIC_DEFAULT_BASE);
    assert_eq!(a.msr_read(MSR_APIC_BASE, 0), Ok(APIC_DEFAULT_BASE | EN | 1 << 8));
    assert_eq!(a.msr_read(ID, 0), Err(Fault), "the x2APIC window is closed in xAPIC mode");
    // EXTD without EN, and reserved bits.
    assert_eq!(a.msr_write(MSR_APIC_BASE, APIC_DEFAULT_BASE | EXTD, 0), Err(Fault));
    assert_eq!(a.msr_write(MSR_APIC_BASE, APIC_DEFAULT_BASE | EN | 1, 0), Err(Fault));
    assert_eq!(a.msr_write(MSR_APIC_BASE, APIC_DEFAULT_BASE | EN | 1 << 9, 0), Err(Fault));
    // xAPIC -> x2APIC.
    assert_eq!(a.msr_write(MSR_APIC_BASE, APIC_DEFAULT_BASE | EN | EXTD, 0), Ok(Effect::Remapped));
    assert_eq!(a.mode(), Mode::X2Apic);
    assert_eq!(a.msr_read(MSR_APIC_BASE, 0), Ok(APIC_DEFAULT_BASE | EN | EXTD | 1 << 8), "BSP is not the guest's to change");
    // x2APIC -> xAPIC is refused; x2APIC -> disabled is not.
    assert_eq!(a.msr_write(MSR_APIC_BASE, APIC_DEFAULT_BASE | EN, 0), Err(Fault));
    assert_eq!(a.msr_write(MSR_APIC_BASE, APIC_DEFAULT_BASE, 0), Ok(Effect::Remapped));
    assert_eq!(a.mode(), Mode::Off);
    // Disabled -> x2APIC directly is refused; through xAPIC it is not.
    assert_eq!(a.msr_write(MSR_APIC_BASE, APIC_DEFAULT_BASE | EN | EXTD, 0), Err(Fault));
    assert_eq!(a.msr_write(MSR_APIC_BASE, APIC_DEFAULT_BASE | EN, 0), Ok(Effect::Remapped));
    // Relocating the page is a remap too.
    assert_eq!(a.msr_write(MSR_APIC_BASE, 0xFED0_0000 | EN, 0), Ok(Effect::Remapped));
    assert_eq!(a.mmio_base(), 0xFED0_0000);
    // A disabled APIC takes no interrupt.
    a.msr_write(MSR_APIC_BASE, 0xFED0_0000, 0).unwrap();
    let ipi = Ipi { vector: 0x40, delivery: Delivery::Fixed, logical: false, level: false, assert: true, dest: 0, broadcast: true, shorthand: Shorthand::None };
    assert!(!a.accepts(&ipi));
    a.deliver(&ipi);
    assert!(!a.has_work());
}

// ── priority and EOI ────────────────────────────────────────────────────

#[test]
fn the_highest_priority_class_goes_first_and_in_service_blocks_the_lower() {
    let mut a = x2(0);
    for v in [0x31u64, 0x45, 0x91] {
        wr(&mut a, SELF_IPI, v);
    }
    // IRR is visible: 0x31 = word 1 bit 17, 0x45 = word 2 bit 5, 0x91 = word 4 bit 17.
    assert_eq!(rd(&mut a, IRR0 + 1), 1 << 17);
    assert_eq!(rd(&mut a, IRR0 + 2), 1 << 5);
    assert_eq!(rd(&mut a, IRR0 + 4), 1 << 17);
    assert_eq!(a.pending(), Some(0x91));
    assert_eq!(take(&mut a), Some(0x91));
    assert_eq!(rd(&mut a, ISR0 + 4), 1 << 17);
    assert_eq!(rd(&mut a, IRR0 + 4), 0, "requested -> in service");
    // PPR is now the class in service: 0x90. Lower classes wait.
    assert_eq!(rd(&mut a, PPR), 0x90);
    assert_eq!(a.pending(), None);
    // A higher class interrupts it.
    wr(&mut a, SELF_IPI, 0xA2);
    assert_eq!(take(&mut a), Some(0xA2));
    assert_eq!(rd(&mut a, PPR), 0xA0);
    // EOI retires the highest in service, innermost first.
    wr(&mut a, EOI, 0);
    assert_eq!(rd(&mut a, PPR), 0x90);
    assert_eq!(rd(&mut a, ISR0 + 5), 0);
    wr(&mut a, EOI, 0);
    assert_eq!(rd(&mut a, PPR), 0);
    assert_eq!(rd(&mut a, ISR0 + 4), 0);
    assert_eq!(take(&mut a), Some(0x45), "now the next class is deliverable");
    assert_eq!(take(&mut a), None, "0x31 waits behind 0x45 in service");
    wr(&mut a, EOI, 0);
    assert_eq!(take(&mut a), Some(0x31));
    // EOI with nothing in service is harmless.
    wr(&mut a, EOI, 0);
    wr(&mut a, EOI, 0);
    assert_eq!(a.pending(), None);
}

#[test]
fn the_task_priority_blocks_its_own_class_and_below() {
    let mut a = x2(0);
    wr(&mut a, SELF_IPI, 0x45);
    wr(&mut a, TPR, 0x40);
    assert_eq!(a.pending(), None, "same class as TPR is not enough");
    wr(&mut a, TPR, 0x4F);
    assert_eq!(a.pending(), None, "TPR[3:0] does not count");
    wr(&mut a, TPR, 0x30);
    assert_eq!(a.pending(), Some(0x45));
    // Raised again after the vector is requested: it is held, not lost.
    wr(&mut a, TPR, 0x50);
    assert_eq!(a.pending(), None);
    assert!(a.has_work());
    wr(&mut a, TPR, 0);
    assert_eq!(take(&mut a), Some(0x45));
    // PPR in the same class as the TPR keeps the TPR's low nibble.
    wr(&mut a, TPR, 0x4F);
    assert_eq!(rd(&mut a, PPR), 0x4F);
    // PPR with TPR above the in-service class is the TPR.
    wr(&mut a, TPR, 0x70);
    assert_eq!(rd(&mut a, PPR), 0x70);
}

#[test]
fn only_a_level_triggered_vector_broadcasts_its_eoi() {
    let mut a = x2(0);
    let level = Ipi { vector: 0x60, delivery: Delivery::Fixed, logical: false, level: true, assert: true, dest: 0, broadcast: true, shorthand: Shorthand::None };
    a.deliver(&level);
    a.deliver(&Ipi { vector: 0x70, level: false, ..level });
    assert_eq!(take(&mut a), Some(0x70));
    assert_eq!(a.msr_write(EOI, 0, 0), Ok(Effect::None), "edge: nothing to broadcast");
    assert_eq!(take(&mut a), Some(0x60));
    assert_eq!(a.msr_write(EOI, 0, 0), Ok(Effect::Eoi(0x60)));
    // The TMR bit says which: 0x60 = word 3 bit 0.
    assert_eq!(rd(&mut a, 0x818 + 3), 1);
}

#[test]
fn a_software_disabled_apic_masks_the_lvt_and_takes_no_fixed_interrupt() {
    let mut a = x2(0);
    wr(&mut a, LVT_TIMER, 0xEF);
    assert_eq!(rd(&mut a, LVT_TIMER), 0xEF);
    wr(&mut a, SVR, 0xFF);
    assert_eq!(rd(&mut a, LVT_TIMER), 0xEF | MASK, "disabling masks every entry");
    wr(&mut a, SELF_IPI, 0x40);
    assert!(!a.has_work());
    // While disabled a write cannot unmask.
    wr(&mut a, LVT_TIMER, 0xEF);
    assert_eq!(rd(&mut a, LVT_TIMER), 0xEF | MASK);
    wr(&mut a, SVR, 0x1FF);
    wr(&mut a, LVT_TIMER, 0xEF);
    assert_eq!(rd(&mut a, LVT_TIMER), 0xEF);
}

#[test]
fn errors_are_latched_into_esr_and_raise_the_error_vector() {
    let mut io = io();
    let mut v = vec![x2(0)];
    // A fixed IPI with a vector below 16 is an illegal send: nothing goes out.
    assert_eq!(v[0].msr_write(ICR, 5, 0), Ok(Effect::None));
    wr(&mut v[0], ESR, 0);
    assert_eq!(rd(&mut v[0], ESR), 1 << 5);
    wr(&mut v[0], ESR, 0);
    assert_eq!(rd(&mut v[0], ESR), 0, "the latch is consumed");
    // An illegal vector arriving.
    wr(&mut v[0], SELF_IPI, 3);
    wr(&mut v[0], ESR, 0);
    assert_eq!(rd(&mut v[0], ESR), 1 << 6);
    // The error LVT delivers its vector when unmasked.
    wr(&mut v[0], LVT_ERROR, 0xFE);
    send(&mut v, &mut io, 0, 5);
    assert_eq!(v[0].pending(), Some(0xFE));
    // An error LVT whose own vector is illegal does not recurse.
    take(&mut v[0]);
    wr(&mut v[0], LVT_ERROR, 0x05);
    send(&mut v, &mut io, 0, 5);
    wr(&mut v[0], ESR, 0);
    assert_eq!(rd(&mut v[0], ESR), 1 << 5 | 1 << 6);
}

// ── the timer ──────────────────────────────────────────────────────────

#[test]
fn the_divide_register_encodes_2_4_8_16_32_64_128_1() {
    // bit 3 and bits 1:0 form the index; 7 is divide by 1.
    for (enc, div) in [(0u64, 2u64), (1, 4), (2, 8), (3, 16), (8, 32), (9, 64), (0xA, 128), (0xB, 1)] {
        let mut a = x2(0);
        wr(&mut a, LVT_TIMER, 0xEF);
        wr(&mut a, DIVIDE, enc);
        a.msr_write(INITIAL, 7, 1000).unwrap();
        assert_eq!(a.next_deadline(), Some(1000 + 7 * div * TPT), "encoding {enc:#x}");
    }
    // Reserved bits of the divide register do not stick.
    let mut a = x2(0);
    wr(&mut a, DIVIDE, 0xFF);
    assert_eq!(rd(&mut a, DIVIDE), 0xB);
}

#[test]
fn one_shot_counts_down_fires_once_and_stops() {
    let mut a = x2(0);
    wr(&mut a, LVT_TIMER, 0xEF);
    wr(&mut a, DIVIDE, 3); // divide by 16: one count = 160 TSC cycles
    assert_eq!(a.next_deadline(), None, "nothing armed");
    a.msr_write(INITIAL, 100, 1000).unwrap();
    assert_eq!(a.next_deadline(), Some(1000 + 100 * 160));
    assert_eq!(a.msr_read(CURRENT, 1000), Ok(100));
    assert_eq!(a.msr_read(CURRENT, 1000 + 8000), Ok(50));
    a.tick(1000 + 15_999);
    assert_eq!(a.pending(), None);
    a.tick(17_000);
    assert_eq!(a.pending(), Some(0xEF));
    assert_eq!(a.msr_read(CURRENT, 17_000), Ok(0));
    assert_eq!(a.msr_read(CURRENT, 99_000), Ok(0), "it stays at zero");
    assert_eq!(a.next_deadline(), None);
    assert_eq!(take(&mut a), Some(0xEF));
    a.tick(99_000);
    assert_eq!(a.pending(), None, "one-shot fires once");
    // Re-arm: a write of the initial count restarts it.
    a.msr_write(INITIAL, 10, 200_000).unwrap();
    assert_eq!(a.next_deadline(), Some(200_000 + 1600));
    // Writing zero stops it.
    a.msr_write(INITIAL, 0, 200_100).unwrap();
    assert_eq!(a.next_deadline(), None);
    a.tick(300_000);
    assert!(a.pending().is_none());
}

#[test]
fn periodic_reloads_and_coalesces_the_periods_it_missed() {
    let mut a = x2(0);
    wr(&mut a, LVT_TIMER, 0xEF | 1 << 17); // periodic
    wr(&mut a, DIVIDE, 0xB); // divide by 1: one count = 10 cycles
    a.msr_write(INITIAL, 10, 0).unwrap();
    assert_eq!(a.next_deadline(), Some(100));
    a.tick(100);
    assert_eq!(take(&mut a), Some(0xEF));
    wr(&mut a, EOI, 0);
    assert_eq!(a.next_deadline(), Some(200), "reloaded");
    // 2.5 periods late: one interrupt, the schedule stays on the grid.
    a.tick(450);
    assert_eq!(take(&mut a), Some(0xEF));
    wr(&mut a, EOI, 0);
    assert_eq!(take(&mut a), None);
    assert_eq!(a.next_deadline(), Some(500));
    // The count runs from the grid: 450 is 5 counts into the period of 10.
    assert_eq!(a.msr_read(CURRENT, 450), Ok(5));
    assert_eq!(a.msr_read(CURRENT, 400), Ok(10), "a period starts full");
    wr(&mut a, EOI, 0);
}

#[test]
fn a_guest_tsc_near_the_top_of_the_range_cannot_overflow_the_timer() {
    // The guest can WRMSR IA32_TSC to anything, so `now` is guest-chosen.
    let near = u64::MAX - 10;
    // One-shot armed near the top: the expiry saturates and does not wrap
    // to a small value (which would fire at once).
    let mut a = x2(0);
    wr(&mut a, LVT_TIMER, 0xEF);
    wr(&mut a, DIVIDE, 3);
    a.msr_write(INITIAL, 100, near).unwrap();
    assert_eq!(a.next_deadline(), Some(u64::MAX));
    a.tick(near);
    assert_eq!(a.pending(), None, "it did not fire at once");
    assert_eq!(a.msr_read(CURRENT, near), Ok(100));
    // Periodic: reload past the top saturates instead of panicking.
    let mut p = x2(0);
    wr(&mut p, LVT_TIMER, 0xEF | 1 << 17);
    wr(&mut p, DIVIDE, 0xB);
    p.msr_write(INITIAL, 10, 0).unwrap();
    p.tick(u64::MAX);
    assert_eq!(take(&mut p), Some(0xEF));
    assert_eq!(p.next_deadline(), Some(u64::MAX));
    let _ = p.msr_read(CURRENT, u64::MAX).unwrap();
    // A huge initial count times a huge divisor and tsc_per_tick saturates.
    let mut h = Vlapic::new(0, true, u64::MAX);
    h.msr_write(MSR_APIC_BASE, APIC_DEFAULT_BASE | EN | EXTD | 1 << 8, 0).unwrap();
    h.msr_write(SVR, 0x1FF, 0).unwrap();
    h.msr_write(LVT_TIMER, 0xEF, 0).unwrap();
    h.msr_write(DIVIDE, 0xA, 0).unwrap();
    h.msr_write(INITIAL, u32::MAX as u64, near).unwrap();
    assert_eq!(h.next_deadline(), Some(u64::MAX));
    let _ = h.msr_read(CURRENT, near).unwrap();
}

#[test]
fn a_masked_timer_counts_but_never_interrupts() {
    let mut a = x2(0);
    wr(&mut a, LVT_TIMER, 0xEF | MASK);
    wr(&mut a, DIVIDE, 0xB);
    a.msr_write(INITIAL, 10, 0).unwrap();
    assert_eq!(a.next_deadline(), None, "the host need not wake for it");
    assert_eq!(a.msr_read(CURRENT, 30), Ok(7), "the count still reads");
    a.tick(1000);
    assert_eq!(a.pending(), None);
    assert!(!a.has_work());
    assert_eq!(a.msr_read(CURRENT, 1000), Ok(0));
}

#[test]
fn tsc_deadline_fires_at_the_value_and_is_cleared_by_it() {
    let mut a = x2(0);
    wr(&mut a, LVT_TIMER, 0xEE | 2 << 17);
    assert_eq!(a.msr_read(MSR_TSC_DEADLINE, 0), Ok(0));
    assert_eq!(a.msr_write(MSR_TSC_DEADLINE, 5000, 1000), Ok(Effect::None));
    assert_eq!(a.msr_read(MSR_TSC_DEADLINE, 1000), Ok(5000));
    assert_eq!(a.next_deadline(), Some(5000));
    a.tick(4999);
    assert_eq!(a.pending(), None);
    a.tick(5000);
    assert_eq!(a.pending(), Some(0xEE));
    assert_eq!(a.msr_read(MSR_TSC_DEADLINE, 5000), Ok(0), "reads zero once fired");
    assert_eq!(a.next_deadline(), None);
    take(&mut a);
    wr(&mut a, EOI, 0);
    // A deadline already past fires on the write.
    a.msr_write(MSR_TSC_DEADLINE, 3000, 6000).unwrap();
    assert_eq!(take(&mut a), Some(0xEE));
    // Zero disarms.
    a.msr_write(MSR_TSC_DEADLINE, 9000, 6000).unwrap();
    a.msr_write(MSR_TSC_DEADLINE, 0, 6001).unwrap();
    assert_eq!(a.next_deadline(), None);
    // The initial count has no meaning in this mode: it neither arms nor
    // disarms a deadline.
    a.msr_write(INITIAL, 5, 6002).unwrap();
    assert_eq!(a.next_deadline(), None);
    wr(&mut a, EOI, 0);
    a.msr_write(MSR_TSC_DEADLINE, 8000, 6003).unwrap();
    a.msr_write(INITIAL, 7, 6004).unwrap();
    assert_eq!(a.next_deadline(), Some(8000));
    a.tick(8000);
    assert_eq!(a.pending(), Some(0xEE));
}

#[test]
fn a_timer_that_expired_while_masked_is_lost_not_delivered_at_unmask() {
    let mut a = x2(0);
    wr(&mut a, LVT_TIMER, 0xEF | MASK);
    wr(&mut a, DIVIDE, 0xB);
    a.msr_write(INITIAL, 10, 0).unwrap(); // expires at 100
    // The host never ticks (no deadline while masked); the guest unmasks later.
    a.msr_write(LVT_TIMER, 0xEF, 500).unwrap();
    assert_eq!(a.pending(), None);
    assert!(!a.has_work());
    assert_eq!(a.next_deadline(), None, "the one-shot is spent");
    // Periodic: the missed periods are lost too, and the next one is on the grid.
    a.msr_write(LVT_TIMER, 0xEF | 1 << 17 | MASK, 500).unwrap();
    a.msr_write(INITIAL, 10, 1000).unwrap(); // 1100, 1200, ...
    a.msr_write(LVT_TIMER, 0xEF | 1 << 17, 1150).unwrap();
    assert_eq!(a.pending(), None);
    assert_eq!(a.next_deadline(), Some(1200));
}

#[test]
fn changing_the_timer_mode_disarms_it_and_the_deadline_msr_needs_its_mode() {
    let mut a = x2(0);
    wr(&mut a, LVT_TIMER, 0xEE | 2 << 17);
    a.msr_write(MSR_TSC_DEADLINE, 9000, 0).unwrap();
    wr(&mut a, LVT_TIMER, 0xEE | 1 << 17);
    assert_eq!(a.next_deadline(), None, "leaving deadline mode disarms");
    assert_eq!(a.msr_read(MSR_TSC_DEADLINE, 0), Ok(0));
    // In a counting mode the MSR write is ignored.
    a.msr_write(MSR_TSC_DEADLINE, 1, 0).unwrap();
    a.tick(100);
    assert_eq!(a.pending(), None);
    // And the other direction.
    wr(&mut a, DIVIDE, 0xB);
    a.msr_write(INITIAL, 10, 0).unwrap();
    wr(&mut a, LVT_TIMER, 0xEE | 2 << 17);
    assert_eq!(a.next_deadline(), None);
    // Rewriting the same mode keeps what is armed.
    wr(&mut a, LVT_TIMER, 0xEE);
    a.msr_write(INITIAL, 10, 0).unwrap();
    wr(&mut a, LVT_TIMER, 0xED);
    assert_eq!(a.next_deadline(), Some(100));
    // The reserved mode is a #GP.
    assert_eq!(a.msr_write(LVT_TIMER, 3 << 17, 0), Err(Fault));
}

#[test]
fn the_timer_interrupt_waits_for_the_task_priority() {
    let mut a = x2(0);
    wr(&mut a, TPR, 0xF0);
    wr(&mut a, LVT_TIMER, 0xEF);
    wr(&mut a, DIVIDE, 0xB);
    a.msr_write(INITIAL, 1, 0).unwrap();
    a.tick(10);
    assert_eq!(a.pending(), None);
    assert!(a.has_work(), "the vCPU must not sleep through it");
    wr(&mut a, TPR, 0);
    assert_eq!(a.pending(), Some(0xEF));
}

// ── IPIs ───────────────────────────────────────────────────────────────

fn icr(vector: u8, delivery: u64, dest: u32, flags: u64) -> u64 {
    vector as u64 | delivery << 8 | flags | (dest as u64) << 32
}

#[test]
fn a_physical_ipi_reaches_the_one_vcpu_it_names() {
    let mut v = vm(4);
    let mut io = io();
    assert_eq!(send(&mut v, &mut io, 0, icr(0x41, 0, 2, 0)), 1 << 2);
    assert_eq!((v[0].pending(), v[1].pending(), v[2].pending(), v[3].pending()), (None, None, Some(0x41), None));
    // Broadcast.
    assert_eq!(send(&mut v, &mut io, 1, icr(0x42, 0, 0xFFFF_FFFF, 0)), 0b1111);
    // A destination that names nobody.
    assert_eq!(send(&mut v, &mut io, 1, icr(0x43, 0, 9, 0)), 0);
}

#[test]
fn the_shorthands_pick_self_all_or_all_but_self() {
    let mut v = vm(3);
    let mut io = io();
    assert_eq!(send(&mut v, &mut io, 1, icr(0x50, 0, 0, 1 << 18)), 0b010);
    assert_eq!(send(&mut v, &mut io, 1, icr(0x51, 0, 0, 2 << 18)), 0b111);
    assert_eq!(send(&mut v, &mut io, 1, icr(0x52, 0, 0, 3 << 18)), 0b101);
    assert_eq!(take(&mut v[1]), Some(0x51), "self and all, not the all-but-self one");
    wr(&mut v[1], EOI, 0);
    assert_eq!(take(&mut v[1]), Some(0x50));
    assert_eq!(v[1].pending(), None);
}

#[test]
fn logical_destinations_match_cluster_and_bit() {
    let mut v = vm(20);
    let mut io = io();
    // vCPU 3: cluster 0 bit 3; vCPU 17: cluster 1 bit 1.
    let logical = 1 << 11;
    assert_eq!(send(&mut v, &mut io, 0, icr(0x60, 0, 0b1010, logical)), 1 << 1 | 1 << 3);
    assert_eq!(send(&mut v, &mut io, 0, icr(0x61, 0, 1 << 16 | 0b0010, logical)), 1 << 17);
    assert_eq!(send(&mut v, &mut io, 0, icr(0x62, 0, 2 << 16 | 0b0010, logical)), 0, "no such cluster");
    assert_eq!(send(&mut v, &mut io, 0, icr(0x63, 0, 0b0, logical)), 0);
}

#[test]
fn lowest_priority_picks_the_vcpu_with_the_lowest_processor_priority() {
    let mut v = vm(3);
    let mut io = io();
    for (i, t) in [(0, 0x30), (1, 0x10), (2, 0x20)] {
        wr(&mut v[i], TPR, t);
    }
    let logical = 1 << 11;
    assert_eq!(send(&mut v, &mut io, 0, icr(0x70, 1, 0b111, logical)), 1 << 1);
    // A vCPU busy with a high-priority interrupt in service loses.
    take(&mut v[1]);
    wr(&mut v[1], SELF_IPI, 0xC0);
    take(&mut v[1]);
    assert_eq!(send(&mut v, &mut io, 0, icr(0x71, 1, 0b111, logical)), 1 << 2);
    // Ties go to the lowest index.
    for a in v.iter_mut() {
        wr(a, TPR, 0);
    }
    wr(&mut v[1], EOI, 0);
    assert_eq!(send(&mut v, &mut io, 2, icr(0x72, 1, 0b111, logical)), 1);
}

#[test]
fn init_startup_nmi_and_smi_are_events_for_the_target_vcpu() {
    let mut v = vm(2);
    let mut io = io();
    let assert_flag = 1 << 14;
    send(&mut v, &mut io, 0, icr(0, 5, 1, assert_flag));
    send(&mut v, &mut io, 0, icr(0x9A, 6, 1, assert_flag));
    send(&mut v, &mut io, 0, icr(0, 4, 1, assert_flag));
    send(&mut v, &mut io, 0, icr(0, 2, 1, assert_flag));
    assert!(v[1].has_work());
    assert_eq!(
        [v[1].take_event(), v[1].take_event(), v[1].take_event(), v[1].take_event(), v[1].take_event()],
        [Some(Event::Init), Some(Event::Startup(0x9A)), Some(Event::Smi), Some(Event::Nmi), None]
    );
    assert!(!v[1].has_work());
    assert_eq!(v[0].take_event(), None, "only the target");
    // An INIT level de-assert (level trigger, assert clear) is only a sync.
    send(&mut v, &mut io, 0, icr(0, 5, 1, 1 << 15));
    assert_eq!(v[1].take_event(), None);
    // INIT resets the register state but not the ID or the mode.
    wr(&mut v[1], TPR, 0x40);
    wr(&mut v[1], SELF_IPI, 0x55);
    v[1].init_reset();
    assert_eq!((v[1].pending(), v[1].id(), v[1].mode()), (None, 1, Mode::X2Apic));
    assert_eq!(rd(&mut v[1], TPR), 0);
    assert_eq!(rd(&mut v[1], SVR), 0xFF, "software-disabled again");
    assert_eq!(rd(&mut v[1], LVT_TIMER), MASK);
}

#[test]
fn a_level_triggered_ipi_broadcasts_its_eoi_to_the_ioapic() {
    let mut v = vm(2);
    let mut io = io();
    // IOAPIC pin 3: level, vector 0x66, vCPU 1, with the line held high.
    ioapic_program(&mut io, 3, 0x66 | 1 << 15, 1);
    deliver_all(&mut v, &io.set_irq(3, true));
    assert_eq!(take(&mut v[1]), Some(0x66));
    // Another level IPI with the same vector from vCPU 0 shares the TMR bit
    // semantics: its EOI is a broadcast too.
    let e = v[1].msr_write(EOI, 0, 0).unwrap();
    assert_eq!(e, Effect::Eoi(0x66));
    assert_eq!(deliver_effect(&mut v, &mut io, 1, e), 1 << 1, "line still high: sent again");
    assert_eq!(v[1].pending(), Some(0x66));
}

// ── xAPIC mode through MMIO ──────────────────────────────────────────────

fn xapic(id: u32) -> Vlapic {
    let mut a = Vlapic::new(id, id == 0, TPT);
    a.mmio_write(APIC_DEFAULT_BASE + 0xF0, 4, 0x1FF, 0).unwrap();
    a
}

#[test]
fn the_xapic_page_answers_32_bit_aligned_accesses_inside_it() {
    let mut a = xapic(3);
    let b = APIC_DEFAULT_BASE;
    assert_eq!(a.mmio_read(b + 0x20, 4, 0), Ok(3 << 24), "xAPIC ID is in bits 31:24");
    assert_eq!(a.mmio_read(b + 0x30, 4, 0), Ok(0x0006_0014));
    assert_eq!(a.mmio_read(b + 0x20, 8, 0), Err(Fault));
    assert_eq!(a.mmio_read(b + 0x20, 2, 0), Err(Fault));
    assert_eq!(a.mmio_read(b + 0x24, 4, 0), Err(Fault), "registers sit on 16 bytes");
    assert_eq!(a.mmio_read(b + 0x1000, 4, 0), Err(Fault));
    assert_eq!(a.mmio_read(b - 16, 4, 0), Err(Fault));
    // Reserved offsets read as zero and ignore writes; read-only ones too.
    assert_eq!(a.mmio_read(b + 0x3C0, 4, 0), Ok(0));
    assert_eq!(a.mmio_write(b + 0x3C0, 4, 9, 0), Ok(Effect::None));
    assert_eq!(a.mmio_write(b + 0x20, 4, 9, 0), Ok(Effect::None));
    assert_eq!(a.mmio_read(b + 0x20, 4, 0), Ok(3 << 24));
    // The page is closed once the guest is in x2APIC mode.
    a.msr_write(MSR_APIC_BASE, APIC_DEFAULT_BASE | EN | EXTD, 0).unwrap();
    assert_eq!(a.mmio_read(b + 0x20, 4, 0), Err(Fault));
}

#[test]
fn the_xapic_icr_is_two_registers_and_the_low_write_sends() {
    let mut v = vec![xapic(0), xapic(1), xapic(2)];
    let mut io = io();
    let b = APIC_DEFAULT_BASE;
    assert_eq!(v[0].mmio_write(b + 0x310, 4, 2 << 24, 0), Ok(Effect::None), "the high half only stores");
    let e = v[0].mmio_write(b + 0x300, 4, 0x41, 0).unwrap();
    assert_eq!(deliver_effect(&mut v, &mut io, 0, e), 1 << 2);
    assert_eq!(v[2].pending(), Some(0x41));
    assert_eq!(v[0].mmio_read(b + 0x310, 4, 0), Ok(2 << 24));
    // xAPIC broadcast is 0xFF.
    v[0].mmio_write(b + 0x310, 4, 0xFF << 24, 0).unwrap();
    let e = v[0].mmio_write(b + 0x300, 4, 0x42, 0).unwrap();
    assert_eq!(deliver_effect(&mut v, &mut io, 0, e), 0b111);
}

#[test]
fn xapic_logical_destinations_use_flat_or_cluster_format() {
    let mut v = vec![xapic(0), xapic(1), xapic(2)];
    let b = APIC_DEFAULT_BASE;
    // Flat (the reset DFR): one bit per APIC in LDR[31:24].
    for (i, a) in v.iter_mut().enumerate() {
        a.mmio_write(b + 0xD0, 4, (1 << i) << 24, 0).unwrap();
    }
    assert_eq!(v[1].mmio_read(b + 0xD0, 4, 0), Ok(2 << 24));
    assert_eq!(v[1].mmio_read(b + 0xE0, 4, 0), Ok(0xFFFF_FFFF));
    let logical = |dest: u32| Ipi { vector: 0x80, delivery: Delivery::Fixed, logical: true, level: false, assert: true, dest, broadcast: false, shorthand: Shorthand::None };
    assert_eq!(route(&mut v, None, &logical(0b110)), 0b110);
    // Cluster model (DFR = 0): high nibble is the cluster, low the member bits.
    for a in v.iter_mut() {
        a.mmio_write(b + 0xE0, 4, 0, 0).unwrap();
    }
    v[0].mmio_write(b + 0xD0, 4, 0x13 << 24, 0).unwrap();
    v[1].mmio_write(b + 0xD0, 4, 0x24 << 24, 0).unwrap();
    v[2].mmio_write(b + 0xD0, 4, 0x21 << 24, 0).unwrap();
    assert_eq!(route(&mut v, None, &logical(0x11)), 0b001);
    assert_eq!(route(&mut v, None, &logical(0x25)), 0b110);
    assert_eq!(route(&mut v, None, &logical(0x22)), 0, "right cluster, no member bit");
    assert_eq!(route(&mut v, None, &logical(0x31)), 0, "no such cluster");
    assert_eq!(route(&mut v, None, &logical(0xF1)), 0b101, "cluster F is every cluster");
}

#[test]
fn the_xapic_timer_registers_work_through_the_page() {
    let mut a = xapic(0);
    let b = APIC_DEFAULT_BASE;
    a.mmio_write(b + 0x320, 4, 0xEF, 0).unwrap();
    a.mmio_write(b + 0x3E0, 4, 0xB, 0).unwrap();
    a.mmio_write(b + 0x380, 4, 50, 1000).unwrap();
    assert_eq!(a.mmio_read(b + 0x390, 4, 1200), Ok(30));
    assert_eq!(a.next_deadline(), Some(1500));
    a.tick(1500);
    assert_eq!(a.pending(), Some(0xEF));
    assert_eq!(a.mmio_write(b + 0xB0, 4, 0, 0), Ok(Effect::None));
    // The LVT keeps the status bits read-only: polarity / trigger stick on LINT0 only.
    a.mmio_write(b + 0x350, 4, 0x0000_A700 | 0x30, 0).unwrap();
    assert_eq!(a.mmio_read(b + 0x350, 4, 0), Ok(0xA730 & !(1 << 12)));
}

#[test]
fn local_interrupt_entries_deliver_by_their_mode_when_unmasked() {
    let mut a = x2(0);
    // LINT0 masked: swallowed.
    a.raise(Lvt::Lint0);
    assert!(!a.has_work());
    // ExtINT (mode 7) and NMI (mode 4) become events; fixed becomes a vector.
    wr(&mut a, LVT_LINT0, 7 << 8);
    a.raise(Lvt::Lint0);
    assert_eq!(a.take_event(), Some(Event::ExtInt));
    wr(&mut a, LVT_LINT0, 4 << 8);
    a.raise(Lvt::Lint0);
    assert_eq!(a.take_event(), Some(Event::Nmi));
    wr(&mut a, LVT_LINT0, 0x90);
    a.raise(Lvt::Lint0);
    assert_eq!(a.pending(), Some(0x90));
}

// ── the IOAPIC ──────────────────────────────────────────────────────────

const IO_SEL: u64 = IOAPIC_DEFAULT_BASE;
const IO_WIN: u64 = IOAPIC_DEFAULT_BASE + 0x10;
const IO_EOI: u64 = IOAPIC_DEFAULT_BASE + 0x40;

fn io_rd(io: &Vioapic, idx: u32) -> u32 {
    // Index through a copy: reading needs only the selection.
    let mut c = io.clone();
    c.mmio_write(IO_SEL, 4, idx).unwrap();
    c.mmio_read(IO_WIN, 4).unwrap()
}

fn io_wr(io: &mut Vioapic, idx: u32, v: u32) -> azos_hv::vioapic::Msgs {
    io.mmio_write(IO_SEL, 4, idx).unwrap();
    io.mmio_write(IO_WIN, 4, v).unwrap()
}

/// Program redirection entry `pin`: low dword `lo`, physical destination `dest`.
fn ioapic_program(io: &mut Vioapic, pin: u32, lo: u32, dest: u8) -> azos_hv::vioapic::Msgs {
    io_wr(io, 0x11 + 2 * pin, (dest as u32) << 24);
    io_wr(io, 0x10 + 2 * pin, lo)
}

#[test]
fn the_ioapic_resets_masked_and_describes_itself() {
    let io = Vioapic::new(2, IOAPIC_DEFAULT_BASE);
    assert_eq!(io_rd(&io, 0), 2 << 24);
    // Version 0x20, highest entry 23.
    assert_eq!(io_rd(&io, 1), 0x0017_0020);
    for pin in 0..24 {
        assert_eq!(io_rd(&io, 0x10 + 2 * pin), 1 << 16, "pin {pin} masked");
        assert_eq!(io_rd(&io, 0x11 + 2 * pin), 0);
    }
    assert_eq!(io_rd(&io, 0x10 + 48), 0, "past the table");
    // IOREGSEL reads back.
    let mut io = io;
    io.mmio_write(IO_SEL, 4, 0x13).unwrap();
    assert_eq!(io.mmio_read(IO_SEL, 4), Ok(0x13));
    // Only 32-bit accesses inside the window.
    assert_eq!(io.mmio_read(IO_WIN, 1), Err(Fault));
    assert_eq!(io.mmio_write(IO_WIN, 8, 0), Err(Fault));
    assert_eq!(io.mmio_read(IOAPIC_DEFAULT_BASE + 0x1000, 4), Err(Fault));
    assert_eq!(io.mmio_read(IOAPIC_DEFAULT_BASE - 4, 4), Err(Fault));
}

#[test]
fn an_entry_reads_back_with_the_read_only_bits_the_hardware_owns() {
    let mut io = io();
    // Vector 0x34, delivery mode 1, logical, active low, edge, unmasked;
    // bits 12 and 14 written 1 must not stick.
    ioapic_program(&mut io, 5, 0x34 | 1 << 8 | 1 << 11 | 1 << 12 | 1 << 13 | 1 << 14, 0x81);
    assert_eq!(io_rd(&io, 0x10 + 10), 0x34 | 1 << 8 | 1 << 11 | 1 << 13);
    assert_eq!(io_rd(&io, 0x11 + 10), 0x81 << 24);
    // The low bits of the high dword are reserved.
    io_wr(&mut io, 0x11 + 10, 0x00FF_FFFF);
    assert_eq!(io_rd(&io, 0x11 + 10), 0);
    // ID is 4 bits.
    io_wr(&mut io, 0, 0xFF00_0000);
    assert_eq!(io_rd(&io, 0), 0x0F00_0000);
    // Version is read-only.
    io_wr(&mut io, 1, 0);
    assert_eq!(io_rd(&io, 1), 0x0017_0020);
}

#[test]
fn an_edge_line_reaches_the_vlapic_its_entry_names_once_per_rising_edge() {
    let mut v = vm(4);
    let mut io = io();
    ioapic_program(&mut io, 4, 0x34, 1);
    let m = io.set_irq(4, true);
    assert_eq!(m.len(), 1);
    assert_eq!(deliver_all(&mut v, &m), 1 << 1);
    assert_eq!(take(&mut v[1]), Some(0x34));
    assert!(v[0].pending().is_none() && v[2].pending().is_none());
    // Held high: nothing more. A new edge: one more.
    assert!(io.set_irq(4, true).is_empty());
    assert!(io.set_irq(4, false).is_empty());
    assert_eq!(deliver_all(&mut v, &io.set_irq(4, true)), 1 << 1);
    // An out-of-range pin is nothing.
    assert!(io.set_irq(24, true).is_empty());
}

#[test]
fn a_masked_entry_loses_edges_and_resends_levels_when_unmasked() {
    let mut v = vm(2);
    let mut io = io();
    ioapic_program(&mut io, 2, 0x40 | 1 << 16, 0);
    assert!(io.set_irq(2, true).is_empty());
    assert!(io.set_irq(2, false).is_empty());
    // Unmasking an edge entry with the line low sends nothing.
    assert!(ioapic_program(&mut io, 2, 0x40, 0).is_empty());
    // A level entry, line high while masked: sent at unmask.
    ioapic_program(&mut io, 6, 0x50 | 1 << 15 | 1 << 16, 1);
    assert!(io.set_irq(6, true).is_empty());
    let m = ioapic_program(&mut io, 6, 0x50 | 1 << 15, 1);
    assert_eq!(deliver_all(&mut v, &m), 1 << 1);
    assert_eq!(v[1].pending(), Some(0x50));
}

#[test]
fn a_level_entry_stays_outstanding_until_the_eoi_and_resends_if_still_high() {
    let mut v = vm(2);
    let mut io = io();
    ioapic_program(&mut io, 9, 0x50 | 1 << 15, 0);
    let m = io.set_irq(9, true);
    assert_eq!(m.len(), 1);
    assert!(m.as_slice()[0].level);
    deliver_all(&mut v, &m);
    // Remote IRR is visible in the entry.
    assert_eq!(io_rd(&io, 0x10 + 18) & (1 << 14), 1 << 14);
    // Line toggling while outstanding sends nothing.
    assert!(io.set_irq(9, false).is_empty());
    assert!(io.set_irq(9, true).is_empty());
    // The guest takes it, then EOIs: the vLAPIC says broadcast; the line is
    // still high, so it is sent again.
    assert_eq!(take(&mut v[0]), Some(0x50));
    let e = v[0].msr_write(EOI, 0, 0).unwrap();
    assert_eq!(e, Effect::Eoi(0x50));
    assert_eq!(deliver_effect(&mut v, &mut io, 0, e), 1);
    assert_eq!(v[0].pending(), Some(0x50));
    // Drop the line, EOI again: remote IRR clears and nothing is sent.
    io.set_irq(9, false);
    take(&mut v[0]);
    let e = v[0].msr_write(EOI, 0, 0).unwrap();
    assert_eq!(deliver_effect(&mut v, &mut io, 0, e), 0);
    assert_eq!(io_rd(&io, 0x10 + 18) & (1 << 14), 0);
    assert_eq!(v[0].pending(), None);
}

#[test]
fn the_eoi_register_and_a_switch_to_edge_clear_remote_irr() {
    let mut io = io();
    ioapic_program(&mut io, 1, 0x61 | 1 << 15, 0);
    ioapic_program(&mut io, 2, 0x62 | 1 << 15, 0);
    io.set_irq(1, true);
    io.set_irq(2, true);
    assert_eq!(io_rd(&io, 0x10 + 2) >> 14 & 1, 1);
    // Vector 0x61 through the EOI register (offset 0x40): line high, resends.
    let m = io.mmio_write(IO_EOI, 4, 0x61).unwrap();
    assert_eq!(m.len(), 1);
    assert_eq!(m.as_slice()[0].vector, 0x61);
    // Pin 2: reprogrammed as edge, the outstanding level is dropped.
    ioapic_program(&mut io, 2, 0x62, 0);
    assert_eq!(io_rd(&io, 0x10 + 4) >> 14 & 1, 0);
    // An EOI of a vector nobody has outstanding does nothing.
    assert!(io.mmio_write(IO_EOI, 4, 0x77).unwrap().is_empty());
    // Two pins sharing a vector are both released.
    ioapic_program(&mut io, 7, 0x90 | 1 << 15, 0);
    ioapic_program(&mut io, 8, 0x90 | 1 << 15, 0);
    io.set_irq(7, true);
    io.set_irq(8, true);
    io.set_irq(7, false);
    io.set_irq(8, false);
    assert!(io.eoi(0x90).is_empty());
    assert_eq!(io_rd(&io, 0x10 + 14) >> 14 & 1, 0);
    assert_eq!(io_rd(&io, 0x10 + 16) >> 14 & 1, 0);
}

#[test]
fn polarity_decides_which_level_of_the_line_is_active() {
    let mut v = vm(1);
    let mut io = io();
    // Edge, active low: the falling edge sends.
    ioapic_program(&mut io, 3, 0x38 | 1 << 13, 0);
    assert!(io.set_irq(3, true).is_empty(), "the line going high is the inactive edge");
    assert_eq!(deliver_all(&mut v, &io.set_irq(3, false)), 1);
    take(&mut v[0]);
    wr(&mut v[0], EOI, 0);
    // Level, active low: sends while low.
    // The line resets low, which is active here: unmasking sends at once.
    let m = ioapic_program(&mut io, 4, 0x39 | 1 << 13 | 1 << 15, 0);
    assert_eq!(deliver_all(&mut v, &m), 1);
    assert_eq!(v[0].pending(), Some(0x39));
    assert!(io.set_irq(4, false).is_empty(), "outstanding until the EOI");
}

#[test]
fn delivery_modes_logical_destinations_and_broadcast_of_an_entry() {
    let mut v = vm(3);
    // NMI to vCPU 2.
    let mut io = io();
    ioapic_program(&mut io, 0, 4 << 8, 2);
    assert_eq!(deliver_all(&mut v, &io.set_irq(0, true)), 1 << 2);
    assert_eq!(v[2].take_event(), Some(Event::Nmi));
    // ExtINT: the PIC's line, an event for the vCPU.
    ioapic_program(&mut io, 1, 7 << 8, 0);
    assert_eq!(deliver_all(&mut v, &io.set_irq(1, true)), 1);
    assert_eq!(v[0].take_event(), Some(Event::ExtInt));
    // Physical destination 0xFF is every APIC.
    ioapic_program(&mut io, 2, 0x44, 0xFF);
    assert_eq!(deliver_all(&mut v, &io.set_irq(2, true)), 0b111);
    // Logical, lowest priority, over x2APIC LDRs 1 | 2 | 4.
    for (i, t) in [(0, 0x20), (1, 0x10), (2, 0x30)] {
        wr(&mut v[i], TPR, t);
    }
    ioapic_program(&mut io, 3, 0x45 | 1 << 8 | 1 << 11, 0b111);
    assert_eq!(deliver_all(&mut v, &io.set_irq(3, true)), 1 << 1);
    // A reserved delivery mode sends nothing.
    ioapic_program(&mut io, 4, 0x46 | 3 << 8, 0);
    assert!(io.set_irq(4, true).is_empty());
}
