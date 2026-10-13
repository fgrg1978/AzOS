// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64 hooks of the masked-window tracer (`azos_arch_api::lat`).
//!
//! Compiled only with `lat-trace`. Same contract as the RISC-V module of the
//! same name: the hart id (`TPIDR_EL1`) and the counter (`CNTVCT_EL0`) are
//! read here, the caller supplies only a site. Masking inside this module is
//! raw `DAIF` access, never the hooked `Interrupts::disable_all`.
//!
//! Polarity: `DAIF.I` SET means masked, and `SPSR_EL1` carries the
//! interrupted context's `DAIF` at the same bit positions (bit 7 = I).

use core::panic::Location;

/// The ISA-neutral bookkeeping, reachable through the `azos_arch` facade.
pub use azos_arch_api::lat;
use azos_arch_api::lat::Kind;

use crate::sysregs::{read_daif, write_daif, DAIF_I};

/// The site value the bookkeeping stores for a `Location`.
#[inline(always)]
pub fn site(loc: &'static Location<'static>) -> usize {
    loc as *const Location<'static> as usize
}

#[inline(always)]
fn now() -> u64 {
    crate::sysregs::read_cntvct_el0()
}

#[inline(always)]
fn hart() -> usize {
    crate::cpu::hart_id()
}

/// Interrupts just went from enabled to masked at `loc`.
#[inline(never)]
pub fn irq_off(loc: &'static Location<'static>) {
    lat::open(Kind::Irq, hart(), now(), site(loc));
}

/// Interrupts are about to go from masked to enabled at `loc`. Called while
/// still masked.
#[inline(never)]
pub fn irq_on(loc: &'static Location<'static>) {
    lat::close(Kind::Irq, hart(), now(), site(loc));
}

/// `Interrupts::restore(prev)` is about to run from a guard taken at `loc`:
/// close the window now, with `loc` as its end, if the restore re-enables.
#[inline]
pub fn irq_restore_at(prev: u64, loc: &'static Location<'static>) {
    if prev & DAIF_I == 0 && read_daif() & DAIF_I != 0 {
        irq_on(loc);
    }
}

/// Exception entry. `spsr` is the saved `SPSR_EL1`: with `I` clear the
/// interrupted context had IRQs enabled, so the exception opened a window.
#[inline(never)]
pub fn trap_enter(spsr: u64, loc: &'static Location<'static>) {
    if spsr & DAIF_I == 0 {
        lat::open(Kind::Irq, hart(), now(), site(loc));
    }
}

/// Exception exit towards a context whose `SPSR_EL1` is `spsr`.
#[inline(never)]
pub fn trap_exit(spsr: u64, loc: &'static Location<'static>) {
    if spsr & DAIF_I == 0 {
        lat::close(Kind::Irq, hart(), now(), site(loc));
    }
}

/// IRQ-path exit (`aarch64_trap_resched`): an IRQ is only taken from a
/// context with IRQs unmasked, so the `eret` always re-enables.
#[inline(never)]
pub fn irq_exit(loc: &'static Location<'static>) {
    lat::close(Kind::Irq, hart(), now(), site(loc));
}

/// Preemption just went from enabled to disabled at `loc`.
#[inline(never)]
pub fn preempt_off(loc: &'static Location<'static>) {
    let d = read_daif();
    write_daif(d | DAIF_I);
    lat::open(Kind::Preempt, hart(), now(), site(loc));
    write_daif(d);
}

/// Preemption just went from disabled to enabled; the guard that ended the
/// window was taken at `loc`.
#[inline(never)]
pub fn preempt_on(loc: &'static Location<'static>) {
    let d = read_daif();
    write_daif(d | DAIF_I);
    lat::close(Kind::Preempt, hart(), now(), site(loc));
    write_daif(d);
}
